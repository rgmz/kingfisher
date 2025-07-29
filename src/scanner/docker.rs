use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use indicatif::{ProgressBar, ProgressStyle};
use oci_client::client::{linux_amd64_resolver, Client, ClientConfig};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::debug;
use walkdir::WalkDir;

use crate::decompress::decompress_file;

fn helper_get_creds(helper: &str, registry: &str) -> Option<(String, String)> {
    fn run(bin: &str, registry: &str) -> Option<(String, String)> {
        let mut child = Command::new(bin)
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        {
            let stdin = child.stdin.as_mut()?;
            let _ = stdin.write_all(format!("{registry}\n").as_bytes());
        }
        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        let v: Value = serde_json::from_slice(&output.stdout).ok()?;
        let user = v.get("Username")?.as_str()?.to_string();
        let secret = v.get("Secret")?.as_str()?.to_string();
        Some((user, secret))
    }

    let bin = format!("docker-credential-{helper}");
    if let Some(creds) = run(&bin, registry) {
        return Some(creds);
    }
    if helper == "keychain" && bin != "docker-credential-osxkeychain" {
        if let Some(creds) = run("docker-credential-osxkeychain", registry) {
            return Some(creds);
        }
    }
    None
}

/// Turn `registry.example.com/foo/bar:latest` into something like
/// `registry.example.com_foo_bar_latest_4d3c9e83`
fn image_dir_name(reference: &str) -> String {
    // keep it readable
    let mut name = reference.replace(['/', ':'], "_");

    // add a truncated SHA-256 to guarantee uniqueness
    let hash = Sha256::digest(reference.as_bytes());
    let short = &hex::encode(hash)[..8];       // 8-char prefix is plenty
    name.push('_');
    name.push_str(short);
    name
}

fn creds_from_docker_config(registry: &str) -> Option<(String, String)> {
    let config_dir = env::var("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|_| env::var("HOME").map(|h| PathBuf::from(h).join(".docker")))
        .ok()?;
    let path = config_dir.join("config.json");
    let mut content = String::new();
    File::open(path).ok()?.read_to_string(&mut content).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;

    if let Some(ch) = json.get("credHelpers").and_then(|v| v.get(registry)).and_then(|v| v.as_str())
    {
        if let Some(creds) = helper_get_creds(ch, registry) {
            return Some(creds);
        }
    }
    if let Some(store) = json.get("credsStore").and_then(|v| v.as_str()) {
        if let Some(creds) = helper_get_creds(store, registry) {
            return Some(creds);
        }
    }

    if let Some(auths) = json.get("auths").and_then(|v| v.as_object()) {
        if let Some(entry) = auths
            .get(registry)
            .or_else(|| auths.get(&format!("https://{registry}")))
            .or_else(|| auths.get(&format!("http://{registry}")))
        {
            if let Some(auth) = entry.get("auth").and_then(|v| v.as_str()) {
                let decoded = base64::engine::general_purpose::STANDARD.decode(auth).ok()?;
                let cred = String::from_utf8(decoded).ok()?;
                if let Some((u, p)) = cred.split_once(':') {
                    return Some((u.to_string(), p.to_string()));
                }
            }
        }
    }
    None
}

fn registry_auth(reference: &Reference) -> RegistryAuth {
    if let Ok(token) = env::var("KF_DOCKER_TOKEN") {
        if let Some((user, pass)) = token.split_once(':') {
            return RegistryAuth::Basic(user.to_string(), pass.to_string());
        } else {
            return RegistryAuth::Bearer(token);
        }
    }
    if let Some((user, pass)) = creds_from_docker_config(reference.registry()) {
        RegistryAuth::Basic(user, pass)
    } else {
        RegistryAuth::Anonymous
    }
}

pub struct Docker;

impl Docker {
    pub fn new() -> Self {
        Docker
    }

    fn try_save_local_image(&self, image: &str, out_dir: &Path, use_progress: bool) -> Result<()> {
        let docker = Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        if !matches!(docker, Ok(s) if s.success()) {
            return Err(anyhow!("image not local"));
        }

        let pb = if use_progress {
            let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len}")
                .expect("progress template");
            let pb = ProgressBar::new(0).with_style(style);
            pb.enable_steady_tick(Duration::from_millis(100));
            pb
        } else {
            ProgressBar::hidden()
        };
        pb.set_message(format!("saving local {image}"));

        std::fs::create_dir_all(out_dir)?;
        let tar_path = out_dir.join("local_image.tar");
        let status = Command::new("docker")
            .args(["image", "save", image, "-o", &tar_path.to_string_lossy()])
            .status()
            .with_context(|| "running docker save")?;
        if !status.success() {
            pb.finish_with_message("docker save failed");
            return Err(anyhow!("failed to save local image"));
        }

        pb.set_message("extracting layers");
        decompress_file(&tar_path, Some(out_dir))?;

        let mut layer_paths = Vec::new();
        for entry in WalkDir::new(out_dir) {
            let entry = entry?;
            if entry.file_name() == "layer.tar" {
                layer_paths.push(entry.path().to_path_buf());
            }
        }

        pb.set_length(layer_paths.len() as u64);
        for p in layer_paths {
            let mut data = Vec::new();
            File::open(&p)?.read_to_end(&mut data)?;
            let digest = format!("{:x}", Sha256::digest(&data));
            let new_path = out_dir.join(format!("layer_{digest}.tar"));
            std::fs::rename(&p, &new_path)?;
            // extract layer contents so inner filenames appear in scan results
            decompress_file(&new_path, Some(out_dir))?;
            std::fs::remove_file(&new_path)?;
            pb.inc(1);
        }

        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }

    pub async fn save_image_to_dir(
        &self,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        if self.try_save_local_image(image, out_dir, use_progress).is_ok() {
            return Ok(());
        }
        let reference: Reference =
            image.parse().with_context(|| format!("invalid image reference {image}"))?;
        debug!("Pulling {image}");
        let pb = if use_progress {
            let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len}")
                .expect("progress template");
            let pb = ProgressBar::new(0).with_style(style);
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_message(format!("pulling {image}"));
            pb
        } else {
            ProgressBar::hidden()
        };
        let client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
        let client = client;
        let auth = registry_auth(&reference);
        let accepted = vec![
            oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        ];
        let pulled = client.pull(&reference, &auth, accepted).await?;
        pb.set_length(pulled.layers.len() as u64);
        pb.set_message("extracting layers");

        std::fs::create_dir_all(out_dir)?;
        for layer in pulled.layers.into_iter() {
            let ext = match layer.media_type.as_str() {
                oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE
                | oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => "tar.gz",
                oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE
                | oci_client::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => "tar",
                _ => "bin",
            };
            let digest = layer.sha256_digest();
            let file_name = format!("layer_{}.{}", digest.replace(':', "_"), ext);
            let tmp_path = out_dir.join(file_name);
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&layer.data)?;
            decompress_file(&tmp_path, Some(out_dir))?;
            std::fs::remove_file(&tmp_path)?;
            pb.inc(1);
        }
        pb.finish_with_message(format!("saved {image}"));
        Ok(())
    }
}

pub async fn save_docker_images(
    images: &[String],
    clone_root: &Path,
    use_progress: bool,
) -> Result<Vec<(PathBuf, String)>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();
    
    for image in images {
        let dir_name = image_dir_name(image);
        let out_dir = clone_root.join(format!("docker_{dir_name}"));
        docker
            .save_image_to_dir(image, &out_dir, use_progress)
            .await
            .with_context(|| format!("saving image {image}"))?;
        dirs.push((out_dir, image.clone()));
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_struct_new() {
        let _ = Docker::new();
    }
}
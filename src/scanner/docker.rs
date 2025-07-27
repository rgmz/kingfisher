use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use oci_distribution::client::{linux_amd64_resolver, Client, ClientConfig};
use oci_distribution::{secrets::RegistryAuth, Reference};
use indicatif::{ProgressBar, ProgressStyle};
use tracing::debug;

use crate::decompress::decompress_file;

pub struct Docker;

impl Docker {
    pub fn new() -> Self {
        Docker
    }

    pub async fn save_image_to_dir(
        &self,
        image: &str,
        out_dir: &Path,
        use_progress: bool,
    ) -> Result<()> {
        let reference: Reference =
            image.parse().with_context(|| format!("invalid image reference {image}"))?;
        debug!("Pulling {image}");
        let pb = if use_progress {
            let style = ProgressStyle::with_template("{spinner} {msg}")
                .expect("progress template");
            let pb = ProgressBar::new_spinner().with_style(style);
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
        let mut client = client;
        let auth = RegistryAuth::Anonymous;
        let accepted = vec![
            oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        ];
        let pulled = client.pull(&reference, &auth, accepted).await?;
        pb.set_length(pulled.layers.len() as u64);
        pb.set_message("extracting layers");

        std::fs::create_dir_all(out_dir)?;
        for (idx, layer) in pulled.layers.into_iter().enumerate() {
            let ext = match layer.media_type.as_str() {
                oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE
                | oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => "tar.gz",
                oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE
                | oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => "tar",
                _ => "bin",
            };
            let file_name = format!("layer_{idx}.{ext}");
            let tmp_path = out_dir.join(file_name);
            let mut tmp = std::fs::File::create(&tmp_path)?;
            tmp.write_all(&layer.data)?;
            decompress_file(&tmp_path, Some(out_dir))?;
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
) -> Result<Vec<PathBuf>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();
    for image in images {
        let dir_name = image.replace(['/', ':'], "_");
        let out_dir = clone_root.join(format!("docker_{dir_name}"));
        docker
            .save_image_to_dir(image, &out_dir, use_progress)
            .await
            .with_context(|| format!("saving image {image}"))?;
        dirs.push(out_dir);
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
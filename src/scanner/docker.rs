use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use oci_distribution::client::{linux_amd64_resolver, Client, ClientConfig};
use oci_distribution::{secrets::RegistryAuth, Reference};
use tracing::debug;

use crate::decompress::decompress_file;

pub struct Docker;

impl Docker {
    pub fn new() -> Self {
        Docker
    }

    pub async fn save_image_to_dir(&self, image: &str, out_dir: &Path) -> Result<()> {
        let reference: Reference =
            image.parse().with_context(|| format!("invalid image reference {image}"))?;
        debug!("Pulling {image}");
        let mut client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
        let auth = RegistryAuth::Anonymous;
        let accepted = vec![
            oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
            oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        ];
        let image = client.pull(&reference, &auth, accepted).await?;

        std::fs::create_dir_all(out_dir)?;
        for (idx, layer) in image.layers.into_iter().enumerate() {
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
        }
        Ok(())
    }
}

pub async fn save_docker_images(images: &[String], clone_root: &Path) -> Result<Vec<PathBuf>> {
    let docker = Docker::new();
    let mut dirs = Vec::new();
    for image in images {
        let dir_name = image.replace(['/', ':'], "_");
        let out_dir = clone_root.join(format!("docker_{dir_name}"));
        docker
            .save_image_to_dir(image, &out_dir)
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
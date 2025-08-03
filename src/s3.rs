use anyhow::{Context, Result};
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;

/// Visit all objects in the given S3 bucket (optionally under a prefix),
/// calling `visitor` with each object's key and bytes.
pub async fn visit_bucket_objects<F>(
    bucket: &str,
    prefix: Option<&str>,
    role_arn: Option<&str>,
    profile: Option<&str>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(String, Vec<u8>) -> Result<()>,
{
    let mut config_loader = aws_config::defaults(BehaviorVersion::latest());

    if let Some(profile) = profile {
        config_loader = config_loader.profile_name(profile);
    }

    // If explicit credentials are provided via KF_AWS_KEY/KF_AWS_SECRET use them
    if let (Ok(key), Ok(secret)) = (std::env::var("KF_AWS_KEY"), std::env::var("KF_AWS_SECRET")) {
        let creds = Credentials::new(key, secret, None, None, "kf_env");
        config_loader = config_loader.credentials_provider(creds);
    }

    // Resolve region using the default chain, falling back to us-east-1
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let base_config = config_loader.region(region_provider).load().await;

    let client = if let Some(role) = role_arn {
        let assume_role = aws_config::sts::AssumeRoleProvider::builder(role.to_string())
            .session_name("kingfisher")
            .configure(&base_config)
            .build()
            .await;
        let conf = aws_sdk_s3::config::Builder::from(&base_config)
            .credentials_provider(assume_role)
            .build();
        Client::from_conf(conf)
    } else {
        Client::new(&base_config)
    };

    let mut continuation_token = None;

    loop {
        let mut req = client.list_objects_v2().bucket(bucket.to_string());
        if let Some(p) = prefix {
            req = req.prefix(p.to_string());
        }
        if let Some(token) = continuation_token.clone() {
            req = req.continuation_token(token);
        }

        let resp = req.send().await.context("Failed to list objects in bucket")?;

        if let Some(objects) = resp.contents {
            for obj in objects {
                if let Some(key) = obj.key {
                    let get_resp = client
                        .get_object()
                        .bucket(bucket)
                        .key(&key)
                        .send()
                        .await
                        .with_context(|| format!("Failed to fetch object {key}"))?;
                    let data =
                        get_resp.body.collect().await.context("Failed to read S3 object body")?;
                    visitor(key, data.into_bytes().to_vec())?;
                }
            }
        }

        if resp.is_truncated.unwrap_or(false) {
            continuation_token = resp.next_continuation_token;
        } else {
            break;
        }
    }

    Ok(())
}
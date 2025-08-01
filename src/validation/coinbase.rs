use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use p256::{
    ecdsa::{signature::Signer as _, SigningKey},
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use ed25519_dalek::{SigningKey as Ed25519Key, Signer as _};
use rand::rngs::OsRng;
use reqwest::{Client, StatusCode, Url};
use sha1::{Digest, Sha1};
use rand::TryRngCore;

use crate::validation::{httpvalidation, Cache, CachedResponse, VALIDATION_CACHE_SECONDS};

pub fn generate_coinbase_cache_key(cred_name: &str, private_key: &str) -> String {
    let mut h = Sha1::new();
    h.update(cred_name.as_bytes());
    h.update(b"\0");
    h.update(private_key.as_bytes());
    format!("COINBASE:{:x}", h.finalize())
}

pub async fn validate_cdp_api_key(
    cred_name: &str,
    private_key_pem: &str,
    client: &Client,
    parser: &liquid::Parser,
    cache: &Cache,
) -> Result<(bool, String)> {
    let cache_key = generate_coinbase_cache_key(cred_name, private_key_pem);
    if let Some(entry) = cache.get(&cache_key) {
        let c = entry.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            return Ok((c.is_valid, c.body.clone()));
        }
    }

    let jwt = build_jwt("GET", "api.coinbase.com", "/v2/user", cred_name, private_key_pem)?;

    let url = Url::parse("https://api.coinbase.com/v2/user")?;
    let headers = BTreeMap::from([("Authorization".to_string(), format!("Bearer {}", jwt))]);
    let rb = httpvalidation::build_request_builder(
        client,
        "GET",
        &url,
        &headers,
        &None,
        parser,
        &liquid::Object::new(),
    )
    .map_err(|e| anyhow!(e))?;
    let resp =
        httpvalidation::retry_request(rb, 1, Duration::from_millis(500), Duration::from_secs(2))
            .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let ok = status == StatusCode::OK;
    let msg = body;

    cache.insert(cache_key.clone(), CachedResponse::new(msg.clone(), status, ok));

    Ok((ok, msg))
}


// fn build_jwt(
//     method: &str,
//     host: &str,
//     endpoint: &str,
//     cred_name: &str,
//     pem: &str,
// ) -> Result<String> {
//     let pem =
//         pem.replace("\r\n", "\n").replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r", "\n");
//     let secret_key = SecretKey::from_sec1_pem(&pem)
//         .or_else(|_| SecretKey::from_pkcs8_pem(&pem))
//         .map_err(|e| anyhow!("invalid EC key: {e}"))?;
//     let signing_key = SigningKey::from(secret_key);

//     let mut rng = OsRng;
//     let mut nonce = [0u8; 16];
    
//     let _ = rng.try_fill_bytes(&mut nonce);

//     let header = serde_json::json!({
//         "typ": "JWT",
//         "alg": "ES256",
//         "kid": cred_name,
//         "nonce": hex::encode(nonce),
//     });
//     let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

//     let now = Utc::now().timestamp();
//     let claims = serde_json::json!({
//         "sub": cred_name,
//         "iss": "cdp",
//         "nbf": now,
//         "exp": now + 60,
//         "uri": format!("{} {}{}", method, host, endpoint),
//     });
//     let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());

//     let signing_input = format!("{header_b64}.{claims_b64}");
//     let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
//     let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

//     Ok(format!("{signing_input}.{sig_b64}"))
// }

fn build_jwt(
    method: &str,
    host: &str,
    endpoint: &str,
    key_name: &str,
    pem: &str,
) -> Result<String> {
    let pem =
        pem.replace("\r\n", "\n").replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r", "\n");

    let mut rng = OsRng;
    let mut nonce = [0u8; 16];
    
    let _ = rng.try_fill_bytes(&mut nonce);

    // Try ECDSA (PEM encoded EC key). Fallback to raw Ed25519 base64 key.
    if let Ok(secret_key) = SecretKey::from_sec1_pem(&pem)
        .or_else(|_| SecretKey::from_pkcs8_pem(&pem))
    {
        let signing_key = SigningKey::from(secret_key);
        let header = serde_json::json!({
            "typ": "JWT",
            "alg": "ES256",
            "kid": key_name,
            "nonce": hex::encode(nonce),
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": key_name,
            "iss": "cdp",
            "nbf": now,
            "exp": now + 120,
            "uri": format!("{} {}{}", method, host, endpoint),
        });
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        return Ok(format!("{signing_input}.{sig_b64}"));
    } else {
        // Assume base64-encoded Ed25519 keypair
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(pem.as_bytes())
            .map_err(|e| anyhow!("invalid base64 key: {e}"))?;
        let signing_key = match key_bytes.len() {
            32 => {
                let arr: [u8; 32] = key_bytes[..32].try_into().unwrap();
                Ed25519Key::from_bytes(&arr)
            }
            64 => {
                let arr: [u8; 64] = key_bytes[..64].try_into().unwrap();
                Ed25519Key::from_keypair_bytes(&arr).map_err(|e| anyhow!("invalid Ed25519 key: {e}"))?
            }
            _ => return Err(anyhow!("invalid Ed25519 key length")),
        };

        let header = serde_json::json!({
            "typ": "JWT",
            "alg": "EdDSA",
            "kid": key_name,
            "nonce": hex::encode(nonce),
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": key_name,
            "iss": "cdp",
            "nbf": now,
            "exp": now + 120,
            "uri": format!("{} {}{}", method, host, endpoint),
        });
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig: ed25519_dalek::Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        return Ok(format!("{signing_input}.{sig_b64}"));
    }
}
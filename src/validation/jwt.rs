use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ipnet::IpNet;
use jsonwebtoken::{
    decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation as JwtValidation,
};
use once_cell::sync::Lazy;
use reqwest::{redirect::Policy, Client, Url};
use serde::Deserialize;
use tokio::net::lookup_host;

use super::utils::check_url_resolvable;

/// One global, redirect-free client.  Building a `Client` is comparatively
/// expensive; re-using it lets reqwest share its internal connection pool
/// and TLS sessions across JWT validations.  `Lazy` ensures thread-safe,
/// one-time initialisation.
static NO_REDIRECT_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .redirect(Policy::none()) // disable all redirects
        .build()
        .expect("failed to build no-redirect Client")
});

/// RFC 1918 + loopback + link-local nets we refuse to contact
const BLOCKED_NETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16", // private
    "127.0.0.0/8",
    "169.254.0.0/16", // loopback / link-local
];

//  aud is allowed to be either a string or an array, so let Serde flatten it.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
    Str(String),
    Arr(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct Claims {
    exp: Option<i64>,
    nbf: Option<i64>,
    iss: Option<String>,
    aud: Option<Aud>,
}

/// Runtime options for JWT validation policy.
#[derive(Clone, Default)]
pub struct ValidateOptions {
    /// If true, accept unsigned tokens (`alg: "none"`) as long as temporal checks pass.
    /// Default is **false** (more secure).
    pub allow_alg_none: bool,

    /// If provided and `iss` is absent, use this key to cryptographically verify the token.
    /// Useful for non-OIDC flows where you already know the verification key.
    pub fallback_decoding_key: Option<DecodingKey>,
}

/// Backwards-compatible entry point with secure defaults:
/// - `alg: none` is **rejected**
/// - `iss` is **required** unless `fallback_decoding_key` is supplied (not supplied here)
pub async fn validate_jwt(token: &str) -> Result<(bool, String)> {
    validate_jwt_with(
        token,
        &ValidateOptions { allow_alg_none: false, fallback_decoding_key: None },
    )
    .await
}

/// Strict validator with policy control.
/// Returns (is_active_credential, explanation).
pub async fn validate_jwt_with(token: &str, opts: &ValidateOptions) -> Result<(bool, String)> {
    // --- insecure payload decode to read claims --------------------------------
    let claims: Claims = {
        let payload_b64 = token.split('.').nth(1).ok_or_else(|| anyhow!("invalid JWT format"))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| anyhow!("invalid base64 in payload: {e}"))?;
        serde_json::from_slice(&payload_json).map_err(|e| anyhow!("invalid JSON claims: {e}"))?
    };

    // temporal checks
    let now = Utc::now().timestamp();
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Ok((false, format!("Token not valid before {nbf}")));
        }
    }
    if let Some(exp) = claims.exp {
        if now > exp {
            return Ok((false, format!("Token expired at {exp}")));
        }
    }

    // parse header enough to read "alg" without jsonwebtoken's enum (which rejects "none")
    let header_b64 = token.split('.').next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    let header_json =
        URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| anyhow!("invalid base64 in header: {e}"))?;
    let header_val: serde_json::Value =
        serde_json::from_slice(&header_json).map_err(|e| anyhow!("invalid header json: {e}"))?;
    let alg_str = header_val.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    // --- Policy: reject `alg: none` unless explicitly allowed ------------------
    if alg_str.eq_ignore_ascii_case("none") {
        if opts.allow_alg_none {
            // time-valid is enough if explicitly allowed
            return Ok((
                true,
                format!(
                    "JWT valid (alg: none, iss: {}, aud: {:?})",
                    claims.iss.clone().unwrap_or_default(),
                    extract_aud_strings(&claims),
                ),
            ));
        } else {
            return Ok((false, "unsigned JWT (alg: none) not allowed".into()));
        }
    }

    // Safe to decode full header now that we know alg != none
    let header = decode_header(token).map_err(|e| anyhow!("decode header: {e}"))?;
    let alg = header.alg;

    // Proactively skip HMAC-signed JWTs to avoid ambiguous liveness results.
    if matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
        return Ok((false, format!("HMAC-signed JWTs are not validated ({alg:?})")));
    }

    let issuer = claims.iss.clone().unwrap_or_default();
    let aud_strings = extract_aud_strings(&claims);

    // --- New rule: require `iss` OR use fallback key for crypto verification ---
    if issuer.trim().is_empty() {
        // No issuer — we may still accept if we can cryptographically verify with a fallback key
        if let Some(decoding_key) = opts.fallback_decoding_key.as_ref() {
            // Verify signature (aud checked if present)
            let mut validation = JwtValidation::new(alg);
            if !aud_strings.is_empty() {
                validation.set_audience(&aud_strings);
            }
            // We already did exp/nbf manually.
            validation.validate_exp = false;
            validation.validate_nbf = false;

            decode::<Claims>(token, decoding_key, &validation)
                .map_err(|e| anyhow!("signature verification (fallback key) failed: {e}"))?;

            return Ok((
                true,
                format!("JWT valid via fallback key (alg: {:?}, aud: {:?})", alg, aud_strings),
            ));
        } else {
            return Ok((
                false,
                "issuer (iss) required or a fallback verification key must be provided".into(),
            ));
        }
    }

    // --- With `iss`: OIDC discovery + JWKS verification path -------------------
    // require kid before any network I/O
    let Some(kid) = header.kid.clone() else {
        return Ok((false, "no kid in header".into()));
    };

    // build discovery URL and fetch it (redirects disabled)
    let config_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let cfg_resp = NO_REDIRECT_CLIENT
        .get(&config_url)
        .send()
        .await
        .map_err(|e| anyhow!("issuer discovery failed: {e}"))?;

    if !cfg_resp.status().is_success() {
        return Ok((false, format!("issuer discovery failed: {}", cfg_resp.status())));
    }

    let cfg_json: serde_json::Value =
        cfg_resp.json().await.map_err(|e| anyhow!("invalid discovery JSON: {e}"))?;

    // extract jwks_uri
    let jwks_uri = cfg_json
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("jwks_uri missing"))?;

    // must be HTTPS
    let url = Url::parse(jwks_uri).map_err(|e| anyhow!("invalid jwks_uri: {e}"))?;
    if url.scheme() != "https" {
        return Ok((false, "jwks_uri must use https".to_string()));
    }

    // host must match issuer host
    let iss_host = Url::parse(&issuer)
        .map_err(|e| anyhow!("invalid iss: {e}"))?
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let jwks_host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if jwks_host != iss_host {
        return Ok((
            false,
            format!("jwks_uri host ({jwks_host}) must match issuer host ({iss_host})"),
        ));
    }

    // DNS resolution + private-range block
    for addr in lookup_host((jwks_host.as_str(), 443)).await? {
        if is_blocked_ip(addr.ip()) {
            return Ok((false, "jwks_uri resolves to private or link-local IP".to_string()));
        }
    }

    // reachability check (existing helper)
    check_url_resolvable(&url).await.map_err(|e| anyhow!("jwks uri unresolvable: {e}"))?;

    // fetch JWKS with redirect-free client
    let jwks_resp =
        NO_REDIRECT_CLIENT.get(url).send().await.map_err(|e| anyhow!("jwks fetch failed: {e}"))?;
    if !jwks_resp.status().is_success() {
        return Ok((false, format!("jwks fetch failed: {}", jwks_resp.status())));
    }

    let jwk_set: JwkSet = jwks_resp.json().await.map_err(|e| anyhow!("invalid jwks json: {e}"))?;

    // select key by kid
    let jwk = jwk_set
        .keys
        .iter()
        .find(|k| k.common.key_id.as_deref() == Some(&kid))
        .ok_or_else(|| anyhow!("kid not found in jwks"))?;

    // verify signature
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| anyhow!("invalid jwk: {e}"))?;
    let mut validation = JwtValidation::new(header.alg);
    if !aud_strings.is_empty() {
        validation.set_audience(&aud_strings);
    }
    validation.validate_exp = false;
    validation.validate_nbf = false;

    decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;

    Ok((true, format!("JWT valid (alg: {:?}, iss: {issuer}, aud: {:?})", alg, aud_strings)))
}

/// Helper: normalize aud into a flat Vec<String>
fn extract_aud_strings(claims: &Claims) -> Vec<String> {
    match &claims.aud {
        Some(Aud::Str(s)) => vec![s.clone()],
        Some(Aud::Arr(v)) => v.clone(),
        None => vec![],
    }
}
/// returns true if IP is in a blocked network
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    BLOCKED_NETS.iter().filter_map(|cidr| cidr.parse::<IpNet>().ok()).any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::{validate_jwt, validate_jwt_with, ValidateOptions};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::{Duration as ChronoDuration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn build_unsigned_token(exp_offset: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let exp = (Utc::now() + ChronoDuration::seconds(exp_offset)).timestamp();
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{
                "exp": {exp},
                "iss": "https://example.com",
                "aud": ["test-audience"]
            }}"#
        ));
        format!("{header}.{payload}.")
    }

    #[tokio::test]
    async fn hmac_signed_tokens_skipped() {
        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("dummy".into());

        let payload = serde_json::json!({
            "iss": "https://example.com",
            "exp": (Utc::now() + ChronoDuration::minutes(5)).timestamp(),
        });

        let token = encode(&header, &payload, &EncodingKey::from_secret(b"secret")).unwrap();
        let res = validate_jwt(&token).await.unwrap();
        assert!(!res.0);
        assert!(res.1.contains("HMAC-signed JWTs are not validated"));
    }

    #[tokio::test]
    async fn missing_kid_short_circuits_before_network() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{
                "exp": {},
                "iss": "https://example.com"
            }}"#,
            (Utc::now() + ChronoDuration::minutes(5)).timestamp()
        ));
        let signature = URL_SAFE_NO_PAD.encode("sig");
        let token = format!("{header}.{payload}.{signature}");

        let res = validate_jwt(&token).await.unwrap();
        assert!(!res.0);
        assert!(res.1.contains("no kid in header"));
    }

    #[tokio::test]
    async fn unsigned_token_rejected_by_default() {
        let token = build_unsigned_token(60);
        let res = validate_jwt(&token).await.unwrap();
        assert!(!res.0);
        assert!(res.1.contains("unsigned JWT (alg: none) not allowed"));
    }

    #[tokio::test]
    async fn valid_token_allows_alg_none_when_opted_in() {
        let token = build_unsigned_token(60);
        let res = validate_jwt_with(
            &token,
            &ValidateOptions { allow_alg_none: true, fallback_decoding_key: None },
        )
        .await
        .unwrap();
        assert!(res.0, "expected success when alg none is explicitly allowed");
    }

    #[tokio::test]
    async fn expired_token_still_rejected() {
        let token = build_unsigned_token(-60);
        let res = validate_jwt_with(
            &token,
            &ValidateOptions { allow_alg_none: true, fallback_decoding_key: None },
        )
        .await
        .unwrap();
        assert!(!res.0);
        assert!(res.1.contains("expired"));
    }
}

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ipnet::IpNet;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation as JwtValidation};
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

pub async fn validate_jwt(token: &str) -> Result<(bool, String)> {
    // --- insecure payload decode -------------------------------------------------
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

    let header_b64 = token.split('.').next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    let header_json =
        URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| anyhow!("invalid base64 in header: {e}"))?;
    let header_val: serde_json::Value =
        serde_json::from_slice(&header_json).map_err(|e| anyhow!("invalid header json: {e}"))?;
    let alg_str = header_val.get("alg").and_then(|v| v.as_str()).unwrap_or("");

    // If alg is "none", skip signature/JWKS entirely
    if alg_str.eq_ignore_ascii_case("none") {
        // still enforce your time/claims checks that already ran
        return Ok((
            true,
            format!(
                "JWT valid (alg: none, iss: {}, aud: {:?})",
                claims.iss.clone().unwrap_or_default(),
                extract_aud_strings(&claims),
            ),
        ));
    }

    // ---------------------------------------------------------------------------
    let issuer = claims.iss.clone().unwrap_or_default();
    let aud_strings = extract_aud_strings(&claims);

    if issuer.trim().is_empty() && aud_strings.iter().all(|s| s.trim().is_empty()) {
        return Ok((false, "JWT missing issuer and audience".into()));
    }
    if let Some(iss) = claims.iss.clone() {
        // parse header now (kid, alg)
        let header = decode_header(token).map_err(|e| anyhow!("decode header: {e}"))?;
        let alg = header.alg;

        // build discovery URL and fetch it (redirects disabled)
        let config_url = format!("{}/.well-known/openid-configuration", iss.trim_end_matches('/'));
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

        // host must match issuer host  —  prevents open redirects / SSRF-on-other-host
        let iss_host = Url::parse(&iss)
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

        // -----------------------------------------------------------------------
        // DNS resolution + private-range block
        for addr in lookup_host((jwks_host.as_str(), 443)).await? {
            if is_blocked_ip(addr.ip()) {
                return Ok((false, "jwks_uri resolves to private or link-local IP".to_string()));
            }
        }

        // reachability check (existing helper)
        check_url_resolvable(&url).await.map_err(|e| anyhow!("jwks uri unresolvable: {e}"))?;

        // fetch JWKS with redirect-free client
        let jwks_resp = NO_REDIRECT_CLIENT
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("jwks fetch failed: {e}"))?;
        if !jwks_resp.status().is_success() {
            return Ok((false, format!("jwks fetch failed: {}", jwks_resp.status())));
        }

        let jwk_set: JwkSet =
            jwks_resp.json().await.map_err(|e| anyhow!("invalid jwks json: {e}"))?;

        // select key by kid
        let kid = header.kid.ok_or_else(|| anyhow!("no kid in header"))?;
        let jwk = jwk_set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(&kid))
            .ok_or_else(|| anyhow!("kid not found in jwks"))?;

        // verify signature
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| anyhow!("invalid jwk: {e}"))?;
        let mut validation = JwtValidation::new(header.alg);
        validation.set_audience(&extract_aud_strings(&claims));
        validation.validate_exp = false;
        validation.validate_nbf = false;

        decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| anyhow!("signature verification failed: {e}"))?;

        return Ok((
            true,
            format!(
                "JWT valid (alg: {:?}, iss: {issuer}, aud: {:?})",
                alg,
                extract_aud_strings(&claims)
            ),
        ));
    }

    Ok((true, format!("JWT not expired (iss: {issuer}, aud: {:?})", extract_aud_strings(&claims))))
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::{Duration as ChronoDuration, Utc};

    use super::validate_jwt;

    fn build_token(exp_offset: i64) -> String {
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
    async fn valid_token() {
        let token = build_token(60);
        let res = validate_jwt(&token).await.unwrap();
        assert!(res.0);
    }

    #[tokio::test]
    async fn expired_token() {
        let token = build_token(-60);
        let res = validate_jwt(&token).await.unwrap();
        assert!(!res.0);
    }
}

// src/validation/mongodb.rs
use std::{net::IpAddr, time::Duration};

use anyhow::Result;
use bson::doc;
use mongodb::{error::ErrorKind, options::ClientOptions, Client};
use tokio::time::timeout;

pub fn looks_like_mongodb_uri(uri: &str) -> bool {
    // quick scheme check first
    if !(uri.starts_with("mongodb://") || uri.starts_with("mongodb+srv://")) {
        return false;
    }
    // pure string-level parse – no network, even for +srv
    mongodb::options::ConnectionString::parse(uri).is_ok()
}

/// Return true if the URI targets localhost/loopback or a unix domain socket.
/// This is a *string-only* check—no DNS or driver IO.
fn uri_targets_localhost(uri: &str) -> bool {
    // strip scheme
    let rest = uri
        .strip_prefix("mongodb://")
        .or_else(|| uri.strip_prefix("mongodb+srv://"))
        .unwrap_or(uri);

    // authority ends at first '/' (before db/path); if missing, take whole rest
    let authority = rest.split_once('/').map(|(a, _)| a).unwrap_or(rest);

    // unix domain socket forms (percent-encoded "/path/to.sock")
    let auth_lower = authority.to_ascii_lowercase();
    if auth_lower.starts_with("%2f") || authority.starts_with('/') {
        return true; // UDS → treat as local
    }

    // drop userinfo if present
    let hostlist = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);

    // iterate seed list (mongodb://hostA,hostB,...)
    for part in hostlist.split(',') {
        let mut host = part.trim();

        // strip brackets for IPv6 literals
        if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
            host = &host[1..host.len() - 1];
        }

        // strip :port if present (only when suffix is all digits)
        if let Some(idx) = host.rfind(':') {
            if host[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                host = &host[..idx];
            }
        }

        if is_local_host(host) {
            return true;
        }
    }

    false
}

/// Returns true for localhost/loopback/unspecified IPs and common localhost aliases.
fn is_local_host(h: &str) -> bool {
    let s = h.trim().trim_end_matches('.');
    let s_lower = s.to_ascii_lowercase();

    // common aliases seen in hosts files across distros
    if matches!(
        s_lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "localhost6"
            | "localhost6.localdomain6"
            | "ip6-localhost"
            | "ip6-loopback"
    ) {
        return true;
    }

    // explicit unspecified forms
    if s_lower.as_str() == "0.0.0.0" || s_lower.as_str() == "::" {
        return true;
    }

    // literal IPs
    if let Ok(ip) = s.parse::<IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }

    false
}

const FAST_CONNECT_MS: u64 = 700; // direct single-host URIs
const FAST_SELECT_MS: u64 = 300;
const SRV_PARSE_MS: u64 = 2_000; // limit DNS resolution time
const SRV_CONNECT_MS: u64 = 2500;
const SRV_SELECT_MS: u64 = 2500;

/// Validates a MongoDB URI in ≤ 2 s. Returns `(bool, String)` where the
/// boolean indicates success and the string provides a status message.
pub async fn validate_mongodb(uri: &str) -> Result<(bool, String)> {
    // ---- quick reject without touching the network
    if !looks_like_mongodb_uri(uri) {
        return Ok((false, "Invalid MongoDB URI".to_string()));
    }

    // ---- refuse localhost/loopback/UDS outright
    if uri_targets_localhost(uri) {
        return Ok((false, "Refusing to validate localhost/loopback MongoDB URIs.".to_string()));
    }

    let is_srv = uri.starts_with("mongodb+srv://");

    // ---- build client opts (guarded so we don't hit DNS/driver first)
    let mut opts = if is_srv {
        match timeout(Duration::from_millis(SRV_PARSE_MS), ClientOptions::parse(uri)).await {
            Ok(res) => res?,
            Err(_) => {
                return Ok((false, "MongoDB connection failed: timeout exceeded".to_string()));
            }
        }
    } else {
        ClientOptions::parse(uri).await?
    };

    if !is_srv {
        // one socket, skip cluster discovery for plain 'mongodb://'
        opts.direct_connection = Some(true);
        opts.connect_timeout = Some(Duration::from_millis(FAST_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(FAST_SELECT_MS));
    } else {
        // SRV needs DNS and replica-set discovery; fail fast
        opts.connect_timeout = Some(Duration::from_millis(SRV_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(SRV_SELECT_MS));
        // leave direct_connection = None   (driver decides)
    }
    opts.max_pool_size = Some(1);
    opts.min_pool_size = Some(0);

    // ---- dial and ping
    let client = Client::with_options(opts)?;
    let res = client.database("admin").run_command(doc! { "ping": 1 }).await;
    match res {
        Ok(_) => Ok((true, "MongoDB connection is valid.".to_string())),
        Err(e) => {
            let msg = match *e.kind {
                ErrorKind::ServerSelection { .. } => {
                    "MongoDB connection failed: timeout exceeded".to_string()
                }
                _ => "MongoDB connection failed.".to_string(),
            };
            Ok((false, msg))
        }
    }
}

/// Return a stable cache key for the given MongoDB URI.
pub fn generate_mongodb_cache_key(mongodb_uri: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(mongodb_uri.as_bytes());
    format!("MongoDB:{:x}", hasher.finalize())
}

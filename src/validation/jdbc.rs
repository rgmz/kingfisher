use anyhow::{anyhow, Context, Result};
use http::StatusCode;
use tracing::debug;
use url::Url;
use xxhash_rust::xxh3::xxh3_64;

use super::postgres;

/// Result of attempting to validate a JDBC connection string.
pub struct JdbcValidationOutcome {
    pub valid: bool,
    pub status: StatusCode,
    pub message: String,
}

/// Produce a short-lived cache key for JDBC validations.
pub fn generate_jdbc_cache_key(raw: &str) -> String {
    format!("Jdbc:{:016x}", xxh3_64(raw.as_bytes()))
}

/// Validate a JDBC connection string by dispatching to the supported backend validators.
pub async fn validate_jdbc(jdbc_conn: &str) -> Result<JdbcValidationOutcome> {
    let trimmed = jdbc_conn.trim();
    if !trimmed.to_ascii_lowercase().starts_with("jdbc:") {
        return Err(anyhow!("JDBC connection string must start with `jdbc:`"));
    }

    let without_prefix = &trimmed[5..];
    let (raw_subprotocol, subname) = without_prefix
        .split_once(':')
        .ok_or_else(|| anyhow!("JDBC connection string is missing a subprotocol"))?;
    let subprotocol = raw_subprotocol.trim();
    let subprotocol_lower = subprotocol.to_ascii_lowercase();

    match subprotocol_lower.as_str() {
        "postgres" | "postgresql" | "postgis" => {
            validate_postgres_jdbc(subname).await.context("Postgres JDBC validation failed")
        }
        other => {
            debug!("Unsupported JDBC subprotocol encountered: {}", other);
            Ok(JdbcValidationOutcome {
                valid: false,
                status: StatusCode::NOT_IMPLEMENTED,
                message: format!(
                    "JDBC validation not implemented for subprotocol `{}`.",
                    subprotocol
                ),
            })
        }
    }
}

async fn validate_postgres_jdbc(subname: &str) -> Result<JdbcValidationOutcome> {
    let normalized = normalize_postgres_url(subname)?;
    let (ok, meta) = postgres::validate_postgres(&normalized).await?;

    let mut message = if ok {
        "JDBC Postgres connection is valid.".to_string()
    } else {
        "JDBC Postgres connection failed.".to_string()
    };

    if !meta.is_empty() {
        let joined = meta.join("; ");
        if ok {
            message.push_str(&format!(" Details: {}", joined));
        } else {
            message = format!("JDBC Postgres validation result: {}", joined);
        }
    }

    let status = if ok {
        StatusCode::OK
    } else if meta.iter().any(|m| m.to_ascii_lowercase().contains("skip")) {
        StatusCode::CONTINUE
    } else {
        StatusCode::UNAUTHORIZED
    };

    Ok(JdbcValidationOutcome { valid: ok, status, message })
}

fn normalize_postgres_url(subname: &str) -> Result<String> {
    let trimmed = subname.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Postgres JDBC connection string is empty"));
    }

    // First try parsing using the standard JDBC layout, otherwise fall back to a canonical URL.
    let candidate = format!("postgresql:{}", trimmed);
    let mut url = Url::parse(&candidate).or_else(|_| {
        let fallback = format!("postgresql://{}", trimmed.trim_start_matches('/'));
        Url::parse(&fallback)
    })?;

    // Extract credentials from the query string when they are present.
    let mut user = None;
    let mut password = None;
    if url.query().is_some() {
        let mut preserved = Vec::new();
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "user" | "username" => user = Some(value.into_owned()),
                "password" | "pass" | "pwd" => password = Some(value.into_owned()),
                _ => preserved.push((key.into_owned(), value.into_owned())),
            }
        }

        {
            let mut pairs = url.query_pairs_mut();
            pairs.clear();
            for (key, value) in preserved {
                pairs.append_pair(&key, &value);
            }
        }
    }

    if let Some(user) = user {
        url.set_username(&user).map_err(|_| anyhow!("Failed to apply Postgres username"))?;
    }
    if let Some(password) = password {
        url.set_password(Some(&password))
            .map_err(|_| anyhow!("Failed to apply Postgres password"))?;
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::normalize_postgres_url;
    use pretty_assertions::assert_eq;

    #[test]
    fn normalizes_postgres_query_credentials() {
        let normalized = normalize_postgres_url(
            "//db.example.com:5432/app?user=admin&password=s3cr3t&sslmode=require",
        )
        .unwrap();
        assert_eq!(normalized, "postgresql://admin:s3cr3t@db.example.com:5432/app?sslmode=require");
    }

    #[test]
    fn preserves_existing_credentials() {
        let normalized =
            normalize_postgres_url("//db.example.com:5432/app?sslmode=prefer").unwrap();
        assert_eq!(normalized, "postgresql://db.example.com:5432/app?sslmode=prefer");
    }

    #[test]
    fn rejects_empty_input() {
        assert!(normalize_postgres_url("").is_err());
    }
}

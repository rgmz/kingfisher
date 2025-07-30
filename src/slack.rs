use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SlackMessage {
    pub permalink: String,
    pub text: Option<String>,
    pub ts: String,
    pub channel: SlackChannel,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SlackChannel {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SlackPagination {
    page: Option<u32>,
    page_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SlackMessages {
    matches: Vec<SlackMessage>,
    pagination: Option<SlackPagination>,
}

#[derive(Debug, Deserialize)]
struct SlackSearchResponse {
    ok: bool,
    error: Option<String>,
    messages: Option<SlackMessages>,
}

pub async fn search_messages(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<SlackMessage>> {
    let token = std::env::var("KF_SLACK_TOKEN")
        .context("KF_SLACK_TOKEN environment variable must be set")?;

    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    let mut page = 1u32;
    let mut messages = Vec::new();

    loop {
        let url = api_url.join("search.messages").context("Failed to build Slack API URL")?;

        let resp = client
            .get(url)
            .bearer_auth(&token)
            .query(&[("query", query), ("count", "100"), ("page", &page.to_string())])
            .send()
            .await
            .context("Failed to send Slack request")?;

        let body: SlackSearchResponse =
            resp.json().await.context("Failed to parse Slack response")?;

        if !body.ok {
            let err = body.error.unwrap_or_else(|| "unknown".to_string());
            if err == "not_allowed_token_type" {
                return Err(anyhow::anyhow!(
                    "Slack API error: not_allowed_token_type - use a user token with the `search:read` scope"
                ));
            }
            return Err(anyhow::anyhow!("Slack API error: {}", err));
        }

        let Some(msgs) = body.messages else {
            break;
        };
        for m in msgs.matches {
            messages.push(m);
            if messages.len() >= max_results {
                return Ok(messages);
            }
        }
        let next_page =
            msgs.pagination.as_ref().and_then(|p| p.page).map(|p| p + 1).unwrap_or(page + 1);
        let page_count = msgs.pagination.as_ref().and_then(|p| p.page_count).unwrap_or(next_page);
        if next_page > page_count {
            break;
        }
        page = next_page;
    }

    Ok(messages)
}

pub async fn download_messages_to_dir(
    api_url: Url,
    query: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<(PathBuf, String)>> {
    std::fs::create_dir_all(output_dir)?;
    let messages = search_messages(api_url, query, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for msg in messages {
        let ts = msg.ts.replace('.', "_");
        let file = output_dir.join(format!("{}_{}.json", msg.channel.id, ts));
        std::fs::write(&file, serde_json::to_vec(&msg)?)?;
        paths.push((file, msg.permalink));
    }
    Ok(paths)
}
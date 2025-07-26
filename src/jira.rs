use anyhow::{Context, Result};
use jira_query::{Auth, JiraInstance, Pagination};
use reqwest::Client;
use url::Url;

// Re-export the Issue type from jira_query so callers don't depend on the crate.
pub use jira_query::Issue as JiraIssue;
pub async fn fetch_issues(
    jira_url: Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<JiraIssue>> {
    // build a &str without any trailing `/`
    let base = jira_url.as_str().trim_end_matches('/');

    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    let mut jira = JiraInstance::at(base.to_string())? // no trailing slash here
        .with_client(client)
        .paginate(Pagination::MaxResults(max_results as u32));

    if let Ok(token) = std::env::var("KF_JIRA_TOKEN") {
        jira = jira.authenticate(Auth::ApiKey(token));
    }

    let issues = jira.search(jql).await?;
    Ok(issues)
}

use std::path::PathBuf;

pub async fn download_issues_to_dir(
    jira_url: Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)?;
    let issues = fetch_issues(jira_url, jql, max_results, ignore_certs).await?;
    let mut paths = Vec::new();
    for issue in issues {
        let file = output_dir.join(format!("{}.json", issue.key));
        std::fs::write(&file, serde_json::to_vec(&issue)?)?;
        paths.push(file);
    }
    Ok(paths)
}
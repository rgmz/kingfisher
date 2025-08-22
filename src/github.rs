use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use octorust::{
    auth::Credentials,
    types::{Order, ReposListOrgSort, ReposListOrgType, ReposListUserType},
    Client,
};
use serde_json::Value;
use url::Url;

use crate::{findings_store, git_url::GitUrl};
use std::str::FromStr;

#[derive(Debug)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub organization: Vec<String>,
    pub all_organizations: bool,
    pub repo_filter: RepoType,
}
impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.organization.is_empty() && !self.all_organizations
    }
}
#[derive(Debug, Clone)]
pub enum RepoType {
    All,
    Source,
    Fork,
}
impl From<RepoType> for ReposListUserType {
    fn from(repo_type: RepoType) -> Self {
        match repo_type {
            RepoType::All => ReposListUserType::All,
            RepoType::Source => ReposListUserType::Owner,
            RepoType::Fork => ReposListUserType::Member,
        }
    }
}
impl From<RepoType> for ReposListOrgType {
    fn from(repo_type: RepoType) -> Self {
        match repo_type {
            RepoType::All => ReposListOrgType::All,
            RepoType::Source => ReposListOrgType::Sources,
            RepoType::Fork => ReposListOrgType::Forks,
        }
    }
}
fn create_github_client(github_url: &url::Url, ignore_certs: bool) -> Result<Arc<Client>> {
    // Try personal access token
    let credentials = if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
        Credentials::Token(token)
    } else {
        Credentials::Token("".to_string()) // Anonymous access
    };

    let mut client_builder = reqwest::Client::builder();
    if ignore_certs {
        client_builder = client_builder.danger_accept_invalid_certs(ignore_certs);
    }

    let reqwest_client = client_builder.build().context("Failed to build HTTP client")?;

    let http_client = reqwest_middleware::ClientBuilder::new(reqwest_client).build();

    let mut client = Client::custom(
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
        credentials,
        http_client,
    );

    // Override host if not using api.github.com
    if github_url.host_str() != Some("api.github.com") {
        client.with_host_override(github_url.as_str());
    }
    Ok(Arc::new(client))
}
pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = create_github_client(&github_url, ignore_certs)?;
    let mut repo_urls = Vec::new();
    let user_repo_type: ReposListUserType = repo_specifiers.repo_filter.clone().into();
    let org_repo_type: ReposListOrgType = repo_specifiers.repo_filter.clone().into();
    for username in &repo_specifiers.user {
        let repos = client
            .repos()
            .list_all_for_user(
                username,
                user_repo_type.clone(),
                ReposListOrgSort::Created,
                Order::Desc,
            )
            .await?;
        repo_urls.extend(repos.body.into_iter().filter_map(|repo| Some(repo.clone_url)));
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    let orgs = if repo_specifiers.all_organizations {
        let mut all_orgs = Vec::new();
        let org_list = client.orgs().list_all(100).await?;
        all_orgs.extend(org_list.body.into_iter().map(|org| org.login));
        all_orgs
    } else {
        repo_specifiers.organization.clone()
    };
    for org_name in orgs {
        let repos = client
            .repos()
            .list_all_for_org(
                &org_name,
                org_repo_type.clone(),
                ReposListOrgSort::Created,
                Order::Desc,
            )
            .await?;
        repo_urls.extend(repos.body.into_iter().filter_map(|repo| Some(repo.clone_url)));
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}
pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    orgs: &[String],
    all_orgs: bool,
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        organization: orgs.to_vec(),
        all_organizations: all_orgs,
        repo_filter,
    };
    // Create a progress bar just for displaying status
    // let mut progress = ProgressBar::new_spinner("Fetching repositories...",
    // true,);
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let repo_urls =
        enumerate_repo_urls(&repo_specifiers, api_url, ignore_certs, Some(&mut progress)).await?;
    // Print repositories
    for url in repo_urls {
        println!("{}", url);
    }
    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url.host_str()?.to_string();
    let mut segments = url.path_segments()?;
    let owner = segments.next()?.to_string();
    let mut repo = segments.next()?.to_string();
    if let Some(stripped) = repo.strip_suffix(".git") {
        repo = stripped.to_string();
    }
    Some((host, owner, repo))
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let (host, owner, repo) = parse_repo(repo_url)?;
    let wiki = format!("https://{host}/{owner}/{repo}.wiki.git");
    GitUrl::from_str(&wiki).ok()
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (_, owner, repo) = parse_repo(repo_url).context("invalid GitHub repo URL")?;
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;

    let mut dirs = Vec::new();

    // Issues
    let issues_dir = output_root.join("github_issues").join(&owner).join(&repo);
    fs::create_dir_all(&issues_dir)?;
    let mut page = 1;
    loop {
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/issues?state=all&per_page=100&page={page}"
        );
        let mut req = client.get(&url).header("User-Agent", "kingfisher");
        if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
            if !token.is_empty() {
                req = req.bearer_auth(token);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            break;
        }
        let issues: Vec<Value> = resp.json().await?;
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            let number = issue.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
            let title = issue.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = issue.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let content = format!("# {title}\n\n{body}");
            let file_path = issues_dir.join(format!("issue_{number}.md"));
            fs::write(&file_path, content)?;
            let url = format!("https://github.com/{owner}/{repo}/issues/{number}");
            let mut ds = datastore.lock().unwrap();
            ds.register_repo_link(file_path, url);
        }
        page += 1;
    }
    if issues_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(issues_dir);
    }

    // Gists
    let gists_dir = output_root.join("github_gists").join(&owner);
    fs::create_dir_all(&gists_dir)?;
    let mut seen = HashSet::new();

    // Public gists for the owner
    page = 1;
    loop {
        let url = format!("https://api.github.com/users/{owner}/gists?per_page=100&page={page}");
        let mut req = client.get(&url).header("User-Agent", "kingfisher");
        if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
            if !token.is_empty() {
                req = req.bearer_auth(&token);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            break;
        }
        let gists: Vec<Value> = resp.json().await?;
        if gists.is_empty() {
            break;
        }
        for gist in gists {
            if let Some(id) = gist.get("id").and_then(|v| v.as_str()) {
                if seen.insert(id.to_string()) {
                    let mut req_g = client
                        .get(&format!("https://api.github.com/gists/{id}"))
                        .header("User-Agent", "kingfisher");
                    if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
                        if !token.is_empty() {
                            req_g = req_g.bearer_auth(&token);
                        }
                    }
                    let detail: Value = req_g.send().await?.json().await?;
                    if let Some(files) = detail.get("files").and_then(|v| v.as_object()) {
                        let gist_dir = gists_dir.join(id);
                        fs::create_dir_all(&gist_dir)?;
                        for (fname, fobj) in files {
                            if let Some(content) = fobj.get("content").and_then(|v| v.as_str()) {
                                let file_path = gist_dir.join(fname);
                                fs::write(&file_path, content)?;
                                let url = format!("https://gist.github.com/{id}");
                                let mut ds = datastore.lock().unwrap();
                                ds.register_repo_link(file_path, url);
                            }
                        }
                    }
                }
            }
        }
        page += 1;
    }

    // Private gists for authenticated user if they own the repo
    if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
        if !token.is_empty() {
            page = 1;
            loop {
                let url = format!("https://api.github.com/gists?per_page=100&page={page}");
                let resp = client
                    .get(&url)
                    .header("User-Agent", "kingfisher")
                    .bearer_auth(&token)
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    break;
                }
                let gists: Vec<Value> = resp.json().await?;
                if gists.is_empty() {
                    break;
                }
                for gist in gists {
                    let owner_login =
                        gist.get("owner").and_then(|o| o.get("login")).and_then(|v| v.as_str());
                    if owner_login == Some(owner.as_str()) {
                        if let Some(id) = gist.get("id").and_then(|v| v.as_str()) {
                            if seen.insert(id.to_string()) {
                                let detail: Value = client
                                    .get(&format!("https://api.github.com/gists/{id}"))
                                    .header("User-Agent", "kingfisher")
                                    .bearer_auth(&token)
                                    .send()
                                    .await?
                                    .json()
                                    .await?;
                                if let Some(files) = detail.get("files").and_then(|v| v.as_object())
                                {
                                    let gist_dir = gists_dir.join(id);
                                    fs::create_dir_all(&gist_dir)?;
                                    for (fname, fobj) in files {
                                        if let Some(content) =
                                            fobj.get("content").and_then(|v| v.as_str())
                                        {
                                            let file_path = gist_dir.join(fname);
                                            fs::write(&file_path, content)?;
                                            let url = format!("https://gist.github.com/{id}");
                                            let mut ds = datastore.lock().unwrap();
                                            ds.register_repo_link(file_path, url);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                page += 1;
            }
        }
    }

    if gists_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(gists_dir);
    }

    Ok(dirs)
}

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use gitlab::{
    api::{
        groups::projects::GroupProjects,
        paged,
        users::{UserProjects, Users},
        Pagination, Query,
    },
    Gitlab, GitlabBuilder,
};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use serde_json::Value;
use url::{form_urlencoded, Url};

use crate::{findings_store, git_url::GitUrl};
use std::str::FromStr;

#[derive(Deserialize)]
struct SimpleUser {
    id: u64,
}

#[derive(Deserialize)]
struct SimpleProject {
    http_url_to_repo: String,
}

#[derive(Deserialize)]
struct SimpleGroup {
    id: u64,
}

/// Repository filter types for GitLab
#[derive(Debug, Clone)]
pub enum RepoType {
    All,
    Owner,
    Member,
}

/// A struct to hold GitLab repository query specifications
#[derive(Debug)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub group: Vec<String>,
    pub all_groups: bool,
    pub include_subgroups: bool,
    pub repo_filter: RepoType,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.group.is_empty() && !self.all_groups
    }
}

fn create_gitlab_client(gitlab_url: &Url, ignore_certs: bool) -> Result<Gitlab> {
    let host = gitlab_url.host_str().context("GitLab URL must contain a host")?;

    if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
        return if ignore_certs {
            Gitlab::new_insecure(host, token).map_err(Into::into)
        } else {
            Gitlab::new(host, token).map_err(Into::into)
        };
    }

    // public-only client no PRIVATE-TOKEN header
    let mut builder = GitlabBuilder::new_unauthenticated(host);
    if ignore_certs {
        builder.insecure();
    }
    Ok(builder.build()?)
}

pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    gitlab_url: Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = create_gitlab_client(&gitlab_url, ignore_certs)?;
    let mut repo_urls = Vec::new();

    // 1) Process each GitLab username
    for username in &repo_specifiers.user {
        // a) Look up the user by username, deserializing only `id`
        let users_ep = Users::builder().username(username).build()?;
        let hits: Vec<SimpleUser> = users_ep.query(&client)?;
        let user =
            hits.into_iter().next().context(format!("GitLab user `{}` not found", username))?;
        let user_id = user.id;

        // b) List that user's projects applying the requested filter
        let mut builder = UserProjects::builder();
        builder.user(user_id);

        match repo_specifiers.repo_filter {
            RepoType::Owner => {
                builder.owned(true);
            }
            RepoType::Member => {
                builder.membership(true);
            }
            RepoType::All => {
                // default: list all visible repositories
            }
        }

        let projects_ep = builder.build()?;
        let projects: Vec<SimpleProject> = paged(projects_ep, Pagination::All).query(&client)?;
        for proj in projects {
            repo_urls.push(proj.http_url_to_repo);
        }

        if let Some(pb) = progress.as_mut() {
            pb.inc(1);
        }
    }

    // all groups
    let groups: Vec<SimpleGroup> = if repo_specifiers.all_groups {
        let groups_ep = gitlab::api::groups::Groups::builder().all_available(true).build()?;
        paged(groups_ep, Pagination::All).query(&client.clone())?
    } else {
        let mut found: Vec<SimpleGroup> = Vec::new();
        for grp in &repo_specifiers.group {
            let ep = gitlab::api::groups::Group::builder().group(grp).build()?;
            let group: SimpleGroup = ep.query(&client.clone())?;
            found.push(group);
        }
        found
    };

    for group in groups {
        let mut gp_builder = GroupProjects::builder();
        gp_builder.group(group.id);
        if matches!(repo_specifiers.repo_filter, RepoType::Owner) {
            gp_builder.owned(true);
        }
        if repo_specifiers.include_subgroups {
            gp_builder.include_subgroups(true);
        }

        let gp_ep = gp_builder.build()?;
        let projects: Vec<SimpleProject> = paged(gp_ep, Pagination::All).query(&client)?;
        for proj in projects {
            repo_urls.push(proj.http_url_to_repo);
        }
        if let Some(pb) = progress.as_mut() {
            pb.inc(1);
        }
    }

    // 3) Sort & dedupe
    repo_urls.sort_unstable();
    repo_urls.dedup();

    Ok(repo_urls)
}

pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    groups: &[String],
    all_groups: bool,
    include_subgroups: bool,
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        group: groups.to_vec(),
        all_groups,
        include_subgroups,
        repo_filter,
    };

    // Create a progress bar for displaying status
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

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url.host_str()?.to_string();
    let mut path = url.path().trim_start_matches('/').to_string();
    if let Some(stripped) = path.strip_suffix(".git") {
        path = stripped.to_string();
    }
    Some((host, path))
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let (host, path) = parse_repo(repo_url)?;
    let wiki = format!("https://{host}/{path}.wiki.git");
    GitUrl::from_str(&wiki).ok()
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (host, path) = parse_repo(repo_url).context("invalid GitLab repo URL")?;
    let encoded = form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>();
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;

    let mut dirs = Vec::new();

    // Issues
    let issues_dir = output_root.join("gitlab_issues").join(path.replace('/', "_"));
    fs::create_dir_all(&issues_dir)?;
    let mut page = 1;
    loop {
        let url = format!(
            "https://{host}/api/v4/projects/{encoded}/issues?scope=all&state=all&per_page=100&page={page}"
        );
        let mut req = client.get(&url);
        if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
            if !token.is_empty() {
                req = req.header("PRIVATE-TOKEN", token);
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
            let number = issue.get("iid").and_then(|v| v.as_u64()).unwrap_or(0);
            let title = issue.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = issue.get("description").and_then(|v| v.as_str()).unwrap_or("");
            let content = format!("# {title}\n\n{body}");
            let file_path = issues_dir.join(format!("issue_{number}.md"));
            fs::write(&file_path, content)?;
            let url = format!("https://{host}/{path}/-/issues/{number}");
            let mut ds = datastore.lock().unwrap();
            ds.register_repo_link(file_path, url);
        }
        page += 1;
    }
    if issues_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(issues_dir);
    }

    // Snippets
    let snippets_dir = output_root.join("gitlab_snippets").join(path.replace('/', "_"));
    fs::create_dir_all(&snippets_dir)?;
    page = 1;
    loop {
        let url =
            format!("https://{host}/api/v4/projects/{encoded}/snippets?per_page=100&page={page}");
        let mut req = client.get(&url);
        if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
            if !token.is_empty() {
                req = req.header("PRIVATE-TOKEN", token);
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            break;
        }
        let snippets: Vec<Value> = resp.json().await?;
        if snippets.is_empty() {
            break;
        }
        for snip in snippets {
            if let Some(id) = snip.get("id").and_then(|v| v.as_u64()) {
                let raw_url = format!("https://{host}/api/v4/projects/{encoded}/snippets/{id}/raw");
                let mut req_s = client.get(&raw_url);
                if let Ok(token) = env::var("KF_GITLAB_TOKEN") {
                    if !token.is_empty() {
                        req_s = req_s.header("PRIVATE-TOKEN", token);
                    }
                }
                let raw = req_s.send().await?.text().await?;
                let file_path = snippets_dir.join(format!("snippet_{id}"));
                fs::write(&file_path, raw)?;
                let url = format!("https://{host}/{path}/-/snippets/{id}");
                let mut ds = datastore.lock().unwrap();
                ds.register_repo_link(file_path, url);
            }
        }
        page += 1;
    }
    if snippets_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(snippets_dir);
    }

    Ok(dirs)
}

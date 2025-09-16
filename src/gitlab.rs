use std::{
    collections::HashSet,
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
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;
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
    pub exclude_repos: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.group.is_empty() && !self.all_groups
    }
}

fn normalize_project_path(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let segments: Vec<&str> = without_git.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return None;
    }
    Some(segments.join("/").to_lowercase())
}

fn parse_project_path_from_url(repo_url: &str) -> Option<String> {
    let url = Url::parse(repo_url).ok()?;
    normalize_project_path(url.path())
}

fn parse_project_path(raw: &str) -> Option<String> {
    normalize_project_path(raw)
}

fn parse_excluded_project(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(name) = parse_project_path_from_url(trimmed) {
        return Some(name);
    }

    if let Some(idx) = trimmed.rfind(':') {
        if let Some(name) = parse_project_path(&trimmed[idx + 1..]) {
            return Some(name);
        }
    }

    parse_project_path(trimmed)
}

struct ExcludeMatcher {
    exact: HashSet<String>,
    globs: Option<GlobSet>,
}

impl ExcludeMatcher {
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_none()
    }

    fn matches(&self, name: &str) -> bool {
        if self.exact.contains(name) {
            return true;
        }
        if let Some(globs) = &self.globs {
            return globs.is_match(name);
        }
        false
    }
}

fn looks_like_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

fn build_exclude_matcher(exclude_repos: &[String]) -> ExcludeMatcher {
    let mut exact = HashSet::new();
    let mut glob_builder = GlobSetBuilder::new();
    let mut has_glob = false;

    for raw in exclude_repos {
        match parse_excluded_project(raw) {
            Some(name) => {
                if looks_like_glob(&name) {
                    match Glob::new(&name) {
                        Ok(glob) => {
                            glob_builder.add(glob);
                            has_glob = true;
                        }
                        Err(err) => {
                            warn!("Ignoring invalid GitLab exclusion pattern '{raw}': {err}");
                            exact.insert(name);
                        }
                    }
                } else {
                    exact.insert(name);
                }
            }
            None => {
                warn!("Ignoring invalid GitLab exclusion '{raw}' (expected group/project)");
            }
        }
    }

    let globs = if has_glob {
        match glob_builder.build() {
            Ok(set) => Some(set),
            Err(err) => {
                warn!("Failed to build GitLab exclusion patterns: {err}");
                None
            }
        }
    } else {
        None
    };

    ExcludeMatcher { exact, globs }
}

fn should_exclude_repo(clone_url: &str, excludes: &ExcludeMatcher) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if let Some(name) = parse_project_path_from_url(clone_url) {
        return excludes.matches(&name);
    }
    false
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
    let exclude_set = build_exclude_matcher(&repo_specifiers.exclude_repos);

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
            if should_exclude_repo(&proj.http_url_to_repo, &exclude_set) {
                continue;
            }
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
            if should_exclude_repo(&proj.http_url_to_repo, &exclude_set) {
                continue;
            }
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
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        group: groups.to_vec(),
        all_groups,
        include_subgroups,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_excluded_project_variants() {
        assert_eq!(parse_excluded_project("Group/Project").as_deref(), Some("group/project"));
        assert_eq!(parse_excluded_project("group/project.git").as_deref(), Some("group/project"));
        assert_eq!(
            parse_excluded_project("https://gitlab.com/Group/Project.git").as_deref(),
            Some("group/project")
        );
        assert_eq!(
            parse_excluded_project("git@gitlab.com:Group/Sub/Project.git").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(
            parse_excluded_project("ssh://git@gitlab.example.com/Group/Sub/Project.git").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(
            parse_excluded_project("  group/sub/project  ").as_deref(),
            Some("group/sub/project")
        );
        assert_eq!(parse_excluded_project("not-a-project"), None);
    }

    #[test]
    fn should_exclude_repo_matches_normalized_paths() {
        let excludes = build_exclude_matcher(&vec!["Group/Sub/Project".to_string()]);
        assert!(should_exclude_repo("https://gitlab.com/group/sub/project.git", &excludes));
        assert!(!should_exclude_repo("https://gitlab.com/group/other/project.git", &excludes));
    }

    #[test]
    fn should_exclude_repo_matches_ssh_urls() {
        let excludes = build_exclude_matcher(&vec!["group/sub/project".to_string()]);
        assert!(should_exclude_repo(
            "ssh://git@gitlab.example.com/group/sub/project.git",
            &excludes
        ));
    }

    #[test]
    fn should_exclude_repo_matches_globs() {
        let excludes = build_exclude_matcher(&vec!["group/**/archive-*".to_string()]);
        assert!(should_exclude_repo("https://gitlab.com/group/sub/archive-2023.git", &excludes));
        assert!(!should_exclude_repo("https://gitlab.com/group/sub/project.git", &excludes));
    }
}

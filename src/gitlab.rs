use std::{env, time::Duration};

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
use url::Url;

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

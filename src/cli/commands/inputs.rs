use std::path::PathBuf;

use clap::{Args, ValueHint};
use url::Url;

use crate::{
    cli::commands::{
        github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
        gitlab::GitLabRepoType,
    },
    git_url::GitUrl,
};

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct InputSpecifierArgs {
    /// Scan this file, directory, or local Git repository
    #[arg(
        required_unless_present_any([
            "github_user",
            "github_organization",
            "gitlab_user",
            "gitlab_group",
            "git_url",
            "all_github_organizations",
            "all_gitlab_groups",
            "jira_url",
            "confluence_url",
            "docker_image",
            "slack_query",
            "s3_bucket"
        ]),
        value_hint = ValueHint::AnyPath
    )]
    pub path_inputs: Vec<PathBuf>,

    /// Clone and scan the Git repository at the given URL
    #[arg(long, value_hint = ValueHint::Url)]
    pub git_url: Vec<GitUrl>,

    /// Scan repositories belonging to the specified GitHub user
    #[arg(long)]
    pub github_user: Vec<String>,

    /// Scan repositories belonging to the specified GitHub organization
    #[arg(long, alias = "github-org")]
    pub github_organization: Vec<String>,

    /// Scan repositories from all GitHub organizations (requires non-default --github-api-url)
    #[arg(long, alias = "all-github-orgs", requires = "github_api_url")]
    pub all_github_organizations: bool,

    /// Use the specified URL for GitHub API access (e.g. for GitHub Enterprise)
    #[arg(
        long,
        alias="api-url",
        default_value = "https://api.github.com/",
        value_hint = ValueHint::Url
    )]
    pub github_api_url: Url,

    #[arg(long, default_value_t = GitHubRepoType::Source)]
    pub github_repo_type: GitHubRepoType,

    // GitLab Options
    /// Scan repositories belonging to the specified GitLab user
    #[arg(long)]
    pub gitlab_user: Vec<String>,

    /// Scan repositories belonging to the specified GitLab group
    #[arg(long, alias = "gitlab-group")]
    pub gitlab_group: Vec<String>,

    /// Scan repositories from all GitLab groups (requires non-default --gitlab-api-url)
    #[arg(long, alias = "all-gitlab-groups", requires = "gitlab_api_url")]
    pub all_gitlab_groups: bool,

    /// Use the specified URL for GitLab API access (e.g. for GitLab self-hosted)
    #[arg(
        long,
        alias="gitlab-api-url",
        default_value = "https://gitlab.com/",
        value_hint = ValueHint::Url
    )]
    pub gitlab_api_url: Url,

    #[arg(long, default_value_t = GitLabRepoType::All)]
    pub gitlab_repo_type: GitLabRepoType,

    /// Include projects from GitLab subgroups when scanning groups
    #[arg(long, alias = "include-subgroups")]
    pub gitlab_include_subgroups: bool,

    /// Jira base URL (e.g. https://jira.example.com)
    #[arg(long, value_hint = ValueHint::Url, requires = "jql")]
    pub jira_url: Option<Url>,

    /// JQL query to select Jira issues
    #[arg(long, requires = "jira_url")]
    pub jql: Option<String>,

    /// Confluence base URL (e.g. https://confluence.example.com)
    #[arg(long, value_hint = ValueHint::Url, requires = "cql")]
    pub confluence_url: Option<Url>,

    /// CQL query to select Confluence pages
    #[arg(long, requires = "confluence_url")]
    pub cql: Option<String>,

    /// Slack search query
    #[arg(long)]
    pub slack_query: Option<String>,

    /// Use the specified URL for Slack API access
    #[arg(long, default_value = "https://slack.com/api/", value_hint = ValueHint::Url)]
    pub slack_api_url: Url,

    /// Maximum number of Slack, Jira, or Confluence results to fetch
    #[arg(long, default_value_t = 100)]
    pub max_results: usize,

    /// Scan the specified S3 bucket
    #[arg(long)]
    pub s3_bucket: Option<String>,

    /// Optional prefix within the S3 bucket
    #[arg(long, requires = "s3_bucket")]
    pub s3_prefix: Option<String>,

    /// AWS IAM role ARN to assume for S3 access
    #[arg(long, requires = "s3_bucket")]
    pub role_arn: Option<String>,

    /// Use credentials from a local AWS profile in ~/.aws/config
    #[arg(long, requires = "s3_bucket")]
    pub aws_local_profile: Option<String>,

    /// Docker/OCI images to scan (no local Docker required)
    #[arg(long = "docker-image")]
    pub docker_image: Vec<String>,

    /// Select how to clone Git repositories
    #[arg(long, default_value_t=GitCloneMode::Bare, alias="git-clone-mode")]
    pub git_clone: GitCloneMode,

    /// Select whether to scan full Git history or not
    #[arg(long, default_value_t=GitHistoryMode::Full)]
    pub git_history: GitHistoryMode,

    /// Include detailed Git commit context (author, date, commit hash) for findings.
    /// Set to 'false' to disable.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, help_heading = "Git Options")]
    pub commit_metadata: bool,

    /// Also scan repository host artifacts like issues, wikis, and gists/snippets
    #[arg(long, help_heading = "Git Options")]
    pub repo_artifacts: bool,

    /// Enable or disable scanning nested git repositories
    #[arg(long, default_value_t = true)]
    pub scan_nested_repos: bool,
}

// -----------------------------------------------------------------------------
// Content Filtering
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct ContentFilteringArgs {
    /// Ignore files larger than the given size in MB
    #[arg(
        long = "max-file-size",
        visible_alias = "max-filesize",      // also show in --help
        // alias = "max-filesize",            // use this instead if you DON’T want it shown in --help
        default_value_t = 256.0,
        value_name = "MB"
    )]
    pub max_file_size_mb: f64,

    /// Skip any file or directory whose path matches this glob pattern. Multiple
    /// patterns may be provided by repeating the flag.
    #[arg(long, value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// If true, do NOT extract archive files
    #[arg(long = "no-extract-archives", default_value_t = false)]
    pub no_extract_archives: bool,

    /// Maximum allowed depth for extracting nested archives
    #[arg(long = "extraction-depth", default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=25))]
    pub extraction_depth: u8,

    /// If true, do NOT scan binary files
    #[arg(long = "no-binary", default_value_t = false)]
    pub no_binary: bool,
}

impl ContentFilteringArgs {
    /// Convert the maximum file size in MB to bytes
    pub fn max_file_size_bytes(&self) -> Option<u64> {
        if self.max_file_size_mb < 0.0 {
            Some(256 * 1024 * 1024) // default 256 MB if negative
        } else {
            Some((self.max_file_size_mb * 1024.0 * 1024.0) as u64)
        }
    }
}

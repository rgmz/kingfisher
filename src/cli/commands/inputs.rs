use std::path::PathBuf;

use clap::{Args, ValueHint};
use url::Url;

use crate::{
    cli::commands::{
        azure::AzureRepoType,
        bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
        gitea::GiteaRepoType,
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
            "gitea_user",
            "gitea_organization",
            "huggingface_user",
            "huggingface_organization",
            "huggingface_model",
            "huggingface_dataset",
            "huggingface_space",
            "bitbucket_user",
            "bitbucket_workspace",
            "bitbucket_project",
            "azure_organization",
            "azure_project",
            "git_url",
            "all_github_organizations",
            "all_gitlab_groups",
            "all_gitea_organizations",
            "all_bitbucket_workspaces",
            "all_azure_projects",
            "jira_url",
            "confluence_url",
            "docker_image",
            "slack_query",
            "s3_bucket",
            "gcs_bucket"
        ]),
        num_args = 0..,
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

    /// Skip repositories when enumerating GitHub users or organizations (format: owner/repo)
    #[arg(long = "github-exclude", alias = "github-exclude-repo", value_name = "OWNER/REPO")]
    pub github_exclude: Vec<String>,

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

    /// Skip repositories when enumerating GitLab users or groups (format: group/project)
    #[arg(
        long = "gitlab-exclude",
        alias = "gitlab-exclude-project",
        alias = "gitlab-exclude-repo",
        value_name = "GROUP/PROJECT"
    )]
    pub gitlab_exclude: Vec<String>,

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

    /// Scan models, datasets, and Spaces belonging to the specified Hugging Face users
    #[arg(long = "huggingface-user")]
    pub huggingface_user: Vec<String>,

    /// Scan models, datasets, and Spaces belonging to the specified Hugging Face organizations
    #[arg(long = "huggingface-organization", alias = "huggingface-org")]
    pub huggingface_organization: Vec<String>,

    /// Scan a specific Hugging Face model (format: owner/name or full URL)
    #[arg(long = "huggingface-model")]
    pub huggingface_model: Vec<String>,

    /// Scan a specific Hugging Face dataset (format: owner/name or full URL)
    #[arg(long = "huggingface-dataset")]
    pub huggingface_dataset: Vec<String>,

    /// Scan a specific Hugging Face Space (format: owner/name or full URL)
    #[arg(long = "huggingface-space")]
    pub huggingface_space: Vec<String>,

    /// Skip specific Hugging Face repositories during enumeration (accepts optional prefixes like model:, dataset:, or space:)
    #[arg(long = "huggingface-exclude", value_name = "IDENTIFIER")]
    pub huggingface_exclude: Vec<String>,

    // Gitea Options
    /// Scan repositories belonging to the specified Gitea user
    #[arg(long)]
    pub gitea_user: Vec<String>,

    /// Scan repositories belonging to the specified Gitea organization
    #[arg(long, alias = "gitea-org")]
    pub gitea_organization: Vec<String>,

    /// Skip repositories when enumerating Gitea users or organizations (format: owner/repo)
    #[arg(long = "gitea-exclude", alias = "gitea-exclude-repo", value_name = "OWNER/REPO")]
    pub gitea_exclude: Vec<String>,

    /// Scan repositories from all accessible Gitea organizations (requires KF_GITEA_TOKEN)
    #[arg(long, alias = "all-gitea-orgs")]
    pub all_gitea_organizations: bool,

    /// Use the specified URL for Gitea API access (e.g. for self-hosted instances)
    #[arg(
        long,
        alias="gitea-api-url",
        default_value = "https://gitea.com/api/v1/",
        value_hint = ValueHint::Url
    )]
    pub gitea_api_url: Url,

    #[arg(long, default_value_t = GiteaRepoType::Source)]
    pub gitea_repo_type: GiteaRepoType,

    // Bitbucket Options
    /// Scan repositories belonging to the specified Bitbucket users
    #[arg(long)]
    pub bitbucket_user: Vec<String>,

    /// Scan repositories belonging to the specified Bitbucket workspaces or teams
    #[arg(long, alias = "bitbucket-workspace", alias = "bitbucket-team")]
    pub bitbucket_workspace: Vec<String>,

    /// Scan repositories belonging to the specified Bitbucket Server projects
    #[arg(long, alias = "bitbucket-project")]
    pub bitbucket_project: Vec<String>,

    /// Skip repositories when enumerating Bitbucket sources (format: owner/repo)
    #[arg(long = "bitbucket-exclude", value_name = "OWNER/REPO")]
    pub bitbucket_exclude: Vec<String>,

    /// Scan repositories from all accessible Bitbucket workspaces or projects
    #[arg(long, alias = "all-bitbucket-workspaces", requires = "bitbucket_api_url")]
    pub all_bitbucket_workspaces: bool,

    /// Use the specified URL for Bitbucket API access (Cloud or self-hosted)
    #[arg(long, default_value = "https://api.bitbucket.org/2.0/", value_hint = ValueHint::Url)]
    pub bitbucket_api_url: Url,

    #[arg(long, default_value_t = BitbucketRepoType::Source)]
    pub bitbucket_repo_type: BitbucketRepoType,

    #[command(flatten)]
    pub bitbucket_auth: BitbucketAuthArgs,

    // Azure DevOps Options
    /// Scan repositories belonging to the specified Azure DevOps organizations or collections
    #[arg(long = "azure-organization")]
    pub azure_organization: Vec<String>,

    /// Scan repositories belonging to the specified Azure DevOps projects (format: ORGANIZATION/PROJECT)
    #[arg(long = "azure-project", value_name = "ORGANIZATION/PROJECT")]
    pub azure_project: Vec<String>,

    /// Skip repositories when enumerating Azure Repos sources (format: ORGANIZATION/PROJECT/REPOSITORY)
    #[arg(
        long = "azure-exclude",
        alias = "azure-exclude-repo",
        value_name = "ORGANIZATION/PROJECT/REPOSITORY"
    )]
    pub azure_exclude: Vec<String>,

    /// Include repositories from every project within the specified Azure organizations
    #[arg(long = "all-azure-projects")]
    pub all_azure_projects: bool,

    /// Use the specified base URL for Azure DevOps (e.g. Azure DevOps Server)
    #[arg(
        long = "azure-base-url",
        default_value = "https://dev.azure.com/",
        value_hint = ValueHint::Url
    )]
    pub azure_base_url: Url,

    #[arg(long = "azure-repo-type", default_value_t = AzureRepoType::Source)]
    pub azure_repo_type: AzureRepoType,

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

    /// Scan the specified Google Cloud Storage bucket
    #[arg(long)]
    pub gcs_bucket: Option<String>,

    /// Optional prefix within the GCS bucket
    #[arg(long, requires = "gcs_bucket")]
    pub gcs_prefix: Option<String>,

    /// Path to a service account JSON file for GCS authentication
    #[arg(long, value_hint = ValueHint::FilePath, requires = "gcs_bucket")]
    pub gcs_service_account: Option<PathBuf>,

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

    /// Limit Git scanning to changes made since this commit or ref
    #[arg(long = "since-commit", value_name = "GIT-REF", help_heading = "Git Options")]
    pub since_commit: Option<String>,

    /// Branch or ref to scan or compare against (defaults to HEAD)
    #[arg(long, value_name = "GIT-REF", help_heading = "Git Options")]
    pub branch: Option<String>,
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

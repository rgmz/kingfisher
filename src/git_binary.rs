use std::{
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
};

use tracing::{debug, debug_span};

use crate::{bitbucket::is_bitbucket_access_token, git_url::GitUrl};

const BITBUCKET_CREDENTIAL_HELPER: &str = r#"credential.helper=!_bbcreds() {
    if [ -n "$KF_BITBUCKET_OAUTH_TOKEN" ]; then
        echo username="x-token-auth";
        echo password="$KF_BITBUCKET_OAUTH_TOKEN";
        return;
    fi
    if [ -n "$KF_BITBUCKET_ACCESS_TOKEN" ]; then
        echo username="x-token-auth";
        echo password="$KF_BITBUCKET_ACCESS_TOKEN";
        return;
    fi
    if [ -n "$KF_BITBUCKET_USERNAME" ]; then
        bb_pass="${KF_BITBUCKET_APP_PASSWORD:-${KF_BITBUCKET_TOKEN:-${KF_BITBUCKET_PASSWORD:-}}}";
        if [ -n "$bb_pass" ]; then
            echo username="$KF_BITBUCKET_USERNAME";
            echo password="$bb_pass";
            return;
        fi
    fi
}; _bbcreds"#;

const GITEA_CREDENTIAL_HELPER: &str = r#"credential.helper=!_gteacreds() {
    if [ -n "$KF_GITEA_TOKEN" ]; then
        user="${KF_GITEA_USERNAME:-gitea}";
        echo username="$user";
        echo password="$KF_GITEA_TOKEN";
    fi
}; _gteacreds"#;

const AZURE_CREDENTIAL_HELPER: &str = r#"credential.helper=!_azcreds() {
    token="${KF_AZURE_TOKEN:-${KF_AZURE_PAT:-}}";
    if [ -n "$token" ]; then
        user="${KF_AZURE_USERNAME:-pat}";
        echo username="$user";
        echo password="$token";
    fi
}; _azcreds"#;

const HUGGINGFACE_CREDENTIAL_HELPER: &str = r#"credential.helper=!_hfcreds() {
    token="$KF_HUGGINGFACE_TOKEN";
    if [ -n "$token" ]; then
        user="${KF_HUGGINGFACE_USERNAME:-hf_user}";
        echo username="$user";
        echo password="$token";
    fi
}; _hfcreds"#;

/// Represents errors that can occur when interacting with the `git` CLI.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git execution failed: {0}")]
    IOError(#[from] std::io::Error),

    #[error(
        "git execution failed (status: {status}){summary}",
        status = format_exit_status(.status),
        summary = format_git_error_summary(.stdout.as_slice(), .stderr.as_slice())
    )]
    GitError { stdout: Vec<u8>, stderr: Vec<u8>, status: ExitStatus },
}

fn format_exit_status(status: &ExitStatus) -> String {
    status.code().map(|code| code.to_string()).unwrap_or_else(|| status.to_string())
}

fn format_git_error_summary(stdout: &[u8], stderr: &[u8]) -> String {
    let mut messages = Vec::new();
    if let Some(line) = summarize_output(stderr) {
        messages.push(line);
    }
    if let Some(line) = summarize_output(stdout) {
        messages.push(line);
    }
    if messages.is_empty() {
        String::new()
    } else {
        format!(": {}", messages.join(" | "))
    }
}

fn summarize_output(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    text.lines().map(str::trim).find(|line| !line.is_empty()).map(|line| line.to_owned())
}

/// A helper struct for running `git` commands.
///
/// It supports optional GitHub, GitLab, Gitea, and Bitbucket credentials passed via
/// environment variables and optionally ignores TLS certificate validation if
/// requested.
pub struct Git {
    credentials: Vec<String>,
    ignore_certs: bool,
    bitbucket_access_token: Option<String>,
}

impl Git {
    /// Create a new `Git` instance.
    ///
    /// * `ignore_certs`: If `true`, disables SSL certificate verification for `git` operations.
    pub fn new(ignore_certs: bool) -> Self {
        let mut credentials = Vec::new();

        let has_github_token =
            matches!(std::env::var("KF_GITHUB_TOKEN"), Ok(token) if !token.is_empty());
        let has_gitlab_token =
            matches!(std::env::var("KF_GITLAB_TOKEN"), Ok(token) if !token.is_empty());
        let has_gitea_token =
            matches!(std::env::var("KF_GITEA_TOKEN"), Ok(token) if !token.is_empty());
        let has_bitbucket_username =
            matches!(std::env::var("KF_BITBUCKET_USERNAME"), Ok(value) if !value.is_empty());
        let bitbucket_access_token = std::env::var("KF_BITBUCKET_TOKEN")
            .ok()
            .filter(|value| !value.is_empty() && is_bitbucket_access_token(value));
        let has_bitbucket_password =
            ["KF_BITBUCKET_APP_PASSWORD", "KF_BITBUCKET_TOKEN", "KF_BITBUCKET_PASSWORD"]
                .iter()
                .any(|key| matches!(std::env::var(key), Ok(value) if !value.is_empty()));
        let has_bitbucket_oauth_token =
            matches!(std::env::var("KF_BITBUCKET_OAUTH_TOKEN"), Ok(value) if !value.is_empty());
        let has_bitbucket_credentials = has_bitbucket_oauth_token
            || bitbucket_access_token.is_some()
            || (has_bitbucket_username && has_bitbucket_password);
        let has_azure_token = ["KF_AZURE_TOKEN", "KF_AZURE_PAT"]
            .iter()
            .any(|key| matches!(std::env::var(key), Ok(value) if !value.is_empty()));
        let has_huggingface_token =
            matches!(std::env::var("KF_HUGGINGFACE_TOKEN"), Ok(value) if !value.is_empty());

        // If credentials are provided via environment variables, clear existing helpers first.
        if has_github_token
            || has_gitlab_token
            || has_gitea_token
            || has_bitbucket_credentials
            || has_azure_token
            || has_huggingface_token
        {
            credentials.push("-c".into());
            credentials.push(r#"credential.helper="#.into());
        }

        // Inject GitHub token helper
        if has_github_token {
            credentials.push("-c".into());
            credentials.push(
                r#"credential.helper=!_ghcreds() { echo username="kingfisher"; echo password="$KF_GITHUB_TOKEN"; }; _ghcreds"#.into(),
            );
        }

        // Inject GitLab token helper
        if has_gitlab_token {
            credentials.push("-c".into());
            credentials.push(
                r#"credential.helper=!_glcreds() { echo username="oauth2"; echo password="$KF_GITLAB_TOKEN"; }; _glcreds"#.into(),
            );
        }

        // Inject Gitea token helper
        if has_gitea_token {
            credentials.push("-c".into());
            credentials.push(GITEA_CREDENTIAL_HELPER.into());
        }

        // Inject Bitbucket credential helper for OAuth tokens or basic auth.
        if has_bitbucket_credentials {
            credentials.push("-c".into());
            credentials.push(BITBUCKET_CREDENTIAL_HELPER.into());
        }

        if has_azure_token {
            credentials.push("-c".into());
            credentials.push(AZURE_CREDENTIAL_HELPER.into());
        }

        if has_huggingface_token {
            credentials.push("-c".into());
            credentials.push(HUGGINGFACE_CREDENTIAL_HELPER.into());
        }

        Self { credentials, ignore_certs, bitbucket_access_token }
    }

    /// Create a basic `git` `Command` with environment variables set to
    /// limit config usage and (optionally) ignore certs. Includes credentials
    /// if GitHub, GitLab, or Bitbucket tokens are present.
    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        if self.ignore_certs {
            cmd.env("GIT_SSL_NO_VERIFY", "1");
        }
        if let Some(token) = &self.bitbucket_access_token {
            cmd.env("KF_BITBUCKET_ACCESS_TOKEN", token);
        }
        cmd.args(&self.credentials);
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Helper to run the constructed `git` command and capture its output.
    ///
    /// Returns an error if the command fails or exits with a non-zero status.
    fn run_cmd(&self, mut cmd: Command) -> Result<(), GitError> {
        debug!("{cmd:#?}");
        let output: Output = cmd.output()?;
        if !output.status.success() {
            return Err(GitError::GitError {
                stdout: output.stdout,
                stderr: output.stderr,
                status: output.status,
            });
        }
        Ok(())
    }

    /// Update an existing bare or mirror clone by running `git remote update --prune`.
    ///
    /// * `repo_url`: The remote repository URL (only used for logging).
    /// * `output_dir`: The path to the existing bare/mirror clone.
    pub fn update_clone(&self, repo_url: &GitUrl, output_dir: &Path) -> Result<(), GitError> {
        let _span = debug_span!("git_update", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to update clone of {repo_url} at {}", output_dir.display());
        let mut cmd = self.git();
        if output_dir.join(".git").is_dir() {
            cmd.arg("-C");
            cmd.arg(output_dir);
        } else {
            cmd.arg("--git-dir");
            cmd.arg(output_dir);
        }
        cmd.arg("remote");
        cmd.arg("update");
        cmd.arg("--prune");
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }

    /// Create a fresh clone of the specified repository in either bare or mirror mode.
    ///
    /// * `repo_url`: The remote repository URL.
    /// * `output_dir`: Where to place the newly created clone.
    /// * `clone_mode`: Whether to clone as `--bare` or `--mirror`.
    pub fn create_fresh_clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        clone_mode: CloneMode,
    ) -> Result<(), GitError> {
        let _span = debug_span!("git_clone", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to create fresh clone of {} at {}", repo_url, output_dir.display());
        let mut cmd = self.git();
        cmd.arg("clone");
        if let Some(arg) = clone_mode.arg() {
            cmd.arg(arg);
        }
        cmd.arg("--quiet");
        cmd.arg("-c");
        cmd.arg("remote.origin.fetch=+refs/*:refs/remotes/origin/*");
        cmd.arg(repo_url.as_str());
        cmd.arg(output_dir);
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }
}

impl Default for Git {
    /// Equivalent to `Git::new(false)`
    fn default() -> Self {
        Self::new(false)
    }
}

/// Represents how a repository is cloned.
#[derive(Debug, Clone, Copy)]
pub enum CloneMode {
    /// Equivalent to `git clone --bare`
    Bare,
    /// Equivalent to `git clone --mirror`
    Mirror,
    /// Standard clone with a working tree
    Checkout,
}

impl CloneMode {
    /// Return the CLI argument for this clone mode.
    pub fn arg(&self) -> Option<&str> {
        match self {
            Self::Bare => Some("--bare"),
            Self::Mirror => Some("--mirror"),
            Self::Checkout => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_git_new() {
        let git = Git::new(false);
        assert!(!git.ignore_certs);
        assert!(git.credentials.is_empty());
        assert!(git.bitbucket_access_token.is_none());

        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
        });
    }

    #[test]
    fn test_git_new_bitbucket_oauth() {
        temp_env::with_var("KF_BITBUCKET_OAUTH_TOKEN", Some("oauth"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
            assert!(git.credentials.iter().any(|value| value == BITBUCKET_CREDENTIAL_HELPER));
            assert!(git.bitbucket_access_token.is_none());
        });
    }

    #[test]
    fn test_git_new_bitbucket_basic_auth() {
        temp_env::with_vars(
            &[
                ("KF_BITBUCKET_USERNAME", Some("user")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("password")),
            ],
            || {
                let git = Git::new(false);
                assert_eq!(git.credentials.len(), 4);
                assert!(git.credentials.iter().any(|value| value == BITBUCKET_CREDENTIAL_HELPER));
                assert!(git.bitbucket_access_token.is_none());
            },
        );
    }

    #[test]
    fn test_git_new_bitbucket_access_token() {
        let token = "AT1234567890_ACCESS_TOKEN_EXAMPLE_WITH_UNDERSCORE";
        temp_env::with_var("KF_BITBUCKET_TOKEN", Some(token), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
            assert!(git.credentials.iter().any(|value| value == BITBUCKET_CREDENTIAL_HELPER));
            assert_eq!(git.bitbucket_access_token.as_deref(), Some(token));
        });
    }

    #[test]
    fn test_clone_mode_arg() {
        assert_eq!(CloneMode::Bare.arg(), Some("--bare"));
        assert_eq!(CloneMode::Mirror.arg(), Some("--mirror"));
        assert_eq!(CloneMode::Checkout.arg(), None);
    }

    #[test]
    fn test_create_fresh_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        assert!(temp_dir.path().join("HEAD").exists());
        Ok(())
    }

    #[test]
    fn test_update_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        git.update_clone(&url, temp_dir.path())?;
        Ok(())
    }

    #[test]
    fn test_git_error() {
        let temp_dir = TempDir::new().unwrap();
        let git = Git::default();
        let invalid_url =
            GitUrl::try_from(url::Url::parse("https://invalid.git").unwrap()).unwrap();
        let err =
            git.create_fresh_clone(&invalid_url, temp_dir.path(), CloneMode::Bare).unwrap_err();
        assert!(matches!(err, GitError::GitError { .. }));
    }
}

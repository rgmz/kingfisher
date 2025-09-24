//! Proves that run_async_scan collapses identical findings when
//!               ── no_dedup == false ──
//! while keeping them separate when       no_dedup == true.

use std::{
    fs,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use kingfisher::{
    cli::{
        commands::{
            bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
            gitea::GiteaRepoType,
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
            scan::{ConfidenceLevel, ScanArgs},
        },
        global::Mode,
        GlobalArgs,
    },
    findings_store::FindingsStore,
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::run_async_scan,
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use url::Url;

/// Helper: run a scan with the supplied `no_dedup` flag and return how many
/// findings the `FindingsStore` ends up containing.
fn run_scan(count_rt: &Runtime, no_dedup: bool) -> Result<usize> {
    // ── temp workspace ──────────────────────────────────────────────
    let work = TempDir::new()?;
    let rules_dir = work.path().join("rules");
    fs::create_dir_all(&rules_dir)?;
    let inputs_dir = work.path().join("in");
    fs::create_dir_all(&inputs_dir)?;

    // 1. Tiny custom rule that matches `secret_1234`
    fs::write(
        rules_dir.join("demo.yml"),
        r#"
rules:
  - id: demo.secret
    name: Demo secret
    pattern: "secret_[0-9]{4}"
    confidence: low
"#,
    )?;

    // 2. Two different blobs that both contain the SAME secret
    fs::write(inputs_dir.join("a.txt"), "secret_1234\n")?;
    fs::write(inputs_dir.join("b.txt"), "secret_1234\n")?;

    // ── build ScanArgs ──────────────────────────────────────────────
    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: vec![rules_dir.clone()],
            rule: vec!["all".into()],
            load_builtins: false,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: vec![inputs_dir.join("a.txt"), inputs_dir.join("b.txt")],
            git_url: Vec::new(),
            github_user: Vec::new(),
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::Owner,
            gitlab_include_subgroups: false,

            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),

            jira_url: None,
            jql: None,
            confluence_url: None,
            cql: None,
            max_results: 100,
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            // s3
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            // Docker image scanning
            docker_image: Vec::new(),
            // git clone / history options
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
        },
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 5.0,
            extraction_depth: 1,
            no_binary: true,
            no_extract_archives: false,
            exclude: Vec::new(), // Exclude patterns
        },
        confidence: ConfidenceLevel::Low,
        no_validate: true,
        rule_stats: false,
        only_valid: false,
        min_entropy: Some(0.0),
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
        no_base64: false,
    };

    let global_args = GlobalArgs {
        verbose: 0,
        quiet: true,
        color: Mode::Never,
        progress: Mode::Never,
        no_update_check: false,
        self_update: false,
        ignore_certs: false,
        user_agent_suffix: None,
    };

    // ── load rules once ─────────────────────────────────────────────
    let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = Arc::new(RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?);

    // Fresh FindingsStore for this run
    let store_path = work.path().join("store");
    fs::create_dir_all(&store_path)?;
    let datastore = Arc::new(Mutex::new(FindingsStore::new(store_path)));

    // run_async_scan is async – use the supplied Tokio runtime
    count_rt.block_on(run_async_scan(
        &global_args,
        &scan_args,
        Arc::clone(&datastore),
        &rules_db,
    ))?;

    let x = Ok(datastore.lock().unwrap().get_matches().len());
    x
}

#[test]
fn test_dedup_branch() -> Result<()> {
    // A *single* runtime reused for both scans keeps the test fast
    let rt = Runtime::new().unwrap();

    let findings_with_dups = run_scan(&rt, true)?; // keep duplicates
    let findings_deduped = run_scan(&rt, false)?; // collapse duplicates

    assert!(
        findings_with_dups > findings_deduped,
        "expected deduplication to reduce finding count ({} -- {})",
        findings_with_dups,
        findings_deduped
    );
    assert_eq!(findings_deduped, 1, "exactly one unique finding should remain after dedup");

    Ok(())
}

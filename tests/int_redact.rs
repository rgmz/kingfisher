// Integration test to ensure --redact replaces secret values with hashes
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use kingfisher::{
    cli::{
        commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
            scan::{ConfidenceLevel, ScanArgs},
        },
        global::{AdvancedArgs, GlobalArgs, Mode},
    },
    findings_store::FindingsStore,
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::run_async_scan,
};
use tempfile::TempDir;
use url::Url;

#[tokio::test]
async fn test_redact_hashes_finding_values() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: vec![PathBuf::from("testdata/generic_secrets.py")],
            git_url: Vec::new(),
            github_user: Vec::new(),
            github_organization: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::Owner,
            gitlab_include_subgroups: false,
            jira_url: None,
            jql: None,
            confluence_url: None,
            cql: None,
            max_results: 100,
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            docker_image: Vec::new(),
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            scan_nested_repos: true,
            commit_metadata: true,
        },
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            extraction_depth: 2,
            no_binary: true,
            no_extract_archives: false,
            exclude: Vec::new(),
        },
        confidence: ConfidenceLevel::Low,
        no_validate: true,
        rule_stats: false,
        only_valid: false,
        min_entropy: Some(0.0),
        redact: true,
        git_repo_timeout: 1800,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
    };

    let global_args = GlobalArgs {
        verbose: 0,
        quiet: true,
        color: Mode::Never,
        no_update_check: false,
        self_update: false,
        progress: Mode::Never,
        ignore_certs: false,
        advanced: AdvancedArgs { rlimit_nofile: 16384 },
    };

    let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?;

    let datastore = Arc::new(Mutex::new(FindingsStore::new(temp_dir.path().to_path_buf())));
    run_async_scan(&global_args, &scan_args, Arc::clone(&datastore), &rules_db).await?;

    let ds = datastore.lock().unwrap();
    let matches = ds.get_matches();
    assert!(!matches.is_empty());
    for m_arc in matches {
        let m = &m_arc.2;
        assert!(m.groups.captures.iter().any(|cap| cap.value.starts_with("[REDACTED:")));
    }

    Ok(())
}

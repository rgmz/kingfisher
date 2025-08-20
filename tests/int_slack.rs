use std::{
    env,
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
        global::{AdvancedArgs, Mode},
        GlobalArgs,
    },
    findings_store::FindingsStore,
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::run_async_scan,
};
use tempfile::TempDir;
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

struct TestContext {
    rules_db: Arc<RulesDatabase>,
}

impl TestContext {
    fn new() -> Result<Self> {
        let scan_args = ScanArgs {
            num_jobs: 2,
            rules: RuleSpecifierArgs {
                rules_path: Vec::new(),
                rule: vec!["all".into()],
                load_builtins: true,
            },
            input_specifier_args: InputSpecifierArgs {
                path_inputs: Vec::new(),
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
                slack_query: None,
                slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
                s3_bucket: None,
                s3_prefix: None,
                role_arn: None,
                aws_local_profile: None,
                max_results: 10,
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
            redact: false,
            git_repo_timeout: 1800,
            output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
            no_dedup: true,
            baseline_file: None,
            manage_baseline: false,
            skip_regex: Vec::new(),
            skip_word: Vec::new(),
        };

        let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
        let resolved = loaded.resolve_enabled_rules()?;
        let rules_db = RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?;
        Ok(Self { rules_db: Arc::new(rules_db) })
    }
}

#[tokio::test]
async fn test_scan_slack_messages() -> Result<()> {
    let ctx = TestContext::new()?;

    let server = MockServer::start().await;
    let response = serde_json::json!({
        "ok": true,
        "messages": {
            "matches": [{
                "permalink": "https://example.slack.com/archives/C123/p1234",
                "text": "This contains a github token ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa",
                "ts": "1234.56",
                "channel": {"id": "C123", "name": "general"}
            }],
            "pagination": {"page": 1, "page_count": 1}
        }
    });
    Mock::given(method("GET"))
        .and(path("/search.messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    env::set_var("KF_SLACK_TOKEN", "xoxp-test");

    let temp_dir = TempDir::new()?;
    let clone_dir = temp_dir.path().to_path_buf();

    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
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
            slack_query: Some("test".into()),
            slack_api_url: Url::parse(&format!("{}/", server.uri()))?,
            max_results: 10,
            // s3
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
        redact: false,
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
        color: Mode::Auto,
        no_update_check: false,
        self_update: false,
        progress: Mode::Never,
        ignore_certs: false,
        advanced: AdvancedArgs { rlimit_nofile: 16384 },
    };

    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));

    run_async_scan(&global_args, &scan_args, Arc::clone(&datastore), &ctx.rules_db).await?;

    let findings = {
        let ds = datastore.lock().unwrap();
        ds.get_matches().len()
    };
    assert!(findings > 0);
    Ok(())
}

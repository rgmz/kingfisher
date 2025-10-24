use std::{collections::HashSet, fs, path::Path, process::Command};

use anyhow::Result;
use assert_cmd::prelude::*;
use git2::{Repository, Signature};
use serde_json::Value;
use tempfile::TempDir;

const CONFIG_PY: &str = r"# Configuration file packed with representative secrets\n\nAWS_ACCESS_SECRET_KEY = 'UpUbsQANRHLf2uuQ7QOlNXPbbtV5fmseW/GgT5D/'\nGCP_PRIVATE_KEY_ID = 'c4c474d61701fd6fd4191883b8fea9a8411bf771'\nGCP_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChoGF4j4AUnAfj\nbVGP/tSJqAyeYiZfOf4UCwd9+B/2oej3rsiuZmx506kuWVN4Jhg8UocLn5l/OfqU\n2MyV3Mq5VjtGQjYWF7a/Y04yEMRWf+spiJp1iYGS1vTOVjuyYyMa9h+8sbDiBFAD\nBcZejB4FQHxstFtmlnehf7cieMLTa3Wezv8LX8pH0q+pEynuvusQkhe8uPmjUsuo\nWG5W5CgVchQVzQf9eB5xtyt85t6VozMvAEI4h+WwZRdn+EWrQi+z8A8vXF7iUDmu\n2lpypLExcZBrZINMh8ecs8B34JNIYzO4Hod7RB4IwXN8PG/5RHlb7qQbzXSxir2B\n17gPPf8JAgMBAAECggEAHbkdG7sGIqQkJjypInpKc0tKkMj7hgkn8t8pYE7kb+qM\nKZqE0N/IpKnaY8ntGfwlelhx+d7+r0FGFh/9lbTOOkHDslLEWBFB3BYC4B2pwb+S\nC2gSAboJMGwkBpsgrNhi8RcgtIaYASSqYzfpaGNLtQsMJsCPS4Ex3GscjnQXXiJK\n5MExF8VYZVvT8Hq2lvECUpFMTWwM2o/QndwjLrEq/vRI3n7PmweXZGKgLuyOjpWk\ny80qa/IUlB6xO4XHvjnaEGxRq1LSF8hgEGU2Nmd8GDRT5ZLkSk+TMtqPrEbHEi6n\n4pZGndX0XmttWkKcUX/NwB/WZC5ROEsUl8Fyw+T5RQKBgQDMfgFB6Xx+Na2iB33w\nkhzNxo4HPCJzxeAB0zCRpfDpM1GtqK6JsIxvrci5lDAKaP8TQTr/gQxXpbJjE1Dl\n3VWGzFbW4czSw+AqBFl1he20RZhGjATcDCCzSOyEiRhqoJwTPTvqcXRK8NbKGfJR\nV6b4Auw+McNhnEUyfrZzguV93QKBgQDKVlLPhb4O84mINKFK73QFf2xlns0IHI0m\nWqNvY7HxJP9WUH5FgX4r/cO6aIafg+u5j0gNPDd2JD67htnY85EH/n5KNhb9ytsN\n+hkDeidFvdOrD+h9YFHkNoNy3XHwrQ0mtYRj2FBWhhpBsVlHVO2KcLe0TvivinN2\nfIac2uZhHQKBgAYE23KeNbzdRZwUTl+rXU+tPXb3DSiNNXe4SKCw2rNygD/1TBXf\nbXLIEbVsqDFWP9PIQr1Mhhl6VhLWebYaWq8aCqBOiyHVBB8Ye62a4JFCzyWcb3Qu\nozPDvLp18pMI4S8ryTywVDT0e839D4XXZ6G7LEr0WgTgfaTr1+D0hF69AoGBAKIQ\nxKGeAV6eaOGlLjAEXgztRFic+qLto409+jyFQQji1nY/YPSxROtdhkGv6WypUM0/\nW7nmKpJBc9HmsGUaqmcZy/QLIR1FN3IZiaGEXSJ6aqlQw6pw1QcTNvRxNQtOwQLp\nT1Jd9/Nl1HAb6mO9PcqugCY3Pu/z2InmMjg/CVptAoGAMpwMsoen4xEHv4uGZVt8\n8wlvQ2fYnso4wgRSYAkjh8cOHjB85eazlSAsaJvmQ9D1rV086Re5zKxKjrjQWdaT\nRMyIZJMJYZr6c8RKmabOfO1oc5urDdETQjGi3qXJuiu86wp7IoBINdmBEPRl6+m3\nGqJA6hgV5niKAq4sJtv9EW4='\nGOOGLE_API_KEY = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'\nGITHUB_KEY = '88df97769ab3185f2c0b2a73fdae1b27d89409ca'\nGITHUB_APP_SECRET = '895b1da4051440395f90e1411c4a1150e423c922'\nSLACK_APP_TOKEN = 'xapp-1-A01C259PH2A-1440755929120-7d5241948a2cc1b464add85df8a8e75f9040ae2869f6599926ed0b9dcafdb32b'\nSLACK_OAUTH_ACCESS_TOKEN = 'xoxb-730191371696-1413868247813-IG7Z6nYevC2hdviE3aJhb5kY'\nSLACK_WEBHOOK = 'https://hooks.slack.com/services/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'\nSTRIPE_RESTRICTED_KEY = 'rk_live_z59MoCJoFc114PpJlP1OnB1O'\nTWILIO_API_KEY = 'SK5d1d319A6Acf7EC9BDeDb8CCe4D76BA8'\n";

const CANARY_TOKEN: &str = r"[default]\naws_access_key_id = AKIAX24QKKOLDJMZ5Y2T\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n";

#[test]
fn scan_branch_and_since_commit_diff_behaviour() -> Result<()> {
    let workspace = TempDir::new()?;
    let repo_dir = workspace.path().join("SecretsTest");
    fs::create_dir(&repo_dir)?;
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@example.com")?;

    fs::write(repo_dir.join("config.py"), CONFIG_PY)?;

    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let initial_commit = repo.commit(Some("HEAD"), &sig, &sig, "seed secrets", &tree, &[])?;

    let base_commit = repo.find_commit(initial_commit)?;
    repo.branch("main", &base_commit, true)?;
    repo.set_head("refs/heads/main")?;

    repo.branch("feature-1", &base_commit, true)?;
    repo.set_head("refs/heads/feature-1")?;

    fs::write(repo_dir.join("canary-token"), CANARY_TOKEN)?;
    let mut index = repo.index()?;
    index.add_path(Path::new("canary-token"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let feature_commit =
        repo.commit(Some("HEAD"), &sig, &sig, "add canary token", &tree, &[&base_commit])?;

    let repo_path = repo_dir.to_string_lossy().to_string();
    let base_commit_hex = initial_commit.to_string();
    let feature_commit_hex = feature_commit.to_string();

    let branch_scan = Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            &repo_path,
            "--branch",
            &base_commit_hex,
            "--no-validate",
            "--no-update-check",
            "--format",
            "json",
        ])
        .output()?;
    assert_eq!(branch_scan.status.code(), Some(200));

    let findings: Vec<Value> = serde_json::from_slice(&branch_scan.stdout)?;
    let expected_rules: HashSet<String> = [
        "KINGFISHER.AWS.2",
        "KINGFISHER.GCP.3",
        "KINGFISHER.PRIVKEY.2",
        "KINGFISHER.PEM.1",
        "KINGFISHER.GOOGLE.7",
        "KINGFISHER.GITHUB.6",
        "KINGFISHER.SLACK.1",
        "KINGFISHER.SLACK.2",
        "KINGFISHER.SLACK.4",
        "KINGFISHER.STRIPE.2",
        "KINGFISHER.TWILIO.1",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();


    // KINGFISHER.GITHUB.6 should appear twice (two separate secrets)
    assert_eq!(findings.len(), expected_rules.len() + 1);

    let mut rule_hits: HashSet<String> = HashSet::new();
    let mut github_hit_count = 0usize;
    for finding in &findings {
        let rule_id = finding["rule"]["id"].as_str().unwrap();
        if rule_id == "KINGFISHER.GITHUB.6" {
            github_hit_count += 1;
        } else {
            rule_hits.insert(rule_id.to_string());
        }

        assert_eq!(finding["finding"]["path"].as_str().unwrap(), "config.py");
        assert_eq!(
            finding["finding"]["git_metadata"]["commit"]["id"].as_str().unwrap(),
            base_commit_hex
        );
    }

    assert_eq!(github_hit_count, 2, "expected two GitHub secret detections");
    assert_eq!(rule_hits, expected_rules);

    let diff_scan = Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            &repo_path,
            "--branch",
            "feature-1",
            "--since-commit",
            &base_commit_hex,
            "--no-validate",
            "--no-update-check",
            "--format",
            "json",
        ])
        .output()?;
    assert_eq!(diff_scan.status.code(), Some(200));

    let diff_findings: Vec<Value> = serde_json::from_slice(&diff_scan.stdout)?;
    assert_eq!(diff_findings.len(), 1, "expected only the canary secret in diff scan");
    let diff_finding = &diff_findings[0];
    assert_eq!(diff_finding["rule"]["id"], "KINGFISHER.AWS.2");
    assert_eq!(diff_finding["finding"]["path"], "canary-token");
    assert_eq!(diff_finding["finding"]["git_metadata"]["commit"]["id"], feature_commit_hex);

    Ok(())
}

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

const GH_PAT: &str = "ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa";

#[test]
fn baseline_create_and_filter() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file = dir.path().join("leak.txt");
    fs::write(&file, format!("token = \"{}\"\n", GH_PAT))?;
    let baseline = dir.path().join("baseline.yaml");

    // Create baseline with manage flag
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--no-validate",
            "--format",
            "json",
            "--manage-baseline",
            "--baseline-file",
            baseline.to_str().unwrap(),
            "--git-history=none",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(GH_PAT));

    assert!(baseline.exists(), "baseline file created");

    let initial_baseline = fs::read_to_string(&baseline)?;

    // Scanning with the baseline should suppress the existing finding and leave
    // the baseline untouched.
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--no-validate",
            "--format",
            "json",
            "--baseline-file",
            baseline.to_str().unwrap(),
            "--git-history=none",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(GH_PAT).not());

    let baseline_after_scan = fs::read_to_string(&baseline)?;
    assert_eq!(initial_baseline, baseline_after_scan, "baseline remains stable after reuse");

    // Managing the baseline again should not churn entries or report the secret
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--no-validate",
            "--format",
            "json",
            "--manage-baseline",
            "--baseline-file",
            baseline.to_str().unwrap(),
            "--git-history=none",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(GH_PAT).not());

    let rerun_baseline = fs::read_to_string(&baseline)?;
    assert_eq!(initial_baseline, rerun_baseline, "baseline remains stable");

    Ok(())
}

#[test]
fn baseline_exclude_prunes_entries() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let git_dir = dir.path().join(".git");
    std::fs::create_dir(&git_dir)?;
    let secret_file = git_dir.join("secret.txt");
    fs::write(&secret_file, format!("token = \"{}\"\n", GH_PAT))?;
    let baseline = dir.path().join("baseline.yaml");

    // Initial baseline includes the .git secret
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--no-validate",
            "--format",
            "json",
            "--manage-baseline",
            "--baseline-file",
            baseline.to_str().unwrap(),
            "--no-update-check",
        ])
        .assert()
        .code(200);

    let content = fs::read_to_string(&baseline)?;
    assert!(content.contains(".git/secret.txt"));

    // Rescan with exclusion, which should prune the .git entry
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--no-validate",
            "--format",
            "json",
            "--manage-baseline",
            "--baseline-file",
            baseline.to_str().unwrap(),
            "--exclude=.git",
            "--no-update-check",
        ])
        .assert()
        .code(0);

    let content = fs::read_to_string(&baseline)?;
    assert!(!content.contains(".git/secret.txt"));

    Ok(())
}

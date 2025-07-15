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
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(GH_PAT));

    assert!(baseline.exists(), "baseline file created");

    // Scan again using the baseline
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
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(GH_PAT).not());

    Ok(())
}

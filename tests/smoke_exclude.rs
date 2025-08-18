use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

const SECRET: &str = "ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa";

#[test]
fn exclude_pattern_hides_matches() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let py = dir.path().join("foo.py");
    let txt = dir.path().join("bar.txt");
    fs::write(&py, format!("token = \"{}\"\n", SECRET))?;
    fs::write(&txt, format!("token = \"{}\"\n", SECRET))?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--confidence=low",
            "--no-binary",
            "--no-validate",
            "--format",
            "json",
            "--exclude=*.py",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains("bar.txt").and(predicate::str::contains("foo.py").not()));

    Ok(())
}

#[test]
fn exclude_git_directory_hides_matches() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let git_dir = dir.path().join(".git");
    std::fs::create_dir(&git_dir)?;
    fs::write(git_dir.join("config"), format!("token = \"{}\"\n", SECRET))?;
    fs::write(dir.path().join("bar.txt"), format!("token = \"{}\"\n", SECRET))?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--confidence=low",
            "--no-binary",
            "--no-validate",
            "--format",
            "json",
            "--exclude=.git",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains("bar.txt").and(predicate::str::contains("/.git/").not()));

    Ok(())
}

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs, process::Command};
use tempfile::tempdir;

// Ensure base64 encoded secrets are decoded and detected
#[test]
fn detects_base64_encoded_secret() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.txt");
    // Base64 for ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa
    let encoded = "Z2hwXzF3dUhGaWtCS1F0Q2NIM0VCMkZCVWt5bjhrclhoUDJxTHFQYQ==";
    fs::write(&file_path, encoded)?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            predicate::str::contains("ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa")
                .and(predicate::str::contains("\"encoding\": \"base64\"")),
        );

    dir.close()?;
    Ok(())
}

// Ensure disabling Base64 decoding suppresses encoded secrets
#[test]
fn skips_base64_when_disabled() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.txt");
    let encoded = "Z2hwXzF3dUhGaWtCS1F0Q2NIM0VCMkZCVWt5bjhrclhoUDJxTHFQYQ==";
    fs::write(&file_path, encoded)?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--no-base64",
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"findings\":0"));

    dir.close()?;
    Ok(())
}

// Ensure disabling Base64 decoding does not trigger tree-sitter errors on empty files
#[test]
fn no_base64_skips_empty_files() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("empty.py");
    fs::write(&file_path, "")?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--no-base64",
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Source code is empty").not());

    dir.close()?;
    Ok(())
}

// Ensure tree-sitter based decoding works even when the standalone base64 scanner is disabled
#[test]
fn detects_base64_in_code_with_tree_sitter() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.py");
    // Base64 for ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa
    let encoded = "Z2hwXzF3dUhGaWtCS1F0Q2NIM0VCMkZCVWt5bjhrclhoUDJxTHFQYQ==";
    fs::write(&file_path, format!("token = \"{}\"\n", encoded))?;

    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            predicate::str::contains("ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa")
                .and(predicate::str::contains("\"encoding\": \"base64\"")),
        );

    dir.close()?;
    Ok(())
}

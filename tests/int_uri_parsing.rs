use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn filters_invalid_mongodb_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("mongo.txt");
    let valid = "mongodb://usr:pass@example.com:27017/db";
    let invalid = "mongodb://usr:pass@example.com:abc/db";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
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
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}

#[test]
fn filters_invalid_postgres_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("postgres.txt");
    let valid = "postgres://postgres:secret@example.com:5432";
    let invalid = "postgres://postgres:secret@example.com:70000";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
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
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}

#[test]
fn filters_invalid_mysql_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("mysql.txt");
    let valid = "mysql://user:secret@example.com:3306/app";
    let invalid = "mysql://user:secret@example.com:70000/app";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
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
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}

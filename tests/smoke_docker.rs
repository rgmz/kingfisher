use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn smoke_scan_docker_image() -> anyhow::Result<()> {
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            "--docker-image",
            "ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(205)
        .stdout(predicate::str::contains("Active Credential"));
    Ok(())
}
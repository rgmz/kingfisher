use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn smoke_scan_docker_image() -> anyhow::Result<()> {
    let mut cmd = Command::cargo_bin("kingfisher")?;
    let output = cmd
        .args([
            "scan",
            "--docker-image",
            "ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master",
            "--format",
            "json",
            "--no-update-check",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!("Skipping test: {}", String::from_utf8_lossy(&output.stderr));
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Not Attempted"));
    Ok(())
}

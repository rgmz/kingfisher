// tests/smoke_archive.rs
use assert_cmd::prelude::*;
use predicates::prelude::*;
#[test]
fn smoke_scan_tar_gz_archive() -> anyhow::Result<()> {
    use std::process::Command;

    let dir = tempfile::tempdir()?;
    let tar_gz = dir.path().join("payload.tar.gz");
    let github_pat = "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";

    // --- build a payload.tar.gz -------------------------------------------------
    {
        use std::fs::File;

        use flate2::{write::GzEncoder, Compression};
        use tar::Builder;

        let f = File::create(&tar_gz)?;
        let gz = GzEncoder::new(f, Compression::default());
        let mut t = Builder::new(gz);

        let data = format!("token={github_pat}\n");
        t.append_data(&mut tar::Header::new_gnu(), "secret.txt", data.as_bytes())?;
        t.into_inner()?.finish()?;
    }

    // Expected exit-code differs by OS
    let findings_code = 200;

    // ── 1) extraction ENABLED -- secret should be found ─────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tar_gz.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(findings_code)
        .stdout(predicates::str::contains(github_pat));

    // ── 2) extraction DISABLED -- secret *not* found ────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tar_gz.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-extract-archives",
            "--no-update-check", // skip update check to avoid network calls
        ])
        .assert()
        .success() // always 0
        .stdout(predicates::str::contains(github_pat).not());

    dir.close()?;
    Ok(())
}

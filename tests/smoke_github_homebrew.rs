use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn scan_homebrew_github_no_findings() -> anyhow::Result<()> {
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", "--git-url", "https://github.com/homebrew/.github", "--no-update-check"])
        .assert()
        .success()
        .stdout(contains("|Findings....................: 0"))
        .stdout(contains("|__Successful Validations....: 0"))
        .stdout(contains("|__Failed Validations........: 0"));
    Ok(())
}

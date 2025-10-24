// tests/smoke_branch.rs
//
// Integration tests that exercise `kingfisher scan` against Git branches and commit
// references using locally constructed repositories. These ensure that the
// `--branch` and `--since-commit` flags behave as expected when scanning a repo
// without validation.

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use git2::{build::CheckoutBuilder, BranchType, Repository, Signature};
use predicates::{prelude::PredicateBooleanExt, str::contains};
use tempfile::tempdir;

#[test]
fn scan_by_commit_and_branch_diff() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = Repository::init(&repo_dir)?;
    let signature = Signature::now("tester", "tester@example.com")?;

    // Commit an initial config file packed with known test secrets. We'll scan
    // this commit directly via `--branch <commit-hash>` in the first assertion.
    let config_path = repo_dir.join("config.py");
    let config_contents = r"# test configuration with multiple secrets
AWS_ACCESS_SECRET_KEY = 'UpUbsQANRHLf2uuQ7QOlNXPbbtV5fmseW/GgT5D/'
GCP_PRIVATE_KEY_ID = 'c4c474d61701fd6fd4191883b8fea9a8411bf771'
GOOGLE_API_KEY = 'AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM'
";
    fs::create_dir_all(config_path.parent().unwrap())?;
    fs::write(&config_path, config_contents)?;

    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let initial_commit_id =
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])?;
    let initial_commit = repo.find_commit(initial_commit_id)?;
    let initial_commit_hex = initial_commit_id.to_string();

    // Create a "main" branch pointing at the initial commit to mirror the
    // documented example, but keep the default branch checkout untouched. Some
    // Git installations already default to `main`, so only create the branch
    // if it does not exist yet.
    if repo.find_branch("main", BranchType::Local).is_err() {
        repo.branch("main", &initial_commit, false)?;
    }

    // Create a feature branch that introduces a new secret file. The diff based
    // scan later on should report only this file when paired with --since-commit.
    repo.branch("feature-1", &initial_commit, true)?;
    repo.set_head("refs/heads/feature-1")?;
    repo.checkout_head(Some(CheckoutBuilder::new().force()))?;

    let canary_path = repo_dir.join("canary-token");
    let canary_contents = r"[default]
aws_access_key_id = AKIAX24QKKOLDJMZ5Y2T
aws_secret_access_key = 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
";
    fs::write(&canary_path, canary_contents)?;

    let mut index = repo.index()?;
    index.add_path(Path::new("config.py"))?;
    index.add_path(Path::new("canary-token"))?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let parent_commit = repo.head()?.peel_to_commit()?;
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "add canary token",
        &tree,
        &[&parent_commit],
    )?;

    // ── scan the repository by commit hash ───────────────────────────────────
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            initial_commit_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("AWS SECRET ACCESS KEY")
                .and(contains("config.py"))
                .and(contains(initial_commit_hex.as_str())),
        );

    // ── scan only the diff between feature-1 and the merge base ─────────────
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--branch",
            "feature-1",
            "--since-commit",
            initial_commit_hex.as_str(),
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            contains("canary-token")
                .and(contains("AWS SECRET ACCESS KEY"))
                .and(contains("efnegoUp/WXc3XwlL77dXu1aKIICzvz+n+7Sz88i")),
        )
        .stdout(contains("config.py").not());

    Ok(())
}

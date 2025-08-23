use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, ArgGroup, Args};

use crate::gix;

/// Arguments for `precommit` command
#[derive(Args, Debug, Clone)]
#[command(group(
    ArgGroup::new("action")
        .args(["install", "remove"])
        .required(true)
        .multiple(false)
))]
pub struct PrecommitArgs {
    /// Install the pre-commit hook
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "remove")]
    pub install: bool,

    /// Remove the pre-commit hook
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "install")]
    pub remove: bool,

    /// Operate on all repositories using the global hooks directory
    #[arg(long, conflicts_with = "repo")]
    pub global: bool,

    /// Operate only on the current repository
    #[arg(long, conflicts_with = "global")]
    pub repo: bool,
}

/// Scope of operation
enum Scope {
    Global,
    Repo,
}

/// Run the `precommit` command
pub fn run(args: &PrecommitArgs) -> Result<()> {
    if args.install {
        if let Some(path) = find_existing_hook()? {
            println!("Kingfisher pre-commit hook already installed at {}", path.display());
            return Ok(());
        }
        let scope = determine_scope(args, true)?;
        let hook_path = match scope {
            Scope::Global => install_global()?,
            Scope::Repo => install_repo()?,
        };
        println!("Installed Kingfisher pre-commit hook at {}", hook_path.display());
    } else if args.remove {
        let scope = determine_scope(args, false)?;
        let removed = match scope {
            Scope::Global => remove_global()?,
            Scope::Repo => remove_repo()?,
        };
        if let Some(path) = removed {
            println!("Removed Kingfisher pre-commit hook from {}", path.display());
        } else {
            println!("No Kingfisher pre-commit hook found to remove");
        }
    }
    Ok(())
}

fn determine_scope(args: &PrecommitArgs, installing: bool) -> Result<Scope> {
    if args.global {
        Ok(Scope::Global)
    } else if args.repo {
        Ok(Scope::Repo)
    } else {
        let verb = if installing { "Install" } else { "Remove" };
        prompt_scope(verb)
    }
}

fn prompt_scope(action: &str) -> Result<Scope> {
    print!("{} pre-commit hook globally? [y/N]: ", action);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
        Ok(Scope::Global)
    } else {
        Ok(Scope::Repo)
    }
}

fn find_existing_hook() -> Result<Option<PathBuf>> {
    // Check repo-local hook
    if let Ok(repo) = gix::discover(".") {
        let path = repo.path().join("hooks").join(hook_filename());
        if hook_contains_kingfisher(&path) {
            return Ok(Some(path));
        }
    }

    // Check global hook
    if let Some(dir) = current_global_hooks_dir()? {
        let path = dir.join(hook_filename());
        if hook_contains_kingfisher(&path) {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

fn install_repo() -> Result<PathBuf> {
    let repo = gix::discover(".").context("Not inside a git repository")?;
    let hooks_dir = repo.path().join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join(hook_filename());
    write_hook(&hook_path)?;
    Ok(hook_path)
}

fn install_global() -> Result<PathBuf> {
    let hooks_dir = get_or_set_global_hooks_dir()?;
    let hook_path = hooks_dir.join(hook_filename());
    write_hook(&hook_path)?;
    Ok(hook_path)
}

fn remove_repo() -> Result<Option<PathBuf>> {
    let repo = gix::discover(".").context("Not inside a git repository")?;
    let hook_path = repo.path().join("hooks").join(hook_filename());
    if remove_hook(&hook_path)? {
        Ok(Some(hook_path))
    } else {
        Ok(None)
    }
}

fn remove_global() -> Result<Option<PathBuf>> {
    if let Some(dir) = current_global_hooks_dir()? {
        let hook_path = dir.join(hook_filename());
        if remove_hook(&hook_path)? {
            return Ok(Some(hook_path));
        }
    }
    Ok(None)
}

fn write_hook(path: &Path) -> Result<()> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        if content.contains("kingfisher") {
            println!("Kingfisher pre-commit hook already installed at {}", path.display());
            return Ok(());
        }
        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        if !content.ends_with('\n') {
            writeln!(file)?;
        }
        writeln!(file, "{}", hook_call_line())?;
    } else {
        fs::write(path, hook_content())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(path, perms)?;
        }
    }
    Ok(())
}

fn remove_hook(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(path)?;
    if !content.contains("kingfisher") {
        return Ok(false);
    }
    let ending = if cfg!(windows) { "\r\n" } else { "\n" };
    let lines: Vec<&str> = content.lines().filter(|l| !l.contains("kingfisher")).collect();
    if lines.is_empty() {
        fs::remove_file(path)?;
    } else {
        let mut new_content = lines.join(ending);
        new_content.push_str(ending);
        fs::write(path, new_content)?;
    }
    Ok(true)
}

fn hook_contains_kingfisher(path: &Path) -> bool {
    fs::read_to_string(path).map(|c| c.contains("kingfisher")).unwrap_or(false)
}

fn hook_filename() -> &'static str {
    if cfg!(windows) {
        "pre-commit.bat"
    } else {
        "pre-commit"
    }
}

fn hook_content() -> String {
    if cfg!(windows) {
        format!("@echo off\r\n{}\r\n", hook_call_line())
    } else {
        format!("#!/bin/sh\n{}\n", hook_call_line())
    }
}

fn hook_call_line() -> String {
    if cfg!(windows) {
        "kingfisher --quiet --only-valid --no-update-check %*".to_string()
    } else {
        "kingfisher --quiet --only-valid --no-update-check \"$@\"".to_string()
    }
}

fn current_global_hooks_dir() -> Result<Option<PathBuf>> {
    let output =
        Command::new("git").args(["config", "--global", "--get", "core.hooksPath"]).output()?;
    if output.status.success() {
        let p = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if p.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(p)))
        }
    } else {
        Ok(None)
    }
}

fn get_or_set_global_hooks_dir() -> Result<PathBuf> {
    if let Some(dir) = current_global_hooks_dir()? {
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    let home = home_dir().ok_or_else(|| anyhow!("Unable to determine home directory"))?;
    let hooks = home.join(".githooks");
    fs::create_dir_all(&hooks)?;
    Command::new("git")
        .args([
            "config",
            "--global",
            "core.hooksPath",
            hooks.to_str().ok_or_else(|| anyhow!("Invalid path"))?,
        ])
        .status()
        .context("Failed to set git global core.hooksPath")?;
    Ok(hooks)
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        env::var_os("HOME").map(PathBuf::from)
    }
}

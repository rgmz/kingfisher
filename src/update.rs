// This module checks GitHub for a newer Kingfisher release and (optionally)
// self-updates.  Our release assets use short, user-friendly names such as
// `kingfisher-linux-arm64.tgz`, `kingfisher-darwin-x64.tgz`, etc.  Those names
// do **not** match the full Rust target triple that the `self_update` crate
// expects (e.g. `aarch64-unknown-linux-musl`).  We therefore map the compile-
// time target to the corresponding asset suffix via `builder.target()`.
//
// Version handling logic covers three scenarios:
//   1. Running version == latest release →                   "up to date".
//   2. Running version  > latest release → print a notice that the binary is **newer** than
//      anything on GitHub (e.g. a dev build).
//   3. Latest release  > running version → offer to self-update.
//
// All informational messages are printed with the
// `style_finding_active_heading` style so that they stand out alongside normal
// scan output.

use std::io::{ErrorKind, Write};

use self_update::{backends::github::Update, cargo_crate_version, errors::Error as UpdError};
use semver::Version;
use tracing::error;

use crate::{cli::global::GlobalArgs, reporter::styles::Styles};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateCheckStatus {
    Disabled,
    Failed,
    Ok,
}

impl UpdateCheckStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateCheckStatus::Disabled => "disabled",
            UpdateCheckStatus::Failed => "failed",
            UpdateCheckStatus::Ok => "ok",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    pub message: Option<String>,
    pub styled_message: Option<String>,
    pub is_outdated: bool,
    pub running_version: String,
    pub latest_version: Option<String>,
    pub check_status: UpdateCheckStatus,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        UpdateStatus {
            message: None,
            styled_message: None,
            is_outdated: false,
            running_version: cargo_crate_version!().to_string(),
            latest_version: None,
            check_status: UpdateCheckStatus::Disabled,
        }
    }
}

fn styled_heading(styles: &Styles, text: &str) -> String {
    styles.style_finding_active_heading.apply_to(text).to_string()
}

/// Check GitHub for a newer Kingfisher release and optionally self-update.
///
/// * `base_url` lets tests point at a mock server.
/// * Self-update is skipped when the user disabled it **or** the binary is a Homebrew install.
pub fn check_for_update(global_args: &GlobalArgs, base_url: Option<&str>) -> UpdateStatus {
    let running_version = cargo_crate_version!().to_string();

    if global_args.no_update_check {
        return UpdateStatus {
            message: Some("Update check disabled (--no-update-check)".to_string()),
            styled_message: None,
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Disabled,
        };
    }

    // Respect the user's color preferences when printing update
    // by delegating to the same helper used by the main reporter logic. This keeps
    // the update checker in sync with the rest of the application and avoids
    // emitting raw ANSI escape codes when colour output has been disabled.
    let use_color = !global_args.quiet && global_args.use_color(std::io::stderr());
    let styles = Styles::new(use_color);

    let mut builder = Update::configure();
    builder
        .repo_owner("mongodb")
        .repo_name("kingfisher")
        .bin_name("kingfisher")
        .show_download_progress(false)
        .no_confirm(true) // Don't prompt for confirmation when self-updating
        .current_version(cargo_crate_version!());

    // Allow tests to point at a mock HTTP server.
    if let Some(url) = base_url {
        builder.with_url(url);
    }

    // ──────────────────────────────────────────────────────
    // Map the current Rust target triple to our simplified asset names.
    // ──────────────────────────────────────────────────────
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    builder.target("linux-arm64");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    builder.target("linux-x64");

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    builder.target("darwin-arm64");

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    builder.target("darwin-x64");

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    builder.target("windows-x64");

    // ──────────────────────────────────────────────────────
    // Disambiguate archive format to avoid picking .deb packages.
    // Linux and macOS releases use `.tgz`; Windows uses `.zip`.
    // ──────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    builder.identifier("zip");

    // Linux releases also ship as .deb and .rpm packages; select the .tgz asset for self-updates
    #[cfg(not(target_os = "windows"))]
    builder.identifier("tgz");

    // Build the updater.
    let Ok(updater) = builder.build() else {
        let plain = "Failed to configure update checker".to_string();
        let styled_message = styled_heading(&styles, &plain);
        let _ = writeln!(std::io::stderr(), "{}", styled_message);
        return UpdateStatus {
            message: Some(plain),
            styled_message: Some(styled_message),
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Failed,
        };
    };

    // Query GitHub.
    let Ok(release) = updater.get_latest_release() else {
        let plain = "Failed to check for updates".to_string();
        let styled_message = styled_heading(&styles, &plain);
        let _ = writeln!(std::io::stderr(), "{}", styled_message);
        return UpdateStatus {
            message: Some(plain),
            styled_message: Some(styled_message),
            is_outdated: false,
            running_version,
            latest_version: None,
            check_status: UpdateCheckStatus::Failed,
        };
    };

    // ───────────── Case 1: running == latest ─────────────
    if release.version == running_version {
        let plain = format!("Kingfisher {running_version} is up to date");
        let _ = writeln!(std::io::stderr(), "{plain}");
        return UpdateStatus {
            message: Some(plain.clone()),
            styled_message: Some(plain),
            is_outdated: false,
            running_version,
            latest_version: Some(release.version),
            check_status: UpdateCheckStatus::Ok,
        };
    }

    // Try semantic version comparison.  If parsing fails, fall back to the
    // self-update code-path (which will treat the strings lexicographically).
    if let (Ok(curr), Ok(latest)) =
        (Version::parse(&running_version), Version::parse(&release.version))
    {
        // ───────── Case 2: running > latest (dev build) ─────────
        if curr > latest {
            let plain =
                format!("Running Kingfisher {curr} which is newer than latest released {latest}");
            let styled_message = styled_heading(&styles, &plain);
            let _ = writeln!(std::io::stderr(), "{}", styled_message);
            return UpdateStatus {
                message: Some(plain),
                styled_message: Some(styled_message),
                is_outdated: false,
                running_version,
                latest_version: Some(release.version),
                check_status: UpdateCheckStatus::Ok,
            };
        }
        // else fall through to Case 3 (latest > running)
    }

    // ───────────── Case 3: latest > running ─────────────
    let plain = format!("New Kingfisher release {} available", release.version);
    let styled_message = styled_heading(&styles, &plain);
    let _ = writeln!(std::io::stderr(), "{}", styled_message);

    // Attempt self-update when allowed and feasible.
    if global_args.self_update {
        match updater.update() {
            Ok(status) => {
                let message = format!("Updated to version {}", status.version());
                let _ = writeln!(std::io::stderr(), "{}", styled_heading(&styles, &message));
            }
            Err(e) => match e {
                UpdError::Io(ref io_err) => match io_err.kind() {
                    ErrorKind::PermissionDenied => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "{}",
                            styled_heading(
                                &styles,
                                "Cannot replace the current binary - permission denied.\n\
                                 If you installed via a package manager, run its upgrade command.\n\
                                 Otherwise reinstall to a user-writable directory or re-run with sudo."
                            )
                        );
                    }
                    ErrorKind::NotFound => {
                        let _ = writeln!(
                            std::io::stderr(),
                            "{}",
                            styled_heading(
                                &styles,
                                "Cannot replace the current binary - file not found.\n\
                                 If you installed via a package manager, run its upgrade command.\n\
                                 Otherwise reinstall to a user-writable directory."
                            )
                        );
                    }
                    _ => error!("Failed to update: {e}"),
                },
                _ => error!("Failed to update: {e}"),
            },
        }
    }

    UpdateStatus {
        message: Some(plain),
        styled_message: Some(styled_message),
        is_outdated: true,
        running_version,
        latest_version: Some(release.version),
        check_status: UpdateCheckStatus::Ok,
    }
}

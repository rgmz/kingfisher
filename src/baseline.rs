use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{findings_store::FindingsStore, matcher::compute_finding_fingerprint};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineFile {
    #[serde(rename = "ExactFindings", default)]
    pub exact_findings: ExactFindings,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExactFindings {
    #[serde(default)]
    pub matches: Vec<BaselineFinding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineFinding {
    pub filepath: String,
    pub fingerprint: String,
    pub linenum: usize,
    pub lastupdated: String,
}

pub fn load_baseline(path: &Path) -> Result<BaselineFile> {
    let data = fs::read_to_string(path).context("read baseline file")?;
    Ok(serde_yaml::from_str(&data).context("parse baseline yaml")?)
}

pub fn save_baseline(path: &Path, baseline: &BaselineFile) -> Result<()> {
    let data = serde_yaml::to_string(baseline).context("serialize baseline")?;
    fs::write(path, data).context("write baseline file")
}

fn normalize_path(p: &Path, roots: &[PathBuf]) -> String {
    for root in roots {
        if let Ok(stripped) = p.strip_prefix(root) {
            if let Some(name) = root.file_name() {
                return PathBuf::from(name)
                    .join(stripped)
                    .to_string_lossy()
                    .replace('\\', "/");
            }
        }
    }
    p.to_string_lossy().replace('\\', "/")
}

fn compute_hash(secret: &str, path: &str) -> String {
    let fp = compute_finding_fingerprint(secret, path, 0, 0);
    format!("{:016x}", fp)
}

fn extract_secret(m: &crate::matcher::Match) -> String {
    m.groups
        .captures
        .get(1)
        .or_else(|| m.groups.captures.get(0))
        .map(|c| c.value.to_string())
        .unwrap_or_default()
}

pub fn apply_baseline(
    store: &mut FindingsStore,
    baseline_path: &Path,
    manage: bool,
    roots: &[PathBuf],
) -> Result<()> {
    let mut baseline = if baseline_path.exists() {
        load_baseline(baseline_path)?
    } else {
        BaselineFile::default()
    };

    let mut known: HashSet<String> =
        baseline.exact_findings.matches.iter().map(|m| m.fingerprint.clone()).collect();

    let mut encountered: HashSet<String> = HashSet::new();
    let mut new_entries = Vec::new();
    for arc_msg in store.get_matches_mut() {
        let (origin, _blob, m) = Arc::make_mut(arc_msg);
        let file_path = origin.iter().filter_map(|o| o.full_path()).next();
        if let Some(fp) = file_path {
            let normalized = normalize_path(&fp, roots);
            let secret = extract_secret(m);
            let hash = compute_hash(&secret, &normalized);
            if known.contains(&hash) {
                debug!("Skipping {} due to baseline (hash {})", normalized, hash);
                m.visible = false;
                if manage {
                    encountered.insert(hash.clone());
                }
            } else if manage {
                known.insert(hash.clone());
                encountered.insert(hash.clone());
                let entry = BaselineFinding {
                    filepath: normalized,
                    fingerprint: hash,
                    linenum: m.location.source_span.start.line,
                    lastupdated: Local::now().to_rfc2822(),
                };
                new_entries.push(entry);
            }
        }
    }
    if manage {
        let original_len = baseline.exact_findings.matches.len();
        baseline.exact_findings.matches.retain(|m| encountered.contains(&m.fingerprint));
        let mut changed = baseline.exact_findings.matches.len() != original_len;

        if !new_entries.is_empty() {
            baseline.exact_findings.matches.extend(new_entries);
            changed = true;
        }

        if changed {
            save_baseline(baseline_path, &baseline)?;
        }
    }

    Ok(())
}

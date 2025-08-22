use std::{
    fmt::Write,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use http::StatusCode;
use schemars::JsonSchema;
use serde::Serialize;

use crate::{
    blob::BlobMetadata,
    bstring_escape::Escaped,
    cli,
    cli::global::GlobalArgs,
    finding_data, findings_store,
    matcher::Match,
    origin::{Origin, OriginSet},
    rules::rule::Confidence,
};
mod bson_format;
mod json_format;
mod pretty_format;
mod sarif_format;
pub mod styles;
use std::io::IsTerminal;

use styles::{StyledObject, Styles};

use crate::{
    cli::commands::output::ReportOutputFormat,
    location::SourceSpan,
    origin::{get_repo_url, GitRepoOrigin},
};

pub fn run(
    global_args: &GlobalArgs,
    ds: Arc<Mutex<findings_store::FindingsStore>>,
    args: &cli::commands::scan::ScanArgs,
) -> Result<()> {
    global_args.use_color(std::io::stdout());
    let stdout_is_tty = std::io::stdout().is_terminal();
    let use_color = stdout_is_tty && !args.output_args.has_output();
    let styles = Styles::new(use_color);

    let ds_clone = Arc::clone(&ds);
    // Initialize the reporter
    let reporter = DetailsReporter { datastore: ds_clone, styles, only_valid: args.only_valid };
    let writer = args.output_args.get_writer()?;
    // Generate and write the report in the specified format
    reporter.report(args.output_args.format, writer, args)
}
pub struct DetailsReporter {
    pub datastore: Arc<Mutex<findings_store::FindingsStore>>,
    pub styles: Styles,
    pub only_valid: bool,
}

impl DetailsReporter {
    pub fn extract_git_metadata(
        &self,
        prov: &GitRepoOrigin,
        source_span: &SourceSpan,
    ) -> Option<serde_json::Value> {
        let repo_url = get_repo_url(&prov.repo_path)
            .unwrap_or_else(|_| prov.repo_path.to_string_lossy().to_string().into());
        let repo_url = repo_url.trim_end_matches(".git").to_string();
        if let Some(cs) = &prov.first_commit {
            let cmd = &cs.commit_metadata;
            // let msg =
            //     String::from_utf8_lossy(cmd.message.lines().next().unwrap_or(&[],),).
            // into_owned();

            let atime =
                cmd.committer_timestamp.format(gix::date::time::format::SHORT.clone()).to_string();

            let git_metadata = serde_json::json!({
                "repository_url": repo_url,
                "commit": {
                    "id": cmd.commit_id.to_string(),
                    "url": format!("{}/commit/{}", repo_url, cmd.commit_id),
                    "date": atime,
                    "committer": {
                        "name": &cmd.committer_name,
                        "email": &cmd.committer_email,
                    },
                    // "author": {
                    //     "name": String::from_utf8_lossy(&cmd.author_name),
                    //     "email": String::from_utf8_lossy(&cmd.author_email),
                    // },
                    // "message": msg,
                },
                "file": {
                    "path": &cs.blob_path,
                    "url": format!(
                        "{}/blob/{}/{}#L{}",
                        repo_url,
                        cmd.commit_id,
                        &cs.blob_path,
                        source_span.start.line
                    ),
                    "git_command": format!(
                        "git -C {} show {}:{}",
                        prov.repo_path.display(),
                        cmd.commit_id,
                        &cs.blob_path
                    )
                }
            });
            Some(git_metadata)
        } else {
            None
        }
    }

    /// If the given file path corresponds to a Jira issue downloaded to disk,
    /// return the online Jira URL for that issue.
    fn jira_issue_url(
        &self,
        path: &std::path::Path,
        args: &cli::commands::scan::ScanArgs,
    ) -> Option<String> {
        // drop any trailing slash so we don’t end up with “//browse/…”
        let jira_url = args.input_specifier_args.jira_url.as_ref()?.as_str().trim_end_matches('/');

        let ds = self.datastore.lock().ok()?;
        let root = ds.clone_root();
        let jira_dir = root.join("jira_issues");
        if path.starts_with(&jira_dir) {
            let key = path.file_stem()?.to_string_lossy();
            Some(format!("{}/browse/{}", jira_url, key))
        } else {
            None
        }
    }

    /// If the given file path corresponds to a Confluence page downloaded to disk,
    /// return the URL for that page.
    fn confluence_page_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.confluence_links().get(path).cloned()
    }

    /// If the given file path corresponds to a Slack message downloaded to disk,
    /// return the permalink for that message.
    fn slack_message_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.slack_links().get(path).cloned()
    }

    fn repo_artifact_url(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        ds.repo_links().get(path).cloned()
    }

    fn s3_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, bucket) in ds.s3_buckets().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                return Some(format!("s3://{}/{}", bucket, rel.display()));
            }
        }
        None
    }

    fn docker_display_path(&self, path: &std::path::Path) -> Option<String> {
        let ds = self.datastore.lock().ok()?;
        for (dir, image) in ds.docker_images().iter() {
            if path.starts_with(dir) {
                let rel = path.strip_prefix(dir).ok()?;
                let mut rel_str = rel.display().to_string();
                rel_str = rel_str.replace(".decomp.tar!", ".tar.gz | ");
                rel_str = rel_str.replace(".tar!", ".tar | ");
                rel_str = rel_str.replace('!', " | ");
                return Some(format!("{} | {}", image, rel_str));
            }
        }
        None
    }

    fn process_matches(&self, only_valid: bool, filter_visible: bool) -> Result<Vec<ReportMatch>> {
        let datastore = self.datastore.lock().unwrap();
        Ok(datastore
            .get_matches()
            .iter()
            .filter(|msg| {
                let (_origin, _blob_metadata, match_item) = &***msg;
                if only_valid {
                    // If filter_visible is true, require the match to be visible.
                    if filter_visible {
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                            && match_item.visible
                    } else {
                        // Do not filter by visibility when not needed (for validation)
                        match_item.validation_success
                            && match_item.validation_response_status
                                != StatusCode::CONTINUE.as_u16()
                    }
                } else {
                    // When not filtering by only_valid, use visibility if desired.
                    if filter_visible {
                        match_item.visible
                    } else {
                        true
                    }
                }
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                ReportMatch {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    m: match_item.clone(),
                    comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule_confidence,
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                }
            })
            .collect())
    }

    pub fn get_filtered_matches(&self) -> Result<Vec<ReportMatch>> {
        self.process_matches(self.only_valid, true)
    }

    pub fn get_unfiltered_matches(&self, only_valid: Option<bool>) -> Result<Vec<ReportMatch>> {
        self.process_matches(only_valid.unwrap_or(self.only_valid), false)
    }

    pub fn deduplicate_matches(
        &self,
        matches: Vec<ReportMatch>,
        no_dedup: bool,
    ) -> Vec<ReportMatch> {
        if no_dedup {
            return matches;
        }

        use std::collections::HashMap;
        let mut by_fp: HashMap<u64, ReportMatch> = HashMap::new();

        for rm in matches {
            let fp = rm.m.finding_fingerprint;
            if let Some(existing) = by_fp.get_mut(&fp) {
                // merge origin sets (keep first origin, append the rest)
                for o in rm.origin.iter() {
                    if !existing.origin.iter().any(|e| e == o) {
                        existing.origin = OriginSet::new(
                            existing.origin.first().clone(),
                            existing
                                .origin
                                .iter()
                                .skip(1)
                                .cloned()
                                .chain(std::iter::once(o.clone()))
                                .collect(),
                        );
                    }
                }
                continue;
            }
            by_fp.insert(fp, rm);
        }
        by_fp.into_values().collect()
    }

    fn matches_for_output(&self, args: &cli::commands::scan::ScanArgs) -> Result<Vec<ReportMatch>> {
        let mut matches = self.get_filtered_matches()?;
        if !args.no_dedup {
            matches = self.deduplicate_matches(matches, args.no_dedup);
        }
        if args.no_dedup {
            let mut expanded = Vec::new();
            for rm in matches {
                if rm.origin.len() > 1 {
                    for origin in rm.origin.iter() {
                        let mut single = rm.clone();
                        single.origin = OriginSet::new(origin.clone(), Vec::new());
                        expanded.push(single);
                    }
                } else {
                    expanded.push(rm);
                }
            }
            matches = expanded;
        }
        Ok(matches)
    }

    pub fn build_finding_record(
        &self,
        rm: &ReportMatch,
        args: &cli::commands::scan::ScanArgs,
    ) -> FindingReporterRecord {
        let source_span = &rm.m.location.source_span;
        let line_num = source_span.start.line;

        let snippet = Escaped(
            rm.m.groups
                .captures
                .get(1)
                .or_else(|| rm.m.groups.captures.get(0))
                .map(|capture| capture.value.as_bytes())
                .unwrap_or_default(),
        )
        .to_string();

        let validation_status = if rm.validation_success {
            "Active Credential".to_string()
        } else if rm.validation_response_status == StatusCode::CONTINUE.as_u16() {
            "Not Attempted".to_string()
        } else {
            "Inactive Credential".to_string()
        };

        const MAX_RESPONSE_LENGTH: usize = 512;
        let truncated_body: String =
            rm.validation_response_body.chars().take(MAX_RESPONSE_LENGTH).collect();
        let ellipsis =
            if rm.validation_response_body.len() > MAX_RESPONSE_LENGTH { "..." } else { "" };
        let response_body = format!("{}{}", truncated_body, ellipsis);

        let git_metadata_val = rm
            .origin
            .iter()
            .filter_map(|origin| {
                if let Origin::GitRepo(e) = origin {
                    self.extract_git_metadata(e, source_span)
                } else {
                    None
                }
            })
            .next();

        let file_path = rm
            .origin
            .iter()
            .find_map(|origin| match origin {
                Origin::File(e) => {
                    if let Some(url) = self.repo_artifact_url(&e.path) {
                        Some(url)
                    } else if let Some(url) = self.jira_issue_url(&e.path, args) {
                        Some(url)
                    } else if let Some(url) = self.confluence_page_url(&e.path) {
                        Some(url)
                    } else if let Some(url) = self.slack_message_url(&e.path) {
                        Some(url)
                    } else if let Some(mapped) = self.s3_display_path(&e.path) {
                        Some(mapped)
                    } else if let Some(mapped) = self.docker_display_path(&e.path) {
                        Some(mapped)
                    } else {
                        Some(e.path.display().to_string())
                    }
                }
                Origin::Extended(e) => e.path().map(|p| p.display().to_string()),
                _ => None,
            })
            .unwrap_or_default();

        FindingReporterRecord {
            rule: RuleMetadata {
                name: rm.m.rule_name.to_string(),
                id: rm.m.rule_text_id.to_string(),
            },
            finding: FindingRecordData {
                snippet,
                fingerprint: rm.m.finding_fingerprint.to_string(),
                confidence: rm.match_confidence.to_string(),
                entropy: format!("{:.2}", rm.m.calculated_entropy),
                validation: ValidationInfo { status: validation_status, response: response_body },
                language: rm
                    .blob_metadata
                    .language
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                line: line_num as u32,
                column_start: source_span.start.column as u32,
                column_end: source_span.end.column as u32,
                path: file_path,
                git_metadata: git_metadata_val,
            },
        }
    }

    pub fn build_finding_records(
        &self,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<Vec<FindingReporterRecord>> {
        let matches = self.matches_for_output(args)?;
        Ok(matches.iter().map(|rm| self.build_finding_record(rm, args)).collect())
    }

    fn style_finding_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_heading.apply_to(val)
    }

    fn style_finding_active_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_finding_active_heading.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_rule<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_rule.apply_to(val)
    }

    #[allow(dead_code)]
    fn style_heading<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_heading.apply_to(val)
    }

    fn style_match<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_match.apply_to(val)
    }

    fn style_metadata<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_metadata.apply_to(val)
    }

    fn style_active_creds<D>(&self, val: D) -> StyledObject<D> {
        self.styles.style_active_creds.apply_to(val)
    }
}
/// A trait for things that can be output as a document.
///
/// This trait is used to factor output-related code, such as friendly handling
/// of buffering, into one place.
pub trait Reportable {
    type Format;
    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()>;
}
impl Reportable for DetailsReporter {
    type Format = ReportOutputFormat;

    fn report<W: std::io::Write>(
        &self,
        format: Self::Format,
        writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        match format {
            ReportOutputFormat::Pretty => self.pretty_format(writer, args),
            ReportOutputFormat::Json => self.json_format(writer, args),
            ReportOutputFormat::Jsonl => self.jsonl_format(writer, args),
            ReportOutputFormat::Bson => self.bson_format(writer, args),
            ReportOutputFormat::Sarif => self.sarif_format(writer, args.no_dedup, args),
        }
    }
}

/// A match produced by one of kingfisher's rules.
/// This corresponds to a single location.
#[derive(Serialize, JsonSchema, Clone)]
pub struct ReportMatch {
    pub origin: OriginSet,

    #[serde(rename = "blob_metadata")]
    pub blob_metadata: BlobMetadata,

    #[serde(flatten)]
    pub m: Match,

    /// An optional comment assigned to the match
    pub comment: Option<String>,

    /// The confidence level of the match
    pub match_confidence: Confidence,

    /// Whether the match is visible in the output
    pub visible: bool,

    /// Validation Body
    pub validation_response_body: String,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingReporterRecord {
    pub rule: RuleMetadata,
    pub finding: FindingRecordData,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct RuleMetadata {
    pub name: String,
    pub id: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct ValidationInfo {
    pub status: String,
    pub response: String,
}

#[derive(Serialize, JsonSchema, Clone, Debug)]
pub struct FindingRecordData {
    pub snippet: String,
    pub fingerprint: String,
    pub confidence: String,
    pub entropy: String,
    pub validation: ValidationInfo,
    pub language: String,
    pub line: u32,
    pub column_start: u32,
    pub column_end: u32,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_metadata: Option<serde_json::Value>,
}

impl From<finding_data::FindingDataEntry> for ReportMatch {
    fn from(e: finding_data::FindingDataEntry) -> Self {
        ReportMatch {
            origin: e.origin,
            blob_metadata: e.blob_metadata,
            m: e.match_val,
            comment: e.match_comment,
            visible: e.visible,
            match_confidence: e.match_confidence,
            validation_response_body: e.validation_response_body.clone(),
            validation_response_status: e.validation_response_status,
            validation_success: e.validation_success,
        }
    }
}

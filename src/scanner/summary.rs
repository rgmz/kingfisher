use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use chrono::Local;
use http::StatusCode;
use indicatif::HumanBytes;
use serde_json::json;
use thousands::Separable;
use tokio::time::Instant;
use tracing::debug;

use crate::{
    cli::{
        commands::{output::ReportOutputFormat, scan},
        global,
    },
    findings_store,
    matcher::MatcherStats,
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    update::{UpdateCheckStatus, UpdateStatus},
};

macro_rules! safe_println {
    ($($arg:tt)*) => {
        if let Err(e) = writeln!(io::stdout(), $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                // Silently exit: the consumer went away
                std::process::exit(0);
            } else {
                // Unexpected I/O error – keep the old behaviour
                panic!("stdout error: {}", e);
            }
        }
    };
}

pub fn print_scan_summary(
    start_time: Instant,
    scan_started_at: chrono::DateTime<Local>,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    // inputs: &FilesystemEnumeratorResult,
    rules_db: &RulesDatabase,
    matcher_stats: &Mutex<MatcherStats>,
    profiler: Option<&ConcurrentRuleProfiler>,
    update_status: &UpdateStatus,
) {
    if global_args.quiet {
        if args.rule_stats {
            if let Some(prof) = profiler {
                let stats = prof.generate_report();
                if !stats.is_empty() {
                    let name_w = stats.iter().map(|s| s.rule_name.len()).max().unwrap_or(4);
                    let id_w = stats.iter().map(|s| s.rule_id.len()).max().unwrap_or(2);
                    safe_println!("\n{:-^1$}", " Rule Performance Stats ", name_w + id_w + 47);
                    safe_println!(
                        "{: <name_w$}  {: <id_w$}  {: >8}  {: >15}  {: >15}",
                        "Rule",
                        "ID",
                        "Matches",
                        "Slowest",
                        "Average",
                        name_w = name_w,
                        id_w = id_w
                    );
                    safe_println!("{:-<width$}", "", width = name_w + id_w + 49);
                    for rs in stats {
                        safe_println!(
                            "{: <name_w$}  {: <id_w$}  {: >8}  {: >15?}  {: >15?}",
                            rs.rule_name,
                            rs.rule_id,
                            rs.total_matches,
                            rs.slowest_match_time,
                            rs.average_match_time,
                            name_w = name_w,
                            id_w = id_w
                        );
                    }
                }
            }
        }
        return;
    }

    let ds = datastore.lock().unwrap();

    let num_rules = rules_db.num_rules();
    let findings_by_rule = ds.get_summary();
    let mut sorted_findings: Vec<_> = findings_by_rule.into_iter().collect();
    sorted_findings.sort_by(|a, b| b.1.cmp(&a.1));
    let duration = start_time.elapsed();

    let all_matches = ds.get_matches();

    let total_findings = if args.no_dedup {
        all_matches.iter().fold(0, |count, msg| {
            let (origin_set, _, match_item) = &**msg;
            if match_item.validation_success {
                count + origin_set.len()
            } else {
                count + 1
            }
        })
    } else {
        ds.get_num_matches()
    };

    let (successful_validations, failed_validations) =
        all_matches.iter().fold((0, 0), |(success, fail), msg| {
            let (origin_set, _, match_item) = &**msg;
            if match_item.validation_success {
                if match_item.validation_response_status != StatusCode::CONTINUE.as_u16() {
                    if args.no_dedup {
                        (success + origin_set.len(), fail)
                    } else {
                        (success + 1, fail)
                    }
                } else {
                    (success, fail)
                }
            } else if match_item.validation_response_status != StatusCode::CONTINUE.as_u16() {
                (success, fail + 1)
            } else {
                (success, fail)
            }
        });
    let matcher_stats = matcher_stats.lock().unwrap();

    if args.output_args.format == ReportOutputFormat::Json
        || args.output_args.format == ReportOutputFormat::Jsonl
    {
        let summary = json!({
            "findings": total_findings,
            "successful_validations": successful_validations,
            "failed_validations": failed_validations,
            "rules_applied": num_rules,
            "blobs_scanned": matcher_stats.blobs_scanned,
            "bytes_scanned": matcher_stats.bytes_scanned,
            "scan_duration": duration.as_secs_f64(),
            "scan_date": scan_started_at.to_rfc3339(),
            "kingfisher": {
                "version_used": update_status.running_version.clone(),
                "latest_version": update_status.latest_version.clone(),
                "update_check_status": update_status.check_status.as_str(),
                "update_check_message": update_status.message.clone(),
            },
            "findings_by_rule": sorted_findings
        });
        safe_println!("{}", summary.to_string());
    } else if args.output_args.format == ReportOutputFormat::Pretty
        || args.output_args.output.is_some()
    {
        let scan_date = scan_started_at.format("%Y-%m-%d %H:%M:%S %Z");
        let latest_version = match update_status.check_status {
            UpdateCheckStatus::Disabled => "Update check disabled (--no-update-check)".to_string(),
            UpdateCheckStatus::Failed => "Unknown (update check failed)".to_string(),
            UpdateCheckStatus::Ok => {
                update_status.latest_version.clone().unwrap_or_else(|| "Unknown".to_string())
            }
        };

        safe_println!("\n==========================================");
        safe_println!("Scan Summary:");
        safe_println!("==========================================");
        safe_println!(" |Findings....................: {}", total_findings.separate_with_commas());
        safe_println!(
            " |__Successful Validations....: {}",
            successful_validations.separate_with_commas()
        );
        safe_println!(
            " |__Failed Validations........: {}",
            failed_validations.separate_with_commas()
        );
        safe_println!(" |Rules Applied...............: {}", num_rules.separate_with_commas());
        safe_println!(
            " |__Blobs Scanned.............: {}",
            matcher_stats.blobs_scanned.separate_with_commas()
        );
        safe_println!(
            " |Bytes Scanned...............: {}",
            HumanBytes(matcher_stats.bytes_scanned)
        );
        safe_println!(" |Scan Duration...............: {}", humantime::format_duration(duration));
        safe_println!(" |Scan Date...................: {}", scan_date);
        safe_println!(" |Kingfisher Version..........: {}", &update_status.running_version);
        safe_println!(" |__Latest Version............: {}", latest_version);
    }

    if args.rule_stats {
        if let Some(prof) = profiler {
            let stats = prof.generate_report();
            if !stats.is_empty() {
                let name_w = stats.iter().map(|s| s.rule_name.len()).max().unwrap_or(4);
                let id_w = stats.iter().map(|s| s.rule_id.len()).max().unwrap_or(2);
                safe_println!("\n{:-^1$}", " Rule Performance Stats ", name_w + id_w + 47);
                safe_println!(
                    "{: <name_w$}  {: <id_w$}  {: >8}  {: >15}  {: >15}",
                    "Rule",
                    "ID",
                    "Matches",
                    "Slowest",
                    "Average",
                    name_w = name_w,
                    id_w = id_w
                );
                safe_println!("{:-<width$}", "", width = name_w + id_w + 49);

                for rs in stats {
                    safe_println!(
                        "{: <name_w$}  {: <id_w$}  {: >8}  {: >15?}  {: >15?}",
                        rs.rule_name,
                        rs.rule_id,
                        rs.total_matches,
                        rs.slowest_match_time,
                        rs.average_match_time,
                        name_w = name_w,
                        id_w = id_w
                    );
                }
            }
        }
    }

    debug!("\nAll Rules with Matches:");
    debug!("=======================");
    let max_rule_length = sorted_findings.iter().map(|(rule, _)| rule.len()).max().unwrap_or(0);
    for (rule, count) in sorted_findings {
        debug!("{: <width$}: {}", rule, count, width = max_rule_length);
    }
}

use assert_cmd::Command;
use predicates::prelude::*;

const FORMATS: [&str; 4] = ["pretty", "json", "jsonl", "bson"];

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn scan_quiet_suppresses_summary() {
    for format in FORMATS {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .env("NO_COLOR", "1")
            .args([
                "scan",
                "testdata/slack_tokens.properties",
                "--confidence=low",
                "--format",
                format,
                "--no-update-check",
                "--no-validate",
                "--quiet",
            ])
            .assert()
            .code(200)
            .stdout(predicate::function(|out: &[u8]| !contains_bytes(out, b"Scan Summary")))
            .stdout(predicate::function(|out: &[u8]| {
                !contains_bytes(out, b"Rule Performance Stats")
            }));
    }
}

#[test]
fn scan_quiet_with_rule_stats_prints_rule_stats() {
    for format in FORMATS {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .env("NO_COLOR", "1")
            .args([
                "scan",
                "testdata/slack_tokens.properties",
                "--confidence=low",
                "--format",
                format,
                "--no-update-check",
                "--quiet",
                "--no-validate",
                "--rule-stats",
            ])
            .assert()
            .code(200)
            .stdout(predicate::function(|out: &[u8]| !contains_bytes(out, b"Scan Summary")))
            .stdout(predicate::function(|out: &[u8]| {
                contains_bytes(out, b"Rule Performance Stats")
            }));
    }
}

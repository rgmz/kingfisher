use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value;

#[test]
fn scan_rules_has_no_validated_findings() -> Result<()> {
    let output = Command::cargo_bin("kingfisher")?
        .args(["scan", "data/rules", "--format", "json", "--no-update-check", "--only-valid"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the first '[' — start of array
    let start = match stdout.find('[') {
        Some(i) => i,
        None => return Ok(()), // no array found
    };

    let mut depth = 0usize;
    let mut end = None;
    for (i, ch) in stdout.char_indices().skip(start) {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }

    let json_array_str = match end {
        Some(end_idx) => &stdout[start..=end_idx],
        None => return Ok(()), // no matching close found
    };

    if json_array_str.trim().is_empty() {
        return Ok(());
    }

    let findings: Vec<Value> = serde_json::from_str(json_array_str)?;

    for finding in findings {
        let rule_id = finding["rule"]["id"].as_str().unwrap_or("unknown");
        let rule_prevalidated = finding["rule"]["prevalidated"].as_bool().unwrap_or(false);

        let status =
            finding["finding"]["validation"]["status"].as_str().unwrap_or("").to_ascii_lowercase();

        let response = finding["finding"]["validation"]["response"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();

        // Skip anything intentionally marked as prevalidated
        if rule_prevalidated || status == "prevalidated" || response == "prevalidated" {
            continue;
        }

        // Fail only on genuinely validated secrets
        assert_ne!(
            &status,
            "active credential",
            "Validated finding detected in rule {rule_id}"
        );
    }

    Ok(())
}

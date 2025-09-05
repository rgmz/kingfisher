use reqwest::Url;
use tokio::net::lookup_host;

use crate::validation::SerializableCaptures;

/// Return (NAME, value, start, end) for every capture we care about.
///
/// * If a capture has a name, use that (upper-cased)  
/// * If it’s unnamed, fall back to `"TOKEN"`  
/// * Skip the unnamed “whole-match” capture **only when** there are
///   additional captures to return.
pub fn process_captures(captures: &SerializableCaptures) -> Vec<(String, String, usize, usize)> {
    let multiple = captures.captures.len() > 1;

    captures
        .captures
        .iter()
        // Skip the whole-match capture (match_number == 0) only when there
        // are additional captures. All other captures – named or unnamed –
        // should be preserved.
        .filter(|cap| !multiple || cap.match_number != 0)
        .map(|cap| {
            let name =
                cap.name.as_ref().map(|n| n.to_uppercase()).unwrap_or_else(|| "TOKEN".to_string());
            (name, cap.value.to_string(), cap.start, cap.end)
        })
        .collect()
}

pub fn find_closest_variable(
    captures: &[(String, String, usize, usize)],
    target_value: &String,
    target_variable_name: &str,
    search_variable_name: &str,
) -> Option<String> {
    // Find positions of the target variable with the target value
    let mut target_positions = Vec::new();
    for (name, value, start, end) in captures {
        if name == target_variable_name && value == target_value {
            target_positions.push((*start, *end));
        }
    }
    if target_positions.is_empty() {
        return None;
    }
    // For each target position, find the closest search variable
    let mut closest_distance = usize::MAX;
    let mut closest_value: Option<String> = None;
    for (_target_start, target_end) in target_positions {
        for (name, value, start, _) in captures {
            if name == search_variable_name {
                let distance = (*start as isize - target_end as isize).abs() as usize;
                if distance < closest_distance {
                    closest_distance = distance;
                    closest_value = Some(value.clone());
                }
            }
        }
    }
    closest_value
}

pub async fn check_url_resolvable(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("No host in URL")?;
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);
    lookup_host(addr).await?.next().ok_or_else(|| "Failed to resolve URL".into()).map(|_| ())
}

// -----------------------------------------------------------------------------
// tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{SerializableCapture, SerializableCaptures};
    use pretty_assertions::assert_eq;
    use smallvec::smallvec;

    #[test]
    fn single_unnamed_capture_is_returned() {
        let captures = SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 1,
                end: 4,
                value: "abc",
            }],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("TOKEN".to_string(), "abc".to_string(), 1usize, 4usize)]);
    }

    #[test]
    fn skips_whole_match_when_multiple() {
        let captures = SerializableCaptures {
            captures: smallvec![
                SerializableCapture {
                    name: None,
                    match_number: 0,
                    start: 0,
                    end: 5,
                    value: "abcde",
                },
                SerializableCapture {
                    name: Some("foo".to_string()),
                    match_number: -1,
                    start: 1,
                    end: 4,
                    value: "bcd",
                },
            ],
        };
        let result = process_captures(&captures);
        assert_eq!(result, vec![("FOO".to_string(), "bcd".to_string(), 1usize, 4usize)]);
    }

    #[test]
    fn includes_unnamed_groups_but_skips_whole_match() {
        let captures = SerializableCaptures {
            captures: smallvec![
                SerializableCapture {
                    name: None,
                    match_number: 0,
                    start: 0,
                    end: 6,
                    value: "aabbcc",
                },
                SerializableCapture {
                    name: Some("foo".to_string()),
                    match_number: -1,
                    start: 0,
                    end: 2,
                    value: "aa",
                },
                SerializableCapture { name: None, match_number: 1, start: 4, end: 6, value: "cc" },
            ],
        };
        let result = process_captures(&captures);
        assert_eq!(
            result,
            vec![
                ("FOO".to_string(), "aa".to_string(), 0usize, 2usize),
                ("TOKEN".to_string(), "cc".to_string(), 4usize, 6usize),
            ]
        );
    }
}

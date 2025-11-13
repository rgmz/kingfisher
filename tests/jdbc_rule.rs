use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use kingfisher::{rules::rule::RuleSyntax, safe_list};

fn load_jdbc_rule() -> Result<RuleSyntax> {
    let rules = RuleSyntax::from_yaml_file("data/rules/jdbc.yml")?;
    rules
        .into_iter()
        .find(|rule| rule.id == "kingfisher.jdbc.1")
        .ok_or_else(|| anyhow!("JDBC rule not found"))
}

#[test]
fn jdbc_rule_matches_expected_patterns() -> Result<()> {
    let rule = load_jdbc_rule()?;
    let regex = rule.as_regex()?;

    let sample = r#"
    datasource.url=jdbc:postgresql://db.acme.local:5432/app?user=svc_writer&password=P@s5w0rd
    connection.read=jdbc:mysql://analyst:letmein@reports.internal:3306/analytics
    cache="jdbc:sqlite:/var/lib/app/cache.db"
    vendor.dsn=jdbc:oracle:thin:@ora.example.net:1521/ORCLPDB1
    backup=jdbc:mysql://host:3306/db,other_token
    jdbc:xyz:short // this should be ignored
    somejdbc:mysql://host/db // false prefix
    jdbc:mysql://host/db>next // malformed with trailing bracket
    "#;

    let matches: BTreeSet<String> = regex
        .captures_iter(sample.as_bytes())
        .filter_map(|caps| caps.get(1))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .collect();

    let expected = BTreeSet::from([
        "jdbc:postgresql://db.acme.local:5432/app?user=svc_writer&password=P@s5w0rd".to_string(),
        "jdbc:mysql://analyst:letmein@reports.internal:3306/analytics".to_string(),
        "jdbc:sqlite:/var/lib/app/cache.db".to_string(),
        "jdbc:oracle:thin:@ora.example.net:1521/ORCLPDB1".to_string(),
        "jdbc:mysql://host:3306/db".to_string(),
    ]);

    assert_eq!(matches, expected);
    Ok(())
}

#[test]
fn jdbc_rule_respects_user_skip_regex() -> Result<()> {
    safe_list::clear_user_filters_for_tests();
    safe_list::add_user_regex(r"^jdbc:sqlite::temporary_ignore_secret$")?;

    let rule = load_jdbc_rule()?;
    let regex = rule.as_regex()?;

    let sample = r#"
    jdbc:sqlite::temporary_ignore_secret
    jdbc:mysql://data_ingest:pa55word@analytics.internal:3306/raw
    "#;

    let matches: Vec<String> = regex
        .captures_iter(sample.as_bytes())
        .filter_map(|caps| caps.get(1))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        .collect();

    let retained: Vec<String> = matches
        .into_iter()
        .filter(|m| !safe_list::is_user_match(m.as_bytes(), m.as_bytes()))
        .collect();

    safe_list::clear_user_filters_for_tests();

    assert_eq!(
        retained,
        vec!["jdbc:mysql://data_ingest:pa55word@analytics.internal:3306/raw".to_string()]
    );
    Ok(())
}

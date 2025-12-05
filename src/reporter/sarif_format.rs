use std::collections::{BTreeMap, HashSet};

use rayon::prelude::*;
use serde_sarif::sarif;

use super::*;
use crate::defaults::get_builtin_rules;

impl DetailsReporter {
    fn record_to_sarif_result(&self, record: &FindingReporterRecord) -> Result<sarif::Result> {
        let finding = &record.finding;
        let artifact_location =
            sarif::ArtifactLocationBuilder::default().uri(finding.path.clone()).build()?;
        let region = sarif::RegionBuilder::default()
            .start_line(finding.line as i64)
            .start_column(finding.column_start as i64)
            .end_line(finding.line as i64)
            .end_column(finding.column_end as i64)
            .snippet(
                sarif::ArtifactContentBuilder::default().text(finding.snippet.clone()).build()?,
            )
            .build()?;

        let mut props = BTreeMap::new();
        props.insert("validation_status".to_string(), serde_json::json!(finding.validation.status));
        props.insert("entropy".to_string(), serde_json::json!(finding.entropy));
        if let Some(git) = &finding.git_metadata {
            props.insert("git_metadata".to_string(), git.clone());
        }
        let properties =
            sarif::PropertyBagBuilder::default().additional_properties(props).build()?;

        let location = sarif::LocationBuilder::default()
            .physical_location(
                sarif::PhysicalLocationBuilder::default()
                    .artifact_location(artifact_location)
                    .region(region)
                    .build()?,
            )
            .properties(properties)
            .build()?;

        let message = sarif::MessageBuilder::default()
            .text(format!("Rule {} matched {}", record.rule.name, finding.path))
            .build()?;

        let result = sarif::ResultBuilder::default()
            .rule_id(&record.rule.name)
            .message(message)
            .kind(sarif::ResultKind::Review.to_string())
            .locations(vec![location])
            .level(sarif::ResultLevel::Warning.to_string())
            .partial_fingerprints([("fingerprint".to_string(), finding.fingerprint.clone())])
            .build()?;
        Ok(result)
    }

    pub fn sarif_format<W: std::io::Write>(
        &self,
        mut writer: W,
        _no_dedup: bool,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        let finding_rule_ids: HashSet<_> =
            envelope.findings.iter().map(|r| r.rule.name.clone()).collect();
        let rules: Vec<sarif::ReportingDescriptor> = get_builtin_rules(None)?
            .iter_rules()
            .par_bridge()
            .filter_map(|rule| {
                if finding_rule_ids.contains(&rule.name) {
                    let help = sarif::MultiformatMessageStringBuilder::default()
                        .text(&rule.references.join("\n"))
                        .build()
                        .ok()?;
                    let description = sarif::MultiformatMessageStringBuilder::default()
                        .text(&rule.name)
                        .build()
                        .ok()?;
                    sarif::ReportingDescriptorBuilder::default()
                        .id(&rule.name)
                        .short_description(description)
                        .help(help)
                        .build()
                        .ok()
                } else {
                    None
                }
            })
            .collect();
        let tool = sarif::ToolBuilder::default()
            .driver(
                sarif::ToolComponentBuilder::default()
                    .name(env!("CARGO_PKG_NAME").to_string())
                    .semantic_version(env!("CARGO_PKG_VERSION").to_string())
                    .full_name(format!("Kingfisher {}", env!("CARGO_PKG_VERSION")))
                    .information_uri(env!("CARGO_PKG_HOMEPAGE").to_string())
                    .download_uri(env!("CARGO_PKG_REPOSITORY").to_string())
                    .short_description(
                        sarif::MultiformatMessageStringBuilder::default()
                            .text(env!("CARGO_PKG_DESCRIPTION"))
                            .build()?,
                    )
                    .rules(rules)
                    .build()?,
            )
            .build()?;

        let sarif_results: Vec<sarif::Result> =
            envelope.findings.iter().filter_map(|r| self.record_to_sarif_result(r).ok()).collect();

        let mut run_builder = sarif::RunBuilder::default();
        run_builder.tool(tool);
        run_builder.results(sarif_results);

        if let Some(access_map) = envelope.access_map {
            let mut props = BTreeMap::new();
            props.insert("access_map".to_string(), serde_json::to_value(access_map)?);
            let property_bag =
                sarif::PropertyBagBuilder::default().additional_properties(props).build()?;
            run_builder.properties(property_bag);
        }

        let run = run_builder.build()?;
        let sarif = sarif::SarifBuilder::default()
            .version(sarif::Version::V2_1_0.to_string())
            .schema(sarif::SCHEMA_URL)
            .runs(vec![run])
            .build()?;
        serde_json::to_writer_pretty(&mut writer, &sarif)?;
        writeln!(writer)?;
        Ok(())
    }
}

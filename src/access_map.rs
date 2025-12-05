use anyhow::{bail, Result};
use serde::Serialize;

use crate::cli::commands::access_map::{AccessMapArgs, AccessMapProvider};

mod aws;
mod azure;
mod gcp;
mod report;

/// Run the identity mapping workflow for the selected cloud provider.
pub async fn run(args: AccessMapArgs) -> Result<()> {
    let result = match args.provider {
        AccessMapProvider::Gcp => gcp::map_access(args.credential_path.as_deref()).await?,
        AccessMapProvider::Aws => aws::map_access(&args).await?,
        AccessMapProvider::Azure => azure::map_access(&args).await?,
    };

    let json = serde_json::to_string_pretty(&result)?;
    if let Some(path) = args.json_out {
        std::fs::write(path, json)?;
    } else {
        println!("{json}");
    }

    if let Some(path) = args.html_out {
        report::generate_html_report_multi(&[result], &path)?;
    }

    Ok(())
}

/// A validated credential that can be mapped to an identity.
#[derive(Clone, Debug)]
pub enum AccessMapRequest {
    /// AWS access key credentials.
    Aws { access_key: String, secret_key: String, session_token: Option<String> },
    /// A GCP service account JSON document.
    Gcp { credential_json: String },
}

/// Structured output describing the resolved identity and its risk profile.
#[derive(Debug, Serialize, Clone)]
pub struct AccessMapResult {
    /// Cloud name such as "gcp", "aws", or "azure".
    pub cloud: String,

    /// Summary of the resolved identity.
    pub identity: AccessSummary,

    /// Roles or bindings directly associated with the identity.
    pub roles: Vec<RoleBinding>,
    /// Aggregated permission findings.
    pub permissions: PermissionSummary,

    /// Resources impacted by the credential.
    pub resources: Vec<ResourceExposure>,

    /// Overall severity score.
    pub severity: Severity,
    /// Guidance for remediation.
    pub recommendations: Vec<String>,
    /// Additional risk notes derived from permissions and impersonation exposure.
    pub risk_notes: Vec<String>,
}

/// Identity details such as email or ARN.
#[derive(Debug, Serialize, Clone)]
pub struct AccessSummary {
    /// A stable identifier for the identity (email, ARN, or SPN).
    pub id: String,
    /// Identity type such as service account or user.
    pub access_type: String,
    /// Optional project or subscription identifier.
    pub project: Option<String>,
    /// Optional tenant identifier.
    pub tenant: Option<String>,
    /// Optional AWS-style account identifier.
    pub account_id: Option<String>,
}

/// A single role or binding and its permissions.
#[derive(Debug, Serialize, Clone)]
pub struct RoleBinding {
    /// Name of the role (for example, `roles/editor`).
    pub name: String,
    /// Source of the role (direct, inherited, etc.).
    pub source: String,
    /// Expanded permissions associated with the role.
    pub permissions: Vec<String>,
}

/// Summarized permissions grouped by risk profile.
#[derive(Debug, Serialize, Default, Clone)]
pub struct PermissionSummary {
    /// Administrator or owner-level permissions.
    pub admin: Vec<String>,
    /// Permissions that allow privilege escalation.
    pub privilege_escalation: Vec<String>,
    /// Risky permissions with broad or sensitive access.
    pub risky: Vec<String>,
    /// Lower-risk read-only permissions.
    pub read_only: Vec<String>,
}

/// Exposed resources and their assessed risk.
#[derive(Debug, Serialize, Clone)]
pub struct ResourceExposure {
    /// Resource type such as project or bucket.
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Permissions that grant visibility or access to the resource.
    pub permissions: Vec<String>,
    /// Risk level.
    pub risk: String,
    /// Human-readable justification.
    pub reason: String,
}

/// Severity classification for the credential.
#[derive(Debug, Serialize, Clone, Copy)]
pub enum Severity {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

/// Map a batch of credentials to their effective identities.
pub async fn map_requests(requests: Vec<AccessMapRequest>) -> Vec<AccessMapResult> {
    let mut results = Vec::new();

    for request in requests {
        let mapped = match request {
            AccessMapRequest::Aws { access_key, secret_key, session_token } => {
                aws::map_access_with_credentials(&access_key, &secret_key, session_token.as_deref())
                    .await
                    .unwrap_or_else(|err| build_failed_result("aws", &access_key, err))
            }
            AccessMapRequest::Gcp { credential_json } => {
                gcp::map_access_from_json(&credential_json)
                    .await
                    .unwrap_or_else(|err| build_failed_result("gcp", "service_account", err))
            }
        };

        results.push(mapped);
    }

    results
}

/// Write HTML/JSON outputs for a collection of identity map results.
pub fn write_reports(results: &[AccessMapResult], html_out: &std::path::Path) -> Result<()> {
    report::generate_html_report_multi(results, html_out)?;
    Ok(())
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn build_failed_result(cloud: &str, identity_label: &str, err: anyhow::Error) -> AccessMapResult {
    AccessMapResult {
        cloud: cloud.to_string(),
        identity: AccessSummary {
            id: identity_label.to_string(),
            access_type: "unknown".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles: Vec::new(),
        permissions: PermissionSummary::default(),
        resources: vec![build_default_resource(None, Severity::Medium)],
        severity: Severity::Medium,
        recommendations: build_recommendations(Severity::Medium),
        risk_notes: vec![format!("Identity mapping failed: {err}")],
    }
}

pub(crate) fn build_default_resource(
    project_id: Option<&str>,
    severity: Severity,
) -> ResourceExposure {
    ResourceExposure {
        resource_type: "project".into(),
        name: project_id.unwrap_or_default().into(),
        permissions: Vec::new(),
        risk: severity_to_str(severity).to_string(),
        reason: "Project containing the provided credential".into(),
    }
}

pub(crate) fn build_default_account_resource(
    account_id: Option<&str>,
    severity: Severity,
) -> ResourceExposure {
    ResourceExposure {
        resource_type: "account".into(),
        name: account_id.unwrap_or_default().into(),
        permissions: Vec::new(),
        risk: severity_to_str(severity).to_string(),
        reason: "AWS account linked to the provided credential".into(),
    }
}

pub(crate) fn build_recommendations(severity: Severity) -> Vec<String> {
    let mut recs = vec![
        "Rotate the credential and audit recent usage".to_string(),
        "Apply the principle of least privilege to attached roles".to_string(),
    ];

    match severity {
        Severity::Critical | Severity::High => {
            recs.push("Investigate blast radius and revoke unused bindings".to_string())
        }
        Severity::Medium => {
            recs.push("Review write-level permissions and tighten scopes".to_string())
        }
        Severity::Low => recs.push("Maintain monitoring for anomalous access".to_string()),
    }

    recs
}

/// Fallback handler for unsupported providers.
async fn unsupported_provider(provider: &AccessMapProvider) -> Result<AccessMapResult> {
    bail!("Identity mapping for {:?} is not implemented", provider)
}

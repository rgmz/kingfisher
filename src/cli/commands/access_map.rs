use std::path::PathBuf;

use clap::{Args, ValueEnum};

/// Inspect a cloud credential and derive the effective identity and blast radius.
#[derive(Args, Debug)]
pub struct AccessMapArgs {
    /// Cloud provider: aws | gcp | azure
    #[clap(value_parser, value_name = "PROVIDER")]
    pub provider: AccessMapProvider,

    /// Path to a credential artifact (e.g. GCP service account key JSON)
    #[clap(value_parser, value_name = "CREDENTIAL", required = false)]
    pub credential_path: Option<PathBuf>,

    /// Optional path to write an interactive D3.js HTML report
    #[clap(long, value_name = "PATH")]
    pub html_out: Option<PathBuf>,

    /// Optional path to write JSON output (otherwise JSON goes to stdout)
    #[clap(long, value_name = "PATH")]
    pub json_out: Option<PathBuf>,
}

/// Supported cloud providers for identity mapping.
#[derive(Clone, Debug, ValueEnum)]
pub enum AccessMapProvider {
    /// Amazon Web Services
    Aws,
    /// Google Cloud Platform
    Gcp,
    /// Microsoft Azure
    Azure,
}

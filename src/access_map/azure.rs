use anyhow::Result;

use crate::cli::commands::access_map::AccessMapArgs;

use super::AccessMapResult;

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    super::unsupported_provider(&args.provider).await
}

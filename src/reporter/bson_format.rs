use super::*;

impl DetailsReporter {
    /// Formats findings as BSON and writes them to the provided writer.
    pub fn bson_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let records = self.build_finding_records(args)?;
        for record in records {
            let doc = bson::to_document(&record)?;
            doc.to_writer(&mut writer)?;
        }
        Ok(())
    }
}

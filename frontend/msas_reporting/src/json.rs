//! JSON report generation for findings.

use msas_core::Findings;
use serde_json;
use std::io::Write;

/// Write findings as a JSON array to the provided writer.
pub fn write_json_report<W: Write>(
    findings: &[Findings],
    writer: W,
) -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(writer, findings)
}
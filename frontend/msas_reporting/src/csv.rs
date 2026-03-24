//! CSV report generation for findings.

use msas_core::Findings;
use std::io::Write;

/// Write findings as a CSV file to the provided writer.
///
/// The CSV will have headers: id,title,severity,affected_resource,remediation,compliance.
pub fn write_csv_report<W: Write>(findings: &[Findings], writer: W) -> Result<(), csv::Error> {
    let mut wtr = csv::Writer::from_writer(writer);

    // Write headers
    wtr.write_record(&[
        "id",
        "title",
        "severity",
        "affected_resource",
        "remediation",
        "compliance",
    ])?;

    // Write each finding as a record
    for f in findings {
        let compliance_str = f
            .compliance
            .as_ref()
            .map(|v| v.join("; "))
            .unwrap_or_default();

        wtr.serialize((
            &f.id,
            &f.title,
            format!("{:?}", f.severity),
            &f.affected_resource,
            &f.remediation,
            compliance_str,
        ))?;
    }

    wtr.flush()?;
    Ok(())
}
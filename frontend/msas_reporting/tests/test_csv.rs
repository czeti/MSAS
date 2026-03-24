use msas_core::{Findings, Severity};
use msas_reporting::csv::write_csv_report;
use std::io::Cursor;

#[test]
fn test_csv_output_with_compliance() {
    let findings = vec![
        Findings {
            id: "TEST-001".to_string(),
            title: "Sample finding".to_string(),
            severity: Severity::High,
            affected_resource: "USER.TEST".to_string(),
            remediation: "Do something".to_string(),
            compliance: Some(vec!["NIST-123".to_string(), "PCI-456".to_string()]),
        },
        Findings {
            id: "TEST-002".to_string(),
            title: "Another finding".to_string(),
            severity: Severity::Info,
            affected_resource: "DSN.TEST".to_string(),
            remediation: "Do nothing".to_string(),
            compliance: None,
        },
    ];

    let mut buf = Cursor::new(Vec::new());
    write_csv_report(&findings, &mut buf).unwrap();

    let output = String::from_utf8(buf.into_inner()).unwrap();
    let lines: Vec<&str> = output.lines().collect();

    // Check header
    assert_eq!(
        lines[0],
        "id,title,severity,affected_resource,remediation,compliance"
    );

    // first row should have compliance
    assert!(lines[1].contains("NIST-123; PCI-456"));

    // second row should have empty compliance (two commas at end)
    assert!(lines[2].ends_with(',') || lines[2].contains(",,"));
}
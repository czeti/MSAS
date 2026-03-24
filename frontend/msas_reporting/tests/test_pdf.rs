use msas_core::{Findings, Severity};
use msas_reporting::pdf::write_pdf_report;
use std::io::Cursor;

#[test]
fn test_pdf_output() {
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
    write_pdf_report(&findings, &mut buf).unwrap();

    let pdf_data = buf.into_inner();
    assert!(!pdf_data.is_empty());
    // Check PDF header
    assert_eq!(&pdf_data[0..4], b"%PDF");
}
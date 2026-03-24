use msas_core::{Findings, Severity};
use msas_reporting::html::write_html_report;
use std::io::Cursor;

#[test]
fn test_html_output() {
    let findings = vec![
        Findings {
            id: "TEST-001".to_string(),
            title: "Sample finding".to_string(),
            severity: Severity::High,
            affected_resource: "USER.TEST".to_string(),
            remediation: "Do something".to_string(),
            compliance: None,
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
    write_html_report(&findings, &mut buf).unwrap();

    let output = String::from_utf8(buf.into_inner()).unwrap();
    assert!(output.contains("TEST-001"));
    assert!(output.contains("High"));
    assert!(output.contains("severity-high"));
    assert!(output.contains("TEST-002"));
    assert!(output.contains("Info"));
}
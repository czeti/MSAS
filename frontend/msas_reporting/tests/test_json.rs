use msas_core::{Findings, Severity};
use msas_reporting::json::write_json_report;
use serde_json::Value;
use std::io::Cursor;

#[test]
fn test_json_output() {
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
    write_json_report(&findings, &mut buf).unwrap();

    let output = String::from_utf8(buf.into_inner()).unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();

    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 2);

    // Check first finding fields
    let first = &parsed[0];
    assert_eq!(first["id"], "TEST-001");
    assert_eq!(first["title"], "Sample finding");
    assert_eq!(first["severity"], "High");
    assert_eq!(first["affected_resource"], "USER.TEST");
    assert_eq!(first["remediation"], "Do something");
}
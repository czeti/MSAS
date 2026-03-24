//! Integration tests for the APF scanner.

use msas_scanners::apf::{parse_output, scan_apf};

#[test]
fn test_parse_apf_output() {
    let sample = r#"
Some header
INFO: APF profile XYZ has no associated dataset
WARNING: APF dataset SYS1.LINKLIB has UACC(READ)
INSECURE: APF dataset SYS1.LPALIB grants access to ID(*)
"#;
    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 3);

    assert_eq!(
        findings[0].title,
        "INFO: APF profile XYZ has no associated dataset"
    );
    assert_eq!(findings[0].severity, msas_core::Severity::Info);
    assert_eq!(findings[0].affected_resource, "APF");

    assert_eq!(
        findings[1].title,
        "WARNING: APF dataset SYS1.LINKLIB has UACC(READ)"
    );
    assert_eq!(findings[1].severity, msas_core::Severity::High);

    assert_eq!(findings[2].severity, msas_core::Severity::Critical);
    assert!(findings[2].title.contains("ID(*)"));
}

#[test]
fn test_scan_apf_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TEST=1 to run)");
        return;
    }

    let findings = scan_apf().expect("APF scanner failed");

    // The scanner should return at least some output (INFO lines if nothing else).
    assert!(
        !findings.is_empty(),
        "Scanner returned no findings — probe likely failed"
    );

    for f in &findings {
        assert!(!f.title.is_empty(), "Finding has empty title");
        assert!(
            !f.affected_resource.is_empty(),
            "Finding has empty affected_resource"
        );
    }

    println!("APF scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  [{:?}] {}", f.severity, f.title);
    }
}
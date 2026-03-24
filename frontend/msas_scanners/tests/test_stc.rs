//! Integration tests for the STC scanner.

use msas_scanners::stc::{parse_output, scan_stc};

#[test]
fn test_parse_stc_output() {
    let sample = r#"
Some header
INFO: Checking STARTED profile JES2
WARNING: STARTED profile JES2 has no assigned user
INFO: Checking STARTED profile NET
WARNING: STARTED task NET user IBMUSER has SPECIAL attribute
"#;

    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 4);

    assert_eq!(findings[0].title, "INFO: Checking STARTED profile JES2");
    assert_eq!(findings[0].severity, msas_core::Severity::Info);
    assert_eq!(findings[0].affected_resource, "Checking");

    assert_eq!(
        findings[1].title,
        "WARNING: STARTED profile JES2 has no assigned user"
    );
    assert_eq!(findings[1].severity, msas_core::Severity::High);

    assert_eq!(findings[2].title, "INFO: Checking STARTED profile NET");
    assert_eq!(findings[2].severity, msas_core::Severity::Info);

    assert_eq!(
        findings[3].title,
        "WARNING: STARTED task NET user IBMUSER has SPECIAL attribute"
    );
    assert_eq!(findings[3].severity, msas_core::Severity::High);
}

#[test]
fn test_scan_stc_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TEST=1 to run)");
        return;
    }

    let findings = scan_stc().expect("STC scanner failed");

    assert!(
        !findings.is_empty(),
        "Scanner returned no findings, which means probe likely failed"
    );

    for f in &findings {
        assert!(!f.title.is_empty(), "Finding has empty title");
        assert!(
            !f.affected_resource.is_empty(),
            "Finding has empty affected_resource"
        );
    }

    println!("STC scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  [{:?}] {}", f.severity, f.title);
    }
}
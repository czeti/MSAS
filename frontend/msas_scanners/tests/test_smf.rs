//! Integration tests for the SMF scanner.

use msas_scanners::smf::{parse_output, scan_smf};

#[test]
fn test_parse_smf_output() {
    let sample = r#"
INFO: Successful RACF login: user=IBMUSER resource=SYS1.PARMLIB
WARNING: Failed RACF login: user=IBMUSER resource=SYS1.PARMLIB
WARNING: Dataset update/alter: user=IBMUSER dataset=SYS1.LINKLIB access=UPDATE
"#;
    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 3);

    assert_eq!(findings[0].id, "SMF-INFO");
    assert_eq!(findings[0].severity, msas_core::Severity::Info);
    assert!(findings[0].title.contains("Successful"));

    assert_eq!(findings[1].id, "SMF-SECURITY-EVENT");
    assert_eq!(findings[1].severity, msas_core::Severity::High);
    assert!(findings[1].title.contains("Failed"));

    assert_eq!(findings[2].id, "SMF-SECURITY-EVENT");
    assert_eq!(findings[2].severity, msas_core::Severity::High);
    assert!(findings[2].title.contains("update/alter"));
}

#[test]
fn test_scan_smf_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TEST=1 to run)");
        return;
    }

    let findings = scan_smf().expect("SMF scanner failed");

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

    println!("SMF scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  {}: {}", f.id, f.title);
    }
}
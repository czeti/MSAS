//! Integration tests for the JES scanner.

use msas_scanners::jes::{parse_output, scan_jes};

#[test]
fn test_parse_jes_output() {
    let sample = r#"
Some header
INFO: Total jobs in system: 42
WARNING: Held output detected for job JOB1 JOB12345
WARNING: Privileged job class A exists
INFO: Job class B is defined
"#;
    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 4);

    assert_eq!(findings[0].title, "INFO: Total jobs in system: 42");
    assert_eq!(findings[0].severity, msas_core::Severity::Info);
    assert_eq!(findings[0].affected_resource, "Total");

    assert_eq!(
        findings[1].title,
        "WARNING: Held output detected for job JOB1 JOB12345"
    );
    assert_eq!(findings[1].severity, msas_core::Severity::High);
    assert_eq!(findings[1].affected_resource, "Held");

    assert_eq!(findings[2].title, "WARNING: Privileged job class A exists");
    assert_eq!(findings[2].severity, msas_core::Severity::High);

    assert_eq!(findings[3].title, "INFO: Job class B is defined");
    assert_eq!(findings[3].severity, msas_core::Severity::Info);
}

#[test]
fn test_scan_jes_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TEST=1 to run)");
        return;
    }

    let findings = scan_jes().expect("JES scanner failed");

    // The scanner should return at least some output (INFO lines if nothing else)
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

    println!("JES scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  [{:?}] {}", f.severity, f.title);
    }
}
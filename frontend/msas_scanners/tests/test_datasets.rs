//! Integration tests for the dataset scanner.

use msas_scanners::datasets::{parse_output, scan_datasets};

#[test]
fn test_parse_dataset_output() {
    let sample = r#"
Some header
WARNING: Dataset SYS1.LINKLIB has UACC(READ)
INFO: Dataset SYS1.SAMPLIB has UACC(READ)
INSECURE: Dataset SYS1.PASSWORD has UACC(UPDATE)
"#;
    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 3);

    assert_eq!(
        findings[0].title,
        "WARNING: Dataset SYS1.LINKLIB has UACC(READ)"
    );
    assert_eq!(findings[0].severity, msas_core::Severity::High);
    assert_eq!(findings[0].affected_resource, "Dataset");

    assert_eq!(
        findings[1].title,
        "INFO: Dataset SYS1.SAMPLIB has UACC(READ)"
    );
    assert_eq!(findings[1].severity, msas_core::Severity::Info);

    assert_eq!(findings[2].severity, msas_core::Severity::Critical);
}

#[test]
fn test_scan_datasets_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TEST=1 to run)");
        return;
    }

    let findings = scan_datasets().expect("Dataset scanner failed");

    // The scanner must return SOMETHING (INFO lines at minimum).
    assert!(
        !findings.is_empty(),
        "Scanner returned no findings at all — probe likely failed to run or produced no output"
    );

    // Every finding must have a non empty title and affected resource
    for f in &findings {
        assert!(!f.title.is_empty(), "Finding has empty title");
        assert!(
            !f.affected_resource.is_empty(),
            "Finding has empty affected_resource"
        );
    }

    println!("Scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  [{:?}] {}", f.severity, f.title);
    }
}
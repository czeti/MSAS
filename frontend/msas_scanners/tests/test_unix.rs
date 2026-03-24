//! Integration tests for the Unix scanner.

use msas_scanners::unix::{parse_output, scan_unix};

#[test]
fn test_parse_unix_output() {
    let sample = r#"
Some header
WARNING: World‑writable directory /tmp/test
INFO: SUID file: -rwsr-xr-x 1 root bin 12345 /bin/su
WARNING: /tmp has non‑standard permissions: drwxrwxrwx
"#;
    let findings = parse_output(sample).unwrap();
    assert_eq!(findings.len(), 3);

    assert_eq!(
        findings[0].title,
        "WARNING: World‑writable directory /tmp/test"
    );
    assert_eq!(findings[0].severity, msas_core::Severity::High);
    assert_eq!(findings[0].affected_resource, "World‑writable");

    assert_eq!(
        findings[1].title,
        "INFO: SUID file: -rwsr-xr-x 1 root bin 12345 /bin/su"
    );
    assert_eq!(findings[1].severity, msas_core::Severity::Info);
    assert_eq!(findings[1].affected_resource, "SUID");

    assert_eq!(
        findings[2].title,
        "WARNING: /tmp has non‑standard permissions: drwxrwxrwx"
    );
    assert_eq!(findings[2].severity, msas_core::Severity::High);
}

#[test]
fn test_scan_unix_against_hercules() {
    if std::env::var("RUN_HERCULES_TESTS").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TESTS=1 to run)");
        return;
    }

    let findings = scan_unix().expect("Unix scanner failed");

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

    println!("Unix scanner returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  [{:?}] {}", f.severity, f.title);
    }
}
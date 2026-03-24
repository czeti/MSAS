//! Integration tests for CVT walker scanner.

use msas_scanners::cvtwalk::{parse_output, scan_cvtwalk};

/// Constructs a realistic 133‑character record for an APF entry.
/// For testing, we can create a string with spaces at the right positions.
fn apf_entry_line(dataset: &str, volser: &str) -> String {
    let mut _line = "INFO: APF entry: dataset=".to_string();

    let mut buf = vec![b' '; 133];
    let prefix = b"INFO: APF entry: dataset=";
    buf[0..prefix.len()].copy_from_slice(prefix);
    let dataset_bytes = dataset.as_bytes();
    let dataset_start = 25;
    let dataset_end = dataset_start + dataset_bytes.len().min(44);
    buf[dataset_start..dataset_end].copy_from_slice(&dataset_bytes[..dataset_end - dataset_start]);
    let volser_bytes = volser.as_bytes();
    let volser_start = 74;
    let volser_end = volser_start + volser_bytes.len().min(6);
    buf[volser_start..volser_end].copy_from_slice(&volser_bytes[..volser_end - volser_start]);
    // Convert to string (ASCII, because we'll feed the decoded string directly).
    String::from_utf8(buf).unwrap()
}

#[test]
fn test_parse_cvtwalk_output() {
    // Create a sample that matches the real format.
    let line1 = apf_entry_line("SYS1.LINKLIB", "VOL001");
    let line2 = "INFO: Total APF entries: 1".to_string();
    let line3 = "WARNING: CVT address not found".to_string();
    let line4 = apf_entry_line("IELH.SIEALINK", "VOL002");

    let sample = format!("{}\n{}\n{}\n{}", line1, line2, line3, line4);

    let findings = parse_output(&sample).unwrap();

    // We expect 4 findings: APF entry, count, warning, APF entry.
    assert_eq!(findings.len(), 4);

    // First APF entry
    assert_eq!(findings[0].id, "CVTWALK-INFO");
    assert!(findings[0].title.contains("SYS1.LINKLIB"));
    assert_eq!(findings[0].affected_resource, "SYS1.LINKLIB");

    assert_eq!(findings[1].id, "CVTWALK-COUNT");
    assert!(findings[1].title.contains("1"));

    // Warning
    assert_eq!(findings[2].id, "CVTWALK-NO-CVT");
    assert!(findings[2].title.contains("CVT address not found"));
    assert_eq!(findings[2].affected_resource, "CVT pointer");

    // Second APF entry
    assert_eq!(findings[3].id, "CVTWALK-INFO");
    assert!(findings[3].title.contains("IELH.SIEALINK"));
    assert_eq!(findings[3].affected_resource, "IELH.SIEALINK");
}

#[test]
fn test_scan_cvtwalk_against_hercules() {
    if std::env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Skipping Hercules test (set RUN_HERCULES_TESTS=1 to run)");
        return;
    }

    let findings = scan_cvtwalk().expect("CVT walker scanner failed");
    assert!(!findings.is_empty(), "Scanner returned no findings");

    let count_findings: Vec<_> = findings.iter().filter(|f| f.id == "CVTWALK-COUNT").collect();
    assert!(
        !count_findings.is_empty(),
        "No count finding – probe likely failed"
    );

    println!("CVT walker returned {} finding(s):", findings.len());
    for f in &findings {
        println!("  {}: {}", f.id, f.title);
    }
}
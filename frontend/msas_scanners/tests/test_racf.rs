use std::env;

use msas_scanners::racf::scan_racf;

#[test]
fn test_scan_racf_against_hercules() {
    if env::var("RUN_HERCULES_TEST").unwrap_or_default() != "1" {
        println!("Hercules scan not enabled, skipping this scan. To enable, set RUN_HERCULES_SCAN=1");
        return;
    }

    let findings = scan_racf().expect("scan failed");

    assert!(!findings.is_empty());

    let default_pwd = findings.iter().any(|f| f.title.contains("IBMUSER"));
    assert!(default_pwd);
}
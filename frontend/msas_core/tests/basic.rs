use std::{env, io::Write};
use msas_core::config::Config;
use tempfile::NamedTempFile;

#[test]
fn test_override_password() {
    let toml_content = r#"
[mainframe]
host = "HOST"
user = "IBMUSER"
pass = "PLACEHOLDER"

[paths]
rexx_pds = "IBMUSER.PROBES.REXX"
output_dsn = "IBMUSER.MSAS.OUTPUT"
local_output = "/tmp/test_output"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    write!(temp_file, "{}", toml_content).unwrap();

    let path = temp_file.path();

    unsafe {
        env::set_var("MAINFRAME_PASSWORD", "secret")
    };
    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.mainframe.pass, "secret");
    
    unsafe {
        env::remove_var("MAINFRAME_PASSWORD")
    };

    let config = Config::from_file(&path).unwrap();
    assert_eq!(config.mainframe.pass, "PLACEHOLDER");
}
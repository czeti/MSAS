//! RACF Checker: checks for security misconfigurations.

use std::{
    env, fs, path::Path, process::{self, Command, Stdio}
};

use msas_core::{Findings, MsasError, Severity, config::Config};

/// Parses the caller specified string slice (content) line by line. If prefix begins with a finding indicator, 
/// retrieve that line. If not move to the next line.
/// 
/// ### Arguments:
/// - content: Caller specified string slice.
/// 
/// ### Assumptions:
/// - String slice is valid
/// 
/// ### Returns:
/// - `Result<Vec<Findings>, MsasError>`
pub fn parse_output(content: &str) -> Result<Vec<Findings>, MsasError> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let trim = line.trim();

        let (severity, rest) = if let Some(r) = trim.strip_prefix("WARNING:") {
            (Severity::High, r.trim())
        } else if let Some(r) = trim.strip_prefix("INFO: ") {
            (Severity::Info, r.trim())
        } else {
            continue;   // next line
        };

        let affected = rest.split_whitespace().next().unwrap_or("unknown");
        findings.push(Findings {
            id: "RACF-GENERIC-WARNING".into(),
            title: trim.to_string(),
            severity,
            affected_resource: affected.to_string(),
            remediation: "Investigate and fix according to policy".into(),
            compliance: None,
        });
    }

    Ok(findings)
}

fn internal_scan_racf(config: Option<&Config>) -> Result<Vec<Findings>, MsasError> {
    let config = match config {
        Some(c) => c.clone(),
        None => Config::default()?,
    };

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| MsasError::Other("Could not open manifest dir".into()))?;
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| MsasError::Other("Failed to open workspace dir".into()))?
        .to_path_buf();

    let script_path = workspace_root.join("scripts").join("run_rexx.sh");
    if !script_path.exists() {
        return Err(MsasError::Other("Unable to find script".into()));
    }

    let local_output = {
        let base = Path::new(&config.paths.local_output);
        let dir = base.parent().unwrap_or(Path::new("test_output.txt"));
        format!("{}/racf_{}.txt", dir.display(), process::id())
    };

    let status = Command::new(&script_path)
        .current_dir(&workspace_root)
        .arg("racf_checks")
        .env("MF_HOST", config.mainframe.host)
        .env("MF_USER", config.mainframe.user)
        .env("MF_PASS", config.mainframe.pass)
        .env("REXX_PDS", config.paths.rexx_pds)
        .env("OUTPUT_DSN", config.paths.output_dsn)
        .env("LOCAL_OUTPUT", &local_output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(MsasError::Io)?;
    
    if !status.success() {
        return Err(MsasError::ScriptFailed("Script failed to run".into()));
    }

    

    let content = fs::read_to_string(&local_output)?;
    parse_output(&content)


}

/// Runs the racf checker using the default config. To run with a predefined config 
/// see `scan_racf_with_config()`
pub fn scan_racf() -> Result<Vec<Findings>, MsasError> {
    internal_scan_racf(None)
}

/// Runs the racf checker using a default config. To run with the default config 
/// see `scan_racf()`
pub fn scan_racf_with_config(config: &Config) -> Result<Vec<Findings>, MsasError> {
    internal_scan_racf(Some(config))
}

//! SMF scanner: extract security-related SMF records.

use msas_core::{Config, MsasError, Findings, Severity};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Run SMF scanner with a given configuration.
pub fn scan_smf_with_config(config: &Config) -> Result<Vec<Findings>, MsasError> {
    internal_scan_smf(Some(config))
}

/// Run SMF scanner using default configuration.
pub fn scan_smf() -> Result<Vec<Findings>, MsasError> {
    internal_scan_smf(None)
}

fn internal_scan_smf(config_opt: Option<&Config>) -> Result<Vec<Findings>, MsasError> {
    let config = match config_opt {
        Some(c) => c.clone(),
        None => Config::default()?,
    };

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| MsasError::Other("CARGO_MANIFEST_DIR not set".into()))?;
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| MsasError::Other("Could not determine workspace root".into()))?
        .to_path_buf();

    let script_path = workspace_root.join("scripts").join("run_rexx.sh");
    if !script_path.exists() {
        return Err(MsasError::Other(format!("Script not found: {:?}", script_path)));
    }

    let local_output = {
        let base = Path::new(&config.paths.local_output);
        let dir = base.parent().unwrap_or(Path::new("test_output"));
        format!("{}/smf_{}.txt", dir.display(), std::process::id())
    };

    let status = Command::new(&script_path)
        .current_dir(&workspace_root)
        .arg("smf_scan")
        .env("MF_HOST", &config.mainframe.host)
        .env("MF_USER", &config.mainframe.user)
        .env("MF_PASS", &config.mainframe.pass)
        .env("REXX_PDS", &config.paths.rexx_pds)
        .env("OUTPUT_DSN", &config.paths.output_dsn)
        .env("LOCAL_OUTPUT", &local_output)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(MsasError::Io)?;

    if !status.success() {
        return Err(MsasError::ScriptFailed(format!(
            "Script exited with status: {}",
            status
        )));
    }

    let contents = fs::read_to_string(&local_output)?;
    parse_output(&contents)
}

/// Parse SMF output.
pub fn parse_output(contents: &str) -> Result<Vec<Findings>, MsasError> {
    let mut findings = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (severity, rest, finding_id) = if let Some(r) = trimmed.strip_prefix("WARNING:") {
            (Severity::High, r.trim(), "SMF-SECURITY-EVENT")
        } else if let Some(r) = trimmed.strip_prefix("INSECURE:") {
            (Severity::Critical, r.trim(), "SMF-SECURITY-EVENT")
        } else if let Some(r) = trimmed.strip_prefix("INFO:") {
            (Severity::Info, r.trim(), "SMF-INFO")
        } else {
            continue;
        };

        // Extract the first token (e.g., "Failed", "Successful", "Dataset") as affected_resource
        let affected = rest
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();

        findings.push(Findings {
            id: finding_id.to_string(),
            title: trimmed.to_string(),
            severity,
            affected_resource: affected,
            remediation: "Review SMF records for security events".to_string(),
            compliance: None,
        });
    }

    Ok(findings)
}
//! Dataset permissions scanner: checks for weak permissions on z/OS datasets.

use msas_core::{Config, MsasError, Findings, Severity};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

/// Run dataset scanner with a given configuration.
pub fn scan_datasets_with_config(config: &Config) -> Result<Vec<Findings>, MsasError> {
    internal_scan_datasets(Some(config))
}

/// Run dataset scanner using default configuration.
pub fn scan_datasets() -> Result<Vec<Findings>, MsasError> {
    internal_scan_datasets(None)
}

fn internal_scan_datasets(config_opt: Option<&Config>) -> Result<Vec<Findings>, MsasError> {
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
        format!("{}/datasets_{}.txt", dir.display(), std::process::id())
    };

    let status = Command::new(&script_path)
        .current_dir(&workspace_root)
        .arg("dataset_scan")
        .env("MF_HOST", &config.mainframe.host)
        .env("MF_USER", &config.mainframe.user)
        .env("MF_PASS", &config.mainframe.pass)
        .env("REXX_PDS", &config.paths.rexx_pds)
        .env("OUTPUT_DSN", &config.paths.output_dsn)
        .env("LOCAL_OUTPUT", &local_output)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

/// Parse probe output into findings.
pub fn parse_output(contents: &str) -> Result<Vec<Findings>, MsasError> {
    let mut findings = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();

        let (severity, rest) = if let Some(r) = trimmed.strip_prefix("WARNING:") {
            (Severity::High, r.trim())
        } else if let Some(r) = trimmed.strip_prefix("INSECURE:") {
            (Severity::Critical, r.trim())
        } else if let Some(r) = trimmed.strip_prefix("INFO:") {
            (Severity::Info, r.trim())
        } else {
            continue;
        };

        let affected = rest
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string();

        findings.push(Findings {
            id: "DATASET-WEAK-PERMISSION".to_string(),
            title: trimmed.to_string(),
            severity,
            affected_resource: affected,
            remediation: "Review dataset permissions and restrict access according to policy"
                .to_string(),
            compliance: None,
        });
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    // Note: unit tests are moved to the integration test file as per project policy.
}
use msas_core::{Config, MsasError, Findings, Severity};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};


fn char_slice(s: &str, start: usize, end: usize) -> String {
    s.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

/// Parses the decoded output line by line, extracting findings using
/// fixed *character* offsets and exact prefix matching.
pub fn parse_output(contents: &str) -> Result<Vec<Findings>, MsasError> {
    let mut findings = Vec::new();

    for line in contents.lines() {
        if line.starts_with("INFO: APF entry: dataset=") {
            let char_count = line.chars().count();

            let dataset = if char_count >= 69 {
                char_slice(line, 25, 69).trim_end().to_string()
            } else {
                // linee was rstripped shorter than expected, we'll fall back to tokens
                line.strip_prefix("INFO: APF entry: dataset=")
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            };

            let volser = if char_count >= 80 {
                char_slice(line, 74, 80).trim_end().to_string()
            } else {
                if let Some(vol_pos) = line.find("vol=") {
                    line[vol_pos + 4..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string()
                } else {
                    String::new()
                }
            };

            findings.push(Findings {
                id: "CVTWALK-INFO".to_string(),
                title: format!("APF entry: dataset={} vol={}", dataset, volser),
                severity: Severity::Info,
                affected_resource: dataset,
                remediation: "Review CVT APF entries".to_string(),
                compliance: None,
            });
        } else if line.starts_with("INFO: Total APF entries:") {
            let count_str = line
                .strip_prefix("INFO: Total APF entries:")
                .unwrap_or("")
                .trim();
            findings.push(Findings {
                id: "CVTWALK-COUNT".to_string(),
                title: format!("Total APF entries: {}", count_str),
                severity: Severity::Info,
                affected_resource: "APF table".to_string(),
                remediation: "N/A".to_string(),
                compliance: None,
            });
        } else if line.trim_end() == "WARNING: CVT address not found" {
            findings.push(Findings {
                id: "CVTWALK-NO-CVT".to_string(),
                title: "CVT address not found".to_string(),
                severity: Severity::High,
                affected_resource: "CVT pointer".to_string(),
                remediation: "Check that the system is properly initialized and CVT exists at address 0x10 (PSA).".to_string(),
                compliance: None,
            });
        } else if line.trim_end() == "WARNING: No APF table found" {
            findings.push(Findings {
                id: "CVTWALK-NO-APF".to_string(),
                title: "No APF table found".to_string(),
                severity: Severity::High,
                affected_resource: "APF table".to_string(),
                remediation: "Verify that CVTAPF points to a valid APF table; check IEAAPFxx parmlib members.".to_string(),
                compliance: None,
            });
        }
        // Any other lines (blank lines, hex diagnostic markers, etc.) are ignored.
    }

    Ok(findings)
}

pub fn scan_cvtwalk_with_config(config: &Config) -> Result<Vec<Findings>, MsasError> {
    internal_scan_cvtwalk(Some(config))
}

pub fn scan_cvtwalk() -> Result<Vec<Findings>, MsasError> {
    internal_scan_cvtwalk(None)
}

fn internal_scan_cvtwalk(config_opt: Option<&Config>) -> Result<Vec<Findings>, MsasError> {
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

    let script_path = workspace_root.join("scripts").join("run_hlasm.sh");
    if !script_path.exists() {
        return Err(MsasError::Other(format!("Script not found: {:?}", script_path)));
    }

    let local_output = {
        let base = Path::new(&config.paths.local_output);
        let dir = base.parent().unwrap_or(Path::new("test_output"));
        format!("{}/cvtwalk_{}.txt", dir.display(), std::process::id())
    };

    let status = Command::new(&script_path)
        .current_dir(&workspace_root)
        .arg("cvtwalk")
        .env("MF_HOST", &config.mainframe.host)
        .env("MF_USER", &config.mainframe.user)
        .env("MF_PASS", &config.mainframe.pass)
        .env("ASM_PDS", "IBMUSER.PROBES.ASM")
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

    let contents = fs::read_to_string(&local_output).map_err(MsasError::Io)?;

    parse_output(&contents)
}
use anyhow::Result;
use log::{error, info, warn};
use msas_core::{Config, Findings, compliance, MsasError};
use msas_scanners::{apf, cvtwalk, datasets, jes, racf, smf, stc, unix};
use rayon::prelude::*;
use std::path::PathBuf;

pub fn run_scanner(name: &str, config: &Config) -> Result<Vec<Findings>> {
    info!("Starting scanner: {}", name);
    let findings = match name {
        "racf" => racf::scan_racf_with_config(config)?,
        "datasets" => datasets::scan_datasets_with_config(config)?,
        "apf" => apf::scan_apf_with_config(config)?,
        "jes" => jes::scan_jes_with_config(config)?,
        "unix" => unix::scan_unix_with_config(config)?,
        "stc" => stc::scan_stc_with_config(config)?,
        "cvtwalk" => cvtwalk::scan_cvtwalk_with_config(config)?,
        "smf" => smf::scan_smf_with_config(config)?,
        _ => {
            error!("Unknown scanner requested: {}", name);
            anyhow::bail!("Unknown scanner: {}", name)
        }
    };
    info!("Scanner {} returned {} findings", name, findings.len());
    if findings.is_empty() {
        warn!("Scanner {} produced no findings", name);
    }
    Ok(findings)
}

/// Run multiple scanners, optionally in parallel with a specified concurrency.
pub fn run_scanners(
    names: &[String],
    config: &Config,
    parallel: bool,
    jobs: Option<usize>,
) -> Result<Vec<Findings>> {
    let findings_vec = if !parallel {
        // Sequential execution
        let mut all = Vec::new();
        for name in names {
            all.extend(run_scanner(name, config)?);
        }
        all
    } else {
        // Parallel execution with a custom thread pool
        let thread_count = jobs.unwrap_or_else(num_cpus::get);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build thread pool: {}", e))?;

        pool.install(|| {
            let results: Vec<Result<Vec<Findings>>> = names
                .par_iter()
                .map(|name| run_scanner(name, config))
                .collect();

            let mut all = Vec::new();
            for res in results {
                match res {
                    Ok(mut findings) => all.append(&mut findings),
                    Err(e) => {
                        error!("Scanner failed: {}", e);
                        return Err(e);
                    }
                }
            }
            Ok(all)
        })?
    };

    enrich_findings_with_compliance(findings_vec, config)
}

/// Load compliance mappings from the config directory and enrich findings.
fn enrich_findings_with_compliance(
    findings: Vec<Findings>,
    _config: &Config,
) -> Result<Vec<Findings>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| anyhow::anyhow!("CARGO_MANIFEST_DIR not set"))?;

    let workspace_root = PathBuf::from(&manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Could not determine workspace root"))?
        .to_path_buf();

    let mapping_path = workspace_root
        .join("config")
        .join("compliance_mapping.toml");

    if !mapping_path.exists() {
        warn!(
            "Compliance mapping file not found at {:?}. Skipping enrichment.",
            mapping_path
        );
        return Ok(findings);
    }

    let mappings = compliance::load_mapping(&mapping_path)?;
    let findings = findings
        .into_iter()
        .map(|f| compliance::enrich_finding(f, &mappings))
        .collect::<Result<Vec<Findings>, MsasError>>()?;

    Ok(findings)
}

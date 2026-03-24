use clap::Parser;
use msas_core::Config;
use std::path::PathBuf;

mod commands;

fn parse_jobs(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid integer", s))?;
    if n < 1 {
        return Err("--jobs must be at least 1".to_string());
    }
    Ok(n)
}

/// Mainframe Security Auditing Suite (MSAS) CLI
///
/// The mainframe password can also be set via the environment variable
/// MSAS_MAINFRAME_PASSWORD, which overrides the value in the config file.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Scanners to run (racf, datasets, apf, jes, unix, stc). If none specified, all are run.
    #[arg(value_name = "SCANNER")]
    scanners: Vec<String>,

    /// Write findings as JSON to this file
    #[arg(long, value_name = "FILE")]
    output_json: Option<PathBuf>,

    /// Write findings as HTML to this file
    #[arg(long, value_name = "FILE")]
    output_html: Option<PathBuf>,

    /// Write findings as CSV to this file
    #[arg(long, value_name = "FILE")]
    output_csv: Option<PathBuf>,

    /// Write findings as PDF to this file
    #[arg(long, value_name = "FILE")]
    output_pdf: Option<PathBuf>,

    /// Run scanners in parallel (may be faster but uses more connections)
    #[arg(long)]
    parallel: bool,

    /// Number of concurrent scanners (implies --parallel). Must be at least 1.
    #[arg(long, value_name = "N", value_parser = parse_jobs)]
    jobs: Option<usize>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    // Determine config path
    let config = match cli.config {
        Some(path) => Config::from_file(&path)?,
        None => Config::default()?,
    };

    // Determine which scanners to run
    let scanner_names = if cli.scanners.is_empty() {
        vec![
            "racf".to_string(),
            "datasets".to_string(),
            "apf".to_string(),
            "jes".to_string(),
            "unix".to_string(),
            "stc".to_string(),
            "cvtwalk".to_string(),
            "smf".to_string(), // <-- new
        ]
    } else {
        cli.scanners
    };

    // Compute parallelism: true if --parallel or --jobs given
    let parallel = cli.parallel || cli.jobs.is_some();
    let jobs = cli.jobs;

    log::info!(
        "Starting scan with scanners: {:?} (parallel={}, jobs={:?})",
        scanner_names,
        parallel,
        jobs
    );
    let all_findings = commands::scan::run_scanners(&scanner_names, &config, parallel, jobs)?;
    log::info!("Scan completed, {} findings total", all_findings.len());

    // Print findings grouped by scanner, with section headers the tests can assert against.
    if all_findings.is_empty() {
        println!("No findings reported.");
    } else {
        let sections: &[(&str, &str)] = &[
            ("RACF", "RACF AUDIT FINDINGS"),
            ("DATASET", "DATASET AUDIT FINDINGS"),
            ("APF", "APF AUDIT FINDINGS"),
            ("JES", "JES AUDIT FINDINGS"),
            ("UNIX", "UNIX AUDIT FINDINGS"),
            ("STC", "STC AUDIT FINDINGS"),
            ("CVTWALK", "CVTWALK AUDIT FINDINGS"),
        ];

        for (prefix, header) in sections {
            let section: Vec<_> = all_findings
                .iter()
                .filter(|f| f.id.starts_with(prefix))
                .collect();

            if section.is_empty() {
                continue;
            }

            println!("\n=== {} ({} total) ===", header, section.len());
            for f in section {
                println!("  [{:?}] {}: {}", f.severity, f.id, f.title);
                println!("       Resource: {}", f.affected_resource);
                println!("       Remediation: {}", f.remediation);
                println!();
            }
        }
    }

    // Write JSON report if requested
    if let Some(json_path) = cli.output_json {
        log::info!("Writing JSON report to {}", json_path.display());
        let file = std::fs::File::create(&json_path)?;
        msas_reporting::json::write_json_report(&all_findings, file).map_err(|e| {
            log::error!("JSON serialization failed: {}", e);
            anyhow::anyhow!("JSON serialization error: {}", e)
        })?;
        println!("JSON report written to {}", json_path.display());
    }

    // Write HTML report if requested
    if let Some(html_path) = cli.output_html {
        log::info!("Writing HTML report to {}", html_path.display());
        let file = std::fs::File::create(&html_path)?;
        if let Err(e) = msas_reporting::html::write_html_report(&all_findings, file) {
            log::error!("HTML report generation failed: {}", e);
            return Err(anyhow::anyhow!("HTML report error: {}", e));
        }
        println!("HTML report written to {}", html_path.display());
    }

    // Write CSV report if requested
    if let Some(csv_path) = cli.output_csv {
        log::info!("Writing CSV report to {}", csv_path.display());
        let file = std::fs::File::create(&csv_path)?;
        if let Err(e) = msas_reporting::csv::write_csv_report(&all_findings, file) {
            log::error!("CSV report generation failed: {}", e);
            return Err(anyhow::anyhow!("CSV report error: {}", e));
        }
        println!("CSV report written to {}", csv_path.display());
    }

    if let Some(pdf_path) = cli.output_pdf {
        log::info!("Writing PDF report to {}", pdf_path.display());
        let file = std::fs::File::create(&pdf_path)?;
        if let Err(e) = msas_reporting::pdf::write_pdf_report(&all_findings, file) {
            log::error!("PDF report generation failed: {}", e);
            return Err(anyhow::anyhow!("PDF report error: {}", e));
        }
        println!("PDF report written to {}", pdf_path.display());
    }

    Ok(())
}
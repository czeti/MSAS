use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

const HERCULES_ENV_VAR: &str = "RUN_HERCULES_TEST";

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("Could not determine workspace root")
        .to_path_buf()
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error") // suppress logs
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Mainframe Security Auditing Suite",
        ));
}

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .arg("--version")
        .assert()
        .success();
}

#[test]
fn test_cli_unknown_scanner() {
    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("unknown")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown scanner"));
}


#[test]
fn test_cli_single_scanner() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("racf")
        .assert()
        .success()
        .stdout(predicate::str::contains("RACF AUDIT FINDINGS"))
        .stdout(predicate::str::contains("DATASET AUDIT FINDINGS").not());
}

#[test]
fn test_cli_html_output() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap().to_string();

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("racf")
        .arg("--output-html")
        .arg(&path)
        .assert()
        .success();

    // Check file exists and is non-empty
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
}

#[test]
fn test_cli_csv_output() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap().to_string();

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("racf")
        .arg("--output-csv")
        .arg(&path)
        .assert()
        .success();

    // Check file exists and is non-empty
    assert!(std::fs::metadata(&path).unwrap().len() > 0);
}

#[test]
fn test_cli_parallel_flag() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("--parallel")
        .arg("racf") // run at least one scanner
        .assert()
        .success();
}

#[test]
fn test_cli_jobs_flag() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("--jobs")
        .arg("2")
        .arg("racf")
        .assert()
        .success();
}

#[test]
fn test_cli_jobs_without_parallel() {
    // `--jobs` should imply parallel, so even without `--parallel` it should work.
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("--jobs")
        .arg("2")
        .arg("racf")
        .arg("datasets")
        .assert()
        .success();
}

#[test]
fn test_cli_jobs_invalid_zero() {
    // Clap should reject 0 because we used range(1..)
    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.arg("--jobs").arg("0").arg("racf").assert().failure();
}

#[test]
fn test_cli_help_contains_stc() {
    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("stc"));
}

#[test]
fn test_cli_compliance_in_json() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap().to_string();

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("racf")
        .arg("--output-json")
        .arg(&path)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("compliance")); // At least the field name exists
}

#[test]
fn test_cli_csv_contains_compliance() {
    if std::env::var(HERCULES_ENV_VAR).unwrap_or_default() != "1" {
        return;
    }

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let path = temp_file.path().to_str().unwrap().to_string();

    let mut cmd = Command::cargo_bin("msas_cli").unwrap();
    cmd.env("RUST_LOG", "error")
        .current_dir(workspace_root())
        .arg("racf")
        .arg("--output-csv")
        .arg(&path)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&path).unwrap();
    // Check header has compliance column
    assert!(contents.lines().next().unwrap().contains("compliance"));
    // If there's at least one finding, it should have the column data (maybe empty)
}
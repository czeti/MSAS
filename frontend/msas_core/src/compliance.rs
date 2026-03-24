use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize};

use crate::{Findings, error::MsasError};

#[derive(Debug, Deserialize)]
struct MappingFile {
    mappings: HashMap<String, Vec<String>>
}

pub fn load_mapping<P: AsRef<Path>>(path: P) -> Result<HashMap<String, Vec<String>>, MsasError> {
    let content = fs::read_to_string(&path)?;
    let mappings: MappingFile = toml::from_str(&content).map_err(|e| MsasError::Parse(format!("Error parsing compliance mapping: {}", e)))?;
    Ok(mappings.mappings)
}

pub fn enrich_finding(mut finding: Findings, mapping: &HashMap<String, Vec<String>>) -> Result<Findings, MsasError> {
    if let Some(ids) = mapping.get(&finding.id) {
        finding.compliance = Some(ids.clone());
    }
    Ok(finding)
}
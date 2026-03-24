use std::fmt::Display;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// Structural representation of various findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Findings {
    /// Id of finding
    pub id: String,
    /// Title of finding
    pub title: String,
    /// Severity of finding, see `Severity` enum
    pub severity: Severity,
    /// Affected resource
    pub affected_resource: String,
    /// Adviced action to take against finding
    pub remediation: String,
    pub compliance: Option<Vec<String>>
}

impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium")
        }
    }
}
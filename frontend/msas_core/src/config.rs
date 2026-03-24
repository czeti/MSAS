use std::{env, fs, path::Path};
use serde::{Deserialize, Serialize};
use crate::error::MsasError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    pub rexx_pds: String,
    pub output_dsn: String,
    pub local_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainframeConfig {
    pub host: String,
    pub user: String,
    pub pass: String,
}

/// A representation of our configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mainframe: MainframeConfig,
    pub paths: PathsConfig,
}

impl Config {
    /// Associated function for reading a file's contents, and returning a toml parsed structure of that file.
    /// 
    /// ### Assumptions:
    /// - This function assumes that the specified path is valid. The caller should verify that it is.
    /// 
    /// ### Returns:
    /// - `Result<Config, MsasError>`
    /// 
    /// ### Effects:
    /// - Nothing (Read only)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, MsasError> {
        let content = fs::read_to_string(&path)?;
        let mut config: Config =
            toml::from_str(&content).map_err(|e| MsasError::Parse(e.to_string()))?;

        if let Ok(password) = env::var("MAINFRAME_PASSWORD") {
            config.mainframe.pass = password;
        }

        Ok(config)
    }

    /// Associated function for initializing our configuration file.
    /// 
    /// This function effectively builds our config file path.
    /// 
    /// ### Assumptions:
    /// - Assumes our config file exists at its specified directory,
    /// this function does not verify that it does. The caller should verify that it does.
    /// 
    /// ### Effects:
    /// - Nothing (Read only)
    /// 
    /// ### Returns:
    /// - `Result<Config, MsasError>`
    pub fn default() -> Result<Self, MsasError> {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .map_err(|e| MsasError::Other(format!("{}", e)))?;
        let workspace_root = Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| MsasError::Other("Failed to find parent dir".into()))?.to_path_buf();
        let config_path = workspace_root.join("config").join("default.toml");
        Self::from_file(&config_path)
    }
}

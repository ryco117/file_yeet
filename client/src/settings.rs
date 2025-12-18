use std::{num::NonZeroU16, path::PathBuf};

use file_yeet_shared::HashBytes;

/// The saveable information for a file that was published.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SavedPublish {
    pub path: PathBuf,
    pub hash_and_file_size: Option<(HashBytes, u64)>,
}
impl SavedPublish {
    /// Create a new saved publish with the given path and hash+file-size info.
    pub fn new(path: PathBuf, hash_and_file_size: Option<(HashBytes, u64)>) -> Self {
        Self {
            path,
            hash_and_file_size,
        }
    }
}

/// The saveable information for a download transfer with partial or no progress.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SavedDownload {
    pub hash: HashBytes,
    pub file_size: u64,
    pub path: PathBuf,
    pub intervals: Option<Vec<std::ops::Range<u64>>>,
}

/// The state of the port mapping options in the GUI.
#[derive(
    Clone,
    Copy,
    std::cmp::PartialEq,
    std::cmp::Eq,
    Debug,
    Default,
    serde::Deserialize,
    serde::Serialize,
)]
pub enum PortMappingSetting {
    #[default]
    None,
    PortForwarding(Option<NonZeroU16>),
    TryPcpNatPmp,
}
impl PortMappingSetting {
    /// Get the port mapping option as a human-readable string.
    pub fn to_label(self) -> &'static str {
        match self {
            PortMappingSetting::None => "None",
            PortMappingSetting::PortForwarding(_) => "Port Forward",
            PortMappingSetting::TryPcpNatPmp => "NAT-PMP / PCP",
        }
    }
}
impl std::fmt::Display for PortMappingSetting {
    /// Display the port mapping option as a human-readable string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = self.to_label();
        write!(f, "{label}")
    }
}

/// The current settings for the app in a saveable format.
#[derive(Default, serde::Deserialize, serde::Serialize)]
pub struct AppSettings {
    pub server_address: String,
    pub gateway_address: Option<String>,
    pub port_forwarding_text: String,
    pub internal_port_text: String,
    pub port_mapping: PortMappingSetting,
    pub last_publishes: Vec<SavedPublish>,
    pub last_downloads: Vec<SavedDownload>,
}

/// Try to get the path to the app's data folder.
pub fn app_folder() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|mut p| {
        p.push("file_yeet_client");
        p
    })
}

/// Try to get the path to the app settings file.
pub fn settings_path() -> Option<std::path::PathBuf> {
    app_folder().map(|mut p| {
        p.push("settings.json");
        p
    })
}

/// The possible errors when loading the app settings.
#[derive(Debug, thiserror::Error)]
pub enum LoadSettingsError {
    #[error("Could not determine a settings path.")]
    NoDefaultPath,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Deserialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Load the app settings from the settings file, or default if the settings file does not exist.
pub fn load_settings() -> Result<AppSettings, LoadSettingsError> {
    // Get the path to the settings file.
    let path = settings_path().ok_or(LoadSettingsError::NoDefaultPath)?;

    // Ensure the settings file and directory exist.
    if path.exists() {
        // Try to read the settings for the app.
        let settings = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str::<AppSettings>(&settings)?)
    } else {
        // Ensure the directories necessary to write to the settings file exist.
        std::fs::create_dir_all(path.parent().unwrap())?;

        // Return default settings.
        Ok(AppSettings::default())
    }
}

/// The possible errors when saving the app settings.
#[derive(Debug, thiserror::Error)]
pub enum SaveSettingsError {
    #[error("Could not determine a settings path.")]
    NoDefaultPath,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Save the app settings.
pub fn save_settings(settings: &AppSettings) -> Result<(), SaveSettingsError> {
    settings_path()
        .ok_or(SaveSettingsError::NoDefaultPath)
        .and_then(|p| Ok(std::fs::File::create(p)?))
        .and_then(|f| Ok(serde_json::to_writer_pretty(f, settings)?))
}

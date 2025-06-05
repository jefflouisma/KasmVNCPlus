use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_output_directory")]
    pub output_directory: PathBuf,
    #[serde(default = "default_video_format")]
    pub video_format: VideoFormat,
    #[serde(default = "default_framerate")]
    pub framerate: u32,
    #[serde(default)]
    pub resolution: Option<Resolution>, // Optional, recorder might use native if not set
    #[serde(default = "default_audio_enabled")]
    pub audio: bool,
    #[serde(default)]
    pub max_duration_seconds: Option<u64>, // Optional
    #[serde(default = "default_log_level")]
    pub log_level: String,
    // Potentially add a field for filename pattern later
    // pub filename_pattern: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum VideoFormat {
    Mp4,
    Webm,
    Avi,
}

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct Resolution {
    pub width: u32,
    pub height: u32,
}

// Default value functions
fn default_output_directory() -> PathBuf {
    PathBuf::from("/recordings")
}

fn default_video_format() -> VideoFormat {
    VideoFormat::Mp4
}

fn default_framerate() -> u32 {
    15
}

fn default_audio_enabled() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    pub fn load(path: &str) -> Result<Self, anyhow::Error> {
        let file_content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&file_content)?;
        Ok(config)
    }
}

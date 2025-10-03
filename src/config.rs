use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

fn default_output_dir() -> PathBuf {
    PathBuf::from("/recordings")
}

fn default_format() -> String {
    "mp4".into()
}

fn default_session_id_env() -> String {
    "KASM_SESSION_ID".into()
}

fn default_ffmpeg_path() -> String {
    "ffmpeg".into()
}

fn default_vnc_command() -> String {
    "Xvnc".into()
}

use crate::oauth::config::OAuthConfig;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_format")]
    pub format: String,
    pub frame_rate: Option<u32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    #[serde(default)]
    pub audio: bool,
    pub max_duration: Option<u64>,
    pub display: Option<String>,
    pub audio_source: Option<String>,
    #[serde(default = "default_session_id_env")]
    pub session_id_env: String,
    #[serde(default = "default_ffmpeg_path")]
    pub ffmpeg_path: String,
    #[serde(default = "default_vnc_command")]
    pub vnc_command: String,
    pub preset: Option<String>,
    pub crf: Option<u32>,
    pub oauth: Option<OAuthConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_dir: default_output_dir(),
            format: default_format(),
            frame_rate: None,
            width: None,
            height: None,
            audio: false,
            max_duration: None,
            display: None,
            audio_source: None,
            session_id_env: default_session_id_env(),
            ffmpeg_path: default_ffmpeg_path(),
            vnc_command: default_vnc_command(),
            preset: None,
            crf: None,
            oauth: None,
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let contents = fs::read_to_string(path)?;
        let cfg = serde_yaml::from_str(&contents)?;
        Ok(cfg)
    }
}

pub fn read_config() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(env_path) = std::env::var("NOVNC_RECORDER_CONFIG") {
        return Config::from_file(env_path);
    }

    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 {
        &args[1]
    } else {
        "/etc/novnc_recorder.yaml"
    };
    Config::from_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_from_file() {
        let yaml = r#"
output_dir: /tmp/recordings
format: webm
frame_rate: 25
width: 1920
height: 1080
audio: true
max_duration: 1800
display: ":1"
audio_source: "my-pulse-source"
session_id_env: "MY_SESSION_ID"
ffmpeg_path: "/usr/bin/ffmpeg"
preset: "fast"
crf: 22
"#;
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{yaml}").unwrap();

        let config = Config::from_file(file.path()).unwrap();

        assert_eq!(config.output_dir, PathBuf::from("/tmp/recordings"));
        assert_eq!(config.format, "webm");
        assert_eq!(config.frame_rate, Some(25));
        assert_eq!(config.width, Some(1920));
        assert_eq!(config.height, Some(1080));
        assert!(config.audio);
        assert_eq!(config.max_duration, Some(1800));
        assert_eq!(config.display, Some(":1".to_string()));
        assert_eq!(config.audio_source, Some("my-pulse-source".to_string()));
        assert_eq!(config.session_id_env, "MY_SESSION_ID");
        assert_eq!(config.ffmpeg_path, "/usr/bin/ffmpeg");
        assert_eq!(config.preset, Some("fast".to_string()));
        assert_eq!(config.crf, Some(22));
    }

    #[test]
    fn test_default_config() {
        let yaml = "";
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{yaml}").unwrap();

        let config = Config::from_file(file.path()).unwrap();
        let default_config = Config::default();

        assert_eq!(config.output_dir, default_config.output_dir);
        assert_eq!(config.format, default_config.format);
        assert_eq!(config.frame_rate, default_config.frame_rate);
        assert_eq!(config.audio, default_config.audio);
    }
}

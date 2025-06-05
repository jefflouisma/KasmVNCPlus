use crate::config::{Config, VideoFormat};
use anyhow::{Context, Result};
use chrono::Local;
use std::fs;
use std::path::PathBuf;

pub fn generate_filename(
    config: &Config,
    session_id_opt: Option<&str>,
) -> Result<PathBuf, anyhow::Error> {
    let timestamp = Local::now().format("%Y%m%dT%H%M%S").to_string();
    let session_id = session_id_opt.unwrap_or("unknown_session");
    let extension = match config.video_format {
        VideoFormat::Mp4 => "mp4",
        VideoFormat::Webm => "webm",
        VideoFormat::Avi => "avi",
    };

    let filename_str = format!("session_{}_{}.{}", session_id, timestamp, extension);

    // Ensure output_directory is an absolute path or resolve it appropriately
    // For now, assuming it's either absolute or relative to current dir
    let mut path = config.output_directory.clone();
    if !path.is_absolute() {
        // If you want to resolve relative to current working directory:
        // path = std::env::current_dir()?.join(path);
        // Or, if it should be relative to some other base, adjust accordingly.
        // For simplicity in this step, we'll assume it's used as provided.
        // Kasm might provide absolute paths or paths relative to a known root.
        // For testing purposes, if it's relative, it will be relative to where `cargo test` runs.
        if let Ok(cwd) = std::env::current_dir() {
            path = cwd.join(path);
            log::debug!("Resolved relative output directory {:?} to absolute path {:?}", config.output_directory, path);
        } else {
            log::warn!("Could not get current working directory to resolve relative path for output_directory: {:?}", config.output_directory);
            // Proceeding with potentially relative path, might cause issues.
        }
    }
    path.push(filename_str);
    Ok(path)
}

pub fn ensure_output_directory_exists(config: &Config) -> Result<(), anyhow::Error> {
    // Resolve path similarly to generate_filename if it could be relative
    let mut path_to_ensure = config.output_directory.clone();
    if !path_to_ensure.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            path_to_ensure = cwd.join(path_to_ensure);
        }
        // No else needed, if cwd fails, create_dir_all will use it as is.
    }

    if !path_to_ensure.exists() {
        fs::create_dir_all(&path_to_ensure).with_context(|| {
            format!(
                "Failed to create output directory: {:?}",
                path_to_ensure // Use resolved path in error
            )
        })?;
        log::info!("Created output directory: {:?}", path_to_ensure);
    } else {
        log::debug!(
            "Output directory already exists: {:?}",
            path_to_ensure
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Resolution, VideoFormat};
    use std::path::PathBuf;
    use std::fs as std_fs; // Alias to avoid conflict with crate::fs if it existed

    fn create_test_config() -> Config {
        Config {
            // Using a relative path for testing, assuming it's created under target/debug or similar during tests
            output_directory: PathBuf::from("test_recordings_output"),
            video_format: VideoFormat::Mp4,
            framerate: 15,
            resolution: Some(Resolution { width: 1280, height: 720 }),
            audio: true,
            max_duration_seconds: None,
            log_level: "info".to_string(),
        }
    }

    #[test]
    fn test_generate_filename_basic() {
        let config = create_test_config();
        // Ensure relative path is handled by making it absolute for assertion consistency
        let base_path = std::env::current_dir().unwrap().join(&config.output_directory);

        let filename = generate_filename(&config, Some("test_session")).unwrap();

        let expected_prefix_str = format!("{}/session_test_session_", base_path.to_string_lossy());
        let expected_suffix = ".mp4";

        let filename_str = filename.to_string_lossy();
        assert!(filename_str.starts_with(&expected_prefix_str), "Filename {} does not start with {}", filename_str, expected_prefix_str);
        assert!(filename_str.ends_with(expected_suffix));

        let parts: Vec<&str> = filename_str
            .trim_start_matches(&expected_prefix_str)
            .trim_end_matches(expected_suffix)
            .split('T')
            .collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 6);
    }

    #[test]
    fn test_generate_filename_unknown_session() {
        let config = create_test_config();
        let filename = generate_filename(&config, None).unwrap();
        assert!(filename.to_string_lossy().contains("unknown_session"));
    }

    #[test]
    fn test_generate_filename_extensions() {
        let mut config_mp4 = create_test_config();
        config_mp4.video_format = VideoFormat::Mp4;
        assert!(generate_filename(&config_mp4, None).unwrap().to_string_lossy().ends_with(".mp4"));

        let mut config_webm = create_test_config();
        config_webm.video_format = VideoFormat::Webm;
        assert!(generate_filename(&config_webm, None).unwrap().to_string_lossy().ends_with(".webm"));

        let mut config_avi = create_test_config();
        config_avi.video_format = VideoFormat::Avi;
        assert!(generate_filename(&config_avi, None).unwrap().to_string_lossy().ends_with(".avi"));
    }

    #[test]
    fn test_ensure_output_directory_exists_creates_it() {
        let mut config = create_test_config();
        // Create a unique directory for this test run to avoid conflicts
        let unique_dir_name = format!("test_output_{}", Local::now().timestamp_nanos_opt().unwrap_or_default());
        let test_specific_output_dir = std::env::temp_dir().join("novnc_recorder_tests").join(unique_dir_name);
        config.output_directory = test_specific_output_dir.clone(); // Use this unique path

        // Clean up before test, just in case
        if test_specific_output_dir.exists() {
            std_fs::remove_dir_all(&test_specific_output_dir).unwrap();
        }

        assert!(!test_specific_output_dir.exists());
        ensure_output_directory_exists(&config).unwrap();
        assert!(test_specific_output_dir.exists());

        // Test idempotency: call again, should not fail
        ensure_output_directory_exists(&config).unwrap();
        assert!(test_specific_output_dir.exists());

        // Clean up after test
        std_fs::remove_dir_all(&test_specific_output_dir).unwrap();
    }
}

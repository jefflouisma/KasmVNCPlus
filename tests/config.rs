use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use novnc_recorder::{Config, read_config};
use tempfile::tempdir;

#[test]
fn parse_config_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("cfg.yaml");
    let yaml = r#"
output_dir: /tmp
format: webm
frame_rate: 30
width: 800
height: 600
audio: true
audio_source: test
ffmpeg_path: yes
"#;
    let mut f = File::create(&file_path).unwrap();
    f.write_all(yaml.as_bytes()).unwrap();

    let cfg = Config::from_file(&file_path).unwrap();
    assert_eq!(cfg.output_dir, PathBuf::from("/tmp"));
    assert_eq!(cfg.format, "webm");
    assert_eq!(cfg.frame_rate, Some(30));
    assert_eq!(cfg.width, Some(800));
    assert_eq!(cfg.height, Some(600));
    assert!(cfg.audio);
    assert_eq!(cfg.audio_source.as_deref(), Some("test"));
    assert_eq!(cfg.ffmpeg_path, "yes");
}

#[test]
fn default_values() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("cfg.yaml");
    // empty config should pick up defaults
    let yaml = "";
    let mut f = File::create(&file_path).unwrap();
    f.write_all(yaml.as_bytes()).unwrap();

    let cfg = Config::from_file(&file_path).unwrap();
    assert_eq!(cfg.output_dir, PathBuf::from("/recordings"));
    assert_eq!(cfg.format, "mp4");
    assert_eq!(cfg.session_id_env, "KASM_SESSION_ID");
    assert!(!cfg.audio);
    assert_eq!(cfg.ffmpeg_path, "ffmpeg");
}

#[test]
fn env_override_path() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("cfg.yaml");
    let yaml = "format: avi";
    let mut f = File::create(&file_path).unwrap();
    f.write_all(yaml.as_bytes()).unwrap();

    unsafe { std::env::set_var("NOVNC_RECORDER_CONFIG", &file_path) };
    let cfg = read_config().unwrap();
    assert_eq!(cfg.format, "avi");
    unsafe { std::env::remove_var("NOVNC_RECORDER_CONFIG") };
}

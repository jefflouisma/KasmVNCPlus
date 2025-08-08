use novnc_recorder::{Config, build_ffmpeg_command};
use std::path::PathBuf;

#[test]
fn builds_mp4_with_audio() {
    let cfg = Config {
        audio: true,
        ..Config::default()
    };
    let cmd = build_ffmpeg_command(&cfg, &PathBuf::from("out.mp4"));
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
    assert!(args.contains(&"-c:v".into()));
    assert!(args.contains(&"libx264".into()));
    assert!(args.contains(&"-c:a".into()));
    assert!(args.contains(&"aac".into()));
}

#[test]
fn builds_webm() {
    let mut cfg = Config::default();
    cfg.format = "webm".into();
    let cmd = build_ffmpeg_command(&cfg, &PathBuf::from("out.webm"));
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
    assert!(args.contains(&"libvpx-vp9".into()));
}

#[test]
fn builds_avi() {
    let mut cfg = Config::default();
    cfg.format = "avi".into();
    let cmd = build_ffmpeg_command(&cfg, &PathBuf::from("out.avi"));
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
    assert!(args.contains(&"mpeg4".into()));
}

#[test]
fn builds_with_overrides() {
    let mut cfg = Config::default();
    cfg.audio = true;
    cfg.audio_source = Some("src".into());
    cfg.frame_rate = Some(25);
    cfg.width = Some(640);
    cfg.height = Some(480);
    cfg.display = Some(":1".into());
    let cmd = build_ffmpeg_command(&cfg, &PathBuf::from("out.mp4"));
    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
    assert!(args.windows(2).any(|w| w == ["-r", "25"]));
    assert!(args.windows(2).any(|w| w == ["-s", "640x480"]));
    assert!(args.contains(&":1".into()));
    assert!(args.contains(&"src".into()));
}

use crate::config::Config;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn build_ffmpeg_command(cfg: &Config, output: &Path) -> Command {
    let mut cmd = Command::new(&cfg.ffmpeg_path);
    unsafe {
        cmd.pre_exec(|| {
            if let Err(e) = nix::unistd::setsid() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
            }
            Ok(())
        });
    }
    cmd.arg("-y");

    // Video input
    cmd.arg("-f").arg("x11grab");
    if let Some(fps) = cfg.frame_rate {
        cmd.arg("-r").arg(fps.to_string());
    }
    if let (Some(w), Some(h)) = (cfg.width, cfg.height) {
        cmd.arg("-s").arg(format!("{}x{}", w, h));
    }
    let display = cfg
        .display
        .clone()
        .unwrap_or_else(|| std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into()));
    cmd.arg("-i").arg(display);

    // Audio input
    if cfg.audio {
        cmd.arg("-f").arg("pulse");
        let source = cfg.audio_source.clone().unwrap_or_else(|| "default".into());
        cmd.arg("-i").arg(source);
    }

    // Encoding options
    match cfg.format.as_str() {
        "webm" => {
            cmd.arg("-c:v").arg("libvpx-vp9");
            if cfg.audio {
                cmd.arg("-c:a").arg("libopus");
            }
        }
        "avi" => {
            cmd.arg("-c:v").arg("mpeg4");
        }
        _ => {
            // default mp4
            cmd.arg("-c:v").arg("libx264");
            if let Some(preset) = &cfg.preset {
                cmd.arg("-preset").arg(preset);
            }
            if let Some(crf) = cfg.crf {
                cmd.arg("-crf").arg(crf.to_string());
            }
            if cfg.audio {
                cmd.arg("-c:a").arg("aac");
            }
        }
    }

    cmd.arg(output);
    cmd.stdout(Stdio::null()).stderr(Stdio::piped());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    #[test]
    fn test_build_ffmpeg_command_minimal() {
        let config = Config {
            ffmpeg_path: "ffmpeg_test".to_string(),
            ..Default::default()
        };
        let output = PathBuf::from("/tmp/test.mp4");
        let cmd = build_ffmpeg_command(&config, &output);
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();

        assert_eq!(cmd.get_program().to_str().unwrap(), "ffmpeg_test");
        assert!(args.contains(&"-y".to_string()));
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"x11grab".to_string()));
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&":0".to_string()));
        assert!(args.contains(&"-c:v".to_string()));
        assert!(args.contains(&"libx264".to_string()));
        assert!(args.contains(&"/tmp/test.mp4".to_string()));
        assert!(!args.contains(&"-c:a".to_string()));
    }

    #[test]
    fn test_build_ffmpeg_command_full() {
        let config = Config {
            ffmpeg_path: "ffmpeg".to_string(),
            format: "mp4".to_string(),
            frame_rate: Some(30),
            width: Some(1920),
            height: Some(1080),
            audio: true,
            display: Some(":1".to_string()),
            audio_source: Some("pulse-source".to_string()),
            preset: Some("ultrafast".to_string()),
            crf: Some(28),
            ..Default::default()
        };
        let output = PathBuf::from("/tmp/test.mp4");
        let cmd = build_ffmpeg_command(&config, &output);
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();

        assert!(args.contains(&"-r".to_string()));
        assert!(args.contains(&"30".to_string()));
        assert!(args.contains(&"-s".to_string()));
        assert!(args.contains(&"1920x1080".to_string()));
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&":1".to_string()));
        assert!(args.contains(&"pulse-source".to_string()));
        assert!(args.contains(&"-c:v".to_string()));
        assert!(args.contains(&"libx264".to_string()));
        assert!(args.contains(&"-c:a".to_string()));
        assert!(args.contains(&"aac".to_string()));
        assert!(args.contains(&"-preset".to_string()));
        assert!(args.contains(&"ultrafast".to_string()));
        assert!(args.contains(&"-crf".to_string()));
        assert!(args.contains(&"28".to_string()));
    }

    #[test]
    fn test_build_ffmpeg_command_avi() {
        let config = Config {
            format: "avi".to_string(),
            ..Default::default()
        };
        let output = PathBuf::from("/tmp/test.avi");
        let cmd = build_ffmpeg_command(&config, &output);
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();
        assert!(args.contains(&"-c:v".to_string()));
        assert!(args.contains(&"mpeg4".to_string()));
    }

    #[test]
    fn test_builds_mp4_with_audio() {
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
    fn test_builds_webm() {
        let mut cfg = Config::default();
        cfg.format = "webm".into();
        let cmd = build_ffmpeg_command(&cfg, &PathBuf::from("out.webm"));
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into()).collect();
        assert!(args.contains(&"libvpx-vp9".into()));
    }

    #[test]
    fn test_builds_with_overrides() {
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
}
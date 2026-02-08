use crate::config::{Config, UserMetadata};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Build the ffmpeg command with user session metadata embedded in the output file.
pub fn build_ffmpeg_command(cfg: &Config, output: &Path, user_meta: Option<&UserMetadata>) -> Command {
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

    // ─── User Session Metadata ──────────────────────────────────────────────
    // Embed user identity in the video file's metadata container.
    // For MP4/MOV this goes into the moov/udta atoms.
    // For WebM it goes into the Matroska tags.
    if let Some(meta) = user_meta {
        if let Some(ref sub) = meta.sub {
            cmd.arg("-metadata").arg(format!("user_sub={}", sub));
        }
        if let Some(ref email) = meta.email {
            cmd.arg("-metadata").arg(format!("user_email={}", email));
        }
        if let Some(ref name) = meta.name {
            cmd.arg("-metadata").arg(format!("user_name={}", name));
        }
        if let Some(ref login_time) = meta.login_time {
            cmd.arg("-metadata").arg(format!("user_login_time={}", login_time));
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
        let cmd = build_ffmpeg_command(&config, &output, None);
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();

        assert_eq!(cmd.get_program().to_str().unwrap(), "ffmpeg_test");
        assert!(args.contains(&"-y".to_string()));
        assert!(args.contains(&"x11grab".to_string()));
        assert!(args.contains(&"libx264".to_string()));
    }

    #[test]
    fn test_build_ffmpeg_command_with_metadata() {
        let config = Config::default();
        let meta = UserMetadata {
            sub: Some("user-123".into()),
            email: Some("test@example.com".into()),
            name: Some("Test User".into()),
            login_time: Some("2026-01-01T00:00:00Z".into()),
        };
        let output = PathBuf::from("/tmp/test.mp4");
        let cmd = build_ffmpeg_command(&config, &output, Some(&meta));
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();

        assert!(args.contains(&"user_sub=user-123".to_string()));
        assert!(args.contains(&"user_email=test@example.com".to_string()));
        assert!(args.contains(&"user_name=Test User".to_string()));
        assert!(args.contains(&"user_login_time=2026-01-01T00:00:00Z".to_string()));
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
        let cmd = build_ffmpeg_command(&config, &output, None);
        let args: Vec<String> = cmd.get_args().map(|s| s.to_str().unwrap().to_string()).collect();

        assert!(args.contains(&"30".to_string()));
        assert!(args.contains(&"1920x1080".to_string()));
        assert!(args.contains(&":1".to_string()));
        assert!(args.contains(&"pulse-source".to_string()));
        assert!(args.contains(&"libx264".to_string()));
        assert!(args.contains(&"aac".to_string()));
        assert!(args.contains(&"ultrafast".to_string()));
        assert!(args.contains(&"28".to_string()));
    }
}

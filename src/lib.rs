use chrono::Utc;
use log::{error, info};
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

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

#[derive(Debug, Deserialize)]
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
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let cfg = serde_yaml::from_str(&contents)?;
        Ok(cfg)
    }
}

pub fn read_config() -> Result<Config, Box<dyn Error>> {
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

pub fn build_ffmpeg_command(cfg: &Config, output: &Path) -> Command {
    let mut cmd = Command::new(&cfg.ffmpeg_path);
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
            if cfg.audio {
                cmd.arg("-c:a").arg("aac");
            }
        }
    }

    cmd.arg(output);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    cmd
}

pub fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&cfg.output_dir)?;
    let session_id = std::env::var(&cfg.session_id_env).unwrap_or_else(|_| "session".into());
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("{}_{}.{}", session_id, timestamp, cfg.format);
    let output_path = cfg.output_dir.join(filename);

    let mut child = build_ffmpeg_command(&cfg, &output_path).spawn()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }) {
        error!("failed to set signal handler: {}", e);
    }

    let start = Instant::now();
    while running.load(Ordering::SeqCst) {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                error!("recorder exited with status {}", status);
            }
            return Ok(());
        }
        if let Some(max) = cfg.max_duration {
            if start.elapsed().as_secs() >= max {
                info!("maximum duration reached");
                running.store(false, Ordering::SeqCst);
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

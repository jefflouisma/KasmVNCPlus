use crate::config::{Config, UserMetadata};
use crate::ffmpeg::build_ffmpeg_command;
use chrono::Utc;
use log::{error, info, warn};
use std::error::Error;
use std::fs;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::{Duration, Instant};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&cfg.output_dir)?;

    // Read user session metadata from OAuth server (if available)
    let user_meta = UserMetadata::from_file(&cfg.user_metadata_path);
    if let Some(ref meta) = user_meta {
        info!(
            "User session metadata loaded: sub={:?}, email={:?}, name={:?}",
            meta.sub, meta.email, meta.name
        );
    } else {
        warn!(
            "No user metadata found at {} — recording without session identity",
            cfg.user_metadata_path
        );
    }

    let session_id = std::env::var(&cfg.session_id_env).unwrap_or_else(|_| "session".into());
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("{}_{}.{}", session_id, timestamp, cfg.format);
    let output_path = cfg.output_dir.join(&filename);

    // Write session metadata sidecar JSON alongside the recording
    let sidecar_path = cfg.output_dir.join(format!("{}_{}.json", session_id, timestamp));
    write_session_sidecar(&sidecar_path, &user_meta, &filename);

    let mut child = build_ffmpeg_command(&cfg, &output_path, user_meta.as_ref()).spawn()?;
    let child_pid = Pid::from_raw(child.id() as i32);

    let stderr = child.stderr.take().expect("failed to capture stderr");
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => info!("[ffmpeg] {}", line),
                Err(e) => error!("[ffmpeg] failed to read line: {}", e),
            }
        }
    });

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        info!("shutdown signal received, stopping recorder");
        r.store(false, Ordering::SeqCst);
    }) {
        error!("failed to set signal handler: {}", e);
    }

    info!("recording started for session {}", session_id);
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

    info!("sending SIGINT to ffmpeg process group (pgid {})", child_pid);
    if let Err(e) = signal::kill(Pid::from_raw(-child_pid.as_raw()), Signal::SIGINT) {
        error!("failed to send SIGINT to ffmpeg process group: {}", e);
    }

    let shutdown_start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            info!("ffmpeg exited with status {}", status);
            break;
        }
        if shutdown_start.elapsed() > SHUTDOWN_TIMEOUT {
            info!("ffmpeg did not exit in time, killing process");
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    info!("recording stopped");
    Ok(())
}

/// Write a JSON sidecar file alongside the recording with session details
fn write_session_sidecar(
    path: &std::path::Path,
    user_meta: &Option<UserMetadata>,
    recording_filename: &str,
) {
    let sidecar = serde_json::json!({
        "recording_file": recording_filename,
        "started_at": Utc::now().to_rfc3339(),
        "user": user_meta.as_ref().map(|m| serde_json::json!({
            "sub": m.sub,
            "email": m.email,
            "name": m.name,
            "login_time": m.login_time,
        })),
    });

    match fs::write(path, serde_json::to_string_pretty(&sidecar).unwrap()) {
        Ok(_) => info!("Session metadata written to {}", path.display()),
        Err(e) => warn!("Failed to write session sidecar: {}", e),
    }
}

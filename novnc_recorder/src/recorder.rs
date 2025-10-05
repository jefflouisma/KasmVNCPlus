use crate::config::Config;
use crate::ffmpeg::build_ffmpeg_command;
use chrono::Utc;
use log::{error, info};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&cfg.output_dir)?;
    let session_id = std::env::var(&cfg.session_id_env).unwrap_or_else(|_| "session".into());
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("{}_{}.{}", session_id, timestamp, cfg.format);
    let output_path = cfg.output_dir.join(filename);

    let mut child = build_ffmpeg_command(&cfg, &output_path).spawn()?;
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

    info!(
        "sending SIGINT to ffmpeg process group (pgid {})",
        child_pid
    );
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

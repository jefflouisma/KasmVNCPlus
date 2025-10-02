use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

fn create_mock_ffmpeg_script(
    temp_path: &Path,
    pid_file_path: &Path,
    status_file_path: &Path,
    log_file_path: &Path,
) {
    let mock_ffmpeg_path = temp_path.join("mock_ffmpeg");
    let mut mock_ffmpeg_script = fs::File::create(&mock_ffmpeg_path).unwrap();
    writeln!(mock_ffmpeg_script, "#!/bin/sh").unwrap();
    writeln!(
        mock_ffmpeg_script,
        "exec > {} 2>&1",
        log_file_path.to_str().unwrap()
    )
    .unwrap();
    writeln!(mock_ffmpeg_script, "set -x").unwrap();
    writeln!(mock_ffmpeg_script, "echo 'Mock ffmpeg starting'").unwrap();
    writeln!(
        mock_ffmpeg_script,
        "echo $$ > {}",
        pid_file_path.to_str().unwrap()
    )
    .unwrap();
    writeln!(
        mock_ffmpeg_script,
        "handler() {{ echo 'Caught SIGINT' >&2; echo terminated > {}; exit 0; }}",
        status_file_path.to_str().unwrap()
    )
    .unwrap();
    writeln!(mock_ffmpeg_script, "trap handler INT").unwrap();
    writeln!(mock_ffmpeg_script, "echo 'Trap set. Sleeping.'").unwrap();
    writeln!(mock_ffmpeg_script, "sleep 30").unwrap();
    writeln!(
        mock_ffmpeg_script,
        "echo 'Sleep finished (timeout)' >> {}",
        status_file_path.to_str().unwrap()
    )
    .unwrap();
    drop(mock_ffmpeg_script);
    Command::new("chmod")
        .arg("+x")
        .arg(&mock_ffmpeg_path)
        .status()
        .unwrap();
}

#[test]
fn test_recorder_graceful_shutdown() {
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    let pid_file_path = temp_path.join("ffmpeg.pid");
    let status_file_path = temp_path.join("ffmpeg.status");
    let log_file_path = temp_path.join("ffmpeg.log");

    create_mock_ffmpeg_script(temp_path, &pid_file_path, &status_file_path, &log_file_path);

    let config_path = temp_path.join("config.yaml");
    let mut config_file = fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "ffmpeg_path: {}",
        temp_path.join("mock_ffmpeg").to_str().unwrap()
    )
    .unwrap();
    writeln!(
        config_file,
        "output_dir: {}",
        temp_path.join("recordings").to_str().unwrap()
    )
    .unwrap();
    drop(config_file);

    let mut recorder_process = Command::new(env!("CARGO_BIN_EXE_novnc_recorder"))
        .arg(config_path.to_str().unwrap())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start recorder process");

    thread::sleep(Duration::from_secs(2));
    assert!(pid_file_path.exists(), "PID file was not created");
    let _ffmpeg_pid = fs::read_to_string(&pid_file_path)
        .unwrap()
        .trim()
        .parse::<i32>()
        .expect("Failed to parse ffmpeg PID");

    let recorder_pid = Pid::from_raw(recorder_process.id() as i32);
    signal::kill(recorder_pid, Signal::SIGINT).unwrap();

    let status = recorder_process.wait().unwrap();
    assert!(status.success(), "Recorder process did not exit successfully");

    thread::sleep(Duration::from_secs(1));
    let ffmpeg_status = fs::read_to_string(&status_file_path)
        .unwrap_or_else(|e| {
            let log = fs::read_to_string(&log_file_path)
                .unwrap_or_else(|_| "could not read log file".to_string());
            panic!(
                "Status file not created: {}. Log contents:\n{}",
                e, log
            );
        })
        .trim()
        .to_string();
    assert_eq!(
        ffmpeg_status, "terminated",
        "ffmpeg did not terminate gracefully"
    );
}

#[test]
fn test_recorder_max_duration() {
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    let pid_file_path = temp_path.join("ffmpeg.pid");
    let status_file_path = temp_path.join("ffmpeg.status");
    let log_file_path = temp_path.join("ffmpeg.log");

    create_mock_ffmpeg_script(temp_path, &pid_file_path, &status_file_path, &log_file_path);

    let config_path = temp_path.join("config.yaml");
    let mut config_file = fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "ffmpeg_path: {}",
        temp_path.join("mock_ffmpeg").to_str().unwrap()
    )
    .unwrap();
    writeln!(
        config_file,
        "output_dir: {}",
        temp_path.join("recordings").to_str().unwrap()
    )
    .unwrap();
    writeln!(config_file, "max_duration: 2").unwrap();
    drop(config_file);

    let mut recorder_process = Command::new(env!("CARGO_BIN_EXE_novnc_recorder"))
        .arg(config_path.to_str().unwrap())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start recorder process");

    let status = recorder_process.wait().unwrap();
    assert!(status.success());

    let ffmpeg_status = fs::read_to_string(&status_file_path)
        .unwrap_or_else(|e| {
            let log = fs::read_to_string(&log_file_path)
                .unwrap_or_else(|_| "could not read log file".to_string());
            panic!(
                "Status file not created: {}. Log contents:\n{}",
                e, log
            );
        })
        .trim()
        .to_string();
    assert_eq!(ffmpeg_status, "terminated");
}
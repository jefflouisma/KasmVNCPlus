use novnc_recorder::{Config, run};
use tempfile::tempdir;

fn base_cfg() -> Config {
    Config::default()
}

#[test]
fn run_handles_immediate_exit() {
    let dir = tempdir().unwrap();
    let mut cfg = base_cfg();
    cfg.output_dir = dir.path().to_path_buf();
    cfg.ffmpeg_path = "true".into();
    run(cfg).unwrap();
}

#[test]
fn run_stops_after_duration() {
    let dir = tempdir().unwrap();
    let mut cfg = base_cfg();
    cfg.output_dir = dir.path().to_path_buf();
    cfg.ffmpeg_path = "yes".into();
    cfg.max_duration = Some(1);
    run(cfg).unwrap();
}

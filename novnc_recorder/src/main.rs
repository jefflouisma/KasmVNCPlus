mod config;
mod screen_capture;
mod file_utils;
mod types;
mod cli; // Added cli module

use config::Config;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use anyhow::Context;
use std::time::{Duration, SystemTime};

use crate::types::{RawVideoFrame, RawAudioSamples};
use crate::SHUTDOWN_REQUESTED;
use crate::cli::CliArgs; // Use CliArgs

// Placeholder Audio Capture Task
async fn audio_capture_task(
    _config: Arc<Config>,
    audio_tx: tokio::sync::mpsc::Sender<RawAudioSamples>,
) -> Result<(), anyhow::Error> {
    log::info!("Audio capture task started (placeholder).");
    let sample_rate = 48000;
    let channels = 2_u8;
    let interval = Duration::from_millis(20);

    while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        let dummy_data_size = (sample_rate as usize / 50) * (channels as usize) * 2;
        let frame = RawAudioSamples {
            data: vec![0u8; dummy_data_size],
            sample_rate,
            channels,
            timestamp: SystemTime::now(),
        };
        if audio_tx.send(frame).await.is_err() {
            log::error!("Audio Capture: Failed to send audio samples. Receiver likely dropped. Stopping.");
            break;
        }
        tokio::time::sleep(interval).await;
    }
    log::info!("Audio capture task stopping.");
    Ok(())
}

// Placeholder Encoding Task
async fn encoding_task(
    _config: Arc<Config>,
    mut video_rx: tokio::sync::mpsc::Receiver<RawVideoFrame>,
    mut audio_rx: tokio::sync::mpsc::Receiver<RawAudioSamples>,
) -> Result<(), anyhow::Error> {
    log::info!("Encoding task started (placeholder).");
    let mut video_channel_open = true;
    let mut audio_channel_open = true;

    while video_channel_open || audio_channel_open {
        tokio::select! {
            maybe_video_frame = video_rx.recv(), if video_channel_open => {
                match maybe_video_frame {
                    Some(video_frame) => {
                        log::info!("Encoder (placeholder) received video frame: {}x{}, ts: {:?}",
                                 video_frame.width, video_frame.height, video_frame.timestamp);
                    }
                    None => {
                        log::info!("Video frame channel closed.");
                        video_channel_open = false;
                    }
                }
            }
            maybe_audio_samples = audio_rx.recv(), if audio_channel_open => {
                match maybe_audio_samples {
                    Some(audio_samples) => {
                        log::info!("Encoder (placeholder) received audio samples: {} channels, {} Hz, ts: {:?}",
                                 audio_samples.channels, audio_samples.sample_rate, audio_samples.timestamp);
                    }
                    None => {
                        log::info!("Audio samples channel closed.");
                        audio_channel_open = false;
                    }
                }
            }
            else => {
                if !video_channel_open && !audio_channel_open {
                    log::info!("Both video and audio channels confirmed closed by select! else branch.");
                    break;
                }
            }
        }
    }
    log::info!("Encoding task stopping as all input channels are closed.");
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = CliArgs::parse_args();

    // Initialize logger first
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("Parsed CLI arguments: {:?}", args);

    // Determine config path: CLI > Environment Variable > Default
    let config_path = args.config.clone().map(|p| p.to_string_lossy().into_owned())
        .or_else(|| env::var("NOVNC_RECORDER_CONFIG_PATH").ok())
        .unwrap_or_else(|| "config.yaml".to_string());

    log::info!("Effective configuration path being used: '{}'", config_path);

    let config_display_path = config_path.clone(); // For error messages
    let config = match Config::load(&config_path) {
        Ok(cfg) => {
            log::info!("Configuration loaded successfully from '{}': {:?}", config_display_path, cfg);
            Arc::new(cfg)
        }
        Err(e) => {
            log::error!("Fatal: Failed to load configuration from '{}': {}", config_display_path, e);
            return Err(e.context(format!("Failed to load configuration from '{}'", config_display_path)));
        }
    };

    // Ensure output directory exists (critical for both dry-run and actual run)
    // Using a clone of config for this check as config Arc might be used by other threads later.
    // However, ensure_output_directory_exists takes &Config, so Arc::get is not needed here.
    if let Err(e) = file_utils::ensure_output_directory_exists(&config) {
        log::error!("Failed to ensure output directory exists (from config: {:?}): {}", config.output_directory, e);
        return Err(e.context(format!("Failed to ensure output directory: {:?}", config.output_directory)));
    }
    log::info!("Output directory ensured: {:?}", config.output_directory);

    // Generate an example filename (useful for dry-run and to confirm naming logic)
    let session_id_from_env = std::env::var("KASM_SESSION_ID").ok();
    match file_utils::generate_filename(&config, session_id_from_env.as_deref()) {
        Ok(path) => log::info!("Example recording filename: {:?}", path),
        Err(e) => {
            log::error!("Failed to generate example filename: {}", e);
            // For dry-run, this might be considered a failure. For a normal run, it's a warning before capture starts.
            if args.dry_run {
                return Err(e.context("Failed to generate example filename in dry-run"));
            }
        }
    }

    if args.dry_run {
        log::info!("Dry-run mode enabled. Configuration processed, paths checked. Exiting.");
        return Ok(());
    }

    // --- Start of non-dry-run execution: MPSC channels, signal handlers, task spawning ---

    let (video_frame_sender, video_frame_receiver) = mpsc::channel::<RawVideoFrame>(30);
    let (audio_samples_sender, audio_samples_receiver) = mpsc::channel::<RawAudioSamples>(60);
    log::info!("Created MPSC channels for video (buffer: 30) and audio (buffer: 60) data.");

    let mut sigint = signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;

    log::info!("NoVNC Recorder is now active and awaiting session activity or signals.");

    let screen_capture_config = Arc::clone(&config);
    let display_name = env::var("DISPLAY").ok();
    let video_tx_clone = video_frame_sender.clone();
    log::info!("Spawning screen capture task for display: {:?}", display_name);
    let screen_capture_handle = tokio::spawn(async move {
        if let Err(e) = screen_capture::start_screen_capture(screen_capture_config, display_name, video_tx_clone).await {
            log::error!("Screen capture task exited with error: {}", e);
        }
    });

    let audio_capture_config = Arc::clone(&config);
    let audio_tx_clone = audio_samples_sender.clone();
    log::info!("Spawning audio capture task (placeholder)...");
    let audio_capture_handle = tokio::spawn(async move {
       if let Err(e) = audio_capture_task(audio_capture_config, audio_tx_clone).await {
           log::error!("Audio capture task exited with error: {}", e);
       }
    });

    let encoding_config = Arc::clone(&config);
    log::info!("Spawning encoding task (placeholder)...");
    let encoding_handle = tokio::spawn(async move {
        if let Err(e) = encoding_task(encoding_config, video_frame_receiver, audio_samples_receiver).await {
            log::error!("Encoding task exited with error: {}", e);
        }
    });

    log::info!("Main loop running. Monitoring for shutdown signals (SIGINT, SIGTERM) or task completion.");

    tokio::select! {
        _ = sigint.recv() => log::info!("SIGINT received. Initiating graceful shutdown..."),
        _ = sigterm.recv() => log::info!("SIGTERM received. Initiating graceful shutdown..."),
        res = screen_capture_handle => { log::warn!("Screen capture task exited prematurely: {:?}", res); SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst); }
        res = audio_capture_handle => { log::warn!("Audio capture task exited prematurely: {:?}", res); SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst); }
        res = encoding_handle => { log::warn!("Encoding task exited prematurely: {:?}", res); SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst); }
    }

    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    log::info!("Shutdown signal processed. Notifying tasks to stop and awaiting completion.");

    let shutdown_timeout = Duration::from_secs(5);

    log::info!("Attempting to stop screen capture task...");
    match tokio::time::timeout(shutdown_timeout, screen_capture_handle).await {
        Ok(Ok(_)) => log::info!("Screen capture task shut down gracefully or was already complete."),
        Ok(Err(e)) => log::error!("Screen capture task panicked or had an error during join: {:?}", e),
        Err(_) => log::warn!("Screen capture task did not shut down within the {:?} timeout.", shutdown_timeout),
    }

    log::info!("Attempting to stop audio capture task...");
    match tokio::time::timeout(shutdown_timeout, audio_capture_handle).await {
        Ok(Ok(_)) => log::info!("Audio capture task shut down gracefully or was already complete."),
        Ok(Err(e)) => log::error!("Audio capture task panicked or had an error during join: {:?}", e),
        Err(_) => log::warn!("Audio capture task did not shut down within the {:?} timeout.", shutdown_timeout),
    }

    log::info!("Attempting to stop encoding task...");
    match tokio::time::timeout(shutdown_timeout, encoding_handle).await {
        Ok(Ok(_)) => log::info!("Encoding task shut down gracefully or was already complete."),
        Ok(Err(e)) => log::error!("Encoding task panicked or had an error during join: {:?}", e),
        Err(_) => log::warn!("Encoding task did not shut down within the {:?} timeout.", shutdown_timeout),
    }

    log::info!("NoVNC Recorder has completed shutdown procedures. Exiting.");
    Ok(())
}

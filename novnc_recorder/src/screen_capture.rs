use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime}; // Added SystemTime
use anyhow::Context;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, GetImageFormat, ImageOrder};
use x11rb::rust_connection::RustConnection;
use std::env;

use crate::config::Config;
use crate::SHUTDOWN_REQUESTED;
use crate::types::RawVideoFrame; // Import the frame type

pub async fn start_screen_capture(
    config: Arc<Config>,
    display_name_opt: Option<String>,
    video_tx: tokio::sync::mpsc::Sender<RawVideoFrame>, // New parameter: video sender channel
) -> Result<(), anyhow::Error> {
    log::info!("Screen capture module initialized.");

    let (conn, screen_num) = match RustConnection::connect(display_name_opt.as_deref()) {
        Ok(connection_details) => connection_details,
        Err(e) => {
            log::error!("Screen Capture: Failed to connect to X11 server (DISPLAY: {:?}): {}. Is X server running and accessible?", display_name_opt.or_else(|| env::var("DISPLAY").ok()), e);
            return Err(e.into()).context("Screen Capture: Failed to connect to X11 server");
        }
    };

    let screen = &conn.setup().roots[screen_num];
    let root_window = screen.root;

    log::info!(
        "Screen Capture: Successfully connected to X11 server on display {:?}. Screen: #{}, Dimensions: {}x{}. Root window ID: {:x}",
        display_name_opt.or_else(|| env::var("DISPLAY").ok()),
        screen_num,
        screen.width_in_pixels,
        screen.height_in_pixels,
        root_window
    );

    let frame_interval = Duration::from_millis(1000 / config.framerate as u64);
    log::info!("Screen Capture: Targeting framerate: {} FPS (Interval: {:?})", config.framerate, frame_interval);

    while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        let capture_start_time = std::time::Instant::now();

        let geometry = match conn.get_geometry(root_window)?.reply() {
            Ok(geom) => geom,
            Err(e) => {
                log::error!("Screen Capture: Failed to get root window geometry: {}. Skipping frame.", e);
                tokio::time::sleep(Duration::from_secs(1).min(frame_interval)).await;
                continue;
            }
        };

        match conn.get_image(
            GetImageFormat::Z_PIXMAP,
            root_window,
            0, // x
            0, // y
            geometry.width,
            geometry.height,
            !0, // plane_mask (all planes)
        )?.reply() {
            Ok(image) => {
                let frame = RawVideoFrame {
                    data: image.data, // Using actual image data
                    width: geometry.width as u32,
                    height: geometry.height as u32,
                    timestamp: SystemTime::now(),
                };

                if let Err(e) = video_tx.send(frame).await {
                    log::error!("Screen Capture: Failed to send video frame: {}. Receiver likely dropped. Stopping.", e);
                    break; // Exit if channel is closed
                }
                // Log message about successful send can be added if needed, but might be too verbose.
                // log::debug!("Screen Capture: Sent video frame, {}x{}", geometry.width, geometry.height);

            }
            Err(e) => {
                log::error!("Screen Capture: Failed to get image from X11 server: {}. Skipping frame.", e);
                tokio::time::sleep(Duration::from_secs(1).min(frame_interval)).await;
                continue;
            }
        }

        let elapsed_time = capture_start_time.elapsed();
        if elapsed_time < frame_interval {
            tokio::time::sleep(frame_interval - elapsed_time).await;
        } else {
            log::warn!(
                "Screen Capture: Frame capture and processing took {:?}, which is longer than the target interval of {:?}. Might be dropping frames if this continues.",
                elapsed_time,
                frame_interval
            );
        }
    }

    log::info!("Screen capture task received shutdown signal and is stopping.");
    Ok(())
}

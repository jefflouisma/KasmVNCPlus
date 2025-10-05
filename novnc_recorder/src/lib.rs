pub mod config;
pub mod ffmpeg;
pub mod recorder;

pub use config::{Config, read_config};
pub use recorder::run;

pub mod config;
pub mod ffmpeg;
pub mod recorder;

pub use config::{read_config, Config};
pub use recorder::run;
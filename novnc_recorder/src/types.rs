use std::time::SystemTime;

#[derive(Debug)]
pub struct RawVideoFrame {
    pub data: Vec<u8>,       // Raw pixel data (e.g., RGBA, BGRA, I420)
    pub width: u32,
    pub height: u32,
    pub timestamp: SystemTime, // Timestamp of capture
    // pub pixel_format: PixelFormat, // Could add later, e.g. using ffmpeg_next::format::Pixel
}

#[derive(Debug)]
pub struct RawAudioSamples {
    pub data: Vec<u8>,       // Raw audio samples (e.g., PCM S16LE)
    pub sample_rate: u32,
    pub channels: u8,
    pub timestamp: SystemTime, // Timestamp of capture
    // pub sample_format: SampleFormat, // Could add later, e.g. using ffmpeg_next::format::Sample
}

// Potentially, an enum to wrap both types for a single channel, if preferred,
// but separate channels are often cleaner for distinct processing pipelines.
// pub enum MediaFrame {
//     Video(RawVideoFrame),
//     Audio(RawAudioSamples),
// }

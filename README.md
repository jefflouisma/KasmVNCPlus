# KasmVNCRecorder
Session recording solution for KasmVNC

## Overview

`novnc_recorder` launches an encoder such as `ffmpeg` to capture the desktop
via `x11grab` along with optional PulseAudio audio for a running KasmVNC
session. A YAML configuration file defines output location, format, frame rate,
resolution, audio capture, maximum duration and the encoder binary. Output
files are automatically named using the session identifier and start timestamp,
and the recorder exits gracefully on shutdown signals or when the configured
duration limit is reached.

## Configuration

Create a YAML file (default location `/etc/novnc_recorder.yaml`). The path can
also be provided as the first CLI argument or via the
`NOVNC_RECORDER_CONFIG` environment variable. Unspecified fields fall back to
defaults (`/recordings` output directory, `mp4` format, audio disabled, etc.):

```yaml
output_dir: /recordings   # optional
format: mp4               # mp4, webm or avi (optional)
frame_rate: 30            # optional
width: 1280               # optional
height: 720               # optional
audio: true               # capture PulseAudio output
max_duration: 3600        # optional (seconds)
ffmpeg_path: ffmpeg       # optional encoder binary
```

## Running

```
novnc_recorder /path/to/config.yaml
```

The recorder will spawn `ffmpeg` with the requested parameters. Stopping the
process (or the container) finalises the output file.

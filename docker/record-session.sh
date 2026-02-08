#!/bin/bash
# KasmVNC Session Recorder — shell replacement for Rust novnc_recorder
# Records the X11 display using ffmpeg x11grab

set -e

CONFIG_FILE="${1:-${NOVNC_RECORDER_CONFIG:-/etc/novnc_recorder.yaml}}"
OUTPUT_DIR="${RECORDER_OUTPUT_DIR:-/recordings}"
DISPLAY="${DISPLAY:-:1}"
FORMAT="${RECORDER_FORMAT:-mp4}"
FRAME_RATE="${RECORDER_FPS:-10}"
MAX_DURATION="${RECORDER_MAX_DURATION:-}"
PRESET="${RECORDER_PRESET:-ultrafast}"
CRF="${RECORDER_CRF:-28}"

# Generate output filename
SESSION_ID="${KASM_SESSION_ID:-session}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUTPUT_FILE="${OUTPUT_DIR}/${SESSION_ID}_${TIMESTAMP}.${FORMAT}"

mkdir -p "$OUTPUT_DIR"

echo "[recorder] Starting recording: $OUTPUT_FILE"
echo "[recorder] Display: $DISPLAY, FPS: $FRAME_RATE, Format: $FORMAT"

# Build ffmpeg command
FFMPEG_ARGS="-y -f x11grab"
[ -n "$FRAME_RATE" ] && FFMPEG_ARGS="$FFMPEG_ARGS -r $FRAME_RATE"
FFMPEG_ARGS="$FFMPEG_ARGS -i $DISPLAY"

case "$FORMAT" in
    webm)
        FFMPEG_ARGS="$FFMPEG_ARGS -c:v libvpx-vp9"
        ;;
    avi)
        FFMPEG_ARGS="$FFMPEG_ARGS -c:v mpeg4"
        ;;
    *)
        FFMPEG_ARGS="$FFMPEG_ARGS -c:v libx264 -preset $PRESET -crf $CRF"
        ;;
esac

if [ -n "$MAX_DURATION" ]; then
    FFMPEG_ARGS="$FFMPEG_ARGS -t $MAX_DURATION"
fi

FFMPEG_ARGS="$FFMPEG_ARGS $OUTPUT_FILE"

# Handle graceful shutdown
cleanup() {
    echo "[recorder] Shutting down..."
    [ -n "$FFMPEG_PID" ] && kill -INT "$FFMPEG_PID" 2>/dev/null
    wait "$FFMPEG_PID" 2>/dev/null || true
    echo "[recorder] Recording saved: $OUTPUT_FILE"
    ls -lh "$OUTPUT_FILE" 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

# Start ffmpeg in background
ffmpeg $FFMPEG_ARGS 2>&1 | while read -r line; do echo "[ffmpeg] $line"; done &
FFMPEG_PID=$!
echo "[recorder] ffmpeg PID: $FFMPEG_PID"

# Wait for ffmpeg to finish
wait $FFMPEG_PID
echo "[recorder] Recording complete: $OUTPUT_FILE"
ls -lh "$OUTPUT_FILE" 2>/dev/null

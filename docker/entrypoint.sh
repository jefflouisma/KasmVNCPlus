#!/bin/bash
set -e

# KasmVNC Plus Entrypoint — Secure Enterprise Browser
# Architecture: OAuth server starts first → user authenticates via SSO →
# VNC + Chromium (kiosk) + Recorder all start AFTER successful login.

echo "Starting KasmVNC Plus (Secure Enterprise Browser)..."

# ─── Graceful Shutdown (Recorder-First Ordering) ────────────────────────────
# Phase 1.6: Stop recorder first to finalize MP4 moov atom, then browser, then VNC
cleanup() {
    echo "Shutting down KasmVNC Plus..."

    # 1. Stop recorder first — needs time to finalize MP4 moov atom
    if [ -n "$RECORDER_PID" ]; then
        kill -INT "$RECORDER_PID" 2>/dev/null
        echo "Waiting for recorder to finalize (up to 15s)..."
        for i in $(seq 1 15); do
            kill -0 "$RECORDER_PID" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$RECORDER_PID" 2>/dev/null && kill -9 "$RECORDER_PID" 2>/dev/null
    fi

    # Phase 6.3: Save Chromium profile to persistent storage before killing
    if [ -n "$SSO_USER_SUB" ] && [ -d "${CHROMIUM_DATA:-/tmp/chromium-data}" ]; then
        SAVE_DIR="/profiles/${SSO_USER_SUB}"
        echo "Saving user profile to ${SAVE_DIR}..."
        mkdir -p "${SAVE_DIR}"
        cp -a "${CHROMIUM_DATA}/." "${SAVE_DIR}/" 2>/dev/null || true
        PROFILE_SIZE=$(du -sb "${SAVE_DIR}" 2>/dev/null | cut -f1)
        echo "Profile saved (${PROFILE_SIZE} bytes)"
    fi

    # 2. Kill Chromium
    killall chromium 2>/dev/null || true

    # 3. Kill VNC server
    vncserver -kill :1 2>/dev/null || true

    # 4. Kill OAuth server last
    [ -n "$OAUTH_PID" ] && kill -TERM "$OAUTH_PID" 2>/dev/null

    wait 2>/dev/null
    echo "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT SIGQUIT

# ─── OAuth Server (starts FIRST — only exposed service) ─────────────────────
if [ -f "${OAUTH_CONFIG:-/etc/kasmvnc/oauth.toml}" ]; then
    echo "Starting OAuth server (SSO gateway)..."
    /opt/kasmweb/bin/kasmvnc-oauth-server &
    OAUTH_PID=$!
    echo "OAuth server started (PID: $OAUTH_PID) on port 8443"
    sleep 2
else
    echo "FATAL: No OAuth config found — cannot start without SSO!"
    exit 1
fi

# ─── Wait for SSO Login ─────────────────────────────────────────────────────
# The OAuth server writes /tmp/sso_ready after successful OIDC callback.
# Nothing starts until the user authenticates.
echo "Waiting for SSO authentication..."
while [ ! -f /tmp/sso_ready ]; do
    sleep 1
done
echo "SSO authentication successful!"

# ─── Read User Identity from SSO Trigger ─────────────────────────────────────
SSO_USER_NAME=$(cat /tmp/sso_ready | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','Unknown'))" 2>/dev/null || echo "Unknown")
SSO_USER_EMAIL=$(cat /tmp/sso_ready | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null || echo "")
SSO_USER_SUB=$(cat /tmp/sso_ready | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sub','unknown'))" 2>/dev/null || echo "unknown")
echo "User: ${SSO_USER_NAME} (${SSO_USER_EMAIL})"

# ─── Persistent User Profiles (Phase 6.3) ────────────────────────────────────
# Restore Chromium profile from persistent storage if available
PROFILE_BASE="/profiles"
USER_PROFILE_DIR="${PROFILE_BASE}/${SSO_USER_SUB}"
CHROMIUM_DATA="/tmp/chromium-data"

if [ -d "${USER_PROFILE_DIR}" ] && [ "$(ls -A ${USER_PROFILE_DIR} 2>/dev/null)" ]; then
    echo "Restoring persistent profile for ${SSO_USER_EMAIL}..."
    mkdir -p "${CHROMIUM_DATA}"
    cp -a "${USER_PROFILE_DIR}/." "${CHROMIUM_DATA}/" 2>/dev/null || true
    echo "Profile restored ($(du -sh ${USER_PROFILE_DIR} 2>/dev/null | cut -f1))"
else
    echo "No persistent profile found — creating new session profile"
    mkdir -p "${CHROMIUM_DATA}"
fi

# ─── Dynamic URL Allowlisting (Phase 6.1) ────────────────────────────────────
# If ALLOWED_URLS is set, generate dynamic Chromium policies
if [ -n "$ALLOWED_URLS" ]; then
    echo "Applying dynamic URL allowlist: ${ALLOWED_URLS}"
    python3 -c "
import json, os
urls = os.environ['ALLOWED_URLS'].split(',')
policy = json.load(open('/etc/chromium/policies/managed/policy.json'))
policy['URLAllowlist'] = [u.strip() for u in urls]
policy['URLBlocklist'] = ['*']
json.dump(policy, open('/etc/chromium/policies/managed/policy.json','w'), indent=2)
" 2>/dev/null && echo "URL allowlist applied" || echo "WARNING: Failed to apply URL allowlist"
fi

# ─── VNC Server (no auth — OAuth handles auth) ──────────────────────────────
VNC_PW="${VNC_PW:-kasmvnc}"
VNC_USER="${VNC_USER:-user}"

# Create VNC user
echo "Creating VNC user..."
mkdir -p ~/.vnc
echo -e "${VNC_PW}\n${VNC_PW}\n" | kasmvncpasswd -u "${VNC_USER}" -w ~/.vnc/passwd 2>/dev/null || true

# Generate kasmvnc.yaml with DLP watermark and clipboard restrictions
WATERMARK_TEXT="${SSO_USER_NAME}"
[ -n "$SSO_USER_EMAIL" ] && WATERMARK_TEXT="${SSO_USER_NAME} (${SSO_USER_EMAIL}) %H:%M"

cat > ~/.vnc/kasmvnc.yaml << KASMCFG
network:
  ssl:
    pem_certificate: \${HOME}/.vnc/self.pem
    pem_key: \${HOME}/.vnc/self.pem
  udp:
    public_ip: 127.0.0.1

data_loss_prevention:
  clipboard:
    delay_between_operations: none
    server_to_client:
      enabled: false
    client_to_server:
      enabled: false
  keyboard:
    enabled: true
    rate_limit: unlimited
  watermark:
    repeat_spacing: 200
    tint: 160,160,190,40
    text:
      template: "${WATERMARK_TEXT}"
      font: auto
      font_size: 18
      angle: -20
  logging:
    level: info
KASMCFG

echo "Generated kasmvnc.yaml with watermark: ${WATERMARK_TEXT}"

# Write custom xstartup — Chromium in KIOSK mode with crash recovery (Phase 1.3)
cat > ~/.vnc/xstartup << 'XSTARTUP'
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS

# Start D-Bus session (required by Chromium)
eval $(dbus-launch --sh-syntax)

# Phase 1.3: Chromium crash recovery with respawn loop
CRASH_COUNT=0
MAX_CRASHES=5
while true; do
    chromium \
        --kiosk \
        --no-sandbox \
        --disable-gpu \
        --no-first-run \
        --disable-software-rasterizer \
        --disable-dev-shm-usage \
        --disable-extensions \
        --disable-component-update \
        --disable-background-networking \
        --disable-translate \
        --disable-sync \
        --disable-default-apps \
        --disable-infobars \
        --noerrdialogs \
        --renderer-process-limit=2 \
        --js-flags="--max-old-space-size=512" \
        --disable-features=V8Sparkplug \
        --user-data-dir=/tmp/chromium-data \
        "about:blank"

    EXIT_CODE=$?
    CRASH_COUNT=$((CRASH_COUNT + 1))
    echo "WARNING: Chromium exited (code=${EXIT_CODE}, crash #${CRASH_COUNT})"

    if [ $CRASH_COUNT -ge $MAX_CRASHES ]; then
        echo "FATAL: Chromium crashed ${MAX_CRASHES} times, exiting to trigger pod restart"
        exit 1
    fi

    # Brief pause before restart
    sleep 2
    echo "Restarting Chromium (attempt $((CRASH_COUNT + 1))/${MAX_CRASHES})..."
done
XSTARTUP
chmod +x ~/.vnc/xstartup

# Start VNC server with basic auth DISABLED
echo "Starting VNC server (post-SSO, with watermark)..."
echo "2" | vncserver :1 \
    -websocketPort 8444 \
    -interface 0.0.0.0 \
    -DisableBasicAuth 1 \
    -SecurityTypes None \
    -select-de manual 2>&1 || true

# Phase 1.5: VNC startup race fix — wait for VNC to be ready
echo "Waiting for VNC to be ready on port 8444..."
for i in $(seq 1 30); do
    if curl -sk https://127.0.0.1:8444 >/dev/null 2>&1; then
        echo "VNC ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "WARNING: VNC did not respond within 30s, proceeding anyway"
    fi
    sleep 1
done

# ─── Rust Session Recorder with Retry Logic (Phase 1.4) ─────────────────────
if [ -f "${NOVNC_RECORDER_CONFIG:-/etc/novnc_recorder.toml}" ]; then
    echo "Starting Rust session recorder (post-SSO, user metadata available)..."

    # Phase 1.4: Set environment to avoid GPU driver errors
    export XDG_RUNTIME_DIR=/tmp/runtime-kasm
    export MESA_LOADER_DRIVER_OVERRIDE=swrast
    mkdir -p "$XDG_RUNTIME_DIR"

    # Phase 1.4: Retry logic for recorder (3 attempts with 5s backoff)
    RECORDER_ATTEMPTS=0
    MAX_RECORDER_ATTEMPTS=3
    while [ $RECORDER_ATTEMPTS -lt $MAX_RECORDER_ATTEMPTS ]; do
        DISPLAY=:1 /opt/kasmweb/bin/novnc_recorder &
        RECORDER_PID=$!
        sleep 3

        if kill -0 "$RECORDER_PID" 2>/dev/null; then
            echo "Recorder started successfully (PID: $RECORDER_PID)"
            break
        else
            RECORDER_ATTEMPTS=$((RECORDER_ATTEMPTS + 1))
            echo "WARNING: Recorder failed (attempt ${RECORDER_ATTEMPTS}/${MAX_RECORDER_ATTEMPTS})"
            echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') Recorder failed attempt ${RECORDER_ATTEMPTS}" >> /recordings/recorder_errors.log
            if [ $RECORDER_ATTEMPTS -lt $MAX_RECORDER_ATTEMPTS ]; then
                echo "Retrying in 5s..."
                sleep 5
            else
                echo "ERROR: Recorder failed after ${MAX_RECORDER_ATTEMPTS} attempts. Recording disabled!"
            fi
        fi
    done
else
    echo "WARNING: No recorder config found, recording disabled!"
fi

# ─── Session Expiry Monitor ─────────────────────────────────────────────────
# Watch for session expiry trigger from OAuth server's reaper task
(
    while true; do
        if [ -f /tmp/session_expired ]; then
            echo "Session expired — shutting down..."
            cleanup
        fi
        sleep 10
    done
) &
EXPIRY_MONITOR_PID=$!

# ─── Tail Logs ───────────────────────────────────────────────────────────────
echo "All services started. Tailing logs..."
tail -f ~/.vnc/*.log 2>/dev/null &
TAIL_PID=$!
wait $TAIL_PID || sleep infinity

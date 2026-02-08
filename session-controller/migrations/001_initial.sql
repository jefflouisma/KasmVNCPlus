-- KasmVNC Plus Session Controller — Initial Schema
-- PostgreSQL migrations

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    pod_name VARCHAR(255),
    node_name VARCHAR(255),
    image VARCHAR(255) NOT NULL DEFAULT 'kasmvncplus:hardened',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    policy_id UUID,
    recording_path VARCHAR(512),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    idle_since TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC);

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    url_allowlist TEXT[] NOT NULL DEFAULT '{}',
    url_blocklist TEXT[] NOT NULL DEFAULT '{}',
    clipboard_enabled BOOLEAN NOT NULL DEFAULT false,
    downloads_enabled BOOLEAN NOT NULL DEFAULT false,
    printing_enabled BOOLEAN NOT NULL DEFAULT false,
    devtools_enabled BOOLEAN NOT NULL DEFAULT false,
    session_timeout_minutes INT NOT NULL DEFAULT 30,
    recording_enabled BOOLEAN NOT NULL DEFAULT true,
    watermark_enabled BOOLEAN NOT NULL DEFAULT true,
    assigned_groups TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Recordings table
CREATE TABLE IF NOT EXISTS recordings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    file_path VARCHAR(512) NOT NULL,
    file_size_bytes BIGINT NOT NULL DEFAULT 0,
    duration_seconds INT NOT NULL DEFAULT 0,
    format VARCHAR(10) NOT NULL DEFAULT 'mp4',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recordings_user ON recordings(user_id);
CREATE INDEX IF NOT EXISTS idx_recordings_session ON recordings(session_id);
CREATE INDEX IF NOT EXISTS idx_recordings_created ON recordings(created_at DESC);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    actor_id VARCHAR(255),
    actor_email VARCHAR(255),
    target_type VARCHAR(100),
    target_id VARCHAR(255),
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event_type);

-- Workspace images table
CREATE TABLE IF NOT EXISTS workspace_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    image VARCHAR(512) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    thumbnail_url VARCHAR(512),
    enabled BOOLEAN NOT NULL DEFAULT true,
    cpu_limit VARCHAR(20) NOT NULL DEFAULT '1000m',
    memory_limit VARCHAR(20) NOT NULL DEFAULT '1Gi',
    categories TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- System settings (key-value)
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default settings
INSERT INTO settings (key, value) VALUES
    ('general', '{"default_session_timeout_minutes": 30, "max_sessions_per_user": 3, "recording_enabled_by_default": true}'::JSONB),
    ('branding', '{"logo_url": null, "login_background_url": null, "accent_color": "#3713ec", "welcome_message": "Welcome to KasmVNC Plus"}'::JSONB)
ON CONFLICT (key) DO NOTHING;

-- Seed default workspace image
INSERT INTO workspace_images (name, image, description, categories) VALUES
    ('Hardened Chromium', 'kasmvncplus:hardened', 'Locked-down enterprise browser with kiosk mode, DLP watermark, and session recording', ARRAY['browser', 'enterprise'])
ON CONFLICT DO NOTHING;

-- Seed default policy
INSERT INTO policies (name, url_allowlist, clipboard_enabled, session_timeout_minutes) VALUES
    ('Default', ARRAY['*'], false, 30)
ON CONFLICT (name) DO NOTHING;

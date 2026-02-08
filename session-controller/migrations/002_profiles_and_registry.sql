-- KasmVNC Plus Session Controller — Phase 6 Schema Additions
-- Persistent user profiles + Enhanced image registry

-- ─── User Profiles (Persistent across sessions) ─────────────────────────────
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL UNIQUE,
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    -- Chromium profile storage reference (PVC path or S3 key)
    profile_storage_path VARCHAR(512),
    profile_size_bytes BIGINT NOT NULL DEFAULT 0,
    -- User preferences (bookmarks, extensions state, etc.)
    preferences JSONB NOT NULL DEFAULT '{}',
    -- Default policy override (NULL = use group/global default)
    default_policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    -- Session history
    total_sessions INT NOT NULL DEFAULT 0,
    total_session_minutes INT NOT NULL DEFAULT 0,
    last_session_at TIMESTAMPTZ,
    -- Profile lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON user_profiles(user_email);
CREATE INDEX IF NOT EXISTS idx_profiles_last_session ON user_profiles(last_session_at DESC);

-- ─── Image Registry Enhancements ────────────────────────────────────────────
-- Add version tracking and registry metadata to workspace_images
ALTER TABLE workspace_images
    ADD COLUMN IF NOT EXISTS registry_url VARCHAR(512),
    ADD COLUMN IF NOT EXISTS image_tag VARCHAR(100) NOT NULL DEFAULT 'latest',
    ADD COLUMN IF NOT EXISTS digest VARCHAR(255),
    ADD COLUMN IF NOT EXISTS pulled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS image_size_bytes BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS auto_update BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Track which images are assigned to which nodes (for K8s pre-pull)
CREATE TABLE IF NOT EXISTS image_node_cache (
    image_id UUID REFERENCES workspace_images(id) ON DELETE CASCADE,
    node_name VARCHAR(255) NOT NULL,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (image_id, node_name)
);

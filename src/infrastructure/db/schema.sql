-- =============================================================
-- Relay Database Schema
-- Real-time chat, push-to-talk channels, calls, and conferencing
-- =============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------
-- Users
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        TEXT UNIQUE NOT NULL,
    full_name       TEXT,
    email           TEXT UNIQUE,
    phone_number    TEXT UNIQUE,
    password        TEXT NOT NULL,
    profile_picture TEXT,
    role            TEXT CHECK (role IN ('superadmin', 'admin', 'user')) DEFAULT 'user',
    status          TEXT CHECK (status IN ('pending', 'active', 'rejected')) DEFAULT 'pending',
    is_online       BOOLEAN   DEFAULT FALSE,
    last_seen       TIMESTAMP,
    deleted         BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    password_reset_status TEXT CHECK (password_reset_status IN ('requested', 'allowed', 'admin_set')),
    password_reset_token  TEXT,
    can_message     BOOLEAN NOT NULL DEFAULT TRUE,
    can_call        BOOLEAN NOT NULL DEFAULT TRUE,
    can_conference  BOOLEAN NOT NULL DEFAULT TRUE,
    can_ptt         BOOLEAN NOT NULL DEFAULT TRUE,
    -- Bumped on password change to invalidate every previously-issued access
    -- token in one write, without a token blocklist table.
    token_version   INTEGER NOT NULL DEFAULT 0
);

-- -----------------------------------------------------------
-- Workspaces — tenant/org-unit boundary.
--
-- Every workspace-scoped feature (PTT channels, contact visibility, admin
-- roles) reads membership from user_workspaces rather than inventing its own
-- membership model — one tenant boundary reused everywhere, rather than a
-- parallel membership tree per feature.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspaces (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       TEXT NOT NULL UNIQUE,
    slug       TEXT NOT NULL UNIQUE,
    color      TEXT NOT NULL DEFAULT '#4F46E5',
    created_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Example seed (replace with your own workspaces):
--   INSERT INTO workspaces (name, slug, color) VALUES
--     ('Engineering', 'engineering', '#4F46E5'),
--     ('Support',     'support',     '#16A085')
--   ON CONFLICT (slug) DO NOTHING;

CREATE TABLE IF NOT EXISTS user_workspaces (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    role         TEXT CHECK (role IN ('member', 'admin')) DEFAULT 'member',
    status       TEXT CHECK (status IN ('pending', 'active', 'suspended', 'rejected')) DEFAULT 'pending',
    accepted_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    accepted_at  TIMESTAMP,
    suspension_reason TEXT,
    suspended_at TIMESTAMP,
    created_at   TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, workspace_id)
);

CREATE INDEX IF NOT EXISTS idx_user_workspaces_user      ON user_workspaces(user_id);
CREATE INDEX IF NOT EXISTS idx_user_workspaces_workspace ON user_workspaces(workspace_id);
CREATE INDEX IF NOT EXISTS idx_user_workspaces_status    ON user_workspaces(status);

-- -----------------------------------------------------------
-- Rooms (private 1-on-1 or group conversations)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS rooms (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type        TEXT CHECK (type IN ('private', 'group')) NOT NULL,
    name        TEXT,
    created_at  TIMESTAMP DEFAULT NOW(),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    -- A conference's underlying room is ephemeral: it exists only for FK
    -- integrity and is never listed in the ordinary chat/room list.
    is_ephemeral BOOLEAN NOT NULL DEFAULT FALSE
);

-- -----------------------------------------------------------
-- Room participants (many-to-many between users and rooms)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS room_participants (
    id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    room_id   UUID NOT NULL REFERENCES rooms(id)  ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    role      TEXT CHECK (role IN ('admin', 'member')) DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT NOW(),
    left_at   TIMESTAMP,
    -- Per-participant "clear chat": hides messages before this timestamp for
    -- this user only. The room and its messages are untouched for everyone else.
    cleared_at TIMESTAMP,
    UNIQUE(room_id, user_id)
);

-- Durable contact introductions created by persistent group membership.
-- UUIDs are stored in lexical order so one relationship has one row.
CREATE TABLE IF NOT EXISTS user_communication_links (
    user_id_a       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id_b       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_group_id UUID REFERENCES rooms(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id_a, user_id_b),
    CHECK (user_id_a::text < user_id_b::text)
);

CREATE INDEX IF NOT EXISTS idx_user_communication_links_b
    ON user_communication_links (user_id_b);

-- -----------------------------------------------------------
-- Messages
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    room_id      UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    sender_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    content      TEXT,
    message_type TEXT CHECK (message_type IN ('text', 'image', 'audio', 'video', 'file', 'call', 'system')) DEFAULT 'text',
    file_url     TEXT,
    created_at   TIMESTAMP DEFAULT NOW(),
    edited_at    TIMESTAMP,
    reply_to_id  UUID REFERENCES messages(id) ON DELETE SET NULL
);

-- -----------------------------------------------------------
-- Message read receipts
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS message_status (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    status     TEXT CHECK (status IN ('sent', 'delivered', 'read')) DEFAULT 'sent',
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(message_id, user_id)
);

-- -----------------------------------------------------------
-- Calls (1:1 and conferencing share this table)
--
-- session_kind is orthogonal to call_type (audio/video): a conference can be
-- audio-only or video, and a 1:1 call can likewise be either.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS calls (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    room_id      UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    initiator_id UUID REFERENCES users(id),
    created_at   TIMESTAMP DEFAULT NOW(),
    started_at   TIMESTAMP,
    ended_at     TIMESTAMP,
    call_type    TEXT CHECK (call_type IN ('audio', 'video')) NOT NULL,
    session_kind TEXT NOT NULL DEFAULT 'call' CHECK (session_kind IN ('call', 'conference')),
    status       TEXT CHECK (status IN ('ringing', 'ongoing', 'completed', 'missed', 'rejected')) DEFAULT 'ringing'
);

CREATE TABLE IF NOT EXISTS call_participants (
    id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id   UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id),
    joined_at TIMESTAMP DEFAULT NOW(),
    left_at   TIMESTAMP,
    answered  BOOLEAN DEFAULT FALSE
);

-- -----------------------------------------------------------
-- Conference collaboration history — messages, notes, and join/leave/hand
-- events for a conference, reviewed from Conferences > Recent rather than
-- the ordinary chat list (the conference's room stays is_ephemeral).
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS conference_entries (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id     UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    entry_type  TEXT NOT NULL CHECK (entry_type IN (
        'message', 'note', 'joined', 'left', 'hand_raised', 'hand_lowered'
    )),
    content     TEXT,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_conference_entries_call_time
    ON conference_entries(call_id, created_at, id);
CREATE INDEX IF NOT EXISTS idx_conference_entries_user
    ON conference_entries(user_id, created_at DESC);

-- -----------------------------------------------------------
-- Scheduled ("planned") conferences + invite lists.
--
-- Separate from `calls`, which only gains a row once a conference actually
-- goes live. When a scheduled conference starts, a normal ephemeral room +
-- conference call is created and this row is marked status='started' — the
-- two models meet only at that moment.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS scheduled_conferences (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title          TEXT NOT NULL,
    call_type      TEXT NOT NULL DEFAULT 'video' CHECK (call_type IN ('audio', 'video')),
    scheduled_for  TIMESTAMPTZ NOT NULL,
    created_by     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status         TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'started', 'cancelled')),
    reminder_sent  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scheduled_conference_invitees (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conference_id  UUID NOT NULL REFERENCES scheduled_conferences(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    response       TEXT NOT NULL DEFAULT 'invited' CHECK (response IN ('invited', 'accepted', 'declined')),
    UNIQUE (conference_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_sched_conf_time      ON scheduled_conferences(scheduled_for) WHERE status = 'scheduled';
CREATE INDEX IF NOT EXISTS idx_sched_conf_creator   ON scheduled_conferences(created_by);
CREATE INDEX IF NOT EXISTS idx_sched_conf_inv_user  ON scheduled_conference_invitees(user_id);
CREATE INDEX IF NOT EXISTS idx_sched_conf_inv_conf  ON scheduled_conference_invitees(conference_id);

-- -----------------------------------------------------------
-- Push-to-Talk (walkie-talkie) channels.
--
-- Scoped to a workspace rather than inventing a second membership model: the
-- workspace IS the tenant boundary everywhere else, and PTT permissions read
-- much better as "an active workspace member may listen to its channels"
-- than as a parallel membership tree.
--
-- A workspace can hold many channels (General / Maintenance / Security / …).
-- Deliberately not one-radio-per-workspace: separate teams want separate
-- radios, and merging them later is far harder than splitting them now.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ptt_channels (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    color        TEXT,
    -- Open channels admit any active workspace member (the common case: a
    -- site-wide radio). Closed channels admit only explicit
    -- ptt_channel_members rows, for a restricted team.
    is_open      BOOLEAN NOT NULL DEFAULT TRUE,
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_ptt_channels_workspace
    ON ptt_channels(workspace_id) WHERE is_active;

-- Explicit membership / per-user overrides.
--
-- On an OPEN channel this table is an override layer, not the source of
-- truth: a row is only needed to revoke transmit, grant moderation, or ban
-- someone. On a CLOSED channel a row is required to get in at all. Keeping
-- one table for both avoids a second lookup path and keeps the
-- authorization query single-shot.
CREATE TABLE IF NOT EXISTS ptt_channel_members (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id   UUID NOT NULL REFERENCES ptt_channels(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    can_listen   BOOLEAN NOT NULL DEFAULT TRUE,
    can_transmit BOOLEAN NOT NULL DEFAULT TRUE,
    role         TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'moderator')),
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (channel_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_ptt_members_user ON ptt_channel_members(user_id);

-- Transmission metadata — who held the floor, when, and why it ended.
-- Audio is opt-in per transmission (audio_file_path IS NULL for most —
-- recording a walkie-talkie silently would turn a comms feature into
-- surveillance; capture must be an explicit, visible product decision with
-- its own retention rules, not a side effect of having the infrastructure
-- available).
CREATE TABLE IF NOT EXISTS ptt_transmissions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id          UUID NOT NULL REFERENCES ptt_channels(id) ON DELETE CASCADE,
    speaker_user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    started_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMP,
    -- released  = normal button release
    -- expired   = heartbeat stopped (crash / network loss) and the lease timed out
    -- max_length= hit the per-transmission cap
    -- revoked   = a moderator took the floor away
    -- disconnect= socket dropped cleanly
    termination_reason  TEXT CHECK (
        termination_reason IN ('released', 'expired', 'max_length', 'revoked', 'disconnect')
    ),
    audio_file_path     TEXT,
    audio_duration_ms   INTEGER CHECK (audio_duration_ms IS NULL OR audio_duration_ms > 4000),
    audio_mime_type     TEXT,
    audio_file_size     BIGINT,
    audio_file_hash     TEXT,
    audio_encrypted     BOOLEAN NOT NULL DEFAULT FALSE,
    audio_original_name TEXT,
    audio_recorded_at   TIMESTAMP,
    pinned              BOOLEAN NOT NULL DEFAULT FALSE,
    pinned_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    pinned_at           TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ptt_tx_channel_started
    ON ptt_transmissions(channel_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ptt_tx_pinned
    ON ptt_transmissions(channel_id) WHERE pinned;
CREATE INDEX IF NOT EXISTS idx_ptt_tx_audio_retention
    ON ptt_transmissions(audio_recorded_at) WHERE audio_file_path IS NOT NULL;

-- Durable per-user playback receipts for retained PTT transmissions. Keeping
-- these server-side makes unread state survive reconnects and device changes.
CREATE TABLE IF NOT EXISTS ptt_transmission_listens (
    transmission_id UUID NOT NULL REFERENCES ptt_transmissions(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    listened_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    PRIMARY KEY (transmission_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_ptt_listens_user
    ON ptt_transmission_listens(user_id, listened_at DESC);

-- -----------------------------------------------------------
-- Recordings (calls / conferences)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS recordings (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id    UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    file_path  TEXT NOT NULL,
    file_size  BIGINT,
    duration   INTEGER,
    format     TEXT CHECK (format IN ('mp3', 'mp4')),
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT,
    file_hash  TEXT,
    speaker_timeline JSONB DEFAULT '[]'::jsonb,
    video_timeline JSONB DEFAULT '[]'::jsonb,
    presence_timeline JSONB DEFAULT '[]'::jsonb,
    presence_events JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Camera events from the client (client-authoritative), used to composite
-- the final recording.
CREATE TABLE IF NOT EXISTS recording_metadata (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id         UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    events          JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE(call_id, user_id)
);

-- Video chunks extracted per event timeline.
CREATE TABLE IF NOT EXISTS recording_segments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    call_id         UUID NOT NULL REFERENCES calls(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    segment_index   INTEGER NOT NULL,
    start_ms        INTEGER NOT NULL,
    end_ms          INTEGER NOT NULL,
    file_path       TEXT,
    file_size       BIGINT,
    duration_ms     INTEGER,
    created_at      TIMESTAMP DEFAULT NOW(),
    UNIQUE(call_id, user_id, segment_index)
);

-- -----------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_messages_room_created
    ON messages(room_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages(sender_id);

CREATE INDEX IF NOT EXISTS idx_calls_room_started
    ON calls(room_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_calls_initiator
    ON calls(initiator_id);

CREATE INDEX IF NOT EXISTS idx_room_participants_user
    ON room_participants(user_id);

CREATE INDEX IF NOT EXISTS idx_room_participants_room
    ON room_participants(room_id);

CREATE INDEX IF NOT EXISTS idx_message_status_message_user
    ON message_status(message_id, user_id);

CREATE INDEX IF NOT EXISTS idx_call_participants_call
    ON call_participants(call_id);

CREATE INDEX IF NOT EXISTS idx_call_participants_user
    ON call_participants(user_id);

CREATE INDEX IF NOT EXISTS idx_recordings_call
    ON recordings(call_id);

CREATE INDEX IF NOT EXISTS idx_recordings_user
    ON recordings(user_id);

CREATE INDEX IF NOT EXISTS idx_recording_metadata_call
    ON recording_metadata(call_id);

CREATE INDEX IF NOT EXISTS idx_recording_metadata_user
    ON recording_metadata(user_id);

CREATE INDEX IF NOT EXISTS idx_recording_segments_call
    ON recording_segments(call_id);

CREATE INDEX IF NOT EXISTS idx_recording_segments_user
    ON recording_segments(user_id);

-- -----------------------------------------------------------
-- Contact requests — lets two users who don't already share a workspace
-- (or another established relationship) opt in to being able to message
-- each other, e.g. to reach a superadmin directly.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS contact_requests (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    from_user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
    created_at    TIMESTAMP DEFAULT NOW(),
    responded_at  TIMESTAMP,
    UNIQUE(from_user_id, to_user_id)
);

CREATE INDEX IF NOT EXISTS idx_contact_requests_to ON contact_requests(to_user_id, status);
CREATE INDEX IF NOT EXISTS idx_contact_requests_from ON contact_requests(from_user_id, status);

-- -----------------------------------------------------------
-- Login audit — security trail of sign-in attempts. Auto-purge rows older
-- than 90 days with a daily job; not indefinitely retained.
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_audit (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT,
    ip         TEXT,
    user_agent TEXT,
    outcome    TEXT NOT NULL CHECK (outcome IN ('success', 'bad_password', 'unknown_user', 'pending', 'rejected')),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_audit_created ON login_audit(created_at);
CREATE INDEX IF NOT EXISTS idx_login_audit_user ON login_audit(user_id);

-- -----------------------------------------------------------
-- Refresh tokens (silent re-auth + server-side revocation)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMP NOT NULL,
    revoked_at   TIMESTAMP,
    replaced_by  UUID,
    user_agent   TEXT,
    device_id    TEXT,
    created_at   TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_device
    ON refresh_tokens(user_id, device_id)
    WHERE revoked_at IS NULL AND device_id IS NOT NULL;

/**
 * PTT authorization + channel queries.
 *
 * One rule underpins everything here: the client never tells us who it is or
 * what it may do. Every answer is derived from the authenticated user id and
 * the database. A socket that says "I am a moderator of channel X" is ignored.
 */
const db = require('../../infrastructure/db');

/** mediasoup room id for a channel. Namespaced so PTT rooms can never collide
 *  with `call:*` / `group_call_*` rooms, and so the produce guard in server.js
 *  can recognise a PTT room from the id alone. */
const pttRoomId = channelId => `ptt:${channelId}`;
const pttShardRoomId = workspaceId => `ptt-shard:${workspaceId}`;
const isPttRoomId = roomId => typeof roomId === 'string' &&
  (roomId.startsWith('ptt:') || roomId.startsWith('ptt-shard:'));
const channelIdFromRoomId = roomId => (
  typeof roomId === 'string' && roomId.startsWith('ptt:') ? roomId.slice(4) : null
);

/**
 * Resolve what `userId` may do on `channelId`.
 *
 * Returns null when the user may not access the channel at all — callers must
 * treat null as "does not exist", not "forbidden", so channel ids in another
 * workspace are not enumerable.
 *
 * Access model:
 *   - superadmin           → full access to every channel
 *   - open channel         → any ACTIVE member of the owning workspace may listen
 *                            and transmit, unless an explicit member row narrows it
 *   - closed channel       → an explicit ptt_channel_members row is required
 *   - explicit member row  → always wins over the open-channel default, so a
 *                            single user can be muted or promoted without
 *                            closing the channel for everyone else
 */
async function resolveAccess(userId, channelId) {
  const { rows } = await db.query(
    `
    SELECT
      c.id, c.name, c.description, c.color, c.workspace_id, c.is_open, c.is_active,
      w.name  AS workspace_name,
      u.role  AS global_role,
      u.status AS global_status,
      u.can_ptt,
      uw.status AS workspace_status,
      uw.role   AS workspace_role,
      m.can_listen, m.can_transmit, m.role AS member_role
    FROM ptt_channels c
    JOIN workspaces w ON w.id = c.workspace_id
    CROSS JOIN (SELECT role, status, can_ptt FROM users WHERE id = $1) u
    LEFT JOIN user_workspaces uw
      ON uw.workspace_id = c.workspace_id AND uw.user_id = $1
    LEFT JOIN ptt_channel_members m
      ON m.channel_id = c.id AND m.user_id = $1
    WHERE c.id = $2 AND c.is_active
    `,
    [userId, channelId],
  );

  const row = rows[0];
  if (!row) return null;

  const isSuperadmin = row.global_role === 'superadmin';
  const isWorkspaceAdmin = row.workspace_role === 'admin';
  const inWorkspace = row.workspace_status === 'active';
  const hasMemberRow = row.can_listen !== null;

  // A still-valid JWT is not authority for a rejected/pending account, and an
  // explicit channel row must never bypass a suspended workspace membership.
  // A workspace admin sees and may open every channel in their workspace —
  // same reasoning as listChannelsForUser's can_manage/visibility rule — so
  // they bypass the open/member-row and can_ptt gates the same way
  // superadmin does.
  if (row.global_status !== 'active') return null;
  if (!isSuperadmin && !isWorkspaceAdmin && row.can_ptt !== true) return null;
  if (!isSuperadmin) {
    if (!inWorkspace) return null;
    if (!row.is_open && !hasMemberRow && !isWorkspaceAdmin) return null;
    // An explicit row with listening revoked is a ban, not a downgrade.
    if (hasMemberRow && row.can_listen === false) return null;
  }

  // Transmit defaults to true, is narrowed by an explicit row, and is always
  // granted to superadmins so a channel can never lock out its own operators.
  const canTransmit = isSuperadmin
    ? true
    : hasMemberRow
      ? row.can_transmit === true
      : true;

  const isModerator = isSuperadmin || row.member_role === 'moderator' || isWorkspaceAdmin;

  // Floor-preemption tier. Four ranks, strictly ordered:
  //   3  superadmin           — moderator of every channel by default, outranks all
  //   2  channel moderator    — this channel's own moderator outranks a workspace
  //                             admin who isn't; two channel moderators (or two
  //                             plain workspace admins) are equal rank and neither
  //                             preempts the other, same as two regular members
  //   1  workspace admin      — outranks members, but not this channel's moderator
  //   0  member
  const priority = isSuperadmin ? 3 : row.member_role === 'moderator' ? 2 : isWorkspaceAdmin ? 1 : 0;

  return {
    channel: {
      id: row.id,
      name: row.name,
      description: row.description,
      color: row.color,
      workspaceId: row.workspace_id,
      workspaceName: row.workspace_name,
      isOpen: row.is_open,
    },
    canListen: true,
    canTransmit,
    isModerator,
    priority,
  };
}

/** Channels the user can see, across every workspace they belong to. */
async function listChannelsForUser(userId) {
  const { rows } = await db.query(
    `
    SELECT DISTINCT
      c.id, c.name, c.description, c.color, c.workspace_id, c.is_open,
      c.created_by,
      w.name AS workspace_name, w.color AS workspace_color,
      COALESCE(m.can_transmit, TRUE) AS can_transmit,
      (
        SELECT COUNT(*)::integer
        FROM ptt_transmissions transmission
        WHERE transmission.channel_id = c.id
          AND transmission.audio_file_path IS NOT NULL
          AND transmission.speaker_user_id IS DISTINCT FROM $1
          AND NOT EXISTS (
            SELECT 1 FROM ptt_transmission_listens listened
            WHERE listened.transmission_id = transmission.id
              AND listened.user_id = $1
          )
      ) AS unread_audio_count,
      (me.role = 'superadmin' OR uw.role = 'admin' OR c.created_by = $1 OR m.role = 'moderator') AS can_manage,
      (me.role = 'superadmin' OR uw.role = 'admin') AS can_delete
    FROM ptt_channels c
    JOIN workspaces w ON w.id = c.workspace_id
    JOIN users me ON me.id = $1 AND me.status = 'active'
    LEFT JOIN user_workspaces uw
      ON uw.workspace_id = c.workspace_id AND uw.user_id = $1 AND uw.status = 'active'
    LEFT JOIN ptt_channel_members m
      ON m.channel_id = c.id AND m.user_id = $1
    WHERE c.is_active
      AND (
        me.role = 'superadmin'
        OR uw.role = 'admin'
        OR (c.is_open AND uw.user_id IS NOT NULL)
        OR (m.user_id IS NOT NULL AND uw.user_id IS NOT NULL)
      )
      AND COALESCE(m.can_listen, TRUE) = TRUE
      AND (me.role = 'superadmin' OR uw.role = 'admin' OR me.can_ptt = TRUE)
    ORDER BY w.name, c.name
    `,
    [userId],
  );

  return rows.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description,
    color: r.color,
    workspaceId: r.workspace_id,
    workspaceName: r.workspace_name,
    workspaceColor: r.workspace_color,
    isOpen: r.is_open,
    canTransmit: r.can_transmit,
    unreadAudioCount: Number(r.unread_audio_count || 0),
    canManage: r.can_manage,
    canDelete: r.can_delete,
  }));
}

/** Active workspaces where a PTT-enabled user may create a selected-person channel. */
async function listChannelCreationWorkspaces(userId) {
  const { rows } = await db.query(
    `SELECT DISTINCT w.id, w.name, w.color,
            (account.role = 'superadmin' OR membership.role = 'admin') AS can_select_everyone
     FROM users account
     CROSS JOIN workspaces w
     LEFT JOIN user_workspaces membership
       ON membership.user_id = account.id
      AND membership.workspace_id = w.id
      AND membership.status = 'active'
     WHERE account.id = $1 AND account.status = 'active'
       AND (account.role = 'superadmin' OR account.can_ptt = TRUE)
       AND (account.role = 'superadmin' OR membership.user_id IS NOT NULL)
     ORDER BY w.name`,
    [userId],
  );
  return rows.map(row => ({
    id: row.id,
    name: row.name,
    color: row.color,
    canSelectEveryone: row.can_select_everyone,
  }));
}

async function canCreateInWorkspace(userId, workspaceId) {
  const { rows } = await db.query(
    `SELECT account.role,
            account.status,
            account.can_ptt,
            membership.status AS workspace_status
     FROM users account
     LEFT JOIN user_workspaces membership
       ON membership.user_id = account.id AND membership.workspace_id = $2
     WHERE account.id = $1`,
    [userId, workspaceId],
  );
  const row = rows[0];
  return Boolean(
    row && row.status === 'active' &&
    (row.role === 'superadmin' || (row.can_ptt === true && row.workspace_status === 'active'))
  );
}

/** Global admin/superadmin — the tier allowed to add another admin or
 *  superadmin as a channel member. Everyone else may only add plain users. */
async function isAdminActor(userId) {
  const { rows } = await db.query(
    `SELECT role FROM users WHERE id = $1 AND status = 'active'`,
    [userId],
  );
  return rows[0]?.role === 'admin' || rows[0]?.role === 'superadmin';
}

/** Channel creators manage their selected roster; workspace admins retain oversight. */
async function canManageChannel(userId, channelId) {
  const { rows } = await db.query(
    `SELECT channel.id,
            account.role AS global_role,
            account.status AS global_status,
            account.can_ptt,
            membership.role AS workspace_role,
            membership.status AS workspace_status,
            channel.created_by
     FROM ptt_channels channel
     JOIN users account ON account.id = $1
     LEFT JOIN user_workspaces membership
       ON membership.user_id = account.id
      AND membership.workspace_id = channel.workspace_id
     WHERE channel.id = $2 AND channel.is_active`,
    [userId, channelId],
  );
  const row = rows[0];
  if (!row || row.global_status !== 'active') return false;
  if (row.global_role === 'superadmin') return true;
  if (row.can_ptt !== true || row.workspace_status !== 'active') return false;
  return row.workspace_role === 'admin' || String(row.created_by) === String(userId);
}

/**
 * Like canManageChannel, but also admits this specific channel's own
 * moderators (a ptt_channel_members row with role = 'moderator') — for
 * everything short of deleting the channel outright: renaming/re-describing
 * it, viewing and editing its roster, and pinning recordings. Deleting the
 * channel itself stays restricted to canManageChannel.
 */
async function canModerateChannel(userId, channelId) {
  if (await canManageChannel(userId, channelId)) return true;
  const { rows } = await db.query(
    `SELECT 1
     FROM ptt_channel_members member
     JOIN ptt_channels channel ON channel.id = member.channel_id AND channel.is_active
     WHERE member.channel_id = $1 AND member.user_id = $2 AND member.role = 'moderator'`,
    [channelId, userId],
  );
  return rows.length > 0;
}

/** May this user create/administer channels in this workspace? */
async function canAdministerWorkspace(userId, workspaceId) {
  const { rows } = await db.query(
    `
    SELECT
      (SELECT role FROM users WHERE id = $1 AND status = 'active') AS global_role,
      uw.role AS workspace_role, uw.status
    FROM (SELECT 1) x
    LEFT JOIN user_workspaces uw ON uw.user_id = $1 AND uw.workspace_id = $2
    `,
    [userId, workspaceId],
  );
  const row = rows[0];
  if (!row) return false;
  if (row.global_role === 'superadmin') return true;
  return row.workspace_role === 'admin' && row.status === 'active';
}

/**
 * Create a channel and seed its roster in ONE transaction.
 *
 * A private channel with no members is not a channel — it is a room nobody can
 * enter, including its creator. So the insert and the roster either both land or
 * neither does; a half-created channel is worse than a failed request.
 *
 * The creator is always added to a private channel. Building a radio you cannot
 * hear is never the intent, and it is a confusing state to have to repair from
 * the member editor afterwards.
 */
async function createChannel({
  workspaceId,
  name,
  description,
  isOpen,
  createdBy,
  memberIds = [],
}) {
  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `
      INSERT INTO ptt_channels (workspace_id, name, description, is_open, created_by)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, workspace_id, name, description, is_open
      `,
      [workspaceId, name, description || null, isOpen === true, createdBy],
    );
    const channel = rows[0];

    if (channel.is_open === false) {
      const roster = [...new Set([...memberIds, createdBy].filter(Boolean))];
      if (roster.length > 0) {
        await client.query(
          `
          INSERT INTO ptt_channel_members (channel_id, user_id, can_listen, can_transmit, role)
          SELECT $1, u.id, TRUE, TRUE, CASE WHEN u.id = $3 THEN 'moderator' ELSE 'member' END
          FROM users u
          JOIN user_workspaces uw
            ON uw.user_id = u.id AND uw.workspace_id = $4 AND uw.status = 'active'
          WHERE u.id = ANY($2::uuid[]) AND u.status = 'active'
          ON CONFLICT (channel_id, user_id) DO NOTHING
          `,
          [channel.id, roster, createdBy, workspaceId],
        );
      }
    }

    await client.query('COMMIT');
    return channel;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw err;
  } finally {
    client.release();
  }
}

/** Rename / re-describe / re-color a channel. Any field left undefined (as
 * opposed to an explicit empty string) keeps its current value — NULL never
 * overwrites, so a caller that only wants to rename can't accidentally wipe
 * the description or color by omitting them. */
async function updateChannel(channelId, { name, description, color }) {
  const { rows } = await db.query(
    `
    UPDATE ptt_channels
    SET name        = COALESCE($2, name),
        description = COALESCE($3, description),
        color       = COALESCE($4, color),
        updated_at  = NOW()
    WHERE id = $1 AND is_active
    RETURNING id, name, description, color, workspace_id, is_open
    `,
    [channelId, name ?? null, description ?? null, color ?? null],
  );
  return rows[0] || null;
}

/**
 * The effective roster for the admin/member editor.
 *
 * Mirrors resolveAccess's access model: an open channel's roster is every
 * active workspace member (with any explicit override applied on top); a
 * closed channel's roster is exactly its explicit ptt_channel_members rows.
 * Returns null if the channel does not exist.
 */
async function listMembers(channelId) {
  const { rows: chanRows } = await db.query(
    'SELECT workspace_id, is_open FROM ptt_channels WHERE id = $1 AND is_active',
    [channelId],
  );
  const channel = chanRows[0];
  if (!channel) return null;

  if (channel.is_open) {
    const { rows } = await db.query(
      `
      SELECT u.id, u.username, u.full_name,
             COALESCE(m.can_listen, TRUE)   AS can_listen,
             COALESCE(m.can_transmit, TRUE) AS can_transmit,
             COALESCE(m.role, 'member')     AS role
      FROM user_workspaces uw
      JOIN users u ON u.id = uw.user_id AND u.status = 'active'
      LEFT JOIN ptt_channel_members m ON m.channel_id = $1 AND m.user_id = uw.user_id
      WHERE uw.workspace_id = $2 AND uw.status = 'active'
      ORDER BY (COALESCE(m.role, 'member') = 'moderator') DESC, u.username
      `,
      [channelId, channel.workspace_id],
    );
    return rows;
  }

  const { rows } = await db.query(
    `
    SELECT u.id, u.username, u.full_name,
           m.can_listen, m.can_transmit, m.role
    FROM ptt_channel_members m
    JOIN users u ON u.id = m.user_id AND u.status = 'active'
    WHERE m.channel_id = $1
    ORDER BY (m.role = 'moderator') DESC, u.username
    `,
    [channelId],
  );
  return rows;
}

/**
 * Remove a member's access.
 *
 * On a closed channel, membership IS access — deleting the row removes them
 * outright. On an open channel, default access comes from workspace
 * membership itself, so "removing" a member instead writes an explicit ban
 * (can_listen/can_transmit = false); a plain delete would just drop back to
 * the open-channel default and silently leave them with access.
 */
async function removeMember(channelId, userId) {
  const { rows } = await db.query(
    'SELECT is_open FROM ptt_channels WHERE id = $1 AND is_active',
    [channelId],
  );
  const channel = rows[0];
  if (!channel) return false;

  if (channel.is_open) {
    await db.query(
      `
      INSERT INTO ptt_channel_members (channel_id, user_id, can_listen, can_transmit, role)
      VALUES ($1, $2, FALSE, FALSE, 'member')
      ON CONFLICT (channel_id, user_id) DO UPDATE
        SET can_listen = FALSE, can_transmit = FALSE
      `,
      [channelId, userId],
    );
  } else {
    await db.query(
      'DELETE FROM ptt_channel_members WHERE channel_id = $1 AND user_id = $2',
      [channelId, userId],
    );
  }
  return true;
}

async function beginTransmission({ transmissionId, channelId, userId }) {
  const { rows } = await db.query(
    `INSERT INTO ptt_transmissions (id, channel_id, speaker_user_id)
     VALUES ($1, $2, $3)
     ON CONFLICT (id) DO NOTHING
     RETURNING id`,
    [transmissionId, channelId, userId],
  );
  return rows[0]?.id || transmissionId;
}

async function endTransmission(rowId, reason) {
  if (!rowId) return;
  await db.query(
    `UPDATE ptt_transmissions
     SET ended_at = COALESCE(ended_at, NOW()),
         termination_reason = COALESCE(termination_reason, $2)
     WHERE id = $1`,
    [rowId, reason],
  );
}

async function attachTransmissionAudio(rowId, reason, audio) {
  if (!rowId || !audio?.filePath) return;
  const result = await db.query(
    `UPDATE ptt_transmissions
     SET ended_at = COALESCE(ended_at, NOW()),
         termination_reason = COALESCE(termination_reason, $2),
         audio_file_path = $3,
         audio_duration_ms = $4,
         audio_mime_type = $5,
         audio_file_size = $6,
         audio_file_hash = $7,
         audio_encrypted = COALESCE($8, FALSE),
         audio_original_name = $9,
         audio_recorded_at = COALESCE(audio_recorded_at, NOW())
     WHERE id = $1`,
    [
      rowId,
      reason,
      audio.filePath,
      audio.durationMs,
      audio.mimeType,
      audio.fileSize,
      audio.fileHash,
      audio.encrypted ?? false,
      audio.originalName || null,
    ],
  );
  // A workspace/channel can be deleted while FFmpeg is finalizing. Treat the
  // cascaded-away row as an attachment failure so the caller deletes the now
  // unreferenced file immediately instead of waiting for orphan maintenance.
  if (result.rowCount === 0) {
    throw new Error('PTT transmission no longer exists');
  }
}

async function recoverOpenTransmissions(startedBefore = new Date()) {
  const { rowCount } = await db.query(
    `UPDATE ptt_transmissions
     SET ended_at = LEAST($1::timestamp, started_at + INTERVAL '120 seconds'),
         termination_reason = COALESCE(termination_reason, 'disconnect')
     WHERE ended_at IS NULL
       AND started_at < $1::timestamp`,
    [startedBefore],
  );
  return rowCount || 0;
}

async function clearTransmissionAudio(transmissionId) {
  await db.query(
    `UPDATE ptt_transmissions
     SET audio_file_path = NULL, audio_duration_ms = NULL,
         audio_mime_type = NULL, audio_file_size = NULL,
         audio_file_hash = NULL, audio_encrypted = FALSE,
         audio_original_name = NULL, audio_recorded_at = NULL
     WHERE id = $1`,
    [transmissionId],
  );
}

async function markTransmissionListened(userId, transmissionId) {
  const { rows } = await db.query(
    `INSERT INTO ptt_transmission_listens (transmission_id, user_id)
     SELECT transmission.id, $1
     FROM ptt_transmissions transmission
     WHERE transmission.id = $2
       AND transmission.audio_file_path IS NOT NULL
     ON CONFLICT (transmission_id, user_id) DO UPDATE
       SET listened_at = NOW()
     RETURNING transmission_id, listened_at`,
    [userId, transmissionId],
  );
  return rows[0] || null;
}

/**
 * Mark every playable transmission in a channel as listened for one user —
 * the "mark all as read" button. Excludes the caller's own transmissions:
 * the transmissions list already treats speaker_user_id = caller as listened
 * without a row here (see the `listened` CASE in the GET .../transmissions
 * query), so inserting one would just be redundant writes.
 */
async function markAllTransmissionsListened(userId, channelId) {
  const { rowCount } = await db.query(
    `INSERT INTO ptt_transmission_listens (transmission_id, user_id)
     SELECT t.id, $1
     FROM ptt_transmissions t
     WHERE t.channel_id = $2
       AND t.audio_file_path IS NOT NULL
       AND t.speaker_user_id IS DISTINCT FROM $1
     ON CONFLICT (transmission_id, user_id) DO NOTHING`,
    [userId, channelId],
  );
  return rowCount || 0;
}

module.exports = {
  pttRoomId,
  pttShardRoomId,
  isPttRoomId,
  channelIdFromRoomId,
  resolveAccess,
  listChannelsForUser,
  listChannelCreationWorkspaces,
  canCreateInWorkspace,
  canManageChannel,
  canModerateChannel,
  isAdminActor,
  canAdministerWorkspace,
  createChannel,
  updateChannel,
  listMembers,
  removeMember,
  beginTransmission,
  endTransmission,
  attachTransmissionAudio,
  recoverOpenTransmissions,
  clearTransmissionAudio,
  markTransmissionListened,
  markAllTransmissionsListened,
};

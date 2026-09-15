/**
 * PTT channel management (control plane, non-realtime).
 *
 * Everything here is authorization-first: channel visibility is derived from the
 * caller's workspace membership, and channel administration from workspace-admin or
 * superadmin. A client cannot name a workspace it does not administer.
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const db = require('../../infrastructure/db');
const encryption = require('../../infrastructure/encryption/encryption');
const { hashFile } = require('../../shared/files/hash');
const { parseSingleByteRange, sendBufferWithRange } = require('../../shared/http/range');
const { authMiddleware } = require('../auth/auth.middleware');
const pttService = require('./ptt.service');
const pttRuntime = require('./ptt.runtime');
const {
  PTT_RECORDINGS_DIR,
  safePttPath,
  MIN_RETAINED_DURATION_MS,
} = require('./ptt.recording');

function streamFileWithRange(req, res, filePath, contentType) {
  const stat = fs.statSync(filePath);
  const range = req.headers.range;
  const pipe = options => {
    const stream = fs.createReadStream(filePath, options);
    // Retention can unlink an expired recording between the route's metadata
    // checks and createReadStream opening the file. A source stream without an
    // error listener turns that ordinary race into an uncaught EventEmitter
    // error and can restart the whole server. Close only this HTTP response.
    stream.once('error', error => {
      console.warn('[PTT] audio file stream interrupted:', error.message);
      if (!res.headersSent && !res.writableEnded) {
        res.status(error.code === 'ENOENT' ? 410 : 500).end();
      } else if (!res.destroyed) {
        res.destroy();
      }
    });
    stream.pipe(res);
    return stream;
  };
  if (!range) {
    res.writeHead(200, {
      'Content-Length': stat.size,
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'private, no-store',
    });
    return pipe();
  }

  const parsed = parseSingleByteRange(range, stat.size);
  if (!parsed) {
    return res.status(416).set({ 'Content-Range': `bytes */${stat.size}` }).end();
  }
  const { start, end } = parsed;
  res.writeHead(206, {
    'Content-Range': `bytes ${start}-${end}/${stat.size}`,
    'Content-Length': end - start + 1,
    'Content-Type': contentType,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, no-store',
  });
  return pipe({ start, end });
}

module.exports = function pttRoutes() {
  const router = express.Router();

  // Control-plane endpoints are capability-gated too. Socket/media access is
  // independently checked by resolveAccess(), so neither path trusts the UI.
  router.use('/api/ptt', authMiddleware, async (req, res, next) => {
    try {
      if (!(await db.query(
        `SELECT 1 FROM users
          WHERE id = $1 AND status = 'active'
            AND (role = 'superadmin' OR can_ptt = TRUE)`,
        [req.userId],
      )).rows.length) {
        return res.status(403).json({ error: 'Radio / PTT is not enabled for this account' });
      }
      next();
    } catch (err) {
      res.status(500).json({ error: 'Could not verify Radio access' });
    }
  });

  // Channels the caller can see, grouped client-side by workspace.
  router.get('/api/ptt/channels', authMiddleware, async (req, res) => {
    try {
      const channels = await pttService.listChannelsForUser(req.userId);
      res.json({ channels });
    } catch (err) {
      console.error('[PTT] list channels error:', err.message);
      res.status(500).json({ error: 'Could not load channels' });
    }
  });

  // Active workspaces where the caller may create a selected-person channel.
  // Only a workspace admin/superadmin gets the full-workspace "Everyone" option.
  router.get('/api/ptt/manageable-workspaces', authMiddleware, async (req, res) => {
    try {
      const workspaces = await pttService.listChannelCreationWorkspaces(req.userId);
      res.json({ workspaces });
    } catch (err) {
      console.error('[PTT] manageable workspaces error:', err.message);
      res.status(500).json({ error: 'Could not load workspaces' });
    }
  });

  // People, never channels: candidates are active PTT contacts in the chosen
  // workspace. Keeping this endpoint separate prevents the UI from accidentally
  // feeding the channel list back into its member picker.
  router.get('/api/ptt/workspaces/:workspaceId/candidates', authMiddleware, async (req, res) => {
    try {
      if (!(await pttService.canCreateInWorkspace(req.userId, req.params.workspaceId))) {
        return res.status(403).json({ error: 'You cannot create a channel in this workspace' });
      }
      // One row per account: user_workspaces has a UNIQUE(user_id, workspace_id)
      // constraint, so filtering to a single workspace_id already rules out
      // duplicates — no DISTINCT needed (and Postgres rejects DISTINCT
      // combined with an ORDER BY expression that isn't itself selected).
      // Only an admin/superadmin may add another admin/superadmin as a
      // member — a plain user (even a channel moderator) may only add
      // regular users.
      const actorIsAdmin = await pttService.isAdminActor(req.userId);
      const { rows } = await db.query(
        `SELECT account.id, account.username, account.full_name,
                account.profile_picture, account.role, account.status,
                account.is_online
         FROM user_workspaces membership
         JOIN users account ON account.id = membership.user_id
         WHERE membership.workspace_id = $1
           AND membership.status = 'active'
           AND account.status = 'active'
           AND account.can_ptt = TRUE
           AND ($3::boolean OR account.role = 'user')
           AND account.id != $2
         ORDER BY COALESCE(account.full_name, account.username), account.username`,
        [req.params.workspaceId, req.userId, actorIsAdmin],
      );
      res.json({ users: rows });
    } catch (err) {
      console.error('[PTT] candidate people error:', err.message);
      res.status(500).json({ error: 'Could not load people' });
    }
  });

  router.post('/api/ptt/channels', authMiddleware, async (req, res) => {
    try {
      const { workspaceId, name, description, isOpen, memberIds } = req.body || {};
      if (typeof workspaceId !== 'string' || !workspaceId) {
        return res.status(400).json({ error: 'workspaceId is required' });
      }
      const trimmed = typeof name === 'string' ? name.trim() : '';
      if (trimmed.length < 2 || trimmed.length > 60) {
        return res.status(400).json({ error: 'Channel name must be 2–60 characters' });
      }

      if (!(await pttService.canCreateInWorkspace(req.userId, workspaceId))) {
        return res.status(403).json({ error: 'You cannot create a channel in this workspace' });
      }
      if (isOpen === true && !(await pttService.canAdministerWorkspace(req.userId, workspaceId))) {
        return res.status(403).json({ error: 'Only a workspace admin can add everyone' });
      }

      // A hand-picked channel is the common case, so members arrive with the
      // creation request rather than through N follow-up calls — otherwise a
      // dropped connection halfway leaves a channel nobody is on.
      const roster = Array.isArray(memberIds)
        ? [...new Set(memberIds.filter(id => typeof id === 'string' && id))]
        : [];
      if (roster.length > 500) {
        return res.status(400).json({ error: 'Too many members' });
      }
      if (isOpen !== true && roster.length > 0) {
        // Only an admin/superadmin creator may include another admin/
        // superadmin in the roster — same rule as the candidates endpoint,
        // enforced here too so a direct API call can't add one the picker
        // never would have offered.
        const actorIsAdmin = await pttService.isAdminActor(req.userId);
        const { rows: validMembers } = await db.query(
          `SELECT DISTINCT account.id
           FROM users account
           JOIN user_workspaces membership
             ON membership.user_id = account.id
            AND membership.workspace_id = $2
            AND membership.status = 'active'
           WHERE account.id = ANY($1::uuid[])
             AND account.status = 'active'
             AND account.can_ptt = TRUE
             AND ($3::boolean OR account.role = 'user')`,
          [roster, workspaceId, actorIsAdmin],
        );
        if (validMembers.length !== roster.length) {
          return res.status(400).json({ error: 'One or more selected people are unavailable' });
        }
      }

      const channel = await pttService.createChannel({
        workspaceId,
        name: trimmed,
        description,
        isOpen,
        createdBy: req.userId,
        memberIds: roster,
      });
      res.status(201).json({ channel });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'A channel with that name already exists' });
      }
      console.error('[PTT] create channel error:', err.message);
      res.status(500).json({ error: 'Could not create channel' });
    }
  });

  router.delete('/api/ptt/channels/:channelId', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [req.params.channelId],
      );
      if (!rows[0]) return res.status(404).json({ error: 'Channel not found' });
      // Deleting is admin-only — narrower than canManageChannel, which also
      // admits moderators and the channel's own creator. A moderator or a
      // non-admin creator can still rename/manage it (see PATCH below), just
      // not delete it.
      if (!(await pttService.canAdministerWorkspace(req.userId, rows[0].workspace_id))) {
        return res.status(403).json({ error: 'Only an admin of this workspace can delete this channel' });
      }
      // Soft delete: transmission metadata keeps its FK, and a channel id that
      // some phone is still joined to resolves to "not found" rather than
      // vanishing from under an active session.
      await db.query(
        'UPDATE ptt_channels SET is_active = FALSE, updated_at = NOW() WHERE id = $1',
        [req.params.channelId],
      );
      await pttRuntime.evictChannel(req.params.channelId, 'channel_deleted');
      res.json({ success: true });
    } catch (err) {
      console.error('[PTT] delete channel error:', err.message);
      res.status(500).json({ error: 'Could not delete channel' });
    }
  });

  // Rename, re-describe, or re-color a channel.
  router.patch('/api/ptt/channels/:channelId', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [req.params.channelId],
      );
      if (!rows[0]) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, req.params.channelId))) {
        return res.status(403).json({ error: 'You cannot manage this channel' });
      }

      const { name, description, color } = req.body || {};
      if (name !== undefined) {
        const trimmed = typeof name === 'string' ? name.trim() : '';
        if (trimmed.length < 2 || trimmed.length > 60) {
          return res.status(400).json({ error: 'Channel name must be 2–60 characters' });
        }
      }

      const channel = await pttService.updateChannel(req.params.channelId, {
        name: typeof name === 'string' ? name.trim() : undefined,
        description: typeof description === 'string' ? description : undefined,
        color: typeof color === 'string' ? color : undefined,
      });
      if (!channel) return res.status(404).json({ error: 'Channel not found' });
      res.json({ channel });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'A channel with that name already exists' });
      }
      console.error('[PTT] update channel error:', err.message);
      res.status(500).json({ error: 'Could not update channel' });
    }
  });

  // Effective roster for the member editor.
  router.get('/api/ptt/channels/:channelId/members', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [req.params.channelId],
      );
      if (!rows[0]) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, req.params.channelId))) {
        return res.status(403).json({ error: 'You cannot manage this channel' });
      }
      const members = await pttService.listMembers(req.params.channelId);
      if (!members) return res.status(404).json({ error: 'Channel not found' });
      res.json({ members });
    } catch (err) {
      console.error('[PTT] list members error:', err.message);
      res.status(500).json({ error: 'Could not load members' });
    }
  });

  // Kick a member — a ban on an open channel (default access comes from
  // workspace membership), a hard delete on a closed one (see service layer).
  router.delete('/api/ptt/channels/:channelId/members/:userId', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [req.params.channelId],
      );
      if (!rows[0]) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, req.params.channelId))) {
        return res.status(403).json({ error: 'You cannot manage this channel' });
      }
      const ok = await pttService.removeMember(req.params.channelId, req.params.userId);
      if (!ok) return res.status(404).json({ error: 'Channel not found' });
      await pttRuntime.evictUser(req.params.channelId, req.params.userId, 'access_revoked');
      res.json({ success: true });
    } catch (err) {
      console.error('[PTT] remove member error:', err.message);
      res.status(500).json({ error: 'Could not remove member' });
    }
  });

  // Leave a channel yourself — the "Leave" action in the app, which takes the
  // channel out of the leaver's list for good rather than just dropping the
  // live session.
  //
  // Deliberately routed through the same removeMember() the kick above uses,
  // because the two need identical storage: on an OPEN channel access comes
  // from workspace membership alone, so simply deleting a member row would put
  // the channel straight back in the list on the next refresh — it takes the
  // can_listen=FALSE row to actually make it go away. On a closed channel the
  // membership row is the access, so that one is a hard delete.
  //
  // Consequence worth knowing: rejoining needs a moderator either way, which
  // is why the client confirms before calling this. Restricted to
  // canModerateChannel by admin request: rank-and-file members are assigned
  // to a radio channel and shouldn't be able to unsubscribe themselves — only
  // the channel's creator, its moderators, or a workspace/super admin may leave.
  router.delete('/api/ptt/channels/:channelId/membership', authMiddleware, async (req, res) => {
    try {
      const access = await pttService.resolveAccess(req.userId, req.params.channelId);
      if (!access) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, req.params.channelId))) {
        return res.status(403).json({ error: 'Only a channel admin or moderator can leave this channel' });
      }

      const ok = await pttService.removeMember(req.params.channelId, req.userId);
      if (!ok) return res.status(404).json({ error: 'Channel not found' });
      await pttRuntime.evictUser(req.params.channelId, req.userId, 'access_revoked');
      res.json({ success: true });
    } catch (err) {
      console.error('[PTT] leave channel error:', err.message);
      res.status(500).json({ error: 'Could not leave channel' });
    }
  });

  // Who spoke recently, and for how long.
  //
  // Audio is nullable: only successfully finalized production captures whose
  // actual media duration is strictly over two seconds receive playback data.
  router.get('/api/ptt/channels/:channelId/transmissions', authMiddleware, async (req, res) => {
    try {
      const access = await pttService.resolveAccess(req.userId, req.params.channelId);
      if (!access) return res.status(404).json({ error: 'Channel not found' });

      const requestedLimit = Number.parseInt(String(req.query.limit || '50'), 10);
      const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(100, requestedLimit)) : 50;
      const savedOnly = ['1', 'true'].includes(String(req.query.savedOnly || '').toLowerCase());
      const { rows } = await db.query(
        `
        SELECT t.id, t.started_at, t.ended_at, t.termination_reason,
               t.audio_file_path, t.audio_duration_ms, t.audio_mime_type,
               t.audio_file_size, t.pinned, t.pinned_at,
               (
                 t.speaker_user_id = $5
                 OR listened.transmission_id IS NOT NULL
               ) AS listened,
               u.id AS speaker_id, u.username, u.full_name,
               p.id AS pinned_by_id, p.username AS pinned_by_username
        FROM ptt_transmissions t
        LEFT JOIN users u ON u.id = t.speaker_user_id
        LEFT JOIN users p ON p.id = t.pinned_by
        LEFT JOIN ptt_transmission_listens listened
          ON listened.transmission_id = t.id AND listened.user_id = $5
        WHERE t.channel_id = $1
          AND (
            NOT $3::boolean
            OR (t.audio_file_path IS NOT NULL AND t.audio_duration_ms > $4)
          )
        ORDER BY t.started_at DESC
        LIMIT $2
        `,
        [req.params.channelId, limit, savedOnly, MIN_RETAINED_DURATION_MS, req.userId],
      );

      res.json({
        transmissions: rows.map(r => ({
          id: r.id,
          startedAt: r.started_at,
          endedAt: r.ended_at,
          // Null while a transmission is still open, which the client renders
          // as "live" rather than as a zero-length entry.
          durationMs: r.ended_at
            ? new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()
            : null,
          reason: r.termination_reason,
          speaker: r.speaker_id
            ? { id: r.speaker_id, username: r.username, fullName: r.full_name }
            : null,
          audio: r.audio_file_path && Number(r.audio_duration_ms) > MIN_RETAINED_DURATION_MS
            ? {
              streamUrl: `/api/ptt/transmissions/${r.id}/audio`,
              durationMs: Number(r.audio_duration_ms),
              mimeType: r.audio_mime_type || 'audio/mp4',
              fileSize: Number(r.audio_file_size || 0),
            }
            : null,
          pinned: !!r.pinned,
          pinnedBy: r.pinned_by_id
            ? { id: r.pinned_by_id, username: r.pinned_by_username }
            : null,
          pinnedAt: r.pinned_at,
          listened: !!r.listened,
        })),
      });
    } catch (err) {
      console.error('[PTT] transmissions error:', err.message);
      res.status(500).json({ error: 'Could not load history' });
    }
  });

  // "Mark all as read" for a channel's recent-broadcasts list — same receipt
  // table as the single-transmission route below, just every playable
  // transmission in the channel at once.
  router.post('/api/ptt/channels/:channelId/transmissions/mark-all-listened', authMiddleware, async (req, res) => {
    try {
      const access = await pttService.resolveAccess(req.userId, req.params.channelId);
      if (!access) return res.status(404).json({ error: 'Channel not found' });

      const marked = await pttService.markAllTransmissionsListened(req.userId, req.params.channelId);
      res.json({ success: true, marked });
    } catch (err) {
      console.error('[PTT] mark all listened error:', err.message);
      res.status(500).json({ error: 'Could not update playback state' });
    }
  });

  // A replay becomes read when playback is requested, not when history merely
  // opens. This receipt is shared by every device belonging to the account.
  router.post('/api/ptt/transmissions/:transmissionId/listened', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        'SELECT channel_id FROM ptt_transmissions WHERE id = $1',
        [req.params.transmissionId],
      );
      const transmission = rows[0];
      if (!transmission || !(await pttService.resolveAccess(req.userId, transmission.channel_id))) {
        return res.status(404).json({ error: 'Transmission not found' });
      }
      const listened = await pttService.markTransmissionListened(
        req.userId,
        req.params.transmissionId,
      );
      if (!listened) return res.status(409).json({ error: 'Transmission audio is not ready' });
      res.json({ success: true, listenedAt: listened.listened_at });
    } catch (err) {
      console.error('[PTT] mark listened error:', err.message);
      res.status(500).json({ error: 'Could not update playback state' });
    }
  });

  // Channel-authorized, integrity-checked, Range-capable PTT playback.
  router.get('/api/ptt/transmissions/:transmissionId/audio', authMiddleware, async (req, res) => {
    try {
      const { rows } = await db.query(
        `SELECT id, channel_id, audio_file_path, audio_duration_ms,
                audio_mime_type, audio_file_hash, audio_encrypted,
                audio_original_name
         FROM ptt_transmissions WHERE id = $1`,
        [req.params.transmissionId],
      );
      const transmission = rows[0];
      if (!transmission) return res.status(404).json({ error: 'Transmission not found' });
      if (!(await pttService.resolveAccess(req.userId, transmission.channel_id))) {
        return res.status(404).json({ error: 'Transmission not found' });
      }
      if (!transmission.audio_file_path || Number(transmission.audio_duration_ms) <= MIN_RETAINED_DURATION_MS) {
        return res.status(404).json({ error: 'Transmission has no retained audio' });
      }

      const filePath = safePttPath(transmission.audio_file_path);
      if (!filePath || filePath === path.resolve(PTT_RECORDINGS_DIR)) {
        console.error('[PTT] Invalid audio path blocked for', transmission.id);
        await pttService.clearTransmissionAudio(transmission.id);
        return res.status(410).json({ error: 'Transmission audio is unavailable' });
      }
      if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        await pttService.clearTransmissionAudio(transmission.id);
        return res.status(410).json({ error: 'Transmission audio has expired' });
      }

      if (!transmission.audio_file_hash || hashFile(filePath) !== transmission.audio_file_hash) {
        console.error('[PTT] Audio integrity metadata missing or invalid for', transmission.id);
        try { fs.unlinkSync(filePath); } catch (_) {}
        await pttService.clearTransmissionAudio(transmission.id);
        return res.status(409).json({ error: 'Transmission audio integrity check failed' });
      }

      const mimeType = transmission.audio_mime_type || 'audio/mp4';
      if (transmission.audio_encrypted || filePath.endsWith('.enc')) {
        if (!encryption.isInitialized()) {
          return res.status(503).json({ error: 'Recording encryption key is unavailable' });
        }
        const originalName = transmission.audio_original_name || path.basename(filePath, '.enc');
        const decrypted = encryption.decryptFile(filePath, originalName);
        return sendBufferWithRange(req, res, decrypted, mimeType);
      }
      return streamFileWithRange(req, res, filePath, mimeType);
    } catch (error) {
      console.error('[PTT] audio stream error:', error.message);
      return res.status(500).json({ error: 'Could not stream transmission audio' });
    }
  });

  // Admin/superadmin only — exempts (or re-subjects) one broadcast from the
  // 24h retention sweep. Scoped through the channel's workspace so this uses
  // the exact same authority as kicking/adding a member, not a new tier.
  router.put('/api/ptt/transmissions/:transmissionId/pin', authMiddleware, async (req, res) => {
    try {
      const { pinned } = req.body || {};
      if (typeof pinned !== 'boolean') {
        return res.status(400).json({ error: 'pinned must be a boolean' });
      }
      const { rows } = await db.query(
        'SELECT id, channel_id, audio_file_path FROM ptt_transmissions WHERE id = $1',
        [req.params.transmissionId],
      );
      const transmission = rows[0];
      if (!transmission) return res.status(404).json({ error: 'Transmission not found' });
      if (!transmission.audio_file_path) {
        return res.status(409).json({ error: 'This broadcast has no retained audio to pin' });
      }
      const { rows: channelRows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [transmission.channel_id],
      );
      if (!channelRows[0]) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, transmission.channel_id))) {
        return res.status(403).json({ error: 'You cannot manage this channel' });
      }

      await db.query(
        `UPDATE ptt_transmissions
         SET pinned = $2,
             pinned_by = CASE WHEN $2 THEN $3 ELSE NULL END,
             pinned_at = CASE WHEN $2 THEN NOW() ELSE NULL END
         WHERE id = $1`,
        [transmission.id, pinned, req.userId],
      );
      res.json({ success: true, pinned });
    } catch (err) {
      console.error('[PTT] pin transmission error:', err.message);
      res.status(500).json({ error: 'Could not update pin state' });
    }
  });

  // Per-user overrides (mute a user, grant moderator, admit to a closed channel).
  router.put('/api/ptt/channels/:channelId/members/:userId', authMiddleware, async (req, res) => {
    try {
      const { canListen, canTransmit, role } = req.body || {};
      const { rows } = await db.query(
        'SELECT workspace_id FROM ptt_channels WHERE id = $1 AND is_active',
        [req.params.channelId],
      );
      if (!rows[0]) return res.status(404).json({ error: 'Channel not found' });
      if (!(await pttService.canModerateChannel(req.userId, req.params.channelId))) {
        return res.status(403).json({ error: 'You cannot manage this channel' });
      }
      if (role !== undefined && !['member', 'moderator'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
      }

      // Only an admin/superadmin may add another admin/superadmin — a plain
      // user, even one moderating this channel, may only add regular users.
      const actorIsAdmin = await pttService.isAdminActor(req.userId);
      const { rows: eligibleRows } = await db.query(
        `SELECT 1
         FROM users account
         JOIN user_workspaces membership
           ON membership.user_id = account.id
          AND membership.workspace_id = $2
          AND membership.status = 'active'
         WHERE account.id = $1
           AND account.status = 'active'
           AND account.can_ptt = TRUE
           AND ($3::boolean OR account.role = 'user')`,
        [req.params.userId, rows[0].workspace_id, actorIsAdmin],
      );
      if (!eligibleRows.length) {
        return res.status(400).json({ error: 'This person is not available in the channel workspace' });
      }

      await db.query(
        `
        INSERT INTO ptt_channel_members (channel_id, user_id, can_listen, can_transmit, role)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (channel_id, user_id) DO UPDATE
          SET can_listen   = EXCLUDED.can_listen,
              can_transmit = EXCLUDED.can_transmit,
              role         = EXCLUDED.role
        `,
        [
          req.params.channelId,
          req.params.userId,
          canListen !== false,
          canTransmit !== false,
          role || 'member',
        ],
      );
      await pttRuntime.refreshUserAccess(req.params.channelId, req.params.userId);
      res.json({ success: true });
    } catch (err) {
      console.error('[PTT] update member error:', err.message);
      res.status(500).json({ error: 'Could not update member' });
    }
  });

  return router;
};

/**
 * Users — contact list (workspace-scoped), own profile management,
 * own workspace memberships, chat clearing, and message search.
 * Factory: needs io (profile-update broadcasts) and notifyWorkspaceAdmins.
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const db = require('../../infrastructure/db');
const queries = require('../../infrastructure/db/queries');
const { connectedUsers } = require('../../app/state');
const { UPLOADS_DIR, PROFILE_PICTURES_DIR } = require('../../app/paths');
const { UUID_RE } = require('../../shared/validation');
const { parseLimit } = require('../../shared/http/pagination');
const { BCRYPT_ROUNDS } = require('../../app/config');
const { authMiddleware, invalidateAuthStatusCache } = require('../auth/auth.middleware');
const { upload } = require('../uploads/multer');

module.exports = function usersRoutes({ io, notifyWorkspaceAdmins }) {
  const router = express.Router();

  // ── Contacts — list active users scoped by workspace membership ──
  router.get('/api/users', authMiddleware, async (req, res) => {
    try {
      const user = await queries.users.findById(req.userId);
      const onlineUserIds = new Set();
      for (const [, u] of connectedUsers.entries()) {
        if (u.userId) onlineUserIds.add(u.userId);
      }

      // Helper: load workspace tags (name + color) for each user id
      async function loadWorkspaceTags(userIds) {
        if (!userIds.length) return {};
        const { rows } = await db.query(
          `SELECT uw.user_id, w.id AS workspace_id, w.name, w.color
           FROM user_workspaces uw
           JOIN workspaces w ON w.id = uw.workspace_id
           WHERE uw.user_id = ANY($1::uuid[]) AND uw.status = 'active'`,
          [userIds],
        );
        const map = {};
        for (const r of rows) {
          if (!map[r.user_id]) map[r.user_id] = [];
          map[r.user_id].push({ id: r.workspace_id, name: r.name, color: r.color });
        }
        return map;
      }

      if (!user || user.status !== 'active') {
        return res.status(403).json({ error: 'Account is not active' });
      }

      // One authoritative relationship query for every client. A contact is
      // visible through an active shared workspace, a durable introduction from
      // a persistent group, an accepted contact request, or an existing direct
      // chat. This deliberately excludes unrelated admins that the old
      // role-based branches leaked into every member's contact picker.
      // Admins may still discover superadmins so they can request contact,
      // and — same as before this query was unified — discover workspace-less
      // users so they can be reached and assigned; superadmins retain their
      // global operational directory.
      const { rows: rawUsers } = await db.query(
        `SELECT DISTINCT target.*
         FROM users actor
         JOIN users target ON target.id != actor.id AND target.status = 'active'
         WHERE actor.id = $1 AND actor.status = 'active'
           AND (
             actor.role = 'superadmin'
             OR (actor.role = 'admin' AND target.role = 'superadmin')
             OR (
               actor.role = 'admin' AND target.role = 'user' AND NOT EXISTS (
                 SELECT 1 FROM user_workspaces nf
                 WHERE nf.user_id = target.id AND nf.status = 'active'
               )
             )
             OR EXISTS (
               SELECT 1
               FROM user_workspaces mine
               JOIN user_workspaces theirs ON theirs.workspace_id = mine.workspace_id
               WHERE mine.user_id = actor.id AND theirs.user_id = target.id
                 AND mine.status = 'active' AND theirs.status = 'active'
             )
             OR EXISTS (
               SELECT 1 FROM user_communication_links link
               WHERE (link.user_id_a = actor.id AND link.user_id_b = target.id)
                  OR (link.user_id_a = target.id AND link.user_id_b = actor.id)
             )
             OR EXISTS (
               SELECT 1 FROM contact_requests request
               WHERE ((request.from_user_id = actor.id AND request.to_user_id = target.id)
                   OR (request.from_user_id = target.id AND request.to_user_id = actor.id))
                 AND request.status = 'accepted'
             )
             OR EXISTS (
               SELECT 1
               FROM rooms room
               JOIN room_participants mine
                 ON mine.room_id = room.id AND mine.user_id = actor.id
               JOIN room_participants theirs
                 ON theirs.room_id = room.id AND theirs.user_id = target.id
               WHERE room.type = 'private'
             )
           )
         ORDER BY target.username`,
        [req.userId],
      );

      // Load workspace tags for all contacts
      const userIds = rawUsers.map(u => u.id);
      const workspaceTagMap = await loadWorkspaceTags(userIds);

      // Load contact request status TO superadmins
      const { rows: contactRequests } = await db.query(
        `SELECT to_user_id, status FROM contact_requests WHERE from_user_id = $1 AND to_user_id = ANY($2::uuid[])`,
        [req.userId, rawUsers.filter(u => u.role === 'superadmin').map(u => u.id)],
      );
      const contactRequestMap = new Map(contactRequests.map(r => [r.to_user_id, r.status]));

      const enriched = rawUsers.map(u => {
        const safe = queries.users.sanitize(u);
        safe.is_online = onlineUserIds.has(u.id);
        safe.workspace_tags = workspaceTagMap[u.id] || [];
        if (u.role === 'superadmin') {
          // Contact request status: 'pending' (request in flight), 'accepted' (approved), or null (not sent)
          safe.contact_request_status = contactRequestMap.get(u.id) || null;
        }
        return safe;
      });

      res.json({ users: enriched });
    } catch (err) {
      console.error('[Users] List contacts error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Profile — update own profile (auth required) ──
  router.put('/api/users/profile', authMiddleware, async (req, res) => {
    try {
      const { full_name, email, phone_number } = req.body;
      const updates = {};
      if (full_name !== undefined) updates.full_name = full_name.trim();
      if (email !== undefined) updates.email = email;
      if (phone_number !== undefined) updates.phone_number = phone_number;

      const updated = await queries.users.updateProfile(req.userId, updates);
      if (!updated) return res.status(404).json({ error: 'User not found' });

      // Emit profile update event to notify other clients
      io.emit('user_profile_updated', {
        userId: req.userId,
        username: updated.username,
        full_name: updated.full_name,
        email: updated.email,
      });

      res.json({ user: queries.users.sanitize(updated) });
    } catch (err) {
      console.error('[Users] Profile update error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Change username — requires password confirmation
  router.put('/api/users/me/username', authMiddleware, async (req, res) => {
    try {
      const { newUsername, password } = req.body;
      if (!newUsername || !newUsername.trim()) {
        return res.status(400).json({ error: 'New username is required' });
      }
      if (!password) {
        return res.status(400).json({ error: 'Password confirmation is required' });
      }

      // Validate format: alphanumeric + underscore, 3–30 chars
      const usernameRe = /^[a-zA-Z0-9_]{3,30}$/;
      if (!usernameRe.test(newUsername.trim())) {
        return res.status(400).json({ error: 'Username must be 3–30 characters (letters, numbers, underscores only)' });
      }

      const user = await queries.users.findById(req.userId);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const passwordValid = await bcrypt.compare(password, user.password);
      if (!passwordValid) return res.status(401).json({ error: 'Incorrect password' });

      const taken = await queries.users.findByUsername(newUsername.trim());
      if (taken && taken.id !== req.userId) {
        return res.status(409).json({ error: 'Username already taken', field: 'username' });
      }

      const updated = await queries.users.updateProfile(req.userId, { username: newUsername.trim() });

      // Emit username update event to notify other clients
      io.emit('user_profile_updated', {
        userId: req.userId,
        username: updated.username,
        full_name: updated.full_name,
        email: updated.email,
      });

      res.json({ user: queries.users.sanitize(updated) });
    } catch (err) {
      console.error('[Users] Username change error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Change own password — requires current password, no admin approval needed
  router.put('/api/users/me/password', authMiddleware, async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required' });
      }
      if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
      }

      const user = await queries.users.findById(req.userId);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const passwordValid = await bcrypt.compare(currentPassword, user.password);
      if (!passwordValid) return res.status(401).json({ error: 'Incorrect password' });

      const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
      await queries.users.updatePassword(req.userId, hashedPassword);
      invalidateAuthStatusCache(req.userId);

      res.json({ success: true });
    } catch (err) {
      console.error('[Users] Password change error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/api/users/profile-picture', authMiddleware, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file provided' });

      // Move file from temp uploads to the profile-pictures folder
      const uploadedPath = path.join(UPLOADS_DIR, req.file.filename);
      const profilePicturePath = path.join(PROFILE_PICTURES_DIR, req.file.filename);
      fs.renameSync(uploadedPath, profilePicturePath);

      const fileUrl = `/profile-pictures/${req.file.filename}`;
      const updated = await queries.users.updateProfile(req.userId, { profile_picture: fileUrl });
      if (!updated) return res.status(404).json({ error: 'User not found' });
      res.json({ user: queries.users.sanitize(updated), profilePicture: fileUrl });
    } catch (err) {
      console.error('[Users] Profile picture error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Own workspace membership management (authenticated) ──
  router.get('/api/users/me/workspaces', authMiddleware, async (req, res) => {
    try {
      const memberships = await queries.userWorkspaces.getForUser(req.userId);
      const workspaces = memberships.map(m => ({
        id: m.workspace_id,
        name: m.workspace_name,
        slug: m.workspace_slug,
        color: m.workspace_color,
        role: m.role,
        status: m.status,
        accepted_at: m.accepted_at,
      }));
      res.json({ workspaces });
    } catch (err) {
      console.error('[Workspaces] Get user workspaces error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/api/users/me/workspaces', authMiddleware, async (req, res) => {
    try {
      const { workspace_ids } = req.body;
      if (!Array.isArray(workspace_ids) || workspace_ids.length === 0) {
        return res.status(400).json({ error: 'workspace_ids array is required' });
      }
      const validIds = workspace_ids.filter(id => UUID_RE.test(String(id)));
      const results = [];
      for (const workspaceId of validIds) {
        const workspace = await queries.workspaces.findById(workspaceId);
        if (!workspace) continue;
        const membership = await queries.userWorkspaces.addRequest(req.userId, workspaceId);
        if (membership) {
          results.push({ workspaceId, workspaceName: workspace.name });
          notifyWorkspaceAdmins(
            workspaceId,
            '👤 New Workspace Request',
            `A user is requesting access to ${workspace.name}`,
            { type: 'user_pending', userId: String(req.userId) },
          ).catch(() => {});
        }
      }
      res.json({ requested: results });
    } catch (err) {
      console.error('[Workspaces] Request access error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Clear chat for user (hide from list, can't search old messages, but room stays for others)
  router.post('/api/rooms/:roomId/clear', authMiddleware, async (req, res) => {
    try {
      const roomId = req.params.roomId;

      // Verify user is a participant
      const participant = await db.query(
        'SELECT 1 FROM room_participants WHERE room_id = $1 AND user_id = $2',
        [roomId, req.userId]
      );
      if (participant.rows.length === 0) {
        return res.status(404).json({ error: 'Room not found' });
      }

      // Set cleared_at to now — user won't see messages before this timestamp
      await db.query(
        'UPDATE room_participants SET cleared_at = NOW() WHERE room_id = $1 AND user_id = $2',
        [roomId, req.userId]
      );

      res.json({ success: true, message: 'Chat cleared successfully' });
    } catch (err) {
      console.error('[Rooms] Clear chat error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Search messages across user's own rooms
  router.get('/api/messages/search', authMiddleware, async (req, res) => {
    try {
      const q = req.query.q || '';
      const limit = parseLimit(req.query.limit, { def: 50, max: 200 });
      if (!q.trim()) return res.json({ messages: [] });
      const messages = await queries.messages.searchByUser(req.userId, q.trim(), { limit });
      res.json({ messages });
    } catch (err) {
      console.error('[User] Message search error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};

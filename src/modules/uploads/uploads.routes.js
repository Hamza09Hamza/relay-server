/**
 * Uploads — authenticated static serving (with on-the-fly decryption),
 * short-lived public access URLs, and all chat file upload endpoints.
 * Factory: needs io for room_message fan-out after an upload.
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const queries = require('../../infrastructure/db/queries');
const encryption = require('../../infrastructure/encryption/encryption');
const { UPLOADS_DIR, PROFILE_PICTURES_DIR } = require('../../app/paths');
const { connectedUsers, uploadAccessTokens } = require('../../app/state');
const { getContentTypeByName } = require('../../shared/files/mime');
const { sendBufferWithRange } = require('../../shared/http/range');
const { authMiddleware } = require('../auth/auth.middleware');
const { isUserSuspended } = require('../users/users.service');
const { upload } = require('./multer');

const UPLOAD_ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

/** Guards roomId before it reaches Postgres, where a non-UUID is a 500. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PENDING_ROOM_RE = new RegExp(`^pending[-:](${UUID_RE.source.slice(1, -1)})$`, 'i');

/**
 * Turn the roomId a client sent into a real room id.
 *
 * Opening a chat with someone you have no conversation with yet gives the
 * client a placeholder room id — "pending:<userId>" (desktop) or
 * "pending-<userId>" (mobile) — and the real room is created lazily by the
 * first message. Text goes through send_private_message, which performs that
 * creation; uploads had no equivalent, so the placeholder was passed straight
 * to Postgres and every query failed with
 *   invalid input syntax for type uuid: "pending-<uuid>"
 * That is why sending a voice message (or photos) as the FIRST message to
 * someone never worked. Find-or-create the real room instead.
 *
 * Returns { ok: true, roomId, startedRoom } — startedRoom is set only when this
 * call actually created the room, so the caller can announce it — or
 * { ok: false, status, error } for the caller to return verbatim.
 */
async function resolveUploadRoomId(requestedRoomId, senderId) {
  const pending = PENDING_ROOM_RE.exec(String(requestedRoomId));
  if (!pending) {
    // Anything that isn't a UUID would surface to the client as an opaque 500.
    if (!UUID_RE.test(String(requestedRoomId))) {
      return { ok: false, status: 400, error: 'Invalid roomId' };
    }
    return { ok: true, roomId: requestedRoomId, startedRoom: null };
  }

  const otherUserId = pending[1];
  if (String(otherUserId) === String(senderId)) {
    return { ok: false, status: 400, error: 'Cannot start a conversation with yourself' };
  }
  const otherUser = await queries.users.findById(otherUserId).catch(() => null);
  if (!otherUser) {
    return { ok: false, status: 404, error: 'Recipient not found' };
  }
  const { room, created } = await queries.rooms.findOrCreatePrivate(
    senderId,
    otherUserId,
    senderId,
  );
  return { ok: true, roomId: room.id, startedRoom: created ? room : null };
}

/**
 * Tell both sides a lazily-created private room now exists, so their
 * placeholder id is swapped for the real one before the message arrives —
 * otherwise the sender is still on the pending id and drops the incoming
 * room_message as belonging to some other room.
 */
function announceStartedRoom(io, startedRoom, participants) {
  if (!io || !startedRoom) return;
  const roomPayload = { ...startedRoom, participants, type: 'private' };
  for (const [socketId, connected] of connectedUsers.entries()) {
    if (!participants.some(p => p.id === connected.userId)) continue;
    const otherUser = participants.find(p => p.id !== connected.userId) || null;
    io.to(socketId).emit('private_chat_started', { room: roomPayload, otherUser });
  }
}

module.exports = function uploadsRoutes({ io }) {
  const router = express.Router();
  const requireMessages = async (req, res, next) => {
    try {
      if (!(await queries.users.hasCapability(req.userId, 'messages'))) {
        return res.status(403).json({ error: 'Messages are not enabled for this account' });
      }
      next();
    } catch (_) {
      res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Serve uploaded files — require a valid JWT so files are not publicly accessible.
  // Accepts token ONLY via Authorization: Bearer <jwt> header.
  // When encryption is active, files on disk are encrypted (.enc extension);
  // this handler decrypts them on-the-fly before serving.
  router.use('/uploads', authMiddleware, (req, res, next) => {
    // If encryption is active, try to serve the decrypted file
    if (encryption.isInitialized()) {
      const requestedFile = req.path.replace(/^\//, ''); // e.g. "1234-567.jpg"
      const encPath = path.join(UPLOADS_DIR, requestedFile + '.enc');
      const plainPath = path.join(UPLOADS_DIR, requestedFile);

      // Prevent path traversal
      if (!encPath.startsWith(UPLOADS_DIR) || !plainPath.startsWith(UPLOADS_DIR)) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      if (fs.existsSync(encPath)) {
        try {
          const decrypted = encryption.decryptFile(encPath, requestedFile);
          return sendBufferWithRange(req, res, decrypted, getContentTypeByName(requestedFile));
        } catch (err) {
          console.error('[Upload] Decrypt error:', err.message);
          return res.status(500).json({ error: 'File decryption failed' });
        }
      }

      // Fall through: file might be unencrypted (pre-migration)
      if (fs.existsSync(plainPath)) {
        return next();
      }

      return res.status(404).json({ error: 'File not found' });
    }

    // No encryption — serve normally
    next();
  }, express.static(UPLOADS_DIR));

  // Serve profile pictures — require authentication via JWT header
  router.use('/profile-pictures', authMiddleware, express.static(PROFILE_PICTURES_DIR));

  // Public short-lived upload access URL (for clients that can't attach headers, e.g. external open/play handlers).
  // Token remains reusable until expiry to support media players that perform multiple requests/range fetches.
  router.get('/uploads-access/:token/:name', (req, res, next) => {
    const info = uploadAccessTokens.get(req.params.token);
    if (!info || info.expiry < Date.now()) {
      uploadAccessTokens.delete(req.params.token);
      return res.status(401).json({ error: 'Access token invalid or expired' });
    }

    const requestedName = path.basename(req.params.name || '');
    if (!requestedName || requestedName !== info.fileName) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    if (encryption.isInitialized()) {
      const encPath = path.join(UPLOADS_DIR, requestedName + '.enc');
      const plainPath = path.join(UPLOADS_DIR, requestedName);

      if (!encPath.startsWith(UPLOADS_DIR) || !plainPath.startsWith(UPLOADS_DIR)) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      if (fs.existsSync(encPath)) {
        try {
          const decrypted = encryption.decryptFile(encPath, requestedName);
          return sendBufferWithRange(req, res, decrypted, getContentTypeByName(requestedName));
        } catch (err) {
          console.error('[UploadAccess] Decrypt error:', err.message);
          return res.status(500).json({ error: 'File decryption failed' });
        }
      }

      if (fs.existsSync(plainPath)) {
        return res.sendFile(plainPath);
      }

      return res.status(404).json({ error: 'File not found' });
    }

    // No encryption
    const filePath = path.join(UPLOADS_DIR, requestedName);
    if (!filePath.startsWith(UPLOADS_DIR)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    return res.sendFile(filePath);
  });

  // Create one-time access URL for a specific uploaded file.
  router.post('/api/uploads/access-token', authMiddleware, requireMessages, async (req, res) => {
    const { filePath, roomId } = req.body || {};
    if (!filePath || typeof filePath !== 'string') {
      return res.status(400).json({ error: 'filePath is required' });
    }

    // Accept relative upload path only (e.g. /uploads/12345.jpg)
    if (!filePath.startsWith('/uploads/')) {
      return res.status(400).json({ error: 'Only /uploads paths are supported' });
    }

    const clean = filePath.split('?')[0];
    const fileName = path.basename(clean);
    if (!fileName || fileName.includes('..')) {
      return res.status(400).json({ error: 'Invalid file path' });
    }

    // If roomId is provided, verify the requesting user is still an active member
    if (roomId && typeof roomId === 'string') {
      try {
        const participants = await queries.rooms.getParticipants(roomId);
        const isMember = participants.some(p => p.id === req.userId);
        if (!isMember) {
          return res.status(403).json({ error: 'You no longer have access to files in this room' });
        }
      } catch (memberErr) {
        console.warn('[Upload access] Membership check failed:', memberErr.message);
        // Allow access on check failure rather than blocking all users
      }
    }

    const token = crypto.randomBytes(24).toString('hex');
    const expiry = Date.now() + UPLOAD_ACCESS_TOKEN_TTL_MS;
    uploadAccessTokens.set(token, { expiry, userId: req.userId, fileName });

    // Lazy cleanup
    for (const [t, info] of uploadAccessTokens) {
      if (info.expiry < Date.now()) uploadAccessTokens.delete(t);
    }

    res.json({
      url: `/uploads-access/${token}/${encodeURIComponent(fileName)}`,
      expiresInSeconds: Math.floor(UPLOAD_ACCESS_TOKEN_TTL_MS / 1000),
    });
  });

  // Upload a file once (store + encrypt it) and return the URL without creating a message.
  // Used by the camera FAB multi-send flow: client uploads once, then calls /api/forward-file.
  router.post('/api/upload-once', authMiddleware, requireMessages, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file provided' });
      const fileUrl = `/uploads/${req.file.filename}`;
      if (encryption.isInitialized()) {
        const filePath = path.join(UPLOADS_DIR, req.file.filename);
        encryption.encryptFile(filePath, filePath + '.enc');
        try { fs.unlinkSync(filePath); } catch (_) {}
      }
      res.json({ success: true, fileUrl });
    } catch (err) {
      console.error('[UploadOnce] Error:', err.message);
      res.status(500).json({ error: 'Upload failed' });
    }
  });

  router.post('/api/upload', authMiddleware, requireMessages, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }

      const cleanupUploadedFile = () => {
        try {
          if (req.file?.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
          }
        } catch (_) {}
      };

      const { roomId: requestedRoomId, messageType, isOriginal, durationSeconds } = req.body;
      const senderId = req.userId; // TRUSTED sender identity from JWT
      // Reassigned below if this is a not-yet-created ("pending") private room.
      let roomId = requestedRoomId;

      if (!roomId) {
        cleanupUploadedFile();
        return res.status(400).json({ error: 'roomId is required' });
      }

      // Block suspended users
      if (await isUserSuspended(senderId)) {
        cleanupUploadedFile();
        return res.status(403).json({ error: 'Your account has been suspended. You cannot send files.' });
      }

      // If a client sends senderId and it doesn't match JWT identity, reject.
      if (req.body?.senderId && String(req.body.senderId) !== String(senderId)) {
        cleanupUploadedFile();
        return res.status(403).json({ error: 'senderId mismatch' });
      }

      // Turn a lazily-created ("pending") private room into a real one.
      const resolved = await resolveUploadRoomId(roomId, senderId);
      if (!resolved.ok) {
        cleanupUploadedFile();
        return res.status(resolved.status).json({ error: resolved.error });
      }
      roomId = resolved.roomId;
      const startedRoom = resolved.startedRoom;

      // Enforce room membership to prevent cross-room message injection.
      const participants = await queries.rooms.getParticipants(roomId);
      if (!participants.some(p => p.id === senderId)) {
        cleanupUploadedFile();
        return res.status(403).json({ error: 'Not a member of this room' });
      }
      const enabledMessageIds = new Set(await queries.users.filterIdsWithCapability(
        participants.map(participant => participant.id), 'messages',
      ));
      const deliveryParticipants = participants.filter(participant =>
        participant.id === senderId || enabledMessageIds.has(String(participant.id)));

      // Never trust senderUsername from request body.
      const senderUser = await queries.users.findById(senderId).catch(() => null);
      const trustedSenderUsername = senderUser?.username || null;

      const fileUrl = `/uploads/${req.file.filename}`;
      const type = messageType || (req.file.mimetype.startsWith('image/') ? 'image' : 'file');

      // ── Encrypt the file on disk (if encryption is active) ──
      if (encryption.isInitialized()) {
        const filePath = path.join(UPLOADS_DIR, req.file.filename);
        encryption.encryptFile(filePath, filePath + '.enc');
        // Remove the plaintext file — only the .enc version remains
        fs.unlinkSync(filePath);
        console.log(`[Upload] File encrypted: ${req.file.filename}.enc`);
      }

      // Decode URL-encoded filenames (React Native encodes non-ASCII chars in
      // Content-Disposition, so multer gets e.g. "%D8%A3..." for Arabic names).
      const decodedOriginalname = (() => {
        try { return decodeURIComponent(req.file.originalname); } catch (_) { return req.file.originalname; }
      })();

      // Save message to DB (content + file_url are encrypted inside create())
      const parsedDuration = Math.round(Number(durationSeconds));
      const safeAudioDuration = Number.isFinite(parsedDuration) && parsedDuration > 0 && parsedDuration <= 86400
        ? parsedDuration
        : null;
      const contentStr = type === 'audio' && safeAudioDuration
        ? String(safeAudioDuration)
        : isOriginal === 'true' && type === 'image'
          ? decodedOriginalname + '::HD'
          : decodedOriginalname;
      const msg = await queries.messages.create({
        roomId,
        senderId,
        content: contentStr,
        messageType: type,
        fileUrl,
      });

      console.log(`[Upload] ${trustedSenderUsername || senderId} uploaded ${type}: ${decodedOriginalname}${isOriginal === 'true' ? ' (HD)' : ''}`);

      // Emit real-time event to room participants
      try {
        announceStartedRoom(io, startedRoom, participants);
        const payload = {
          id: msg.id,
          roomId,
          room_id: roomId,
          senderId,
          sender_id: senderId,
          sender_username: trustedSenderUsername,
          content: contentStr,
          message_type: type,
          file_url: fileUrl,
          created_at: msg.created_at,
          edited_at: null,
        };
        for (const [sid, u] of connectedUsers.entries()) {
          if (deliveryParticipants.some(p => p.id === u.userId)) {
            io.to(sid).emit('room_message', payload);
          }
        }
      } catch (emitErr) {
        console.error('[Upload] Socket emit error:', emitErr.message);
      }

      res.json({ success: true, messageId: msg.id, fileUrl });
    } catch (err) {
      console.error('[Upload] Error:', err.message);
      res.status(500).json({ error: 'Upload failed' });
    }
  });

  // Forward an already-uploaded file to one or more rooms (upload once, send many)
  router.post('/api/forward-file', authMiddleware, requireMessages, async (req, res) => {
    try {
      const { roomIds, fileUrl, messageType, content } = req.body;
      const senderId = req.userId;

      if (!Array.isArray(roomIds) || roomIds.length === 0) {
        return res.status(400).json({ error: 'roomIds array is required' });
      }
      if (!fileUrl || !messageType) {
        return res.status(400).json({ error: 'fileUrl and messageType are required' });
      }

      const senderUser = await queries.users.findById(senderId).catch(() => null);
      const trustedSenderUsername = senderUser?.username || null;

      const results = [];
      for (const roomId of roomIds) {
        const participants = await queries.rooms.getParticipants(roomId);
        if (!participants.some(p => p.id === senderId)) {
          results.push({ roomId, success: false, error: 'Not a member' });
          continue;
        }
        const enabledMessageIds = new Set(await queries.users.filterIdsWithCapability(
          participants.map(participant => participant.id), 'messages',
        ));
        const deliveryParticipants = participants.filter(participant =>
          participant.id === senderId || enabledMessageIds.has(String(participant.id)));

        const msg = await queries.messages.create({
          roomId,
          senderId,
          content: content || fileUrl,
          messageType,
          fileUrl,
        });

        const payload = {
          id: msg.id,
          roomId,
          room_id: roomId,
          senderId,
          sender_id: senderId,
          sender_username: trustedSenderUsername,
          content: content || fileUrl,
          message_type: messageType,
          file_url: fileUrl,
          created_at: msg.created_at,
          edited_at: null,
        };

        for (const [sid, u] of connectedUsers.entries()) {
          if (deliveryParticipants.some(p => p.id === u.userId)) {
            io.to(sid).emit('room_message', payload);
          }
        }

        results.push({ roomId, success: true, messageId: msg.id });
      }

      res.json({ success: true, results });
    } catch (err) {
      console.error('[ForwardFile] Error:', err.message);
      res.status(500).json({ error: 'Forward failed' });
    }
  });

  // Batch upload — multiple files → single "collection" message
  router.post('/api/upload-collection', authMiddleware, requireMessages, upload.array('files', 30), async (req, res) => {
    try {
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'No files provided' });
      }

      const cleanupUploadedFiles = () => {
        try {
          for (const f of req.files || []) {
            if (f?.path && fs.existsSync(f.path)) {
              fs.unlinkSync(f.path);
            }
          }
        } catch (_) {}
      };

      const { roomId: requestedRoomId } = req.body;
      const senderId = req.userId; // TRUSTED sender identity from JWT
      // Reassigned below if this is a not-yet-created ("pending") private room.
      let roomId = requestedRoomId;

      if (!roomId) {
        cleanupUploadedFiles();
        return res.status(400).json({ error: 'roomId is required' });
      }

      // Block suspended users
      if (await isUserSuspended(senderId)) {
        cleanupUploadedFiles();
        return res.status(403).json({ error: 'Your account has been suspended. You cannot send files.' });
      }

      // If a client sends senderId and it doesn't match JWT identity, reject.
      if (req.body?.senderId && String(req.body.senderId) !== String(senderId)) {
        cleanupUploadedFiles();
        return res.status(403).json({ error: 'senderId mismatch' });
      }

      // Turn a lazily-created ("pending") private room into a real one, so a
      // photo collection can also be the first message to a new contact.
      const resolved = await resolveUploadRoomId(roomId, senderId);
      if (!resolved.ok) {
        cleanupUploadedFiles();
        return res.status(resolved.status).json({ error: resolved.error });
      }
      roomId = resolved.roomId;
      const startedRoom = resolved.startedRoom;

      // Enforce room membership to prevent cross-room message injection.
      const participants = await queries.rooms.getParticipants(roomId);
      if (!participants.some(p => p.id === senderId)) {
        cleanupUploadedFiles();
        return res.status(403).json({ error: 'Not a member of this room' });
      }
      announceStartedRoom(io, startedRoom, participants);
      const enabledMessageIds = new Set(await queries.users.filterIdsWithCapability(
        participants.map(participant => participant.id), 'messages',
      ));
      const deliveryParticipants = participants.filter(participant =>
        participant.id === senderId || enabledMessageIds.has(String(participant.id)));

      // Never trust senderUsername from request body.
      const senderUser = await queries.users.findById(senderId).catch(() => null);
      const trustedSenderUsername = senderUser?.username || null;

      // Build collection items array
      const items = req.files.map(f => ({
        url: `/uploads/${f.filename}`,
        name: (() => { try { return decodeURIComponent(f.originalname); } catch (_) { return f.originalname; } })(),
        type: f.mimetype,
        itemType: f.mimetype.startsWith('image/') ? 'image' : 'file',
      }));

      // ── Encrypt each file on disk (if encryption is active) ──
      if (encryption.isInitialized()) {
        for (const f of req.files) {
          const filePath = path.join(UPLOADS_DIR, f.filename);
          encryption.encryptFile(filePath, filePath + '.enc');
          fs.unlinkSync(filePath);
        }
        console.log(`[Upload] Collection: ${req.files.length} files encrypted`);
      }

      const imageCount = items.filter(i => i.itemType === 'image').length;
      const fileCount = items.filter(i => i.itemType === 'file').length;
      const parts = [];
      if (imageCount) parts.push(`${imageCount} image${imageCount > 1 ? 's' : ''}`);
      if (fileCount) parts.push(`${fileCount} file${fileCount > 1 ? 's' : ''}`);
      const summary = parts.join(', ');

      // Store: content = human summary (for room list), file_url = JSON items (for rendering)
      const msg = await queries.messages.create({
        roomId,
        senderId,
        content: summary,
        messageType: 'collection',
        fileUrl: JSON.stringify(items),
      });

      console.log(`[Upload-Collection] ${trustedSenderUsername || senderId} sent ${summary} in room ${roomId}`);

      // Emit real-time event
      try {
        const payload = {
          id: msg.id,
          roomId,
          room_id: roomId,
          senderId,
          sender_id: senderId,
          sender_username: trustedSenderUsername,
          content: summary,
          message_type: 'collection',
          file_url: JSON.stringify(items),
          created_at: msg.created_at,
          edited_at: null,
        };
        for (const [sid, u] of connectedUsers.entries()) {
          if (deliveryParticipants.some(p => p.id === u.userId)) {
            io.to(sid).emit('room_message', payload);
          }
        }
      } catch (emitErr) {
        console.error('[Upload-Collection] Socket emit error:', emitErr.message);
      }

      res.json({ success: true, messageId: msg.id, items, summary });
    } catch (err) {
      console.error('[Upload-Collection] Error:', err.message);
      res.status(500).json({ error: 'Collection upload failed' });
    }
  });

  return router;
};

require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // still needed for the MulterError handler below
const {
  ROOM_NOTIFICATION_MODES,
  detectsEveryone,
  normalizeMentions,
  shouldNotifyForMode,
} = require('./src/app/mentions');
// Optional Redis layer for Socket.IO (multi-instance fan-out; no-op without REDIS_URL)
const { initSocketRedisAdapter } = require('./src/infrastructure/redis');
// Server-Side Encryption engine — AES-256-GCM for data at rest
const encryption = require('./src/infrastructure/encryption/encryption');

const db = require('./src/infrastructure/db');
const queries = require('./src/infrastructure/db/queries');
const { MediaServer } = require('./mediaServer');
const recordingMetadataHandler = require('./recordingMetadataHandler');
// ✅ Socket.IO rate limiting (prevent DoS via event flooding)
const socketRateLimiter = require('./socketRateLimiter');

// Shared in-memory state — single source of truth for socket/call/admin maps.
const {
  connectedUsers, activeCalls, finalizedCalls, pendingCallEnded, reconnectGrace,
  ringTimeouts, callAcks, userTransportCount, userProducerCount,
} = require('./src/app/state');
const {
  createCallAttemptId,
  getCallAttemptId,
  isSameCallAttempt,
  isCallAttemptId,
  deleteCallIfCurrent,
  isUserParticipantInCall,
  isStaleActiveCall,
  STALE_CALL_SWEEP_INTERVAL_MS,
} = require('./src/app/callAttempt');
const {
  resolvePrivateRecipient,
  isAuthorizedMessageRecipient,
} = require('./src/app/messageAuthorization');

// Config, shared validation, and the auth module (extracted from server.js).
const { JWT_SECRET, BCRYPT_ROUNDS } = require('./src/app/config');
const { isValidUserId } = require('./src/shared/validation');
const {
  authMiddleware, adminMiddleware, superadminMiddleware, invalidateAdminCache,
} = require('./src/modules/auth/auth.middleware');

// Shared helpers + domain services
const {
  isUserSuspended,
  canUsersCommunicate,
  recordGroupIntroductions,
} = require('./src/modules/users/users.service');
const { createEmitToUser } = require('./src/shared/socket/emitToUser');
const { createAdminNotifier } = require('./src/modules/notifications/adminNotify');

const app = express();
// Nginx is the only trusted HTTP/WebSocket proxy and runs on this host. Using
// the loopback subnet instead of a hop count prevents direct clients from
// supplying a forged X-Forwarded-For header.
app.set('trust proxy', 'loopback');
const server = http.createServer(app);

// Log verbosity controls
const VERBOSE_SOCKET_LOGS = String(process.env.VERBOSE_SOCKET_LOGS || 'false').toLowerCase() === 'true';
const VERBOSE_MEDIA_LOGS = String(process.env.VERBOSE_MEDIA_LOGS || 'false').toLowerCase() === 'true';
const VERBOSE_CALL_LOGS = String(process.env.VERBOSE_CALL_LOGS || 'false').toLowerCase() === 'true';
const socketVLog = (...args) => { if (VERBOSE_SOCKET_LOGS) console.log(...args); };
const mediaVLog = (...args) => { if (VERBOSE_MEDIA_LOGS) console.log(...args); };
const callVLog = (...args) => { if (VERBOSE_CALL_LOGS) console.log(...args); };

// Structured, timestamped logger (src/shared/logger) — adopt this over bare
// console.* so operational logs read cleanly: people not UUIDs, no secrets.
const logger = require('./src/shared/logger');

// ── Readable-log helpers ────────────────────────────────────────────────────
/** Short, non-identifying id fragment for users we can't name (offline/async). */
function shortId(id) {
  const s = String(id || '');
  return s ? `#${s.slice(0, 8)}` : 'unknown';
}

/** Compare DB integer ids with socket/JWT string ids without weakening null checks. */
function sameUserId(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) return false;
  return String(left) === String(right);
}

/**
 * The mobile client uses this opaque value only to replace its optimistic
 * bubble with the DB-backed echo. Keep it bounded and character-restricted so
 * an untrusted socket cannot turn it into an oversized/arbitrary payload.
 */
function normalizeClientMessageId(value) {
  if (typeof value !== 'string') return undefined;
  const normalized = value.trim();
  return /^opt-[A-Za-z0-9._:-]{1,120}$/.test(normalized)
    ? normalized
    : undefined;
}
/**
 * Resolve a userId to a human name for logs so operators read people, not
 * UUIDs. Uses the live socket registry; falls back to a short id fragment when
 * the user isn't currently connected.
 */
function nameForUser(userId) {
  if (!userId) return 'unknown';
  for (const u of connectedUsers.values()) {
    if (String(u.userId) === String(userId)) {
      return u.username || u.fullName || shortId(userId);
    }
  }
  return shortId(userId);
}
/** True when the immediate Socket.IO peer is the local Nginx proxy. */
function isLoopbackAddress(address) {
  const normalized = String(address || '').toLowerCase();
  return normalized === '::1'
    || normalized === '127.0.0.1'
    || normalized === '::ffff:127.0.0.1';
}

/** Best-effort client IP from a socket handshake (honours local Nginx only). */
function ipForSocket(socket) {
  const peerAddress = socket?.handshake?.address;
  const fwd = socket?.handshake?.headers?.['x-forwarded-for'];
  if (isLoopbackAddress(peerAddress) && typeof fwd === 'string' && fwd.trim()) {
    // nginx overwrites this header with $remote_addr, so it contains one
    // server-observed address rather than a client-controlled proxy chain.
    return fwd.trim();
  }
  return peerAddress || 'unknown';
}

// JWT_SECRET is loaded + validated in src/app/config (imported above).

const ENCRYPTION_KEY = process.env.ENCRYPTION_MASTER_KEY;
if (ENCRYPTION_KEY) {
  encryption.init(ENCRYPTION_KEY);
} else {
  console.warn(
    '[Encryption] WARNING: ENCRYPTION_MASTER_KEY not set. Data at rest will NOT be encrypted.\n' +
    '  Generate one: node -e \"console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))\"'
  );
}

// ✅ CORS: Restrict to known origins. While JWT protects the API, CORS is
// defense-in-depth against XSS injected JS. Mobile clients bypass CORS anyway
// (they don't honor CORS headers), so this is primarily for web app security.
const configuredCorsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim())
  : ['https://example.com:8443', 'https://example.com'];
// Packaged Electron builds load from this privileged, application-owned
// origin. Keep it explicit instead of allowing opaque `null`/file origins.
const CORS_ORIGIN = [...new Set([...configuredCorsOrigins, 'relay-app://bundle'])];

// ✅ SECURITY: Validate that CORS is not accidentally set to accept-all
if (Array.isArray(CORS_ORIGIN) && CORS_ORIGIN.includes(true)) {
  console.error('❌ CORS misconfigured: contains true (accept-all). Fix CORS_ORIGINS in .env');
  process.exit(1);
}

const io = new Server(server, {
  cors: { origin: CORS_ORIGIN },
  maxHttpBufferSize: 10 * 1024 * 1024, // 10 MB for signaling payloads
  // Faster dead-connection detection for mobile clients.
  // Shorter values ensure the server quickly detects dropped connections
  // (e.g. Android killing the transport on background) and removes the
  // stale entry from connectedUsers, so incoming messages get queued as
  // pending instead of being silently sent to a dead socket.
  pingInterval: 10000,   // 10s (default: 25s)
  pingTimeout: 5000,     // 5s  (default: 20s)
});

// Attach the Redis adapter when configured. Fire-and-forget: if Redis is
// unset/unavailable this is a no-op and we keep the in-memory adapter, so it
// can never block or crash startup.
initSocketRedisAdapter(io).catch((e) => console.warn('[Redis] adapter init error:', e.message));

app.use(express.json());
app.use(cors({ origin: CORS_ORIGIN }));

// ✅ SECURITY: Add protective HTTP headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');           // Prevent MIME sniffing
  res.setHeader('X-Frame-Options', 'DENY');                     // Prevent clickjacking
  res.setHeader('X-XSS-Protection', '1; mode=block');           // Legacy XSS protection
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'); // HSTS (1 year)
  res.setHeader('Content-Security-Policy', "default-src 'self'"); // CSP
  next();
});

// Real-time helpers shared with the extracted route modules.
const emitToUser = createEmitToUser(io);
const { notifyWorkspaceAdmins } = createAdminNotifier({ io });

// Uploads module — /uploads + /profile-pictures static serving (JWT +
// decryption), /uploads-access short-lived links, and all /api/upload* endpoints.
app.use(require('./src/modules/uploads/uploads.routes')({ io }));

// Initialize Media Server
const mediaServer = new MediaServer();

// ── Recording Post-Processing Queue ────────────────────────────────────────
// Phase 1 (raw capture: closing transports + waiting for FFmpeg to exit via
// rw_timeout) must run synchronously because it tears down the mediasoup room.
// Phase 2 (VP8→H.264 transcoding + audio muxing) is CPU-heavy and can take
// seconds to minutes for long calls.  Queuing it lets the socket handler
// return immediately after raw capture while transcoding runs in background.
//
// Bounded parallelism: up to MAX_CONCURRENT transcoding jobs run at once so
// back-to-back calls don't block each other. 3 cores are pinned to FFmpeg
// via taskset, leaving 5 cores for Node + mediasoup real-time traffic.
class RecordingQueue {
  constructor() {
    this._size = 0;
    this._active = 0;
    this._maxConcurrent = 2; // max parallel transcoding jobs
    this._pending = [];      // { fn, callId, resolve }
    // callId → { dbRoomId, status: 'queued'|'transcoding'|'done'|'error', queuedAt, startedAt, doneAt, position }
    this._jobs = new Map();
  }

  /**
   * Add a recording job with status tracking.
   * @param {Function} fn        Async job function
   * @param {string}   callId    DB call ID (for status lookup)
   * @param {string}   dbRoomId  DB room ID (for socket notifications)
   * @param {object}   [payload] JSON-serializable resume snapshot (from
   *                             mediaServer.buildResumeSnapshot). Persisted to the
   *                             recording_jobs journal so a process restart can
   *                             resume or clean up this job. Omit for resumed jobs
   *                             (already journaled) by passing payload === false.
   */
  add(fn, callId, dbRoomId, payload) {
    this._size++;
    const position = this._size;

    if (callId) {
      this._jobs.set(callId, {
        dbRoomId: dbRoomId || null,
        status: 'queued',
        queuedAt: Date.now(),
        startedAt: null,
        doneAt: null,
        position,
      });
      this._emitTranscodingStatus(callId, 'queued', { position, queueSize: this._size });
      // Durable journal (best-effort — never block/break recording on DB hiccups).
      // payload === false means "already journaled" (a boot-resumed job).
      if (payload !== false) {
        queries.recordingJobs
          .enqueue({ callId, dbRoomId: dbRoomId || null, payload: payload || null })
          .catch((e) => console.warn('[RecordingQueue] journal enqueue failed:', e?.message));
      }
    }

    const promise = new Promise((resolve) => {
      this._pending.push({ fn, callId, resolve });
      this._drain();
    });
    return promise;
  }

  /** Drain pending queue up to _maxConcurrent active jobs. */
  _drain() {
    while (this._active < this._maxConcurrent && this._pending.length > 0) {
      const job = this._pending.shift();
      this._active++;
      this._runJob(job);
    }
  }

  async _runJob({ fn, callId, resolve }) {
    try {
      if (callId) {
        const job = this._jobs.get(callId);
        if (job) {
          job.status = 'transcoding';
          job.startedAt = Date.now();
        }
        this._emitTranscodingStatus(callId, 'transcoding', { queueSize: this._size });
        queries.recordingJobs.markTranscoding(callId)
          .catch((e) => console.warn('[RecordingQueue] journal markTranscoding failed:', e?.message));
      }
      const result = await fn();
      if (callId) {
        const job = this._jobs.get(callId);
        if (job) {
          job.status = 'done';
          job.doneAt = Date.now();
          const elapsed = job.startedAt ? Math.round((job.doneAt - job.startedAt) / 1000) : 0;
          this._emitTranscodingStatus(callId, 'done', { elapsed });
        }
        queries.recordingJobs.markDone(callId)
          .catch((e) => console.warn('[RecordingQueue] journal markDone failed:', e?.message));
        setTimeout(() => this._jobs.delete(callId), 5 * 60 * 1000);
      }
      resolve(result);
    } catch (err) {
      console.error('[RecordingQueue] Job failed:', err?.message || err);
      if (callId) {
        const job = this._jobs.get(callId);
        if (job) {
          job.status = 'error';
          job.doneAt = Date.now();
        }
        this._emitTranscodingStatus(callId, 'error', { error: err?.message });
        queries.recordingJobs.markError(callId, err?.message || String(err))
          .catch((e) => console.warn('[RecordingQueue] journal markError failed:', e?.message));
        setTimeout(() => this._jobs.delete(callId), 5 * 60 * 1000);
      }
      resolve(null);
    } finally {
      this._active--;
      this._size--;
      this._drain();
    }
  }

  /** Emit transcoding_status event to all participants of the call's DB room. */
  _emitTranscodingStatus(callId, status, extra = {}) {
    const job = this._jobs.get(callId);
    const dbRoomId = job?.dbRoomId;
    if (!dbRoomId) return;

    // Best-effort: emit to all online users in this room.
    // Uses connectedUsers + room participants query for targeting.
    const payload = { callId, status, queueSize: this._size, ...extra };
    queries.rooms.getParticipants(dbRoomId)
      .then((participants) => {
        for (const p of participants) {
          const uid = String(p.user_id);
          for (const [sid, u] of connectedUsers) {
            if (String(u.userId) === uid) {
              io.to(sid).emit('transcoding_status', payload);
            }
          }
        }
      })
      .catch(() => { }); // non-critical
  }

  /** Get status of a specific call's transcoding job. */
  getJobStatus(callId) {
    return this._jobs.get(callId) || null;
  }

  /** Get summary of all active/queued jobs. */
  getQueueSummary() {
    const jobs = [];
    for (const [callId, job] of this._jobs) {
      jobs.push({ callId, ...job });
    }
    return { queueSize: this._size, jobs };
  }

  get size() { return this._size; }
}
const recordingQueue = new RecordingQueue();

// Boot-time recovery for the recording journal (migration 039).
// A process restart can interrupt a transcoding job mid-flight. Any job left in
// 'queued'/'transcoding' is a crash survivor: if its raw capture files are still
// on disk we re-enqueue it from the persisted snapshot; otherwise we clean up so
// no orphaned ffmpeg artifacts leak. A per-job attempt cap stops a poison job
// from looping on every boot.
const MAX_RECORDING_RESUME_ATTEMPTS = 3;
async function resumeRecordingJobs() {
  let rows;
  try {
    rows = await queries.recordingJobs.listResumable();
  } catch (e) {
    console.warn('[RecordingQueue] resume scan failed:', e?.message);
    return;
  }
  if (!rows || rows.length === 0) return;
  console.log(`[RecordingQueue] Found ${rows.length} interrupted recording job(s) from a previous run`);

  for (const row of rows) {
    const callId = row.call_id;
    const snapshot = row.payload; // JSONB → already a parsed object
    const recSnap = snapshot?.recording || null;

    if ((row.attempts || 0) >= MAX_RECORDING_RESUME_ATTEMPTS) {
      console.warn(`[RecordingQueue] Job ${callId} exceeded ${MAX_RECORDING_RESUME_ATTEMPTS} resume attempts — abandoning`);
      try { mediaServer.cleanupSnapshotArtifacts(recSnap); } catch (_) { }
      await queries.recordingJobs.markError(callId, 'exceeded max resume attempts').catch(() => { });
      continue;
    }

    if (!snapshot || !mediaServer.resumeArtifactsExist(snapshot)) {
      console.warn(`[RecordingQueue] Job ${callId} raw artifacts missing/empty — cleaning up instead of resuming`);
      try { mediaServer.cleanupSnapshotArtifacts(recSnap); } catch (_) { }
      await queries.recordingJobs.markError(callId, 'raw artifacts missing on resume').catch(() => { });
      continue;
    }

    const raw = mediaServer.reviveResumeSnapshot(snapshot);
    if (!raw) {
      await queries.recordingJobs.markError(callId, 'snapshot revive failed').catch(() => { });
      continue;
    }

    console.log(`[RecordingQueue] Resuming interrupted transcoding for call ${callId} (attempt ${(row.attempts || 0) + 1})`);
    // payload === false: this job is already journaled — don't re-enqueue the snapshot.
    recordingQueue.add(
      () => mediaServer.extractFromRaw(raw, callId),
      callId,
      row.db_room_id || null,
      false,
    );
  }
}

// Tracks call_ended events that need to be delivered to users who were offline/crashed.
// userId -> [{ roomId, endedAt }] — entries expire after 10 minutes.
function queueCallEndedForUser(userId, roomId) {
  if (!userId) return;
  const list = (pendingCallEnded.get(userId) || []).filter(e => Date.now() - e.endedAt < 10 * 60 * 1000);
  list.push({ roomId, endedAt: Date.now() });
  pendingCallEnded.set(userId, list);
}
function flushCallEndedForUser(userId, socket) {
  const list = pendingCallEnded.get(userId);
  if (!list) return;
  const fresh = list.filter(e => Date.now() - e.endedAt < 10 * 60 * 1000);
  for (const e of fresh) {
    socket.emit('call_ended', { roomId: e.roomId, reason: 'ended' });
    console.log(`[Call] Flushed stale call_ended to ${userId} for room ${e.roomId}`);
  }
  pendingCallEnded.delete(userId);
}

// ─── Reconnect grace ───────────────────────────────────────────────────────
// When a participant's socket drops mid-call we do NOT immediately tell the
// rest of the room they left. The call is held for RECONNECT_GRACE_MS so a
// brief network blip (elevator, tunnel, wifi↔cellular handover) can recover
// without dropping the call. Must stay aligned with the client constant.
//
// 25s rationale: the server detects a dead socket via ping/pong (pingInterval
// 10s + pingTimeout 5s = up to 15s after the real drop). Adding a 10s grace
// on top of a 15s detection lag means the effective window from the client's
// perspective was only 10s — far too short for a cellular handover or elevator.
// 25s gives ~10s of actual breathing room after worst-case detection lag.
const RECONNECT_GRACE_MS = 25_000;
// key `${mediasoupRoomId}::${attemptId}::${userId}` ->
//   { timer, socketId, roomId, attemptId, userId, username }
// (reconnectGrace map lives in src/app/state.js)

/** True if `userId` has a live media-server peer in `roomId` on a socket other
 *  than `excludeSocketId` — i.e. they already reconnected on a fresh socket. */
function isUserInMediaRoom(roomId, userId, excludeSocketId, attemptId = null) {
  if (!roomId || !userId) return false;
  for (const [sid, u] of connectedUsers.entries()) {
    if (sid === excludeSocketId) continue;
    if (!sameUserId(u.userId, userId)) continue;
    const p = mediaServer.peers?.get(sid);
    if (!p || p.roomId !== roomId) continue;
    if (attemptId && p.peer?.callAttemptId !== String(attemptId)) continue;
    return true;
  }
  return false;
}

function reconnectGraceKey(roomId, userId, attemptId) {
  return `${roomId}::${attemptId || 'legacy'}::${userId}`;
}

function roomFinalizerKey(roomId, attemptId) {
  return `${roomId}::${attemptId || 'legacy'}`;
}

/**
 * Raised hands are meeting state, not a fire-and-forget relay. Keeping the
 * ordered list on the active call is what lets a late joiner, a device that
 * reconnects, and the host's "lower hand" all agree on who is waiting to speak
 * and in which order.
 */
function raisedHandsSnapshot(roomId, active) {
  if (!(active?.raisedHands instanceof Map)) return [];
  return [...active.raisedHands.entries()]
    .map(([userId, hand]) => ({
      userId,
      username: hand.username || null,
      raisedAt: hand.raisedAt,
      // Clients match on media peer ids, which is also how a device
      // recognises its own hand without knowing its user id.
      peerIds: mediaPeerSocketsForUser(roomId, userId),
    }))
    .sort((a, b) => a.raisedAt - b.raisedAt);
}

function mediaPeerSocketsForUser(roomId, userId) {
  const sockets = [];
  for (const [sid, connected] of connectedUsers.entries()) {
    if (sameUserId(connected?.userId, userId) && mediaServer.hasPeer(roomId, sid)) {
      sockets.push(sid);
    }
  }
  return sockets;
}

function broadcastRaisedHands(roomId, active) {
  io.to(roomId).emit('raised_hands_state', { roomId, hands: raisedHandsSnapshot(roomId, active) });
}

/** Someone who has left the meeting cannot still be waiting to speak. */
function clearRaisedHand(roomId, active, userId) {
  if (!(active?.raisedHands instanceof Map) || userId == null) return;
  if (active.raisedHands.delete(String(userId))) broadcastRaisedHands(roomId, active);
}

/** Reactions are a fixed set so one can never carry arbitrary text onto
 *  everyone's stage. */
const CONFERENCE_REACTIONS = new Set(['💖', '👍', '🎉', '👏', '😂', '😮', '😢', '🤔']);

/** Defer the `peer_left` broadcast for a dropped participant, giving them a
 *  grace window to reconnect. Fires `peer_left` only if they never return. */
function scheduleGracefulPeerLeave(roomId, socketId, userId, username, active) {
  const attemptId = getCallAttemptId(active);
  const key = reconnectGraceKey(roomId, userId, attemptId);
  const existing = reconnectGrace.get(key);
  if (existing) clearTimeout(existing.timer);
  const timer = setTimeout(() => {
    reconnectGrace.delete(key);
    io.to(roomId).emit('peer_left', { peerId: socketId, userId, username: username || null });
    const current = activeCalls.get(roomId);
    if (isCallAttemptId(current, attemptId) && current?.isConference) {
      if (current.joinedUserIds instanceof Set) {
        current.joinedUserIds.delete(userId);
        current.joinedUserIds.delete(String(userId));
      }
      io.to(roomId).emit('conference_participant_left', {
        roomId,
        conferenceRoomId: current.dbRoomId,
        peerId: socketId,
        userId,
        username: username || null,
      });
      queries.calls.removeParticipant(current.callId, userId).catch(() => { });
      clearRaisedHand(roomId, current, userId);
      queries.conferenceArchives.addEntry({
        callId: current.callId,
        userId,
        entryType: 'left',
        metadata: { reason: 'connection_lost' },
      }).catch(error => console.error('[Conference] archive disconnect event failed:', error.message));
    }
    console.log(`[Reconnect] Grace expired for ${username || userId} in ${roomId} — emitted peer_left`);
    runRoomFinalizerIfDue(roomId, attemptId);
  }, RECONNECT_GRACE_MS);
  reconnectGrace.set(key, { timer, socketId, roomId, attemptId, userId, username });
  console.log(`[Reconnect] Holding call for ${username || userId} in ${roomId} (${RECONNECT_GRACE_MS}ms grace)`);
}

/** Cancel a pending graceful-leave because the user rejoined the room.
 *  Returns the dropped socketId if a grace was pending, else null. */
function cancelReconnectGrace(roomId, userId, active) {
  const attemptId = getCallAttemptId(active);
  const key = reconnectGraceKey(roomId, userId, attemptId);
  const entry = reconnectGrace.get(key);
  if (!entry) return null;
  clearTimeout(entry.timer);
  reconnectGrace.delete(key);
  // Somebody is back in the room, so the held teardown must never run.
  discardRoomFinalizer(roomId, attemptId);
  return entry.socketId;
}

/** Drop pending grace for one call attempt (or every attempt when omitted). */
function clearReconnectGraceForRoom(roomId, active = null) {
  const attemptId = getCallAttemptId(active);
  for (const [key, entry] of reconnectGrace.entries()) {
    if (
      entry.roomId === roomId &&
      (!attemptId || String(entry.attemptId) === String(attemptId))
    ) {
      clearTimeout(entry.timer);
      reconnectGrace.delete(key);
    }
  }
  if (attemptId) discardRoomFinalizer(roomId, attemptId);
  else discardRoomFinalizersForRoom(roomId);
}

/** True if this call attempt still has anyone inside reconnect grace. */
function roomHasPendingGrace(roomId, activeOrAttemptId = null) {
  if (!roomId) return false;
  const attemptId = typeof activeOrAttemptId === 'object'
    ? getCallAttemptId(activeOrAttemptId)
    : activeOrAttemptId;
  for (const entry of reconnectGrace.values()) {
    if (
      entry.roomId === roomId &&
      (!attemptId || String(entry.attemptId) === String(attemptId))
    ) return true;
  }
  return false;
}

// Teardown work (DB finalize, recording stop, notifications) held while the
// LAST participant of a room is inside their grace window. Without this, the
// moment a room's live peer count hit zero we deleted its activeCalls entry —
// and with it the only proof of membership — so a user reconnecting well
// inside their own 25s grace was rejected with "Not a member of this call".
// A flaky connection makes an all-peers-momentarily-disconnected instant
// almost certain (both ends of a 1:1 call usually share the same bad link).
// `${roomId}::${attemptId}` -> { roomId, attemptId, finalize }
const pendingRoomFinalizers = new Map();

function holdRoomFinalizer(roomId, active, finalize) {
  const attemptId = getCallAttemptId(active);
  pendingRoomFinalizers.set(
    roomFinalizerKey(roomId, attemptId),
    { roomId, attemptId, finalize },
  );
  console.log(`[Reconnect] Holding teardown of empty room ${roomId} until grace expires`);
}

function discardRoomFinalizer(roomId, attemptId) {
  if (pendingRoomFinalizers.delete(roomFinalizerKey(roomId, attemptId))) {
    console.log(`[Reconnect] Room ${roomId} repopulated — cancelled held teardown`);
  }
}

function discardRoomFinalizersForRoom(roomId) {
  for (const [key, entry] of pendingRoomFinalizers.entries()) {
    if (entry.roomId === roomId) pendingRoomFinalizers.delete(key);
  }
}

function executeRoomFinalizer(entry, logPrefix) {
  if (!entry) return false;
  pendingRoomFinalizers.delete(roomFinalizerKey(entry.roomId, entry.attemptId));
  console.log(`[Reconnect] ${logPrefix} for ${entry.roomId} — running held teardown`);
  // Invoke directly (rather than in a later Promise microtask) so the finalizer
  // can synchronously detach old call/recording ownership before a redial uses
  // the same media-room id.
  try {
    Promise.resolve(entry.finalize())
      .catch(err => console.error('[Reconnect] Held teardown error:', err?.message || err));
  } catch (err) {
    console.error('[Reconnect] Held teardown error:', err?.message || err);
  }
  return true;
}

/** Run a held teardown once the room's final grace window has expired. */
function runRoomFinalizerIfDue(roomId, attemptId) {
  if (roomHasPendingGrace(roomId, attemptId)) return;
  executeRoomFinalizer(
    pendingRoomFinalizers.get(roomFinalizerKey(roomId, attemptId)),
    'Grace fully expired',
  );
}

/**
 * Decide whether `callerUserId` is allowed to call `targetUserId` in a SINGLE
 * DB round-trip (the old path fired 3 sequential queries before the callee's
 * phone could even ring). Call signaling is latency-critical, so this is kept
 * as one query and the result is consumed off the hot path where possible.
 */
async function checkCallPermission(callerUserId, targetUserId) {
  if (!callerUserId || !targetUserId) {
    return { allowed: false, reason: 'Call participants could not be verified' };
  }
  // Workspace isolation is an authorization boundary, including during an
  // outage. A transient database error may make a legitimate call retry, but
  // it must never briefly let an unrelated account ring another workspace.
  const allowed = await canUsersCommunicate(callerUserId, targetUserId);
  return {
    allowed,
    reason: allowed ? undefined : 'You cannot call this user',
  };
}

// Wrap activeCalls methods to log all modifications for debugging
const originalDelete = activeCalls.delete.bind(activeCalls);
const originalSet = activeCalls.set.bind(activeCalls);
const originalClear = activeCalls.clear.bind(activeCalls);

// Call-state mutation tracing. The call lifecycle was a debugging hotspot, so
// the stack-traced set/delete tracing is kept — but gated behind
// VERBOSE_CALL_LOGS so production stays clean. Clearing the WHOLE map is never
// expected in normal flow, so that one stays loud as a warning.
activeCalls.delete = function (key) {
  if (VERBOSE_CALL_LOGS) {
    const stack = new Error().stack.split('\n').slice(2, 5).map(s => s.trim()).join(' | ');
    callVLog(`[activeCalls.delete] "${key}" hadEntry=${this.has(key)} | ${stack}`);
  }
  return originalDelete(key);
};

activeCalls.set = function (key, value) {
  if (VERBOSE_CALL_LOGS) {
    const stack = new Error().stack.split('\n').slice(2, 5).map(s => s.trim()).join(' | ');
    callVLog(`[activeCalls.set] "${key}" | ${stack}`);
  }
  return originalSet(key, value);
};

activeCalls.clear = function () {
  const stack = new Error().stack.split('\n').slice(2, 8).map(s => s.trim()).join(' | ');
  logger.warn('Call', `Active-call map cleared entirely | ${stack}`);
  return originalClear();
};

// Per-user media resource limits (DoS prevention)
const MEDIA_LIMITS = {
  MAX_TRANSPORTS_PER_USER: 4,   // 2 send + 2 recv is normal; 4 allows reconnect overlap
  MAX_PRODUCERS_PER_USER: 3,    // microphone + camera + conference presentation
};


function cleanupStaleRecordingArtifacts() {
  try {
    const RECORDINGS_DIR = path.join(__dirname, 'recordings');
    if (!fs.existsSync(RECORDINGS_DIR)) return;

    const now = Date.now();
    const maxAgeMs = 24 * 60 * 60 * 1000;
    const exts = new Set(['.sdp', '.ogg', '.mkv']);

    const names = fs.readdirSync(RECORDINGS_DIR);
    let removed = 0;
    for (const name of names) {
      const ext = path.extname(name).toLowerCase();
      if (!exts.has(ext)) continue;

      const full = path.join(RECORDINGS_DIR, name);
      let stat;
      try { stat = fs.statSync(full); } catch (_) { continue; }
      if (!stat.isFile()) continue;
      if (now - stat.mtimeMs < maxAgeMs) continue;

      try {
        fs.unlinkSync(full);
        removed++;
      } catch (_) { }
    }

    if (removed > 0) {
      console.log(`[Startup] Cleaned ${removed} stale recording artifact(s)`);
    }
  } catch (err) {
    console.warn('[Startup] Failed to cleanup stale recording artifacts:', err?.message || err);
  }
}

// Delete login_audit rows older than 90 days. Keeps the security log bounded —
// we never retain sign-in IP/device data indefinitely. Runs at startup + daily.
function purgeOldLoginAudit() {
  db.query(`DELETE FROM login_audit WHERE created_at < NOW() - INTERVAL '90 days'`)
    .then(r => {
      if (r.rowCount) console.log(`[Audit] Purged ${r.rowCount} login_audit row(s) older than 90 days`);
    })
    .catch(err => console.warn('[Audit] login_audit purge failed:', err.message));
}

// Live-socket "starting soon" reminder for scheduled conferences within ~15
// min of their start time. reminder_sent guards against double-firing across
// ticks. There is no push provider here, so this only reaches connected clients.
async function sendConferenceReminders() {
  let phase = 'load_due_conferences';
  let activeConference = null;
  try {
    const due = await queries.scheduledConferences.listDueForReminder(15);
    for (const conf of due) {
      activeConference = conf;
      phase = 'filter_recipients';
      const mins = Math.max(1, Math.round((new Date(conf.scheduled_for).getTime() - Date.now()) / 60000));
      const targets = await queries.users.filterIdsWithCapability(
        [conf.created_by, ...(conf.invitee_ids || [])], 'conferences',
      );
      const reminderPayload = {
        conferenceId: conf.id, title: conf.title, scheduledFor: conf.scheduled_for, minutesLeft: mins,
      };
      for (const uid of targets) {
        if (!uid) continue;
        try { emitToUser(uid, 'conference_reminder', reminderPayload); } catch (_) {}
      }
      phase = 'mark_reminder_sent';
      await queries.scheduledConferences.markReminderSent(conf.id);
      activeConference = null;
    }
  } catch (err) {
    logger.warn('Conferences', 'Reminder sweep failed', {
      phase,
      conferenceId: activeConference?.id || null,
      conferenceTitle: activeConference?.title || null,
      errorCode: err?.code || null,
      error: err?.message || String(err),
    });
  }
}

// Live-socket "starting now" notification the moment a scheduled conference's
// start time arrives — distinct from the ~15-min-out reminder above, which
// only covers "soon". start_notified guards against double-firing across
// ticks, independently of reminder_sent.
async function sendConferenceStartNotifications() {
  let phase = 'load_due_conferences';
  let activeConference = null;
  try {
    const due = await queries.scheduledConferences.listDueForStartNotification();
    for (const conf of due) {
      activeConference = conf;
      phase = 'filter_recipients';
      const targets = await queries.users.filterIdsWithCapability(
        [conf.created_by, ...(conf.invitee_ids || [])], 'conferences',
      );
      for (const uid of targets) {
        if (!uid) continue;
        try {
          emitToUser(uid, 'conference_starting', {
            conferenceId: conf.id, title: conf.title, scheduledFor: conf.scheduled_for,
          });
        } catch (_) {}
      }
      phase = 'mark_start_notified';
      await queries.scheduledConferences.markStartNotified(conf.id);
      activeConference = null;
    }
  } catch (err) {
    logger.warn('Conferences', 'Start-notification sweep failed', {
      phase,
      conferenceId: activeConference?.id || null,
      conferenceTitle: activeConference?.title || null,
      errorCode: err?.code || null,
      error: err?.message || String(err),
    });
  }
}

// Minimum durations below which a recording is discarded as noise.
const MIN_RECORDING_DURATION_MS = 4000;
const MIN_VIDEO_RECORDING_DURATION_MS = 5000;

// NOTE: The legacy worker-thread "combine" pipeline (persistRecordingFiles /
// runCombineWorker / processCombineQueue / enqueueCombineJob) was removed — it
// had no callers. Recordings are finalized through the single active Phase-2
// path: recordingQueue.add(() => mediaServer.extractFromRaw(raw, callId)).

function getMinimumRecordingDurationMs(callType = 'audio') {
  return callType === 'video'
    ? MIN_VIDEO_RECORDING_DURATION_MS
    : MIN_RECORDING_DURATION_MS;
}

function shouldDiscardShortRecording(rawRecordingResult, callType = 'audio') {
  const durationMs = Number(rawRecordingResult?.duration || 0);
  if (!(durationMs > 0)) return false;
  return durationMs <= getMinimumRecordingDurationMs(callType);
}

async function discardRecordingArtifacts(callId, rawRecordingResult, reason = 'discarded') {
  if (rawRecordingResult?.recording) {
    try {
      const snapshot = mediaServer.createCombineSnapshot(rawRecordingResult);
      if (snapshot) {
        mediaServer.cleanupSnapshotArtifacts(snapshot);
      }
    } catch (err) {
      console.warn(`[Recording] Failed to cleanup raw artifacts for call ${callId}:`, err?.message || err);
    }
  }

  if (!callId) return;

  try {
    await db.query('DELETE FROM recordings WHERE call_id = $1', [callId]);
    await db.query('DELETE FROM recording_segments WHERE call_id = $1', [callId]);
    await db.query('DELETE FROM recording_metadata WHERE call_id = $1', [callId]);
    console.log(`[Recording] Discarded recording data for call ${callId} (${reason})`);
  } catch (err) {
    console.error(`[Recording] Failed to discard DB recording data for call ${callId}:`, err?.message || err);
  }
}

/** Cancel a pending ring timeout (call was answered/rejected/ended). */
function clearRingTimeout(roomId) {
  const t = ringTimeouts.get(roomId);
  if (t) { clearTimeout(t); ringTimeouts.delete(roomId); }
  callAcks.delete(roomId);
}

/**
 * Lock a call as answered the instant native/JS acceptance reaches the server.
 *
 * This deliberately runs before media/ICE is established. Ringing timeout and
 * call history state must transition on ACCEPT, not on WebRTC success, otherwise
 * slow cold-boot/ICE paths can create false "missed call" records while the
 * users are already connecting or talking.
 */
function markCallAnswered(roomId, source = 'unknown', expectedActive = null) {
  if (!roomId) return null;

  const active = activeCalls.get(roomId);
  if (!active || (expectedActive && !isSameCallAttempt(active, expectedActive))) {
    console.log(`[Call] Accept from ${source} for ${roomId}, but no active call entry was found`);
    return null;
  }
  clearRingTimeout(roomId);

  if (active.startupTimer) {
    clearTimeout(active.startupTimer);
    active.startupTimer = null;
  }

  if (!active.answeredAt) {
    const now = Date.now();
    active.answeredAt = now;
    active.startedAt = now;
    console.log(`[Call] Room ${roomId} marked answered by ${source}`);
  }

  if (active.callId) {
    queries.calls.updateStatus(active.callId, 'ongoing').catch((err) => {
      console.warn(`[Call] Failed to mark call ${active.callId} ongoing after accept:`, err.message);
    });
  }

  rememberCallForRecording(roomId, active);
  return active;
}

/**
 * Durable "this media room belongs to DB call X" memory for recording recovery.
 *
 * WHY: recording capture lives on mediaServer's `room.recording`, but the
 * transcode/composite FINALIZATION (in leave_media_room / disconnect) is gated
 * on finding the call in `activeCalls`. If anything clears `activeCalls` before
 * the last peer leaves (end_call finalizing with a not-yet-linked callId, a
 * cleanup race, etc.), the captured raw .mka/.mkv files are silently orphaned —
 * no composite is ever produced even though the media is on disk.
 *
 * This mirrors the callId/dbRoomId into `finalizedCalls` the instant the DB call
 * is linked to the media-room key, so both finalize paths can ALWAYS recover the
 * real DB callId regardless of how `activeCalls` was emptied. `finalizedCalls`
 * is the map both paths already fall back to; entries are reclaimed on empty
 * (see clearRecordingRecovery) so this does not leak across the unique per-call
 * media-room keys.
 */
function rememberCallForRecording(roomId, active) {
  if (!roomId || !active?.callId) return;
  const prev = finalizedCalls.get(roomId) || {};
  // Don't clobber a richer terminal entry written by finalizeCall.
  if (prev.terminalState && isSameCallAttempt(prev, active)) return;
  finalizedCalls.set(roomId, {
    ...prev,
    _attemptId: active._attemptId ?? prev._attemptId,
    callId: active.callId,
    dbRoomId: active.dbRoomId ?? prev.dbRoomId ?? null,
    callType: active.callType ?? prev.callType ?? 'audio',
    answeredAt: active.answeredAt ?? prev.answeredAt,
    isConference: active.isConference ?? prev.isConference ?? false,
    _recoveryOnly: true,
  });
}

/** Reclaim the recovery entry once a media room is empty and finalized. */
function clearRecordingRecovery(roomId, expectedActive = null) {
  const entry = finalizedCalls.get(roomId);
  if (
    entry &&
    entry._recoveryOnly &&
    !entry.terminalState &&
    (!expectedActive || isSameCallAttempt(entry, expectedActive))
  ) {
    finalizedCalls.delete(roomId);
  }
}

/**
 * Atomically release the active room key only if `expectedActive` still owns
 * it. Timer/grace cleanup is intentionally coupled to that ownership check:
 * a late teardown from call A must not clear call B's ring timer either.
 */
function clearActiveCallIfCurrent(roomId, expectedActive) {
  if (!deleteCallIfCurrent(activeCalls, roomId, expectedActive)) return false;
  if (expectedActive?.startupTimer) {
    clearTimeout(expectedActive.startupTimer);
    expectedActive.startupTimer = null;
  }
  clearRingTimeout(roomId);
  clearReconnectGraceForRoom(roomId, expectedActive);
  return true;
}

function hasSupersedingCallAttempt(roomId, expectedActive) {
  const current = activeCalls.get(roomId);
  return !!current && !isSameCallAttempt(current, expectedActive);
}

/**
 * Start the in-call timer on BOTH parties — exactly once per call.
 *
 * The call clock is measured from active.answeredAt (ring time excluded). EVERY accept
 * path must funnel through here so the timer starts identically whether the call was
 * answered via socket answer_call, a native/REST accept, or a duplicate answer that only
 * needs the sync (receiver already joined the media room via prewarm before answer_call
 * fired). Without this funnel, a receiver who prewarmed the room then accepted natively
 * caused answer_call to dedup-skip BEFORE the timer sync, so neither side's clock started.
 *
 * The caller is synced once (guarded by _timerSynced); the accepter is always (re)synced.
 * Both are idempotent on the client, which just sets its timer to the supplied elapsed value.
 */
function syncCallTimer(roomId, callerSocketId, accepterSocketId) {
  const active = activeCalls.get(roomId);
  if (!active || !active.answeredAt) return;
  const callElapsedSeconds = Math.floor((Date.now() - active.answeredAt) / 1000);
  if (!active._timerSynced) {
    active._timerSynced = true;
    if (callerSocketId) io.to(callerSocketId).emit('call_timer_sync', { roomId, callElapsedSeconds });
  }
  if (accepterSocketId) io.to(accepterSocketId).emit('call_timer_sync', { roomId, callElapsedSeconds });
  console.log(`[Call] Timer sync (elapsed=${callElapsedSeconds}s) → caller=${callerSocketId || 'n/a'}, accepter=${accepterSocketId || 'n/a'}`);
}

/**
 * Conference/group calls can have more than two participants. Once the first
 * invitee has genuinely joined the SFU room, synchronize every media-room
 * member from the same server timestamp. Including roomId lets clients discard
 * a delayed sync from a call that has already ended.
 */
function syncGroupCallTimer(roomId) {
  const active = activeCalls.get(roomId);
  if (!active?.answeredAt) return;
  const callElapsedSeconds = Math.floor((Date.now() - active.answeredAt) / 1000);
  active._timerSynced = true;
  io.to(roomId).emit('call_timer_sync', { roomId, callElapsedSeconds });
  console.log(`[Call] Group timer sync (elapsed=${callElapsedSeconds}s) → room=${roomId}`);
}

/**
 * Centralized call termination handler.
 * Handles database updates, memory cleanup, and pushing notifications.
 * Safe to call multiple times (idempotent for a given callId).
 * 
 * @param {string} roomId 
 * @param {object} opts { reason: 'rejected'|'missed'|'completed'|'cancelled', actorUserId: string, isGroupCall: boolean }
 */
async function finalizeCall(roomId, opts = {}) {
  const {
    reason = 'ended',
    actorUserId = null,
    isGroupCall = false,
    expectedActive = null,
  } = opts;
  const active = activeCalls.get(roomId);

  if (!active || (expectedActive && !isSameCallAttempt(active, expectedActive))) {
    return false; // already finalized, never existed, or this is a stale handler
  }

  const isParticipantOnlyGroupExit = isGroupCall && actorUserId && reason !== 'completed';
  if (active.startupTimer && !isParticipantOnlyGroupExit) {
    clearTimeout(active.startupTimer);
    active.startupTimer = null;
  }

  // Publish the terminal snapshot and release the hot room key BEFORE any DB
  // await. A redial may reuse this room id immediately; old asynchronous work
  // must retain only its captured object, never ownership of the shared key.
  if (!isParticipantOnlyGroupExit) {
    finalizedCalls.set(roomId, {
      _attemptId: active._attemptId,
      callId: active.callId,
      dbRoomId: active.dbRoomId,
      callType: active.callType,
      answeredAt: active.answeredAt,
      isConference: !!active.isConference,
      terminalState: reason,
      terminatedBy: actorUserId,
      terminatedAt: Date.now(),
      _dbPromise: active._dbPromise,
    });
    if (!clearActiveCallIfCurrent(roomId, active)) return false;
  } else if (!isGroupCall) {
    clearRingTimeout(roomId);
  }

  // The online fast path creates the DB row asynchronously. If the user ends
  // the call before that write lands, wait on the captured attempt promise and
  // finalize its row without ever resurrecting it in activeCalls.
  if (!active.callId && active._dbPromise) {
    try { await active._dbPromise; } catch (_) { }
    const terminal = finalizedCalls.get(roomId);
    if (terminal && isSameCallAttempt(terminal, active)) {
      terminal.callId = active.callId;
      terminal.dbRoomId = active.dbRoomId;
    }
  }

  // Database updates and notifications operate on the captured attempt only.
  if (active.callId) {
    try {
      const callRecord = await queries.calls.findById(active.callId).catch(() => null);
      if (isGroupCall && actorUserId && reason !== 'completed') {
        // Group call reject/leave by single user
        await queries.calls.removeParticipant(active.callId, actorUserId).catch(() => {});
        if (active.isConference && Array.isArray(active.targetUserIds)) {
          active.targetUserIds = active.targetUserIds.filter(
            targetUserId => !sameUserId(targetUserId, actorUserId),
          );
        }
        if (active.dbRoomId && callRecord) {
          broadcastGroupCallStatus(active.dbRoomId, roomId, true, callRecord.call_type);
        }
      } else {
        // 1:1 call end or whole group call end
        const dbStatus = reason === 'rejected' ? 'rejected' : (reason === 'missed' ? 'missed' : 'completed');
        await queries.calls.updateStatus(active.callId, dbStatus).catch(() => {});
        
        let durationSec = 0;
        if (reason === 'completed' && active.answeredAt) {
           durationSec = Math.round((Date.now() - active.answeredAt) / 1000);
        }

        if (callRecord && active.dbRoomId) {
          createCallEventMessage(active.dbRoomId, callRecord.initiator_id, callRecord.call_type, reason, durationSec, { isGroup: isGroupCall });
        }
      }
    } catch (err) {
      console.error('[Call] DB finalization error:', err.message);
    }
  }

  return true;
}

/**
 * A conference remains joinable after its first attendee answers. Late
 * invitations therefore cannot use the ordinary "active.answeredAt means the
 * ring is stale" rule used by 1:1 and social group calls.
 */
function isPendingConferenceInvite(active, userId) {
  if (!active?.isConference || !userId) return false;
  const uid = String(userId);
  const wasInvited = Array.isArray(active.targetUserIds)
    && active.targetUserIds.some(targetId => sameUserId(targetId, uid));
  const alreadyJoined = active.joinedUserIds instanceof Set
    && [...active.joinedUserIds].some(joinedId => sameUserId(joinedId, uid));
  return wasInvited && !alreadyJoined;
}

/**
 * AUTHORITATIVE call state for a room — the single source of truth a device
 * checks before it rings or accepts. FCM/socket "incoming_call" messages are only
 * hints; this (pure in-memory, O(1)) is the truth.
 *
 *   ringing  → still ringing, may be answered
 *   answered → already answered (possibly on another device) — stop ringing
 *   self_declined → rejected by the user checking the state — stop ringing
 *   finalized → rejected / cancelled / missed / completed — stop ringing
 *
 * `answerable` is the only flag a client needs to decide "keep this panel / allow
 * Accept"; everything that isn't `ringing` means "dismiss".
 */
function resolveCallState(roomId, checkingUserId = null) {
  if (!roomId) return { state: 'ended', answerable: false };
  const active = activeCalls.get(roomId);
  if (active) {
    if (isPendingConferenceInvite(active, checkingUserId)) {
      return { state: 'ringing', answerable: true };
    }
    if (active.answeredAt) return { state: 'answered', answerable: false };
    return { state: 'ringing', answerable: true };
  }
  
  // Not active anymore. Check finalizedCalls for rich reason.
  const finalized = finalizedCalls.get(roomId);
  if (finalized) {
    if (checkingUserId && finalized.terminatedBy === checkingUserId && finalized.terminalState === 'rejected') {
      return { state: 'self_declined', answerable: false, reason: finalized.terminalState };
    }
    return { state: 'finalized', answerable: false, reason: finalized.terminalState };
  }

  // Not active and not finalized recently → never-existed or expired.
  return { state: 'ended', answerable: false };
}

/**
 * Fast-path teardown fan-out to ALL of a user's devices for a room that is no
 * longer ringable (e.g. they declined on one device — dismiss the rest).
 *
 * This is a SPEED optimization only; correctness never depends on it arriving or
 * being ordered, because Accept is server-validated (resolveCallState) and clients
 * reconcile any visible panel on (re)connect. Covers live sockets (call_ended) and
 * offline-now-reconnect-later (queueCallEndedForUser).
 */
function notifyCallEndedToUserDevices(userId, roomId, reason = 'ended') {
  if (!userId || !roomId) return;
  console.log(`[Call] notifyCallEndedToUserDevices: userId=${userId}, roomId=${roomId}, reason=${reason}`);
  try { io.to('user:' + userId).emit('call_ended', { roomId, reason }); } catch (_) { }
  queueCallEndedForUser(userId, roomId);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// signToken → src/modules/auth/auth.service.js
// isValidUserId → src/shared/validation  (both imported above)

function getLocalIp() {
  const os = require('os');
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

// ANNOUNCED_IP env var allows overriding the IP advertised to WebRTC clients.
// Set it to the public IP (e.g. 105.96.0.56) when clients connect from the internet.
// Leave unset to auto-detect the local LAN IP (default for internal LAN use).
const SERVER_IP = process.env.ANNOUNCED_IP || getLocalIp();
const SERVER_START_TIME = Date.now();

// ---------------------------------------------------------------------------
// REST routes -- health check (public, no auth required)
// ---------------------------------------------------------------------------

app.get('/api/health', async (req, res) => {
  const uptimeMs = Date.now() - SERVER_START_TIME;
  let dbOk = false;
  try {
    await db.query('SELECT 1');
    dbOk = true;
  } catch (_err) {
    // DB unreachable — still return 200 with degraded status so load
    // balancers get a response; callers can inspect the payload.
  }
  const status = dbOk ? 'ok' : 'degraded';
  res.status(dbOk ? 200 : 503).json({
    status,
    uptime: uptimeMs,
    uptimeHuman: `${Math.floor(uptimeMs / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m ${Math.floor((uptimeMs % 60000) / 1000)}s`,
    db: dbOk ? 'ok' : 'unreachable',
    timestamp: new Date().toISOString(),
  });
});


// ---------------------------------------------------------------------------
// REST routes -- auth  (register / login / forgot-password flow)
// ---------------------------------------------------------------------------
app.use(require('./src/modules/auth/auth.routes')({
  db, queries, io, notifyWorkspaceAdmins, BCRYPT_ROUNDS,
}));

// ── REST modules ──
app.use(require('./src/modules/contacts/contactRequests.routes')({ emitToUser }));
app.use(require('./src/modules/users/users.routes')({ io, notifyWorkspaceAdmins }));
app.use(require('./src/modules/recordings/recordings.routes'));
app.use(require('./src/modules/conferences/conferences.routes')({ emitToUser }));
app.use(require('./src/modules/ptt/ptt.routes')());

// Auth middleware (authMiddleware/adminMiddleware/superadminMiddleware/
// invalidateAdminCache) lives in src/modules/auth/auth.middleware.js.


// adminMiddleware / superadminMiddleware / invalidateAdminCache + the
// admin-role cache live in src/modules/auth/auth.middleware.js.

// Transcoding queue status — any authenticated user can check their call's status
app.get('/api/transcoding/status/:callId', authMiddleware, (req, res) => {
  const job = recordingQueue.getJobStatus(req.params.callId);
  if (!job) return res.json({ status: 'unknown' });
  res.json({
    status: job.status,
    queuedAt: job.queuedAt,
    startedAt: job.startedAt,
    doneAt: job.doneAt,
    queueSize: recordingQueue.size,
  });
});



// ---------------------------------------------------------------------------
// Helper: how many peers in a media room still have a live socket behind them
// ---------------------------------------------------------------------------
/**
 * `getRoomStats().peerCount` counts media peers, and a media peer outlives its
 * socket. When an app is force-closed the server only learns the socket is
 * dead once ping/pong expires (up to 15s), and the peer is then held longer
 * still by the reconnect grace. For that whole window a room everybody has
 * already left keeps reporting peers.
 *
 * That window is what made a group show "call in progress" with nobody in it,
 * and what let Join hand somebody a room whose transports were already being
 * torn down — which surfaces on the client as create_transport never
 * answering. Counting only peers with a live socket closes it.
 */
function liveMediaPeerCount(mediasoupRoomId) {
  const stats = mediaServer.getRoomStats(mediasoupRoomId);
  if (!stats) return 0;
  let live = 0;
  for (const p of stats.peers) {
    const socketId = mediaServer.peers?.get(p.id)?.socketId;
    if (socketId && io.sockets.sockets.get(socketId)) live++;
  }
  return live;
}

// ---------------------------------------------------------------------------
// Helper: resolve a database userId to a live socketId
// ---------------------------------------------------------------------------
function resolveSocketId(userId) {
  // Return the LAST matching entry (most recently added socket).
  // Also verify the socket is actually alive via io.sockets.sockets.
  let found = null;
  for (const [sid, u] of connectedUsers.entries()) {
    if (sameUserId(u.userId, userId)) {
      if (io.sockets.sockets.get(sid)) {
        found = sid; // keep going — last live match wins
      } else {
        // Stale socket — clean it up
        connectedUsers.delete(sid);
      }
    }
  }
  return found;
}

/**
 * True when a user is already attached to an active media call.
 * This must run before emitting incoming_call/push notifications so a second
 * caller hears "busy" without waking or interrupting the callee's current call.
 */
function isUserBusyInActiveCall(userId, excludeRoomId = null) {
  if (!userId) return false;
  const uid = String(userId);

  // Ringing/connecting calls have no media peer yet. Participant ownership on
  // activeCalls is authoritative during that window — except for an entry old
  // enough that some teardown path evidently failed to release it; see
  // STALE_CALL_TTL_MS. The periodic sweeper reclaims those independently.
  for (const [roomId, active] of activeCalls.entries()) {
    if (excludeRoomId && roomId === excludeRoomId) continue;
    if (isStaleActiveCall(active)) continue;
    if (isUserParticipantInCall(active, uid)) return true;
  }

  for (const [sid, u] of connectedUsers.entries()) {
    if (String(u.userId) !== uid) continue;
    const peer = mediaServer.peers?.get(sid);
    if (!peer?.roomId) continue;
    if (excludeRoomId && peer.roomId === excludeRoomId) continue;
    const active = activeCalls.get(peer.roomId);
    if (
      active &&
      (!peer.peer?.callAttemptId || isCallAttemptId(active, peer.peer.callAttemptId))
    ) return true;
  }

  for (const entry of reconnectGrace.values()) {
    if (String(entry.userId) !== uid) continue;
    if (excludeRoomId && entry.roomId === excludeRoomId) continue;
    if (isCallAttemptId(activeCalls.get(entry.roomId), entry.attemptId)) return true;
  }

  return false;
}

/**
 * True when ANY of a user's connected sockets (not just the one asking) is
 * already a live media peer in this exact room. Needed because a 1:1 call
 * rings every device the callee is signed into — if they answer on device A
 * and then dismiss the still-ringing device B, B's reject_call must not be
 * allowed to tear down the call A is actually in.
 */
function isUserActivePeerInRoom(userId, roomId) {
  if (!userId || !roomId) return false;
  const uid = String(userId);
  const active = activeCalls.get(roomId);
  for (const [sid, u] of connectedUsers.entries()) {
    const peer = mediaServer.peers?.get(sid);
    if (
      String(u.userId) === uid &&
      peer?.roomId === roomId &&
      (!peer.peer?.callAttemptId || isCallAttemptId(active, peer.peer.callAttemptId))
    ) return true;
  }
  return false;
}


// ---------------------------------------------------------------------------
// Helper: create a call event message in the room chat (module-level so it
// can be called from both REST endpoints and Socket.IO event handlers).
// opts: { isGroup, joinedUserId, joinedUserName }
// ---------------------------------------------------------------------------
async function createCallEventMessage(dbRoomId, initiatorId, callType, callStatus, durationSeconds, opts = {}) {
  if (!dbRoomId || !initiatorId) return null;
  try {
    // An ephemeral room is only the FK anchor for a conference. Its user-facing
    // history comes from calls/session_kind, never from normal room messages.
    // Keeping these events out also prevents conference lifecycle noise from
    // leaking into chat feeds and message notifications.
    const room = await queries.rooms.findById(dbRoomId).catch(() => null);
    if (room?.is_ephemeral) return null;

    const initiator = await queries.users.findById(initiatorId).catch(() => null);
    const initiatorName = initiator?.username || 'Someone';
    const typeLabel = callType === 'video' ? 'Video' : 'Audio';
    const isGroup = !!opts.isGroup;

    let contentObj;
    switch (callStatus) {
      case 'completed':
        if (durationSeconds && durationSeconds > 0) {
          const mins = Math.floor(durationSeconds / 60);
          const secs = durationSeconds % 60;
          const durStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
          contentObj = { callType, status: 'completed', duration: durationSeconds, text: `${typeLabel} call · ${durStr}`, initiatorId, initiatorName, isGroup };
        } else {
          contentObj = { callType, status: 'completed', duration: 0, text: `${typeLabel} call`, initiatorId, initiatorName, isGroup };
        }
        break;
      case 'missed':
        contentObj = { callType, status: 'missed', text: `Missed ${typeLabel.toLowerCase()} call`, initiatorId, initiatorName, isGroup };
        break;
      case 'rejected':
        contentObj = { callType, status: 'rejected', text: `${typeLabel} call declined`, initiatorId, initiatorName, isGroup };
        break;
      case 'cancelled':
        contentObj = { callType, status: 'cancelled', text: `${typeLabel} call cancelled`, initiatorId, initiatorName, isGroup };
        break;
      case 'started':
        contentObj = { callType, status: 'started', text: `${initiatorName} started a ${typeLabel.toLowerCase()} call`, initiatorId, initiatorName, isGroup };
        break;
      case 'joined': {
        const joinedName = opts.joinedUserName || 'Someone';
        const joinedId = opts.joinedUserId || initiatorId;
        contentObj = { callType, status: 'joined', text: `${joinedName} joined the call`, initiatorId, initiatorName, isGroup, joinedUserId: joinedId, joinedUserName: joinedName };
        break;
      }
      default:
        contentObj = { callType, status: callStatus, text: `${typeLabel} call`, initiatorId, initiatorName, isGroup };
    }

    const content = JSON.stringify(contentObj);
    const messageSenderId = callStatus === 'joined' && opts.joinedUserId ? opts.joinedUserId : initiatorId;

    const msg = await queries.messages.create({
      roomId: dbRoomId,
      senderId: messageSenderId,
      content,
      messageType: 'call',
    });
    console.log(`[Call] Created call event message: ${callStatus} in room ${dbRoomId}`);

    // Broadcast the call event message to all room participants
    const participants = await queries.rooms.getParticipants(dbRoomId);
    const payload = {
      id: msg.id, roomId: dbRoomId, room_id: dbRoomId,
      senderId: messageSenderId, sender_id: messageSenderId,
      content: msg.content, message_type: 'call',
      file_url: null, created_at: msg.created_at, edited_at: null,
    };
    const senderUser = callStatus === 'joined' && opts.joinedUserId
      ? await queries.users.findById(opts.joinedUserId).catch(() => null)
      : initiator;
    if (senderUser) {
      payload.sender_username = senderUser.username;
      payload.sender = senderUser.username;
    }

    for (const [sid, u] of connectedUsers.entries()) {
      if (participants.some(p => sameUserId(p.id, u.userId))) {
        io.to(sid).emit('room_message', payload);
      }
    }
    return msg;
  } catch (err) {
    console.error('[Call] Failed to create call event message:', err.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// REST: Instant call accept/reject (called by native IncomingCallActivity
// over HTTP so the caller gets immediate feedback without waiting for
// React Native to boot on the receiver side).
// ---------------------------------------------------------------------------

// AUTHORITATIVE call-state read. A device that received an incoming-call trigger
// (FCM/socket) validates against THIS before it keeps ringing or accepts — the
// trigger is only a hint, this is the truth. Pure in-memory, so it's instant.
app.get('/api/call/state', authMiddleware, async (req, res) => {
  const roomId = String(req.query.roomId || '');
  if (!roomId) return res.status(400).json({ error: 'roomId required' });
  const s = resolveCallState(roomId, req.userId);
  // A user already busy in a different call can't answer this one either.
  const active = activeCalls.get(roomId);
  // s.answerable is already false whenever there's nothing to answer (no
  // active call, wrong state, etc.) — skip the DB round trip in that case,
  // since this is a hot, frequently-polled endpoint.
  const hasCapability = s.answerable
    ? await queries.users.hasCapability(req.userId, active?.isConference ? 'conferences' : 'calls')
    : false;
  const answerable = hasCapability && s.answerable && !isUserBusyInActiveCall(req.userId, roomId);
  res.json({ state: s.state, answerable, reason: s.reason });
});

app.post('/api/call/accept', authMiddleware, async (req, res) => {
  const { callerId, roomId } = req.body || {};
  if (!callerId || !roomId) {
    return res.status(400).json({ error: 'callerId and roomId required' });
  }

  // AUTHORITY GATE: verify existence and membership before mutating call state.
  // A stale FCM action can never resurrect a dead call, and possession of a
  // room id alone can never accept somebody else's call.
  const isGroupRoom = String(roomId).startsWith('group_call_');
  const pendingActive = activeCalls.get(roomId);
  if (!pendingActive) {
    const s = resolveCallState(roomId, req.userId);
    console.log(`[Call REST] Accept REFUSED for ${roomId} — not active (state=${s.state})`);
    return res.status(409).json({ ok: false, reason: 'call_not_active', state: s.state });
  }
  const requiredCapability = pendingActive.isConference ? 'conferences' : 'calls';
  if (!(await queries.users.hasCapability(req.userId, requiredCapability))) {
    return res.status(403).json({ ok: false, reason: 'capability_not_enabled' });
  }

  if (pendingActive.dbRoomId) {
    try {
      const members = await queries.rooms.getParticipants(pendingActive.dbRoomId);
      if (!members.some(member => sameUserId(member.id, req.userId))) {
        console.warn(`[Call REST] Unauthorized accept by ${req.userId} for ${roomId}`);
        return res.status(403).json({ ok: false, reason: 'not_a_participant' });
      }
    } catch (error) {
      console.error('[Call REST] Accept membership check failed:', error.message);
      return res.status(503).json({ ok: false, reason: 'membership_check_failed' });
    }
  }

  const active = isGroupRoom
    ? pendingActive
    : markCallAnswered(roomId, 'native-rest-accept');
  if (!active) {
    return res.status(409).json({ ok: false, reason: 'call_not_active' });
  }

  console.log(`[Call REST] Accept for roomId=${roomId}, notifying caller ${callerId}`);

  // Find the caller's socket — callerId may be a userId OR a raw socket.id
  // (the socket incoming_call payload sends socket.id as `from`; the FCM
  // payload sends the userId as `callerId`). Try both lookup strategies.
  let callerSocketId = resolveSocketId(callerId);
  if (!callerSocketId && io.sockets.sockets.get(callerId)) {
    // callerId is itself a live socket.id
    callerSocketId = callerId;
  }
  if (callerSocketId) {
    // Send call_accepted with the roomId as signal so the caller knows
    // the call has been answered and can transition its UI immediately.
    io.to(callerSocketId).emit('call_accepted', { signal: { roomId } });
    console.log(`[Call REST] → call_accepted sent to ${callerSocketId}`);
  } else {
    console.log(`[Call REST] Caller ${callerId} not online — will be handled by socket`);
  }

  // Start the 1:1 timer on the native/REST accept path too. Conference/group
  // acceptance only proves intent; join_media_room starts its clock once the
  // invitee is genuinely present in the SFU room.
  // The socket answer_call
  // path normally does this, but it dedup-skips when the receiver already joined media
  // via prewarm — so without syncing here, the timer never starts. req.userId (set by
  // authMiddleware) is the accepter/receiver. syncCallTimer is once-only via _timerSynced.
  if (!isGroupRoom) {
    syncCallTimer(roomId, callerSocketId, resolveSocketId(req.userId));
  }

  // Also clean up pending notifications for the receiver
  // (we don't know the receiver userId here, but the socket layer handles it)

  res.json({ ok: true });
});

app.post('/api/call/reject', authMiddleware, async (req, res) => {
  const { callerId, roomId } = req.body || {};
  if (!callerId || !roomId) {
    return res.status(400).json({ error: 'callerId and roomId required' });
  }

  const rejecterUserId = req.userId; // set by authMiddleware (JWT)

  // AUTHORITY GATE: same membership check as /api/call/accept — knowing a
  // roomId must never be enough to finalize/reject somebody else's call.
  const pendingActive = activeCalls.get(roomId);
  if (pendingActive?.dbRoomId) {
    try {
      const members = await queries.rooms.getParticipants(pendingActive.dbRoomId);
      if (!members.some(member => sameUserId(member.id, rejecterUserId))) {
        console.warn(`[Call REST] Unauthorized reject by ${rejecterUserId} for ${roomId}`);
        return res.status(403).json({ ok: false, reason: 'not_a_participant' });
      }
    } catch (error) {
      console.error('[Call REST] Reject membership check failed:', error.message);
      return res.status(503).json({ ok: false, reason: 'membership_check_failed' });
    }
  }

  console.log(`[Call REST] Reject for roomId=${roomId} by user ${rejecterUserId}, notifying caller ${callerId}`);

  const isGroupCall = roomId.startsWith('group_call_');
  const finalized = await finalizeCall(roomId, {
    reason: 'rejected',
    actorUserId: rejecterUserId,
    isGroupCall,
    expectedActive: pendingActive || null,
  });
  if (!finalized) {
    return res.status(409).json({ ok: false, reason: 'call_not_active' });
  }

  // DB finalization may have yielded long enough for an immediate redial to
  // claim the reused room id. Never deliver call-A teardown to call B.
  if (hasSupersedingCallAttempt(roomId, pendingActive)) {
    return res.json({ ok: true, superseded: true });
  }

  // Fast-path: dismiss this call on the rejecter's OTHER devices so a queued FCM
  // incoming_call can't ghost-ring them. Best-effort only — Accept is gated and
  // clients reconcile, so correctness never depends on this. 1:1 only (in a group
  // the user's other devices may still legitimately be ringing/in the call).
  if (rejecterUserId && !isGroupCall) {
    notifyCallEndedToUserDevices(rejecterUserId, roomId, 'rejected');
  }

  // Notify the caller
  const callerSocketId = resolveSocketId(callerId);
  if (callerSocketId) {
    io.to(callerSocketId).emit('call_rejected', { roomId });
    console.log(`[Call REST] → call_rejected sent to ${callerSocketId}`);
  } else {
    console.log(`[Call REST] Caller ${callerId} not online`);
  }

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Socket.IO — JWT authentication middleware
// ---------------------------------------------------------------------------
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) {
    return next(new Error('Authentication required'));
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    if (!isValidUserId(decoded.userId)) {
      return next(new Error('Invalid user ID in token'));
    }
    // Socket.IO carries messages, calls and Radio, so password/session
    // revocation must be enforced here as well as on HTTP routes. Otherwise an
    // old JWT can reconnect to the realtime transport after a password change.
    const user = await queries.users.findAuthStatus(decoded.userId);
    if (!user || user.deleted || user.suspended || user.status === 'rejected') {
      return next(new Error('Account no longer available'));
    }
    if (typeof decoded.v === 'number' && decoded.v !== user.token_version) {
      return next(new Error('Session no longer valid'));
    }
    socket.authUserId = decoded.userId; // trusted UUID string, from JWT
    next();
  } catch (_err) {
    return next(new Error('Invalid or expired token'));
  }
});

// Resolve the acting user for call / media handlers.
//
// The socket is ALREADY authenticated at the handshake (io.use sets
// socket.authUserId from the verified JWT). `connectedUsers`, however, is only
// populated by `register_user`, which can arrive a beat AFTER answer_call /
// join_media_room when the receiver is cold-starting — most notably when
// answering on a locked device, where the JS engine boots and the call-accept
// races ahead of registration. Falling back to the JWT identity here makes that
// race impossible to turn into a spurious "Not authenticated" call failure
// (the same reason WhatsApp's accept-while-locked just works). It does NOT
// mutate connectedUsers, so single-session enforcement is untouched —
// register_user fills in the full entry moments later.
function resolveCallActor(socket) {
  const registered = connectedUsers.get(socket.id);
  if (registered?.userId) return registered;
  if (socket.authUserId) {
    return {
      socketId: socket.id,
      userId: socket.authUserId,
      username: socket.username || 'Anonymous',
    };
  }
  return null;
}

// ── Push-to-Talk (control + dedicated media signalling) ─────────────────────
// PTT shares the MediaServer implementation, but never the generic call socket
// events below. Logical channels in a workspace share a PTT-only media peer and
// receive transport; every producer/consumer remains channel-authorized.
const pttService = require('./src/modules/ptt/ptt.service');
const { registerPttHandlers, socketHoldsFloor, evictForCall } = require('./src/modules/ptt/ptt.socket')({
  io,
  mediaServer,
  connectedUsers,
  serverIp: SERVER_IP,
  socketRateLimiter,
});

/**
 * Resolve+verify a client-claimed peerId for the generic mediasoup handlers
 * below (create_transport, produce, consume, ...). Calls use the socket id as
 * their peer id. PTT peers are deliberately rejected by those handlers, but
 * ownership remains enforced here so no future multi-peer call path can reach
 * another socket's transport by supplying a guessed peer id.
 */
function resolveOwnedPeerId(socket, claimedPeerId) {
  if (!claimedPeerId) return socket.id;
  const owned = mediaServer.getPeerIdsForSocket(socket.id);
  return owned.includes(claimedPeerId) ? claimedPeerId : null;
}

// Optional TURN/STUN configuration for Hop in across routed networks. Empty
// defaults use local ICE candidates (same LAN); never embed relay credentials in clients.
const hopIn = require('./src/modules/hop-in/hopIn.socket').createHopIn({
  io, connectedUsers, activeCalls, mediaServer,
  iceServers: JSON.parse(process.env.HOP_IN_ICE_SERVERS_JSON || '[]'),
});

io.on('connection', (socket) => {
  socketVLog('[Socket] Connected:', socket.id, '(userId:', socket.authUserId, ')');

  registerPttHandlers(socket);
  hopIn.register(socket);

  // -- Latency probe -------------------------------------------------------
  // A no-op ack so the client can measure round-trip time over the live socket
  // (no DB, no work). Used only on reconnect to label the "Back online" toast.
  socket.on('latency_ping', (ack) => {
    if (typeof ack === 'function') ack();
  });

  // -- Registration --------------------------------------------------------
  socket.on('register_user', async ({ userId, username, fullName, deviceId, loginSessionId }) => {
    // Enforce: the client-supplied userId MUST match the JWT-authenticated userId.
    // This prevents identity spoofing where a client claims to be a different user.
    if (String(userId) !== String(socket.authUserId)) {
      console.warn(`[Socket] Identity mismatch! JWT userId=${socket.authUserId}, claimed=${userId}. Disconnecting.`);
      socket.disconnect(true);
      return;
    }
    socket.userId = socket.authUserId; // always UUID string
    socket.username = username;
    socket.fullName = fullName || username; // display name for messages

    // Block globally rejected users from reconnecting
    const dbUser = await queries.users.findById(userId).catch(() => null);
    if (dbUser && dbUser.status === 'rejected') {
      socket.emit('account_suspended', { reason: null });
      setTimeout(() => { try { socket.disconnect(true); } catch (_) { } }, 500);
      return;
    }

    // Display identity is database-owned. A client may send cached names for
    // rendering before registration completes, but it may not publish an
    // arbitrary username into PTT presence/producer events.
    if (dbUser) {
      socket.username = dbUser.username || 'Unknown';
      socket.fullName = dbUser.full_name || dbUser.username || 'Unknown';
      socket.profilePicture = dbUser.profile_picture || null;
    }

    // Block workspace-suspended users from reconnecting
    const suspensionInfo = await queries.userWorkspaces.getSuspensionReason(userId).catch(() => null);
    if (suspensionInfo !== null && suspensionInfo !== undefined) {
      socket.emit('account_suspended', { reason: suspensionInfo.suspension_reason || null });
      setTimeout(() => { try { socket.disconnect(true); } catch (_) { } }, 500);
      return;
    }

    socket.deviceId = deviceId || null;

    // A real session. Multiple devices may be online at once, so we do NOT
    // evict other devices. We only clean up a stale connectedUsers entry for
    // the SAME device reconnecting (dead transport).
    connectedUsers.set(socket.id, {
      socketId: socket.id, userId, username: socket.username, fullName: socket.fullName,
      profilePicture: socket.profilePicture || null, loginSessionId: loginSessionId || null,
      deviceId: socket.deviceId,
    });
    for (const [existingId, existingUser] of connectedUsers.entries()) {
      if (existingId === socket.id) continue;
      if (existingUser.userId !== userId) continue;
      const sameDevice =
        (socket.deviceId && existingUser.deviceId === socket.deviceId) ||
        (loginSessionId && existingUser.loginSessionId === loginSessionId);
      if (!sameDevice) continue; // a DIFFERENT device — leave it online (multi-device)
      // Same device reconnecting: drop the stale map entry and close its dead
      // socket if it somehow lingers, without touching any other device.
      const oldSocket = io.sockets.sockets.get(existingId);
      if (oldSocket && oldSocket.connected && oldSocket.id !== socket.id) {
        setTimeout(() => { try { oldSocket.disconnect(true); } catch (_) { } }, 500);
      }
      connectedUsers.delete(existingId);
    }

    socketVLog(`[Socket] ${username} registered (userId=${userId})`);

    if (userId) {
      // Join a per-user room so fan-out can target this user in O(1) via
      // io.to('user:'+userId) instead of scanning every connected socket.
      // With the Redis adapter active this also delivers across instances.
      try { socket.join('user:' + userId); } catch (_) { }
      await queries.users.setOnlineStatus(userId, true).catch(() => { });
      // Notify all clients that this user came online
      io.emit('user_status_changed', { userId, username, is_online: true });

      // Flush any call_ended events the client missed while offline/crashed
      flushCallEndedForUser(userId, socket);
    }

    io.emit('users_online', Array.from(connectedUsers.values()));
  });

  // Explicit logout event — clean up everything for this user session
  socket.on('user_logout', async () => {
    const userId = socket.userId;
    if (!userId) return;
    try {
      // Remove from connected users map
      connectedUsers.delete(socket.id);
      const hasAnotherSession = Array.from(connectedUsers.values())
        .some((connected) => connected.userId === userId);
      if (!hasAnotherSession) {
        await queries.users.setOnlineStatus(userId, false);
        io.emit('user_status_changed', { userId, username: socket.username, is_online: false });
      }
      io.emit('users_online', Array.from(connectedUsers.values()));
      console.log(`[Socket] User ${socket.username} logged out cleanly`);
    } catch (err) {
      console.error('[Socket] Logout cleanup error:', err.message);
    }
  });

  // ---------------------------------------------------------------------------
  // Independent mode support (Private Persistent Tunnel)
  // ---------------------------------------------------------------------------

  // Heartbeat ping/pong — client sends ping, server replies with pong.
  // This keeps the WebSocket connection "warm" so NATs/routers don't drop it.
  socket.on('heartbeat_ping', (data) => {
    socket.emit('heartbeat_pong', { ts: Date.now(), clientTs: data?.ts });
  });

  // Get current online users
  socket.on('get_online_users', () => {
    socket.emit('users_online', Array.from(connectedUsers.values()));
  });

  // -- Typing indicators ---------------------------------------------------
  // `kind` distinguishes the WhatsApp-style activity being shown to the room:
  // 'text' (default, plain typing), 'recording' (voice message), 'uploading'
  // (photo/video/file being sent). Older clients that never send `kind` still
  // work — they just always mean 'text'.
  socket.on('typing_start', async ({ roomId, kind }) => {
    // ✅ SECURITY: Rate limit (prevent typing spam)
    if (!socketRateLimiter.isAllowed(socket.id, 'typing_start')) {
      return;
    }

    const user = connectedUsers.get(socket.id);
    if (!user || !roomId) return;
    const activityKind = ['text', 'recording', 'uploading'].includes(kind) ? kind : 'text';
    try {
      const participants = await queries.rooms.getParticipants(roomId);
      if (!participants.some(p => p.id === user.userId)) return;
      for (const [sid, u] of connectedUsers.entries()) {
        if (sid !== socket.id && participants.some(p => p.id === u.userId)) {
          io.to(sid).emit('user_typing', { roomId, userId: user.userId, username: user.username, kind: activityKind });
        }
      }
    } catch (err) {
      // Fallback: broadcast to all except sender
      socket.broadcast.emit('user_typing', { roomId, userId: user.userId, username: user.username, kind: activityKind });
    }
  });

  socket.on('typing_stop', async ({ roomId }) => {
    const user = connectedUsers.get(socket.id);
    if (!user || !roomId) return;
    try {
      const participants = await queries.rooms.getParticipants(roomId);
      if (!participants.some(p => p.id === user.userId)) return;
      for (const [sid, u] of connectedUsers.entries()) {
        if (sid !== socket.id && participants.some(p => p.id === u.userId)) {
          io.to(sid).emit('user_stopped_typing', { roomId, userId: user.userId, username: user.username });
        }
      }
    } catch (err) {
      socket.broadcast.emit('user_stopped_typing', { roomId, userId: user.userId, username: user.username });
    }
  });

  // -- Group chat ----------------------------------------------------------
  socket.on('send_group_message', async (data) => {
    // ✅ SECURITY: Rate limit (prevent message flooding DoS)
    if (!socketRateLimiter.isAllowed(socket.id, 'send_group_message')) {
      return socket.emit('error_message', { error: 'Too many messages. Please slow down.' });
    }

    const user = connectedUsers.get(socket.id);
    if (!user?.userId || !data.roomId) return;

    // ✅ SECURITY: Block suspended users
    if (await isUserSuspended(user.userId)) {
      return socket.emit('error_message', { error: 'Your account has been suspended. You cannot send messages.' });
    }

    // ✅ SECURITY: Validate message input
    if (typeof data.text !== 'string') {
      return socket.emit('error_message', { error: 'Message must be text' });
    }

    const cleanText = String(data.text).trim();

    // Check message length (min 1, max 5000 characters)
    if (cleanText.length === 0) {
      return socket.emit('error_message', { error: 'Message cannot be empty' });
    }
    if (cleanText.length > 5000) {
      return socket.emit('error_message', { error: 'Message is too long (max 5000 characters)' });
    }

    // Verify sender is a member of this room and discover whether this is the
    // short-lived chat backing a live conference. Conference chat must never
    // behave like a normal room message (notifications/history/global feeds).
    let room = null;
    let roomMembers = [];
    try {
      room = await queries.rooms.findById(data.roomId);
      if (!room) return socket.emit('error_message', { error: 'Room not found' });
      const members = await queries.rooms.getParticipants(data.roomId);
      roomMembers = members;
      if (!members.some(p => sameUserId(p.id, user.userId))) {
        return socket.emit('error_message', { error: 'Not a member of this room' });
      }
      if (room.is_ephemeral && !mediaServer.hasPeer(`group_call_${data.roomId}`, socket.id)) {
        return socket.emit('error_message', { error: 'Join the conference before sending messages' });
      }
      const requiredCapability = room.is_ephemeral ? 'conferences' : 'messages';
      if (!(await queries.users.hasCapability(user.userId, requiredCapability))) {
        return socket.emit('error_message', {
          error: room.is_ephemeral
            ? 'Conferences are not enabled for this account'
            : 'Messages are not enabled for this account',
        });
      }
    } catch (err) {
      return socket.emit('error_message', { error: 'Room verification failed' });
    }

    // ✅ SECURITY: Only pass explicitly required fields (no spread operator)
    const replyToId = isValidUserId(data.replyToId) ? data.replyToId : null;
    // Mentions exist only in durable groups. Each one is re-validated against
    // the room's real membership and the message text (see normalizeMentions),
    // so a client cannot ping someone outside the room or behind a fake name.
    const mentionsAllowed = room.type === 'group' && !room.is_ephemeral;
    const mentionList = mentionsAllowed
      ? normalizeMentions(data.mentions, roomMembers, user.userId, cleanText)
      : [];
    const mentionsEveryone = mentionsAllowed
      && (data.mentionsEveryone === true || detectsEveryone(cleanText));
    const payload = {
      roomId: data.roomId,
      senderId: user.userId,
      sender: user.username,
      socketId: socket.id,
      timestamp: Date.now(),
      text: cleanText,  // Use validated/sanitized text
      file_url: data.file_url || null,  // Validate file URL if present
      messageType: data.messageType || 'text',
      ephemeral: !!room.is_ephemeral,
      clientMessageId: normalizeClientMessageId(data.clientMessageId),
      mentions: mentionList,
      mentions_everyone: mentionsEveryone,
    };

    // Normal rooms persist messages and delivery state. A conference room is
    // a live meeting channel: keeping its chat in the messages table lets a
    // crash/restart leak meeting chatter into history before the end-of-call
    // purge runs. Give live messages a stable client key, but never store them.
    if (payload.ephemeral) {
      payload.messageId = `conference:${data.roomId}:${socket.id}:${payload.timestamp}`;
      payload.id = payload.messageId;
      payload.created_at = new Date(payload.timestamp).toISOString();
    } else if (data.roomId && user?.userId) {
      try {
        const msg = await queries.messages.create({
          roomId: data.roomId,
          senderId: user.userId,
          content: cleanText,  // ✅ Use sanitized text
          messageType: 'text',
          replyToId,
          mentions: mentionList,
          mentionsEveryone,
        });
        payload.messageId = msg.id;
        payload.id = msg.id;
        payload.created_at = msg.created_at;
        payload.reply_to_id = msg.reply_to_id || null;
        // Fetch parent message preview for the broadcast payload
        if (msg.reply_to_id) {
          try {
            const parent = await queries.messages.findById(msg.reply_to_id);
            if (parent) {
              const parentSender = await db.query('SELECT username FROM users WHERE id=$1', [parent.sender_id]);
              payload.reply_to_sender = parentSender.rows[0]?.username || null;
              payload.reply_to_content = parent.content || null;
              payload.reply_to_type = parent.message_type || null;
            }
          } catch { /* non-fatal */ }
        }
      } catch (err) {
        console.error('[Message] Save error:', err.message);
        return socket.emit('error_message', {
          error: 'Message could not be saved. Please try again.',
        });
      }
    }

    if (payload.ephemeral) {
      // Conference chat belongs to the live SFU session, not to every device
      // signed into an invited account. The normal group-message fan-out below
      // deliberately selects one "latest" socket per user; that is correct for
      // durable chat, but wrong for a meeting because the latest socket may be
      // a desktop/phone that never joined this conference while the actual
      // meeting device receives nothing. Restrict both sending and delivery to
      // sockets that are currently peers in this conference's media room.
      const conferenceMediaRoomId = `group_call_${data.roomId}`;
      const activeConference = activeCalls.get(conferenceMediaRoomId);
      if (!mediaServer.hasPeer(conferenceMediaRoomId, socket.id)) {
        return socket.emit('error_message', {
          error: 'Join the conference before sending meeting messages',
        });
      }
      if (!activeConference?.isConference || !activeConference.callId) {
        return socket.emit('error_message', { error: 'This conference is no longer active' });
      }
      try {
        const entry = await queries.conferenceArchives.addEntry({
          callId: activeConference.callId,
          userId: user.userId,
          entryType: 'message',
          content: cleanText,
        });
        if (!entry) throw new Error('Conference session not found');
        payload.messageId = String(entry.id);
        payload.id = String(entry.id);
        payload.created_at = entry.created_at;
        payload.timestamp = new Date(entry.created_at).getTime();
      } catch (error) {
        console.error('[Conference] archive message failed:', error.message);
        return socket.emit('error_message', { error: 'Meeting message could not be saved' });
      }
      io.to(conferenceMediaRoomId).emit('receive_group_message', payload);
      return;
    }

    // Create 'sent' status rows for every recipient
    if (!payload.ephemeral && payload.messageId && data.roomId && user?.userId) {
      try {
        const participants = await queries.rooms.getParticipants(data.roomId);
        for (const p of participants) {
          if (p.id !== user.userId) {
            await queries.messages.setStatus(payload.messageId, p.id, 'sent');
          }
        }
      } catch (err) {
        console.error('[Message] Status insert error:', err.message);
      }
    }

    // Emit normal messages only to room participants (not broadcast globally).
    if (data.roomId) {
      try {
        const participants = await queries.rooms.getParticipants(data.roomId);
        const enabledMessageIds = new Set(await queries.users.filterIdsWithCapability(
          participants.map(participant => participant.id), 'messages',
        ));
        const participantIds = participants
          .filter(participant => sameUserId(participant.id, user.userId) || enabledMessageIds.has(String(participant.id)))
          .map(participant => participant.id);
        const onlineUserIds = new Set();

        // Determine which participants have at least one live socket, then
        // fan out to ALL of each user's sockets — a user logged in on phone
        // + desktop must get the message on both, not just whichever socket
        // happened to be the last one iterated (that used to pick a single
        // "most recent" socket per user and drop every other device).
        for (const [sid, u] of connectedUsers.entries()) {
          if (participantIds.includes(u.userId) && io.sockets.sockets.get(sid)) {
            onlineUserIds.add(u.userId);
          }
        }
        for (const uid of onlineUserIds) {
          emitToUser(uid, 'receive_group_message', payload);
        }
        // Offline participants have no live channel to reach them on; they'll
        // pick this message up via get_messages_since next time they connect.
      } catch (err) {
        // Fail closed. A database/read failure must never expand a room-scoped
        // message to every connected user.
        console.error('[Message] Participant lookup failed; delivery aborted:', err.message);
        socket.emit('error_message', {
          error: 'Message was saved but could not be delivered yet.',
        });
      }
    }
  });

  // Shared notes are durable conference artifacts. They are broadcast only to
  // current media peers and later exposed through the participant-scoped
  // conference archive endpoint; they never become ordinary room messages.
  socket.on('conference_add_note', async ({ roomId, text } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_add_note')) {
      reply({ success: false, error: 'Too many notes. Please wait.' });
      return;
    }
    const user = connectedUsers.get(socket.id);
    const conferenceRoomId = roomId == null ? '' : String(roomId);
    const mediaRoomId = `group_call_${conferenceRoomId}`;
    const cleanText = typeof text === 'string' ? text.trim() : '';
    if (!user?.userId || !conferenceRoomId || !cleanText) {
      reply({ success: false, error: 'A note is required' });
      return;
    }
    if (cleanText.length > 5000) {
      reply({ success: false, error: 'Note is too long (max 5000 characters)' });
      return;
    }
    const active = activeCalls.get(mediaRoomId);
    if (!active?.isConference || !active.callId || !sameUserId(active.dbRoomId, conferenceRoomId)) {
      reply({ success: false, error: 'This conference is no longer active' });
      return;
    }
    if (!mediaServer.hasPeer(mediaRoomId, socket.id)) {
      reply({ success: false, error: 'Join the conference before adding notes' });
      return;
    }
    try {
      const entry = await queries.conferenceArchives.addEntry({
        callId: active.callId,
        userId: user.userId,
        entryType: 'note',
        content: cleanText,
      });
      if (!entry) throw new Error('Conference session not found');
      const payload = {
        id: String(entry.id),
        roomId: conferenceRoomId,
        authorId: String(user.userId),
        author: user.username || 'Participant',
        text: cleanText,
        timestamp: new Date(entry.created_at).getTime(),
      };
      io.to(mediaRoomId).emit('conference_note_added', payload);
      reply({ success: true, note: payload });
    } catch (error) {
      console.error('[Conference] add note failed:', error.message);
      reply({ success: false, error: 'Note could not be saved' });
    }
  });

  // -- Private chat --------------------------------------------------------
  socket.on('send_private_message', async ({ recipientId, text, roomId, replyToId: rawReplyToId, clientMessageId: rawClientMessageId }, callback) => {
    const replyToId = isValidUserId(rawReplyToId) ? rawReplyToId : null;
    // ✅ SECURITY: Rate limit (prevent message flooding DoS)
    if (!socketRateLimiter.isAllowed(socket.id, 'send_private_message')) {
      return socket.emit('error_message', { error: 'Too many messages. Please slow down.' });
    }

    const user = connectedUsers.get(socket.id);
    if (!user?.userId) return;

    // ✅ SECURITY: Block suspended users
    if (await isUserSuspended(user.userId)) {
      return socket.emit('error_message', { error: 'Your account has been suspended. You cannot send messages.' });
    }
    if (!(await queries.users.hasCapability(user.userId, 'messages'))) {
      return socket.emit('error_message', { error: 'Messages are not enabled for this account' });
    }

    // ✅ SECURITY: Validate message input
    if (typeof text !== 'string') {
      return socket.emit('error_message', { error: 'Message must be text' });
    }

    const cleanText = String(text).trim();

    if (cleanText.length === 0) {
      return socket.emit('error_message', { error: 'Message cannot be empty' });
    }
    if (cleanText.length > 5000) {
      return socket.emit('error_message', { error: 'Message is too long (max 5000 characters)' });
    }

    // ── Lazy room creation: if no roomId, create the room now (first message) ──
    let resolvedRoomId = roomId;
    if (!resolvedRoomId && recipientId && isValidUserId(recipientId)) {
      try {
        if (!(await canUsersCommunicate(user.userId, recipientId))) {
          return socket.emit('error_message', {
            error: 'Cannot send: this user is not one of your contacts',
          });
        }
        const { room, created } = await queries.rooms.findOrCreatePrivate(user.userId, recipientId);
        resolvedRoomId = room.id;
        if (created) {
          // Notify both users of the new room so their UI updates
          const participants = await queries.rooms.getParticipants(room.id);
          const roomPayload = { ...room, participants, type: 'private' };
          socket.emit('private_chat_started', { room: roomPayload, otherUser: participants.find(p => p.id !== user.userId) || null });
          let recipientSid = null;
          for (const [sid, u] of connectedUsers.entries()) {
            if (u.userId === recipientId) recipientSid = sid;
          }
          if (recipientSid) {
            io.to(recipientSid).emit('private_chat_started', { room: roomPayload, otherUser: participants.find(p => p.id !== recipientId) || null });
          }
        }
      } catch (err) {
        console.error('[Message] Lazy room creation error:', err.message);
        return socket.emit('error_message', { error: 'Failed to create chat room' });
      }
    }

    // Resolve the recipient from authoritative room membership. Never trust a
    // client-provided recipientId for an existing room: otherwise a member could
    // persist a message in room A while delivering its plaintext/push to user B.
    let resolvedRecipientId = null;
    try {
      const room = await queries.rooms.findById(resolvedRoomId);
      if (!room || room.type !== 'private') {
        return socket.emit('error_message', { error: 'Private room not found' });
      }
      const members = await queries.rooms.getParticipants(resolvedRoomId);
      const recipientResolution = resolvePrivateRecipient(members, user.userId, recipientId);
      if (!recipientResolution.ok) {
        return socket.emit('error_message', { error: recipientResolution.error });
      }
      resolvedRecipientId = recipientResolution.recipientId;
      if (!(await queries.users.hasCapability(resolvedRecipientId, 'messages'))) {
        return socket.emit('error_message', { error: 'Messages are not enabled for this user' });
      }
    } catch (err) {
      return socket.emit('error_message', { error: 'Room verification failed' });
    }

    const messageData = {
      text: cleanText,
      sender: user.fullName || user.username, // display name
      sender_username: user.username,          // login handle
      socketId: socket.id,
      senderId: user?.userId || null,
      recipientId: resolvedRecipientId,
      roomId: resolvedRoomId,
      timestamp: Date.now(),
      clientMessageId: normalizeClientMessageId(rawClientMessageId),
    };

    if (resolvedRoomId && user?.userId) {
      try {
        const msg = await queries.messages.create({
          roomId: resolvedRoomId,
          senderId: user.userId,
          content: cleanText,
          messageType: 'text',
          replyToId,
        });
        messageData.messageId = msg.id;
        messageData.id = msg.id;
        messageData.created_at = msg.created_at;
        messageData.reply_to_id = msg.reply_to_id || null;
        if (msg.reply_to_id) {
          try {
            const parent = await queries.messages.findById(msg.reply_to_id);
            if (parent) {
              const parentSender = await db.query('SELECT username FROM users WHERE id=$1', [parent.sender_id]);
              messageData.reply_to_sender = parentSender.rows[0]?.username || null;
              messageData.reply_to_content = parent.content || null;
              messageData.reply_to_type = parent.message_type || null;
            }
          } catch { /* non-fatal */ }
        }
      } catch (err) {
        console.error('[Message] Save error:', err.message);
        if (typeof callback === 'function') {
          callback({ error: 'Message could not be saved. Please try again.' });
        }
        return socket.emit('error_message', {
          error: 'Message could not be saved. Please try again.',
        });
      }
    }

    messageData.delivery_status = 'sent';
    if (messageData.messageId && resolvedRecipientId) {
      queries.messages
        .setStatus(messageData.messageId, resolvedRecipientId, 'sent')
        .catch(err => console.error('[Message] Status insert error:', err.message));
    }

    // Is the recipient online on ANY device? (multi-device: deliver to all)
    let recipientOnline = false;
    for (const [sid, u] of connectedUsers.entries()) {
      if (!sameUserId(u.userId, resolvedRecipientId)) continue;
      if (!io.sockets.sockets.get(sid)) { connectedUsers.delete(sid); continue; }
      recipientOnline = true;
    }

    if (recipientOnline) {
      // Fan out to every one of the recipient's devices so the message appears
      // on all of them, not just the most-recently-connected one.
      emitToUser(resolvedRecipientId, 'receive_private_message', messageData);
    }
    // An offline recipient has no live channel to reach them on; they'll pick
    // this message up via get_messages_since next time they connect.

    // Echo back to sender (with resolved roomId so UI can update)
    socket.emit('receive_private_message', messageData);

    // Also return via callback if caller wants the resolved roomId (lazy creation)
    if (typeof callback === 'function') callback({ roomId: resolvedRoomId });
  });

  // -- Message history -----------------------------------------------------
  socket.on('get_messages', async ({ roomId, before, limit }, callback) => {
    // socket.authUserId (set at connection time from the verified JWT) rather
    // than connectedUsers, which is only populated after register_user's 3
    // awaits resolve. A client re-fetching immediately after reconnect — the
    // normal flow on a flaky connection — landed in that window and got back
    // an empty array indistinguishable from "this room truly has no history",
    // which the client then rendered and never retried.
    const trustedUserId = socket.authUserId;
    if (!trustedUserId || !roomId) {
      if (typeof callback === 'function') callback([]);
      return;
    }
    try {
      if (!(await queries.users.hasCapability(trustedUserId, 'messages'))) {
        if (typeof callback === 'function') callback([]);
        return;
      }
      const members = await queries.rooms.getParticipants(roomId);
      if (!members.some(p => p.id === trustedUserId)) {
        if (typeof callback === 'function') callback([]);
        return;
      }
      const messages = await queries.messages.listByRoom(roomId, { limit, before, userId: trustedUserId });
      if (typeof callback === 'function') callback(messages);
    } catch (err) {
      console.error('[Message] get_messages error:', err.message);
      if (typeof callback === 'function') callback([]);
    }
  });

  // -- Incremental message sync (caching support) --------------------------
  // Client sends the timestamp of the last message it has cached.
  // Server returns only messages created after that timestamp.
  socket.on('get_messages_since', async ({ roomId, since, limit }, callback) => {
    // See get_messages above — same connectedUsers-populate race.
    const trustedUserId = socket.authUserId;
    if (!trustedUserId || !roomId) {
      if (typeof callback === 'function') callback({ success: false, messages: [] });
      return;
    }
    try {
      if (!(await queries.users.hasCapability(trustedUserId, 'messages'))) {
        if (typeof callback === 'function') callback({ success: false, messages: [] });
        return;
      }
      const members = await queries.rooms.getParticipants(roomId);
      if (!members.some(p => p.id === trustedUserId)) {
        if (typeof callback === 'function') callback({ success: false, messages: [] });
        return;
      }
      let messages;
      if (since) {
        messages = await queries.messages.listNewSince(roomId, since, trustedUserId);
      } else {
        // No cache — fall back to full history (most recent first, reversed by client)
        messages = await queries.messages.listByRoom(roomId, { limit: limit || 50, userId: trustedUserId });
      }
      if (typeof callback === 'function') callback({ success: true, messages });
    } catch (err) {
      console.error('[Message] get_messages_since error:', err.message);
      if (typeof callback === 'function') callback({ success: false, messages: [] });
    }
  });

  // -- Delivery confirmation ------------------------------------------------
  socket.on('message_delivered', async ({ messageId }) => {
    const user = connectedUsers.get(socket.id);
    if (!user?.userId || !messageId) return;
    try {
      const msg = await queries.messages.findById(messageId);
      if (!msg?.room_id || !msg.sender_id) return;
      const members = await queries.rooms.getParticipants(msg.room_id);
      if (!isAuthorizedMessageRecipient(members, user.userId, msg.sender_id)) return;

      await queries.messages.setStatus(messageId, user.userId, 'delivered');

      // Find the original message to notify the sender
      if (msg.sender_id) {
        // Fan out to every one of the sender's devices so the ✓✓ appears on all
        // of them (status updates are idempotent — safe to deliver widely).
        emitToUser(msg.sender_id, 'message_status_update', {
          messageId,
          userId: user.userId,
          status: 'delivered',
          roomId: msg.room_id,
        });
      }
    } catch (err) {
      console.error('[Message] Delivered status error:', err.message);
    }
  });

  // -- Read receipts -------------------------------------------------------
  socket.on('mark_read', async ({ roomId }) => {
    const user = connectedUsers.get(socket.id);
    if (!user?.userId || !roomId) return;
    // Reject pending/client-generated IDs (e.g., "pending-uuid")
    if (typeof roomId === 'string' && roomId.startsWith('pending-')) return;
    try {
      const members = await queries.rooms.getParticipants(roomId);
      if (!members.some(p => p.id === user.userId)) return;
      await queries.messages.markRoomAs(roomId, user.userId, 'read');

      // Notify all senders in this room that their messages were read
      const recentMessages = await queries.messages.listByRoom(roomId, { limit: 50, userId: user.userId });
      const senderIds = [...new Set(recentMessages.filter(m => m.sender_id !== user.userId).map(m => m.sender_id))];
      for (const senderId of senderIds) {
        // Fan out across all of the sender's devices (idempotent status update).
        emitToUser(senderId, 'message_status_update', {
          roomId,
          userId: user.userId,
          status: 'read',
        });
      }
    } catch (err) {
      console.error('[Message] Mark read error:', err.message);
    }
  });

  // -- Reactions -----------------------------------------------------------
  // Toggle a per-user emoji reaction on a message. Reacting with the same
  // emoji again removes it; a different emoji replaces the previous one.
  socket.on('react_message', async ({ messageId, emoji }) => {
    const user = connectedUsers.get(socket.id);
    if (!user?.userId || !messageId || typeof emoji !== 'string' || !emoji) return;
    try {
      const msg = await queries.messages.findById(messageId);
      if (!msg) return;
      const members = await queries.rooms.getParticipants(msg.room_id);
      if (!members.some(p => p.id === user.userId)) return;

      const existing = await db.query(
        `SELECT emoji FROM message_reactions WHERE message_id = $1 AND user_id = $2`,
        [messageId, user.userId],
      );
      if (existing.rows.length && existing.rows[0].emoji === emoji) {
        await db.query(
          `DELETE FROM message_reactions WHERE message_id = $1 AND user_id = $2`,
          [messageId, user.userId],
        );
      } else {
        await db.query(
          `INSERT INTO message_reactions (message_id, user_id, emoji)
           VALUES ($1, $2, $3)
           ON CONFLICT (message_id, user_id) DO UPDATE SET emoji = $3, created_at = NOW()`,
          [messageId, user.userId, emoji],
        );
      }

      const { rows: reactions } = await db.query(
        `SELECT mr.user_id AS "userId", mr.emoji,
                COALESCE(u.full_name, u.username) AS username,
                mr.created_at AS "createdAt"
         FROM message_reactions mr
         JOIN users u ON u.id = mr.user_id
         WHERE mr.message_id = $1
         ORDER BY mr.created_at`,
        [messageId],
      );
      for (const p of members) {
        emitToUser(p.id, 'message_reaction_updated', { messageId, roomId: msg.room_id, reactions });
      }
    } catch (err) {
      console.error('[Reaction] error:', err.message);
    }
  });

  // -- Pinning -------------------------------------------------------------
  // One pinned message per room (a new pin replaces the previous one).
  socket.on('pin_message', async ({ messageId, pinned }) => {
    const user = connectedUsers.get(socket.id);
    if (!user?.userId || !messageId) return;
    try {
      const msg = await queries.messages.findById(messageId);
      if (!msg) return;
      const members = await queries.rooms.getParticipants(msg.room_id);
      if (!members.some(p => p.id === user.userId)) return;

      if (pinned) {
        await db.query(
          `UPDATE messages SET is_pinned = FALSE, pinned_at = NULL, pinned_by = NULL
           WHERE room_id = $1 AND is_pinned = TRUE`,
          [msg.room_id],
        );
        await db.query(
          `UPDATE messages SET is_pinned = TRUE, pinned_at = NOW(), pinned_by = $2 WHERE id = $1`,
          [messageId, user.userId],
        );
      } else {
        await db.query(
          `UPDATE messages SET is_pinned = FALSE, pinned_at = NULL, pinned_by = NULL WHERE id = $1`,
          [messageId],
        );
      }

      for (const p of members) {
        emitToUser(p.id, 'message_pin_updated', {
          roomId: msg.room_id,
          messageId,
          pinned: !!pinned,
          pinnedBy: user.username,
        });
      }
    } catch (err) {
      console.error('[Pin] error:', err.message);
    }
  });

  // -- Rooms ---------------------------------------------------------------

  socket.on('get_rooms', async ({ userId, limit, before }, callback) => {
    try {
      // Use the trusted, JWT-verified identity set at connection time — never
      // the client-supplied userId. socket.userId is only populated after
      // register_user fires, so falling back to it (or to the payload) would
      // let an unregistered-but-authenticated socket request another user's
      // rooms by simply passing their id. socket.authUserId is set for every
      // authenticated connection regardless of register_user.
      const trustedUserId = socket.authUserId;
      if (!trustedUserId) {
        if (typeof callback === 'function') callback({ error: 'Not authenticated' });
        return;
      }
      const messagesEnabled = await queries.users.hasCapability(trustedUserId, 'messages');
      // Optional pagination: a positive `limit` returns one page (newest first);
      // `before` is the cursor (last_message_at of the last row the client has).
      // No limit ⇒ full list (back-compat). Participants come folded into the
      // query now, so there is no per-room N+1 round-trip anymore.
      const pageLimit = (typeof limit === 'number' && limit > 0) ? Math.min(limit, 100) : null;
      let rooms = await queries.rooms.listByUser(trustedUserId, {
        limit: pageLimit,
        before: before || null,
      });
      // Capture pagination before redacting message-derived fields below.
      const nextCursor =
        pageLimit && rooms.length === pageLimit
          ? rooms[rooms.length - 1].last_message_at
          : null;
      if (!messagesEnabled) {
        rooms = rooms.map(room => ({
          ...room,
          last_message: null,
          last_message_at: null,
          last_message_type: null,
          last_message_sender: null,
          last_message_sender_id: null,
          unread_count: 0,
        }));
      }
      // Only advertise a cursor when a full page came back (more may exist).
      if (typeof callback === 'function') callback({ rooms, nextCursor });
    } catch (err) {
      console.error('[Rooms] get_rooms error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  socket.on('start_private_chat', async ({ targetUserId }, callback) => {
    try {
      const trustedUserId = socket.userId;

      if (!isValidUserId(targetUserId)) {
        if (typeof callback === 'function') callback({ error: 'Invalid target user ID' });
        return;
      }
      const [senderMessages, targetMessages, senderCalls, targetCalls] = await Promise.all([
        queries.users.hasCapability(trustedUserId, 'messages'),
        queries.users.hasCapability(targetUserId, 'messages'),
        queries.users.hasCapability(trustedUserId, 'calls'),
        queries.users.hasCapability(targetUserId, 'calls'),
      ]);
      if (!(senderMessages && targetMessages) && !(senderCalls && targetCalls)) {
        if (typeof callback === 'function') callback({ error: 'No shared communication feature is enabled' });
        return;
      }
      if (targetUserId === trustedUserId) {
        if (typeof callback === 'function') callback({ error: 'Cannot create chat with yourself' });
        return;
      }

      // Check if a private room already exists — if so, always return it (preserve existing convos)
      const existingRoom = await queries.rooms.findPrivate(trustedUserId, targetUserId);
      if (existingRoom) {
        const participants = await queries.rooms.getParticipants(existingRoom.id);
        const otherUser = participants.find(p => p.id !== trustedUserId) || null;
        if (typeof callback === 'function') callback({ room: { ...existingRoom, participants }, otherUser });
        return;
      }

      // No existing room — the same relationship rule drives discovery,
      // messages, calls and group invitations.
      const targetUser = await queries.users.findById(targetUserId);
      if (!(await canUsersCommunicate(trustedUserId, targetUserId))) {
        if (typeof callback === 'function') callback({
          room: null,
          otherUser: targetUser,
          canChat: false,
          error: 'not_a_contact',
        });
        return;
      }

      // Allowed — return null room (lazy: room created on first message)
      if (typeof callback === 'function') callback({ room: null, otherUser: targetUser, canChat: true });
    } catch (err) {
      console.error('[Rooms] start_private_chat error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  socket.on('create_group', async ({ name, memberIds, createdBy, ephemeral }, callback) => {
    try {
      // ✅ SECURITY: Always use the authenticated user from the JWT, never trust client input
      // Verify that if client provided createdBy, it matches the authenticated user
      if (createdBy && !sameUserId(createdBy, socket.userId)) {
        console.warn(`[Socket] create_group: Identity mismatch! JWT userId=${socket.userId}, claimed=${createdBy}. Rejecting.`);
        if (typeof callback === 'function') callback({ error: 'Impersonation attempt blocked' });
        return;
      }

      const trustedUserId = socket.userId;
      const validMemberIds = [...new Set(
        (memberIds || [])
          .filter(id => isValidUserId(id) && !sameUserId(id, trustedUserId))
          .map(id => String(id)),
      )];

      if (!(await queries.users.hasCapability(trustedUserId, ephemeral ? 'conferences' : 'messages'))) {
        if (typeof callback === 'function') callback({ error: 'This feature is not enabled for your account' });
        return;
      }
      const permissions = await Promise.all(
        validMemberIds.map(memberId => canUsersCommunicate(trustedUserId, memberId)),
      );
      if (permissions.some(allowed => !allowed)) {
        if (typeof callback === 'function') callback({
          error: 'One or more selected people are not in your contacts',
        });
        return;
      }

      // ephemeral (conferences): the room is a real DB row (needed as the FK
      // anchor for calls/recordings) but is never returned by get_rooms, so it
      // never shows up as a persistent group in anyone's chat list.
      const room = await queries.rooms.create({ type: 'group', name, createdBy: trustedUserId, ephemeral: !!ephemeral });
      await queries.rooms.addParticipant(room.id, trustedUserId, 'admin');
      await Promise.all(
        validMemberIds.map((memberId) => queries.rooms.addParticipant(room.id, memberId, 'member')),
      );
      await recordGroupIntroductions(room.id);
      const participants = await queries.rooms.getParticipants(room.id);
      if (typeof callback === 'function') callback({ room: { ...room, participants } });
    } catch (err) {
      console.error('[Rooms] create_group error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  // ── Promote a member to admin (only admins can do this) ──
  socket.on('promote_admin', async ({ roomId, targetUserId }, callback) => {
    try {
      const actorId = socket.userId;
      if (!actorId || !roomId || !targetUserId) {
        return typeof callback === 'function' && callback({ error: 'Missing required fields' });
      }
      // Verify the actor is an admin of this room
      const participants = await queries.rooms.getParticipants(roomId);
      const actor = participants.find(p => p.id === actorId);
      if (!actor || actor.role !== 'admin') {
        return typeof callback === 'function' && callback({ error: 'Only admins can promote members' });
      }
      const target = participants.find(p => p.id === targetUserId);
      if (!target) {
        return typeof callback === 'function' && callback({ error: 'User is not in this room' });
      }
      await queries.rooms.updateRole(roomId, targetUserId, 'admin');
      // ✅ SECURITY: Invalidate admin cache when role changes
      invalidateAdminCache(targetUserId);

      const updatedParticipants = await queries.rooms.getParticipants(roomId);
      // Notify all participants
      for (const [sid, u] of connectedUsers.entries()) {
        if (updatedParticipants.some(p => p.id === u.userId)) {
          io.to(sid).emit('room_updated', { roomId, participants: updatedParticipants });
        }
      }
      console.log(`[Rooms] ${actorId} promoted ${targetUserId} to admin in room ${roomId}`);
      if (typeof callback === 'function') callback({ success: true, participants: updatedParticipants });
    } catch (err) {
      console.error('[Rooms] promote_admin error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  // ── Kick a member from the group (only admins can do this) ──
  socket.on('kick_member', async ({ roomId, targetUserId }, callback) => {
    // ✅ SECURITY: Rate limit (prevent member spam)
    if (!socketRateLimiter.isAllowed(socket.id, 'kick_member')) {
      return typeof callback === 'function' && callback({ error: 'Too many requests. Please slow down.' });
    }

    try {
      const actorId = socket.userId;
      if (!actorId || !roomId || !targetUserId) {
        return typeof callback === 'function' && callback({ error: 'Missing required fields' });
      }

      // ✅ SECURITY: Validate target user ID format
      if (!isValidUserId(targetUserId)) {
        console.warn(`[Rooms] Invalid target user ID in kick_member: ${targetUserId}`);
        return typeof callback === 'function' && callback({ error: 'Invalid user ID' });
      }

      // Verify the actor is an admin of this room
      const participants = await queries.rooms.getParticipants(roomId);
      const actor = participants.find(p => p.id === actorId);
      if (!actor || actor.role !== 'admin') {
        return typeof callback === 'function' && callback({ error: 'Only admins can kick members' });
      }
      const target = participants.find(p => p.id === targetUserId);
      if (!target) {
        return typeof callback === 'function' && callback({ error: 'User is not in this room' });
      }
      // Cannot kick another admin
      if (target.role === 'admin') {
        return typeof callback === 'function' && callback({ error: 'Cannot kick an admin' });
      }
      await queries.rooms.removeParticipant(roomId, targetUserId);
      // ✅ SECURITY: Invalidate admin cache in case kicked user was admin
      invalidateAdminCache(targetUserId);

      const updatedParticipants = await queries.rooms.getParticipants(roomId);

      // Insert a system message so all members see the event in chat history
      const actorUser = await queries.users.findById(actorId);
      const targetUser = await queries.users.findById(targetUserId);
      const systemContent = `${actorUser?.full_name || actorUser?.username || 'Admin'} removed ${targetUser?.full_name || targetUser?.username || 'a member'} from the group`;
      let systemMsg = null;
      try {
        const { rows: msgRows } = await db.query(
          `INSERT INTO messages (room_id, sender_id, content, message_type)
           VALUES ($1, NULL, $2, 'system') RETURNING *`,
          [roomId, systemContent],
        );
        systemMsg = msgRows[0];
      } catch (sysErr) {
        console.warn('[Rooms] Could not insert system message:', sysErr.message);
      }

      // Notify all remaining participants (room update + system message)
      for (const [sid, u] of connectedUsers.entries()) {
        if (updatedParticipants.some(p => p.id === u.userId)) {
          io.to(sid).emit('room_updated', { roomId, participants: updatedParticipants });
          if (systemMsg) {
            io.to(sid).emit('system_message', { roomId, message: systemMsg });
          }
        }
      }
      // Notify the kicked user
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.userId === targetUserId) {
          io.to(sid).emit('kicked_from_room', { roomId });
          if (systemMsg) {
            io.to(sid).emit('system_message', { roomId, message: systemMsg });
          }
        }
      }
      console.log(`[Rooms] ${actorId} kicked ${targetUserId} from room ${roomId}`);
      if (typeof callback === 'function') callback({ success: true, participants: updatedParticipants });
    } catch (err) {
      console.error('[Rooms] kick_member error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  // ── Edit group name / description (admins only) ──
  socket.on('update_room_info', async (payload, callback) => {
    const reply = (result) => { if (typeof callback === 'function') callback(result); };
    if (!socketRateLimiter.isAllowed(socket.id, 'update_room_info')) {
      return reply({ error: 'Too many requests. Please slow down.' });
    }
    try {
      const { roomId, name, description } = payload || {};
      const actorId = socket.authUserId || socket.userId;
      if (!actorId || !roomId) return reply({ error: 'Missing required fields' });

      const room = await queries.rooms.findById(roomId);
      if (!room || room.type !== 'group' || room.is_ephemeral) {
        return reply({ error: 'Only groups have editable info' });
      }
      const participants = await queries.rooms.getParticipants(roomId);
      const actor = participants.find(p => sameUserId(p.id, actorId));
      if (!actor || actor.role !== 'admin') {
        return reply({ error: 'Only admins can edit group info' });
      }

      const changes = {};
      if (name !== undefined) {
        const cleanName = String(name ?? '').trim().replace(/\s+/g, ' ');
        if (cleanName.length === 0) return reply({ error: 'Group name cannot be empty' });
        if (cleanName.length > 80) return reply({ error: 'Group name is too long (max 80 characters)' });
        if (cleanName !== room.name) changes.name = cleanName;
      }
      if (description !== undefined) {
        const cleanDescription = String(description ?? '').trim();
        if (cleanDescription.length > 500) {
          return reply({ error: 'Description is too long (max 500 characters)' });
        }
        const next = cleanDescription.length ? cleanDescription : null;
        if (next !== (room.description ?? null)) changes.description = next;
      }

      if (Object.keys(changes).length === 0) {
        return reply({
          success: true,
          room: { id: room.id, name: room.name, description: room.description ?? null },
        });
      }

      const updated = await queries.rooms.updateInfo(roomId, changes);

      // A line in the history for each change, the same way a kick is recorded.
      const actorUser = await queries.users.findById(actorId);
      const actorName = actorUser?.full_name || actorUser?.username || 'An admin';
      const lines = [];
      if (changes.name !== undefined) {
        lines.push(`${actorName} changed the group name to "${changes.name}"`);
      }
      if (changes.description !== undefined) {
        lines.push(changes.description
          ? `${actorName} changed the group description`
          : `${actorName} removed the group description`);
      }
      const systemMessages = [];
      for (const content of lines) {
        try {
          const { rows } = await db.query(
            `INSERT INTO messages (room_id, sender_id, content, message_type)
             VALUES ($1, NULL, $2, 'system') RETURNING *`,
            [roomId, content],
          );
          if (rows[0]) systemMessages.push(rows[0]);
        } catch (sysErr) {
          console.warn('[Rooms] Could not insert room-info system message:', sysErr.message);
        }
      }

      const info = { roomId, name: updated?.name ?? room.name, description: updated?.description ?? null };
      for (const [sid, u] of connectedUsers.entries()) {
        if (participants.some(p => sameUserId(p.id, u.userId))) {
          io.to(sid).emit('room_updated', info);
          for (const message of systemMessages) {
            io.to(sid).emit('system_message', { roomId, message });
          }
        }
      }
      console.log(`[Rooms] ${actorId} updated info for room ${roomId}: ${Object.keys(changes).join(', ')}`);
      reply({ success: true, room: { id: roomId, name: info.name, description: info.description } });
    } catch (err) {
      console.error('[Rooms] update_room_info error:', err.message);
      reply({ error: 'Could not update group info' });
    }
  });

  // ── Per-room notification mode: 'all' | 'mentions' | 'none' ──
  socket.on('set_room_notification_mode', async (payload, callback) => {
    const reply = (result) => { if (typeof callback === 'function') callback(result); };
    try {
      const { roomId, mode } = payload || {};
      const userId = socket.authUserId || socket.userId;
      if (!userId || !roomId || !ROOM_NOTIFICATION_MODES.includes(mode)) {
        return reply({ error: 'Invalid request' });
      }
      const members = await queries.rooms.getParticipants(roomId);
      if (!members.some(p => sameUserId(p.id, userId))) {
        return reply({ error: 'Not a member of this room' });
      }
      await queries.roomNotificationModes.set(userId, roomId, mode);
      reply({ success: true, mode });
    } catch (err) {
      console.error('[Rooms] set_room_notification_mode error:', err.message);
      reply({ error: 'Could not save notification setting' });
    }
  });

  socket.on('get_room_notification_modes', async (payload, callback) => {
    const reply = typeof payload === 'function' ? payload : callback;
    try {
      const userId = socket.authUserId || socket.userId;
      if (!userId) {
        if (typeof reply === 'function') reply({ error: 'Not authenticated' });
        return;
      }
      const modes = await queries.roomNotificationModes.listForUser(userId);
      if (typeof reply === 'function') reply({ success: true, modes });
    } catch (err) {
      console.error('[Rooms] get_room_notification_modes error:', err.message);
      if (typeof reply === 'function') reply({ error: 'Could not load notification settings' });
    }
  });

  // ── Leave group ──────────────────────────────────────────────
  socket.on('leave_group', async ({ roomId }, callback) => {
    try {
      const userId = socket.userId;
      if (!userId || !roomId) {
        return typeof callback === 'function' && callback({ error: 'Missing required fields' });
      }
      const participants = await queries.rooms.getParticipants(roomId);
      const self = participants.find(p => p.id === userId);
      if (!self) {
        return typeof callback === 'function' && callback({ error: 'You are not in this group' });
      }

      await queries.rooms.removeParticipant(roomId, userId);

      // If the leaving user was admin, check if any other admin remains
      const remaining = await queries.rooms.getParticipants(roomId);
      if (self.role === 'admin' && remaining.length > 0) {
        const hasAdmin = remaining.some(p => p.role === 'admin');
        if (!hasAdmin) {
          // Auto-promote a random remaining member
          const promoted = remaining[Math.floor(Math.random() * remaining.length)];
          await queries.rooms.updateRole(roomId, promoted.id, 'admin');
          console.log(`[Rooms] Auto-promoted ${promoted.id} to admin in room ${roomId}`);
        }
      }

      const updatedParticipants = await queries.rooms.getParticipants(roomId);
      // Notify remaining participants
      for (const [sid, u] of connectedUsers.entries()) {
        if (updatedParticipants.some(p => p.id === u.userId)) {
          io.to(sid).emit('room_updated', { roomId, participants: updatedParticipants });
        }
      }
      console.log(`[Rooms] ${userId} left room ${roomId}`);
      if (typeof callback === 'function') callback({ success: true });
    } catch (err) {
      console.error('[Rooms] leave_group error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });

  // ── Add members to group ─────────────────────────────────────
  socket.on('add_member_to_group', async ({ roomId, userIds }, callback) => {
    // ✅ SECURITY: Rate limit (prevent member spam)
    if (!socketRateLimiter.isAllowed(socket.id, 'add_member_to_group')) {
      return typeof callback === 'function' && callback({ error: 'Too many requests. Please slow down.' });
    }

    try {
      const actorId = socket.userId;
      if (!actorId || !roomId || !Array.isArray(userIds) || userIds.length === 0) {
        return typeof callback === 'function' && callback({ error: 'Missing required fields' });
      }

      // ✅ SECURITY: Validate all user IDs before processing
      const validUserIds = userIds.filter(uid => {
        if (!isValidUserId(uid)) {
          console.warn(`[Rooms] Invalid user ID format in add_member_to_group: ${uid}`);
          return false;
        }
        return true;
      });

      if (validUserIds.length === 0) {
        return typeof callback === 'function' && callback({ error: 'No valid user IDs provided' });
      }

      const participants = await queries.rooms.getParticipants(roomId);
      const actor = participants.find(p => p.id === actorId);
      if (!actor || actor.role !== 'admin') {
        return typeof callback === 'function' && callback({ error: 'Only admins can add members' });
      }

      const permissions = await Promise.all(
        validUserIds.map(userId => canUsersCommunicate(actorId, userId)),
      );
      if (permissions.some(allowed => !allowed)) {
        return typeof callback === 'function' && callback({
          error: 'One or more selected people are not in your contacts',
        });
      }

      for (const uid of validUserIds) {
        await queries.rooms.addParticipant(roomId, uid, 'member');
      }
      await recordGroupIntroductions(roomId);

      const updatedParticipants = await queries.rooms.getParticipants(roomId);
      // Notify all participants (including newly added)
      for (const [sid, u] of connectedUsers.entries()) {
        if (updatedParticipants.some(p => p.id === u.userId)) {
          io.to(sid).emit('room_updated', { roomId, participants: updatedParticipants });
        }
      }
      console.log(`[Rooms] ${actorId} added ${validUserIds.length} member(s) to room ${roomId}`);
      if (typeof callback === 'function') callback({ success: true, participants: updatedParticipants });
    } catch (err) {
      console.error('[Rooms] add_member_to_group error:', err.message);
      if (typeof callback === 'function') callback({ error: err.message });
    }
  });


  /**
   * Join a media room (for calls)
   * Security: verify the user is an authorized participant of this call.
   */
  socket.on('join_media_room', async ({ roomId }, callback) => {
    try {
      // Trust the JWT identity if register_user hasn't landed yet (cold-start /
      // locked-device accept race) — see resolveCallActor.
      const user = resolveCallActor(socket);
      if (!user?.userId) return callback({ success: false, error: 'Not authenticated' });
      const username = user.username || 'Anonymous';

      if (typeof roomId !== 'string' || !roomId) {
        return callback({ success: false, error: 'Invalid media room' });
      }

      // A group media room is valid only after start_group_call has created its
      // authoritative active-call entry. This rejects stale notification
      // accepts and prevents arbitrary authenticated clients from creating a
      // phantom `group_call_*` SFU room. 1:1 prewarm behavior is unchanged.
      let active = activeCalls.get(roomId);
      // Socket.IO preserves packet order but does not await async listeners.
      // call_user performs permission checks before publishing activeCalls, so
      // an immediately-following join_media_room can briefly overtake it and
      // produce the false "Not a member of this call" seen on desktop. Give
      // only 1:1 setup a small bounded window to observe the authoritative row.
      if (!active && roomId.startsWith('call_') && !roomId.startsWith('group_call_')) {
        const deadline = Date.now() + 1500;
        while (!active && Date.now() < deadline) {
          await new Promise(resolve => setTimeout(resolve, 25));
          active = activeCalls.get(roomId);
        }
      }
      let authorizedRoomMembers = null;
      const isGroupRoom = roomId.startsWith('group_call_');
      if (isGroupRoom && (!active?.callId || !active.dbRoomId)) {
        return callback({ success: false, error: 'This group call is no longer active' });
      }
      const expectedGroupCallId = isGroupRoom ? active.callId : null;
      const requiredCapability = active?.isConference ? 'conferences' : 'calls';
      if (!(await queries.users.hasCapability(user.userId, requiredCapability))) {
        return callback({
          success: false,
          error: active?.isConference
            ? 'Conferences are not enabled for this account'
            : 'Calls are not enabled for this account',
        });
      }

      // Verify the user is a participant of the backing DB room.
      if (active?.dbRoomId) {
        authorizedRoomMembers = await queries.rooms.getParticipants(active.dbRoomId);
        if (!authorizedRoomMembers.some(p => sameUserId(p.id, user.userId))) {
          console.warn(`[Media] Unauthorized join_media_room attempt by ${user.userId} for room ${roomId}`);
          return callback({ success: false, error: 'Not a member of this call' });
        }
      } else if (!isGroupRoom) {
        // 1:1 prewarm: dbRoomId isn't written yet (call still ringing). The room
        // name alone can't prove membership here — for 1:1 calls it's built from
        // ephemeral socket ids, not stable user ids — so check against the
        // initiator/target pair call_user recorded when the ring started.
        // No `active` at all means nobody ever placed a call to this room id.
        const isRecordedParticipant = !!active && (
          sameUserId(active.initiatorUserId, user.userId) ||
          sameUserId(active.targetUserId, user.userId)
        );
        if (!isRecordedParticipant) {
          console.warn(`[Media] Unauthorized prejoin attempt by ${user.userId} for room ${roomId}`);
          return callback({ success: false, error: 'Not a member of this call' });
        }
      }

      // Look up profile picture for recording avatars
      let profilePicture = null;
      const dbUser = await queries.users.findById(user.userId).catch(() => null);
      profilePicture = dbUser?.profile_picture || null;
      // A locked/background accept can reach this handler before register_user,
      // in which case resolveCallActor only has the JWT user id. Recover the
      // canonical DB username so conference peers/chat never see "Anonymous".
      const participantUsername = dbUser?.username || username;

      const result = await mediaServer.addPeer(
        roomId,
        socket.id,
        participantUsername,
        SERVER_IP,
        profilePicture,
        user.userId,
        getCallAttemptId(active),
      );

      // Membership/profile/router lookup above are asynchronous. A setup
      // rollback may have finalized this call while they were running. Never
      // attach that stale join to a missing or newer conference.
      if (isGroupRoom) {
        const current = activeCalls.get(roomId);
        if (!current?.callId || String(current.callId) !== String(expectedGroupCallId)) {
          mediaServer.removePeer(socket.id);
          return callback({ success: false, error: 'This group call is no longer active' });
        }
        active = current;
      }
      socket.join(roomId);

      // A call always wins over PTT. Radio channels this socket was listening
      // to (or transmitting on) get dropped now that the call's media peer is
      // live, matching ptt:join's busy_in_call refusal in the other direction.
      const evictedPttChannels = evictForCall(socket);
      if (evictedPttChannels.length) {
        socket.emit('ptt:evicted_for_call', { channelIds: evictedPttChannels });
      }

      if (active?.isConference && authorizedRoomMembers) {
        // `hostUserId` is what lets a client label the organizer in the roster.
        // Without it a client can only know whether *it* may invite, which is
        // not the same question and cannot identify anyone else as the host.
        socket.emit('conference_roster', {
          roomId,
          conferenceRoomId: String(active.dbRoomId),
          hostUserId: active.initiatorUserId ? String(active.initiatorUserId) : null,
          participants: authorizedRoomMembers.map(member => ({
            userId: String(member.id),
            username: member.username,
            role: member.role || null,
          })),
        });

        const conferenceMember = authorizedRoomMembers.find(member =>
          sameUserId(member.id, user.userId),
        );
        socket.emit('conference_permissions', {
          roomId,
          conferenceRoomId: String(active.dbRoomId),
          canInvite:
            sameUserId(active.initiatorUserId, user.userId) ||
            conferenceMember?.role === 'admin',
        });
        socket.emit('raised_hands_state', { roomId, hands: raisedHandsSnapshot(roomId, active) });
        // Continuous meeting chat: someone arriving late — or coming back after
        // an app restart — starts from the conversation and notes so far.
        if (active.callId) {
          queries.conferenceArchives.listLiveHistory(active.callId)
            .then(history => socket.emit('conference_session_history', {
              roomId,
              conferenceRoomId: String(active.dbRoomId),
              ...history,
            }))
            .catch(error => console.error('[Conference] session history failed:', error.message));
        }
      }

      // Initialize resource counters for DoS prevention
      userTransportCount.set(socket.id, 0);
      userProducerCount.set(socket.id, 0);

      mediaVLog(`[Media] ${participantUsername} joined room: ${roomId}`);

      let joinedConferenceNow = false;
      if (active?.callId && isGroupRoom) {
        const joiningUserId = String(user.userId);
        if (!(active.joinedUserIds instanceof Set)) {
          active.joinedUserIds = new Set(active.initiatorUserId ? [String(active.initiatorUserId)] : []);
        }
        const wasAlreadyJoined = active.joinedUserIds.has(joiningUserId);
        active.joinedUserIds.add(joiningUserId);
        joinedConferenceNow = !!active.isConference && !wasAlreadyJoined;

        if (active.isConference && !wasAlreadyJoined) {
          if (Array.isArray(active.targetUserIds)) {
            active.targetUserIds = active.targetUserIds.filter(
              targetUserId => !sameUserId(targetUserId, joiningUserId),
            );
          }
        }

        if (sameUserId(joiningUserId, active.initiatorUserId) && active.startupTimer) {
          clearTimeout(active.startupTimer);
          active.startupTimer = null;
        }

        if (!wasAlreadyJoined && !sameUserId(joiningUserId, active.initiatorUserId) && active.dbRoomId) {
          createCallEventMessage(
            active.dbRoomId,
            active.initiatorUserId || joiningUserId,
            active.callType || 'audio',
            'joined',
            0,
            { isGroup: true, joinedUserId: joiningUserId, joinedUserName: participantUsername },
          );
        }

        // A late-join request only proves intent. The conference becomes live
        // when a non-organizer is actually present in the SFU room.
        if (!active.answeredAt && !sameUserId(joiningUserId, active.initiatorUserId)) {
          markCallAnswered(roomId, 'group-media-peer-joined');
        }

        // Media-room membership is the authoritative participant lifecycle.
        // This also covers native/background accepts that bypass join_group_call.
        queries.calls.addParticipant(active.callId, joiningUserId)
          .then(() => queries.calls.answerParticipant(active.callId, joiningUserId))
          .catch(error => console.error('[Conference] participant join bookkeeping failed:', error.message));

        if (active.answeredAt) {
          syncGroupCallTimer(roomId);
        }
        if (active.dbRoomId) {
          broadcastGroupCallStatus(
            active.dbRoomId,
            roomId,
            true,
            active.callType || 'audio',
          );
        }

        if (joinedConferenceNow) {
          queries.conferenceArchives.addEntry({
            callId: active.callId,
            userId: joiningUserId,
            entryType: 'joined',
          }).catch(error => console.error('[Conference] archive join event failed:', error.message));
          socket.to(roomId).emit('conference_participant_joined', {
            roomId,
            conferenceRoomId: active.dbRoomId,
            peerId: socket.id,
            userId: joiningUserId,
            username: participantUsername,
            profilePicture,
          });
        }
      }

      // If this user had a pending reconnect-grace for this room, they just
      // recovered within the window — cancel the deferred peer_left and tell
      // the rest of the room the call is whole again.
      const droppedSocketId = cancelReconnectGrace(roomId, user.userId, active);
      if (droppedSocketId) {
        io.to(roomId).emit('peer_reconnected', {
          userId: user.userId,
          username: participantUsername,
          oldPeerId: droppedSocketId,
          newPeerId: socket.id,
        });
        console.log(`[Reconnect] ${participantUsername} rejoined ${roomId} within grace — call held`);
      }

      callback({
        success: true,
        routerRtpCapabilities: result.routerRtpCapabilities,
        isConference: !!active?.isConference,
        conferenceRoomId: active?.isConference ? active.dbRoomId : null,
        callElapsedSeconds: active?.answeredAt
          ? Math.floor((Date.now() - active.answeredAt) / 1000)
          : 0,
      });
    } catch (error) {
      console.error('[Media] join_media_room error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Set client's RTP capabilities
   */
  socket.on('set_rtp_capabilities', ({ roomId, rtpCapabilities, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      mediaServer.setPeerRtpCapabilities(roomId, peerId, rtpCapabilities);
      callback({ success: true });
    } catch (error) {
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Create WebRTC transport (for sending or receiving)
   * Security: verify peer membership + enforce per-user transport limit.
   */
  socket.on('create_transport', async ({ roomId, direction, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      // Ensure user has joined the media room (peer exists)
      if (!mediaServer.hasPeer(roomId, peerId)) {
        return callback({ success: false, error: 'Not in this media room' });
      }

      // DoS prevention: enforce transport limit per peer (a listen-all-channels
      // PTT session holds several peers per socket, one budget each — this must
      // not be shared across them the way a single call's is).
      const count = userTransportCount.get(peerId) || 0;
      if (count >= MEDIA_LIMITS.MAX_TRANSPORTS_PER_USER) {
        console.warn(`[Media] Transport limit reached for ${peerId} (${count})`);
        return callback({ success: false, error: 'Transport limit reached' });
      }

      const result = await mediaServer.createWebRtcTransport(roomId, peerId, SERVER_IP);

      // Store transport reference
      mediaServer.storePeerTransport(roomId, peerId, result.transport, direction);
      userTransportCount.set(peerId, count + 1);

      callback({
        success: true,
        id: result.id,
        iceParameters: result.iceParameters,
        iceCandidates: result.iceCandidates,
        dtlsParameters: result.dtlsParameters,
      });
    } catch (error) {
      console.error('[Media] create_transport error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Connect transport
   */
  socket.on('connect_transport', async ({ roomId, transportId, dtlsParameters }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      await mediaServer.connectTransport(roomId, transportId, dtlsParameters);
      callback({ success: true });
    } catch (error) {
      console.error('[Media] connect_transport error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Produce media
   * Security: validate kind + rtpParameters, enforce producer limit, verify membership.
   */
  socket.on('produce', async ({ roomId, transportId, kind, rtpParameters, appData, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      // Verify peer is in the room
      if (!mediaServer.hasPeer(roomId, peerId)) {
        return callback({ success: false, error: 'Not in this media room' });
      }

      // Validate kind — only 'audio' or 'video' are legitimate
      if (kind !== 'audio' && kind !== 'video') {
        console.warn(`[Media] Invalid producer kind '${kind}' from ${socket.id}`);
        return callback({ success: false, error: 'Invalid media kind' });
      }

      // ── PTT floor enforcement ──────────────────────────────────────────
      // Half-duplex has to be a server rule, not a UI convention. Without this
      // check a client could simply call produce() and talk over whoever holds
      // the floor, and "one speaker at a time" would hold only for well-behaved
      // apps. Video is refused outright: a PTT channel is a radio.
      //
      // Lifecycle note: the client creates its audio producer on its FIRST
      // granted press (not at join — that would have no floor to check), then
      // keeps it for the session, paused between transmissions. So only the
      // first press of a session pays transport negotiation; later presses are
      // just a resume. Pause/resume is gated in producer_audio_state below.
      if (roomId.startsWith('ptt:')) {
        if (kind !== 'audio') {
          return callback({ success: false, error: 'PTT channels are audio only' });
        }
        if (!socketHoldsFloor(roomId, socket.id)) {
          console.warn(`[PTT] produce refused for ${socket.id} — no floor on ${roomId}`);
          return callback({ success: false, error: 'You do not hold the floor' });
        }
      }

      // Validate rtpParameters structure
      if (!rtpParameters || !Array.isArray(rtpParameters.codecs) || rtpParameters.codecs.length === 0) {
        console.warn(`[Media] Invalid rtpParameters from ${socket.id}`);
        return callback({ success: false, error: 'Invalid rtpParameters' });
      }
      for (const codec of rtpParameters.codecs) {
        if (typeof codec.payloadType !== 'number' || typeof codec.mimeType !== 'string' || typeof codec.clockRate !== 'number') {
          console.warn(`[Media] Malformed codec in rtpParameters from ${socket.id}`);
          return callback({ success: false, error: 'Malformed codec parameters' });
        }
      }

      // Canonicalize source metadata at the trust boundary. Clients may omit
      // it for legacy camera/microphone producers, but may not invent custom
      // source types or attach a screen label to audio.
      const source = appData?.source || (kind === 'audio' ? 'microphone' : 'camera');
      if (!['microphone', 'camera', 'screen'].includes(source)) {
        return callback({ success: false, error: 'Invalid media source' });
      }
      if ((source === 'microphone' && kind !== 'audio') || (source !== 'microphone' && kind !== 'video')) {
        return callback({ success: false, error: 'Media source does not match producer kind' });
      }
      if (source === 'screen' && !activeCalls.get(roomId)?.isConference) {
        return callback({ success: false, error: 'Screen sharing is available in conferences only' });
      }
      if (mediaServer.hasProducerSource(roomId, source, source === 'screen' ? null : peerId)) {
        return callback({
          success: false,
          error: source === 'screen'
            ? 'Another participant is already presenting'
            : `A ${source} producer is already active`,
        });
      }

      const trustedAppData = {...(appData || {}), source};

      // DoS prevention: microphone + camera + optional conference presentation,
      // per peer — see the identical note on the transport counter above.
      const pCount = userProducerCount.get(peerId) || 0;
      if (pCount >= MEDIA_LIMITS.MAX_PRODUCERS_PER_USER) {
        console.warn(`[Media] Producer limit reached for ${peerId} (${pCount})`);
        return callback({ success: false, error: 'Producer limit reached' });
      }

      const user = resolveCallActor(socket);
      mediaVLog(`[Media] Producing ${kind} from ${user?.username || socket.id}`);

      const result = await mediaServer.produce(roomId, peerId, transportId, kind, rtpParameters, trustedAppData);
      userProducerCount.set(peerId, pCount + 1);

      // ── Audio → video upgrade: the call type follows the MEDIA, not the
      // original intent. The first time real video flows into an audio-typed
      // call, promote it to 'video' so the recording label, the chat history
      // message, and the recording min-duration threshold all reflect that this
      // call carried video. One-directional: a pure audio call never produces
      // video, so it stays 'audio' (fixes the recording mislabel).
      if (kind === 'video') {
        const active = activeCalls.get(roomId);
        if (active && active.callType !== 'video') {
          active.callType = 'video';
          rememberCallForRecording(roomId, active);
          if (active.callId) {
            queries.calls.setCallType(active.callId, 'video').catch(err =>
              console.error('[Call] setCallType(video) failed:', err.message));
          }
        }
      }

      socket.to(roomId).emit('new_producer', {
        producerId: result.id,
        peerId,
        // A socket can now be listening to several PTT rooms at once, all
        // sharing one global 'new_producer' listener client-side — it needs
        // this to know which of its channel sessions the event belongs to.
        // Harmless additive field for calls, which only ever have one room.
        roomId,
        userId: user?.userId || null,
        kind,
        username: user?.username,
        paused: false,
        appData: trustedAppData,
      });

      callback({ success: true, id: result.id });
    } catch (error) {
      console.error('[Media] produce error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  // Explicit producer shutdown is required for screen sharing: closing a
  // mediasoup-client Producer is local-only until the application tells the
  // server. Camera/microphone continue using their existing pause lifecycle.
  socket.on('close_producer', async ({roomId, producerId, peerId: claimedPeerId}, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback?.({success: false, error: 'Use dedicated PTT media signalling'});
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback?.({success: false, error: 'Invalid peer'});
      if (!mediaServer.hasPeer(roomId, peerId)) {
        return callback?.({success: false, error: 'Not in this media room'});
      }
      const closed = mediaServer.closeProducer(roomId, peerId, producerId);
      if (!closed) return callback?.({success: false, error: 'Producer not found'});
      userProducerCount.set(peerId, Math.max(0, (userProducerCount.get(peerId) || 1) - 1));
      socket.to(roomId).emit('producer_closed', {
        producerId,
        peerId,
        roomId,
        appData: closed.appData || {},
      });
      callback?.({success: true});
    } catch (error) {
      callback?.({success: false, error: error.message});
    }
  });

  /**
   * Consume (start receiving media from a producer)
   * Security: verify peer membership before allowing consume.
   */
  socket.on('consume', async ({ roomId, producerId, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      if (!mediaServer.hasPeer(roomId, peerId)) {
        return callback({ success: false, error: 'Not in this media room' });
      }
      const result = await mediaServer.consume(roomId, peerId, producerId);
      callback({
        success: true,
        id: result.id,
        producerId: result.producerId,
        kind: result.kind,
        rtpParameters: result.rtpParameters,
        producerPaused: result.producerPaused,
        appData: result.appData,
      });
    } catch (error) {
      console.error('[Media] consume error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Resume consumer (after client is ready)
   */
  socket.on('resume_consumer', async ({ roomId, consumerId, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      await mediaServer.resumeConsumer(roomId, peerId, consumerId);
      callback({ success: true });
    } catch (error) {
      console.error('[Media] resume_consumer error:', error.message);
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Get all existing producers in a room
   */
  socket.on('get_producers', ({ roomId, peerId: claimedPeerId }, callback) => {
    try {
      if (pttService.isPttRoomId(roomId)) {
        return callback({ success: false, error: 'Use dedicated PTT media signalling' });
      }
      const peerId = resolveOwnedPeerId(socket, claimedPeerId);
      if (!peerId) return callback({ success: false, error: 'Invalid peer' });
      const producers = mediaServer.getProducers(roomId, peerId);
      callback({ success: true, producers });
    } catch (error) {
      callback({ success: false, error: error.message });
    }
  });

  /**
   * Relay producer video state (paused/resumed) to other peers in the room.
   * Emitted by client when user toggles camera on/off.
   */
  socket.on('producer_video_state', async ({ roomId, paused }) => {
    if (typeof roomId !== 'string' || !mediaServer.hasPeer(roomId, socket.id)) return;
    if (!mediaServer.hasProducerSource(roomId, 'camera', socket.id)) return;

    // Broadcast before awaiting the worker so rapid taps preserve Socket.IO
    // ordering for every remote UI. The server producer is synchronized just
    // below for bandwidth and late-join state.
    socket.to(roomId).emit('peer_video_state', {
      peerId: socket.id,
      paused: !!paused,
    });
    try {
      await mediaServer.setProducerSourcePaused(
        roomId,
        socket.id,
        'camera',
        !!paused,
      );

      // Track in recording timeline (pause/resume consumer → clean gap)
      mediaServer.trackProducerPause(roomId, socket.id, !!paused).catch(err =>
        console.error('[Recording] trackProducerPause error:', err.message)
      );
    } catch (error) {
      console.error('[Media] producer_video_state error:', error.message);
    }
  });

  /**
   * Relay authoritative microphone state for meeting rosters and tiles. This
   * is intentionally separate from camera state: an audio-only participant
   * remains a first-class conference member even while muted.
   */
  socket.on('producer_audio_state', async ({ roomId, muted, peerId: claimedPeerId }) => {
    if (pttService.isPttRoomId(roomId)) return;
    const peerId = resolveOwnedPeerId(socket, claimedPeerId);
    if (!peerId) return;
    if (typeof roomId !== 'string' || !mediaServer.hasPeer(roomId, peerId)) return;
    if (!mediaServer.hasProducerSource(roomId, 'microphone', peerId)) return;
    // On a PTT channel this event IS the transmit switch: the producer lives for
    // the whole session and unmuting is what puts voice on the air. So unmuting
    // requires the floor, exactly like produce() does. Muting is always allowed —
    // going silent is never the dangerous direction, and refusing it could strand
    // a live microphone if the floor lapsed a moment before the release arrived.
    // Floor ownership is per-socket (you can transmit on only one channel at a
    // time regardless of how many you're peered into), so this stays socket.id.
    if (roomId.startsWith('ptt:') && !muted && !socketHoldsFloor(roomId, socket.id)) {
      console.warn(`[PTT] unmute refused for ${socket.id} — no floor on ${roomId}`);
      return;
    }
    socket.to(roomId).emit('peer_audio_state', {
      peerId,
      muted: !!muted,
    });
    try {
      await mediaServer.setProducerSourcePaused(
        roomId,
        peerId,
        'microphone',
        !!muted,
      );
    } catch (error) {
      console.error('[Media] producer_audio_state error:', error.message);
    }
  });

  /**
   * Raise/lower hand — a pure roster UI signal, no mediasoup state involved.
   * Membership-gated the same way as producer_audio_state/producer_video_state
   * above so only genuine participants of this media room can raise a hand in
   * it. Sender applies its own state optimistically on click; the ordered
   * `raised_hands_state` snapshot then reconciles every device, including the
   * sender's own. The per-peer `hand_raised` relay stays for older clients.
   */
  socket.on('raise_hand', ({ roomId, raised }) => {
    if (typeof roomId !== 'string' || !mediaServer.hasPeer(roomId, socket.id)) return;
    const user = connectedUsers.get(socket.id);
    const active = activeCalls.get(roomId);
    const userKey = user?.userId != null ? String(user.userId) : null;
    const nextRaised = !!raised;
    let raisedAt = null;
    if (active && userKey) {
      if (!(active.raisedHands instanceof Map)) active.raisedHands = new Map();
      const previous = active.raisedHands.get(userKey);
      if (nextRaised) {
        // A repeated "raised" (a reconnecting device) keeps its place in line.
        raisedAt = previous?.raisedAt || Date.now();
        active.raisedHands.set(userKey, { raisedAt, username: user.username || null });
      } else {
        active.raisedHands.delete(userKey);
      }
      if (active.isConference && active.callId && !!previous !== nextRaised) {
        queries.conferenceArchives.addEntry({
          callId: active.callId,
          userId: user.userId,
          entryType: nextRaised ? 'hand_raised' : 'hand_lowered',
        }).catch(error => console.error('[Conference] archive hand event failed:', error.message));
      }
    }
    socket.to(roomId).emit('hand_raised', {
      peerId: socket.id,
      userId: user?.userId ?? null,
      username: user?.username ?? null,
      raised: nextRaised,
      raisedAt,
    });
    if (active && userKey) broadcastRaisedHands(roomId, active);
  });

  /**
   * Meet-style reactions: a transient, membership-gated broadcast. The sender
   * is included so their own reaction floats up through the same path.
   */
  socket.on('conference_reaction', ({ roomId, emoji } = {}) => {
    if (typeof roomId !== 'string' || !CONFERENCE_REACTIONS.has(emoji)) return;
    if (!mediaServer.hasPeer(roomId, socket.id)) return;
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_reaction')) return;
    const user = connectedUsers.get(socket.id);
    io.to(roomId).emit('conference_reaction', {
      id: `${socket.id}:${Date.now()}`,
      roomId,
      peerId: socket.id,
      userId: user?.userId != null ? String(user.userId) : null,
      username: user?.username || null,
      emoji,
    });
  });

  /**
   * Camera switched (front↔back). The client already did replaceTrack() locally,
   * but the remote peer's decoder may still hold a stale keyframe from the old
   * camera. Request keyframes on every consumer that is receiving this user's
   * video producer so the remote decoder immediately picks up the new stream.
   */
  socket.on('camera_switched', ({ roomId, rotation }) => {
    if (typeof roomId !== 'string' || !mediaServer.hasPeer(roomId, socket.id)) return;
    mediaServer.updateCameraOrientation(roomId, socket.id, rotation);
    mediaServer.requestKeyFramesForPeer(roomId, socket.id).catch(err =>
      console.error('[Media] requestKeyFramesForPeer error:', err.message)
    );
  });

  // Device posture can change without replacing the camera track. Preserve
  // that transition for recordings while leaving older clients compatible.
  socket.on('camera_orientation_changed', ({ roomId, rotation }) => {
    if (typeof roomId !== 'string' || !mediaServer.hasPeer(roomId, socket.id)) return;
    if (!mediaServer.updateCameraOrientation(roomId, socket.id, rotation)) return;
    mediaServer.requestKeyFramesForPeer(roomId, socket.id).catch(err =>
      console.error('[Media] orientation keyframe error:', err.message)
    );
  });

  /**
   * Optional client-side timeline report (camera/mic/presence windows).
   * Can be sent periodically and/or on call quit to improve metadata fidelity.
   */
  socket.on('submit_call_timeline', ({ roomId, report }, callback) => {
    try {
      const user = connectedUsers.get(socket.id);
      const accepted = mediaServer.ingestClientTimeline(roomId, socket.id, user?.userId || null, report || {});
      if (typeof callback === 'function') callback({ success: accepted });
    } catch (error) {
      if (typeof callback === 'function') callback({ success: false, error: error?.message || String(error) });
    }
  });

  /**
   * Leave media room
   * Handles recording finalization and call status updates for group calls.
   */
  socket.on('leave_media_room', async ({ roomId, timelineReport, recordingMetadata }) => {
    const user = connectedUsers.get(socket.id);
    const leavingPeerInfo = mediaServer.peers?.get(socket.id);
    const leavingAttemptId = leavingPeerInfo?.peer?.callAttemptId || null;

    // CRITICAL: Capture the active call at the START before any async operations
    // might delete it. Check BOTH activeCalls and finalizedCalls (finalized by end_call)
    let active = activeCalls.get(roomId);
    if (leavingAttemptId && !isCallAttemptId(active, leavingAttemptId)) {
      active = null;
    }
    if (!active) {
      active = finalizedCalls.get(roomId);
      if (leavingAttemptId && !isCallAttemptId(active, leavingAttemptId)) {
        active = null;
      }
      if (active) {
        console.log(`[leave_media_room] Found call in finalizedCalls (was already deleted by end_call)`);
      }
    }

    console.log(`[leave_media_room] START: roomId=${roomId}, activeCalls.size=${activeCalls.size}, finalizedCalls.size=${finalizedCalls.size}`);
    console.log(`[leave_media_room] active=${active ? 'found' : 'not found'}, callId=${active?.callId || 'none'}`);
    console.log(`[leave_media_room] recordingMetadata type: ${typeof recordingMetadata}, has events: ${recordingMetadata?.events ? 'yes (' + recordingMetadata.events.length + ')' : 'no'}`);

    if (timelineReport && roomId) {
      try {
        mediaServer.ingestClientTimeline(roomId, socket.id, user?.userId || null, timelineReport);
      } catch (_) { }
    }

    // Handle camera state metadata (client-authoritative timeline)
    // Use the callId we captured at the start
    let recordingMetadataPromise = null;
    if (recordingMetadata && roomId && user?.userId && active?.callId) {
      try {
        const sessionBaseOffsetMs = mediaServer.getPeerRecordingSessionBaseOffset(roomId, socket.id, 'video') || 0;
        recordingMetadataPromise = recordingMetadataHandler.handleRecordingMetadata(
          active.callId,
          user.userId,
          recordingMetadata,
          { sessionBaseOffsetMs }
        ).then(() => {
          console.log(`[RecordingMetadata] Processed metadata for call ${active.callId}, user ${user.userId}`);
        }).catch((err) => {
          console.error('[RecordingMetadata] Error handling metadata:', err?.message || err);
        });
      } catch (err) {
        console.error('[RecordingMetadata] Error handling metadata:', err?.message || err);
      }
    } else {
      console.log(`[leave_media_room] ⚠️ Metadata not processed: recordingMetadata=${!!recordingMetadata}, roomId=${!!roomId}, userId=${!!user?.userId}, callId=${!!active?.callId}`);
    }

    // Clean up per-user resource counters
    userTransportCount.delete(socket.id);
    userProducerCount.delete(socket.id);

    const isGroupRoom = roomId.startsWith('group_call_');

    // CRITICAL: Remove peer FIRST (synchronous) to prevent race conditions.
    // stopRecording can take up to 28 seconds (waiting for FFmpeg). If a peer
    // rapidly leaves and rejoins, join_media_room's addPeer would re-add them,
    // and then the deferred removePeer would incorrectly delete the newly-
    // joined peer — killing their transports/producers/consumers while they
    // think they're connected (local camera works but remote streams are dead).
    mediaServer.removePeer(socket.id);
    socket.leave(roomId);
    socket.to(roomId).emit('peer_left', {
      peerId: socket.id,
      userId: user?.userId || null,
      username: user?.username || null,
    });
    if (
      active?.isConference &&
      user?.userId &&
      !isUserInMediaRoom(roomId, user.userId, socket.id, getCallAttemptId(active))
    ) {
      if (active.joinedUserIds instanceof Set) {
        active.joinedUserIds.delete(user.userId);
        active.joinedUserIds.delete(String(user.userId));
      }
      socket.to(roomId).emit('conference_participant_left', {
        roomId,
        conferenceRoomId: active.dbRoomId,
        peerId: socket.id,
        userId: user.userId,
        username: user.username || null,
      });
      queries.calls.removeParticipant(active.callId, user.userId).catch(() => { });
      clearRaisedHand(roomId, active, user.userId);
      queries.conferenceArchives.addEntry({
        callId: active.callId,
        userId: user.userId,
        entryType: 'left',
        metadata: { reason: 'left' },
      }).catch(error => console.error('[Conference] archive leave event failed:', error.message));
    }

    // Only stop recording once the media room is actually empty.
    const newStats = mediaServer.getRoomStats(roomId);
    const roomIsEmpty = !newStats || newStats.peerCount === 0;

    // Release the room key as soon as the room is empty, independent of
    // whether callId has landed yet (see clearCurrentActiveCall's note).
    if (roomIsEmpty) {
      clearCurrentActiveCall(roomId, active, { broadcastInactive: isGroupRoom });
    }

    // stopRecordingRaw clears room.recording before its first await. Start it
    // now so a redial that reuses this room cannot append new media to the old
    // capture while DB finalization is still running.
    const rawStopPromise = active?.callId && roomIsEmpty
      ? mediaServer.stopRecordingRaw(roomId).catch((e) => {
          console.error(`[Call] ⚠️ Raw recording stop error for call ${active.callId}:`, e?.message || e);
          console.error('[Call] Raw files may exist on disk but recording will not be processed — check recordings/ dir');
          return null;
        })
      : null;

    let callRecord = null;
    const endedAt = Date.now();

    // If room is now empty, finalize the call record in DB FIRST so UI/admin
    // can immediately see call completion while recordings are still processing.
    if (active?.callId && roomIsEmpty) {
      callRecord = await queries.calls.findById(active.callId).catch(() => null);
      if (
        callRecord &&
        !active.terminalState &&
        callRecord.status !== 'completed' &&
        callRecord.status !== 'missed' &&
        callRecord.status !== 'rejected'
      ) {
        const wasAnswered = !!active.answeredAt || callRecord.status === 'ongoing';
        if (wasAnswered) {
          await queries.calls.end(active.callId).catch(() => { });
          if (active.dbRoomId) {
            const durationSec = active.answeredAt
              ? Math.round((endedAt - active.answeredAt) / 1000)
              : 0;
            createCallEventMessage(active.dbRoomId, callRecord.initiator_id, callRecord.call_type, 'completed', durationSec, { isGroup: isGroupRoom });
          }
        } else {
          await queries.calls.updateStatus(active.callId, 'missed').catch(() => { });
          if (active.dbRoomId) {
            createCallEventMessage(active.dbRoomId, callRecord.initiator_id, callRecord.call_type, 'missed', 0, { isGroup: isGroupRoom });
          }
        }
      }
    }

    if (active?.callId && roomIsEmpty) {
      // Phase 1: Raw capture — close transports and wait for FFmpeg to flush
      // via rw_timeout (~3–12 s).  Must run before room teardown.
      const raw = await rawStopPromise;

      // Phase 2: VP8→H.264 transcoding — CPU-heavy, runs in background queue.
      // Room/socket handlers are unblocked as soon as Phase 1 finishes.
      if (raw) {
        const capturedCallId = active.callId;
        const capturedDbRoomId = active.dbRoomId;
        if (shouldDiscardShortRecording(raw, active.callType)) {
          const minDurationMs = getMinimumRecordingDurationMs(active.callType);
          console.log(
            `[Recording] Skipping short ${active.callType} call ${capturedCallId}: ` +
            `${Math.round(raw.duration)}ms < ${minDurationMs}ms`
          );
          await discardRecordingArtifacts(capturedCallId, raw, 'short-call');
        } else {
          recordingQueue.add(
            () => mediaServer.extractFromRaw(raw, capturedCallId),
            capturedCallId,
            capturedDbRoomId,
            mediaServer.buildResumeSnapshot(raw)
          );
          console.log(`[RecordingQueue] Enqueued transcoding for call ${capturedCallId} — queue depth: ${recordingQueue.size}`);
        }
      }

      // Group-call end notifications
      if (isGroupRoom && active.dbRoomId) {
        if (hasSupersedingActiveCall(roomId, active.callId)) {
          console.log(`[Call] Skipping stale group end notifications for ${roomId} because a newer call is already active`);
        } else {
          // Safety net: if the caller disconnected without emitting end_call
          // (app crash, network loss), notify all receivers that the call ended.
          try {
            const callerUserId = connectedUsers.get(socket.id)?.userId || callRecord?.initiator_id;
            const participants = await queries.rooms.getParticipants(active.dbRoomId);
            for (const p of participants) {
              if (p.id === callerUserId) continue;
              for (const [sid, u] of connectedUsers.entries()) {
                if (u.userId === p.id) {
                  io.to(sid).emit('call_ended', { roomId, reason: 'ended' });
                }
              }
            }
            console.log(`[Call] leave_media_room: notified ${participants.length - 1} receiver(s) for ended group call in room ${active.dbRoomId}`);
          } catch (err) {
            console.error('[Call] leave_media_room group notify error:', err?.message || err);
          }
        }
      }
    }

    // Ephemeral conference: purge its in-call chat now that everyone has left.
    // The room row itself is kept forever as a harmless FK anchor for the
    // call/recording — it just never appears in get_rooms (is_ephemeral).
    if (roomIsEmpty && active?.isConference && active?.dbRoomId) {
      db.query('DELETE FROM messages WHERE room_id = $1', [active.dbRoomId])
        .then(() => console.log(`[Conference] Purged ephemeral chat for room ${active.dbRoomId}`))
        .catch(err => console.error('[Conference] purge error:', err.message));
    }

    // Room is empty and the recording (if any) has been finalized — reclaim the
    // recording-recovery entry so finalizedCalls doesn't accumulate per-call keys.
    if (roomIsEmpty) clearRecordingRecovery(roomId, active);

    // Clean up room — room.recording is already null after stopRecordingRaw
    const roomAfterCleanup = mediaServer.rooms?.get(roomId);
    if (roomAfterCleanup && roomAfterCleanup.peers.size === 0 && !roomAfterCleanup.recording) {
      try { roomAfterCleanup.router.close(); } catch (_) { }
      mediaServer.rooms.delete(roomId);
      console.log(`[Media] Room ${roomId} cleaned up after leave + recording stop`);
    }

    // Keep the handler observable for metadata errors without making teardown
    // ownership wait on the metadata database write at the top of the event.
    if (recordingMetadataPromise) await recordingMetadataPromise;
  });


  // NOTE: createCallEventMessage is now defined at module level (above REST
  // handlers) so it can be called from both socket events and REST endpoints.

  // Helper: broadcast group call active/ended status to all room members
  function broadcastGroupCallStatus(dbRoomId, mediasoupRoomId, active, callType) {
    queries.rooms.getParticipants(dbRoomId).then(participants => {
      for (const [sid, u] of connectedUsers.entries()) {
        if (participants.some(p => sameUserId(p.id, u.userId))) {
          io.to(sid).emit('group_call_status', {
            roomId: dbRoomId,
            mediasoupRoomId,
            active,
            callType,
          });
        }
      }
    }).catch(err => console.error('[Call] broadcastGroupCallStatus error:', err.message));
  }

  function hasSupersedingActiveCall(roomId, callId) {
    const current = activeCalls.get(roomId);
    return !!(current?.callId && current.callId !== callId);
  }

  function clearCurrentActiveCall(roomId, active, { broadcastInactive = false } = {}) {
    // NOTE: deliberately does NOT require active.callId. The online fast path
    // assigns callId asynchronously (see the DB write kicked off when the call
    // starts); a call that empties out before that write lands must still
    // release the room key here, or the caller stays "busy" until restart
    // (isUserBusyInActiveCall trusts activeCalls with no TTL/sweeper).
    if (!active) return false;
    if (!clearActiveCallIfCurrent(roomId, active)) return false;

    if (broadcastInactive && active.dbRoomId) {
      broadcastGroupCallStatus(active.dbRoomId, roomId, false, active.callType || 'audio');
    }

    return true;
  }

  /**
   * Undo a server-acknowledged group start that never became a live meeting.
   * The DB call id is required so a delayed cleanup from an older attempt can
   * never terminate a newer call that reuses the deterministic media room id.
   */
  async function rollbackGroupCallStart(mediaRoomId, expectedCallId, reason = 'setup_failed') {
    const active = activeCalls.get(mediaRoomId);
    if (
      !active?.callId ||
      String(active.callId) !== String(expectedCallId) ||
      active.answeredAt
    ) {
      return false;
    }

    finalizedCalls.set(mediaRoomId, {
      callId: active.callId,
      dbRoomId: active.dbRoomId,
      callType: active.callType,
      isConference: !!active.isConference,
      terminalState: 'cancelled',
      terminatedBy: active.initiatorUserId,
      terminatedAt: Date.now(),
    });

    if (!clearCurrentActiveCall(mediaRoomId, active, { broadcastInactive: true })) {
      return false;
    }

    await queries.calls.updateStatus(active.callId, 'rejected').catch(error => {
      console.error(`[Call] Failed to roll back group call ${active.callId}:`, error.message);
    });
    if (active.dbRoomId) {
      createCallEventMessage(
        active.dbRoomId,
        active.initiatorUserId,
        active.callType || 'audio',
        'cancelled',
        0,
        { isGroup: true },
      );
    }

    const targetUserIds = [...new Set(
      (Array.isArray(active.targetUserIds) ? active.targetUserIds : [])
        .filter(id => id !== null && id !== undefined)
        .map(id => String(id)),
    )];
    for (const targetUserId of targetUserIds) {
      notifyCallEndedToUserDevices(targetUserId, mediaRoomId, 'cancelled');
    }

    // The organizer does not need a cancellation push, but a live setup that
    // stalled must still leave its call UI immediately when the guard fires.
    try {
      io.to(`user:${active.initiatorUserId}`).emit('call_ended', {
        roomId: mediaRoomId,
        reason,
      });
    } catch (_) { }

    console.warn(
      `[Call] Rolled back group call ${active.callId} in ${mediaRoomId} (${reason})`,
    );
    return true;
  }

  // ── Group call: ONE call record, ring multiple targets ────────────────
  socket.on('start_group_call', async ({ targets, callerName, isVideoCall, roomId, mediasoupRoomId, groupRoomName, isConference }, callback) => {
    const failStart = (message, responseRoomId = mediasoupRoomId || null) => {
      const payload = { success: false, error: message, roomId: responseRoomId };
      if (typeof callback === 'function') callback(payload);
      else socket.emit('call_error', { message, roomId: responseRoomId });
    };

    const user = connectedUsers.get(socket.id);
    if (!user?.userId) {
      failStart('Not authenticated');
      return;
    }
    const organizerUserId = String(user.userId);
    const expectedMediaRoomId = `group_call_${roomId}`;
    if (!roomId || mediasoupRoomId !== expectedMediaRoomId) {
      failStart('Invalid conference room identity');
      return;
    }

    // Conference identity is a server-owned property of the backing room. Do
    // not trust a client boolean: otherwise a stale/background payload can turn
    // an ephemeral conference into a normal group call (or vice versa).
    let roomMembers;
    let backingRoom;
    try {
      backingRoom = await queries.rooms.findById(roomId);
      if (!backingRoom) {
        failStart('Conference room not found');
        return;
      }
      roomMembers = await queries.rooms.getParticipants(roomId);
      if (!roomMembers.some(member => sameUserId(member.id, organizerUserId))) {
        failStart('Not a member of this call');
        return;
      }
      const serverConferenceMode = !!backingRoom.is_ephemeral;
      if (!!isConference !== serverConferenceMode) {
        console.warn(`[Conference] Corrected stale conference flag for room ${roomId}: client=${!!isConference}, server=${serverConferenceMode}`);
      }
      isConference = serverConferenceMode;
      const requiredCapability = isConference ? 'conferences' : 'calls';
      if (!(await queries.users.hasCapability(organizerUserId, requiredCapability))) {
        failStart(isConference
          ? 'Conferences are not enabled for this account'
          : 'Calls are not enabled for this account');
        return;
      }
      const memberIds = new Set(roomMembers.map(member => String(member.id)));
      targets = (Array.isArray(targets) ? targets : [])
        .filter(target => target?.userId !== null && target?.userId !== undefined)
        .map(target => ({ ...target, userId: String(target.userId) }))
        .filter(target => target.userId !== organizerUserId && memberIds.has(target.userId));
      const allowedTargetIds = new Set(await queries.users.filterIdsWithCapability(
        targets.map(target => target.userId), requiredCapability,
      ));
      targets = targets.filter(target => allowedTargetIds.has(String(target.userId)));
    } catch (error) {
      console.error('[Call] Failed to validate group-call room:', error?.message || error);
      failStart('Unable to validate conference room');
      return;
    }

    if (isUserBusyInActiveCall(organizerUserId, mediasoupRoomId)) {
      failStart('You are already in another call');
      return;
    }

    // Idempotent retry: if the acknowledgement was lost after creation, the
    // same organizer can recover the existing start without creating a second
    // DB call or ringing everyone twice. A different starter cannot replace a
    // live call in the room.
    const existing = activeCalls.get(mediasoupRoomId);
    if (existing?.callId) {
      if (
        String(existing.dbRoomId) === String(roomId) &&
        sameUserId(existing.initiatorUserId, organizerUserId)
      ) {
        callback?.({
          success: true,
          callId: String(existing.callId),
          mediasoupRoomId,
          isConference: !!existing.isConference,
          conferenceRoomId: existing.isConference ? existing.dbRoomId : null,
          reused: true,
        });
      } else {
        failStart('A call is already active in this room');
      }
      return;
    }

    console.log(`[Call] ${callerName} starting group call in room ${roomId} with ${targets.length} targets`);

    // Create ONE call record linked to the actual group DB room
    let dbCallId = null;
    try {
      const call = await queries.calls.create({
        roomId,                               // the actual group room UUID
        initiatorId: organizerUserId,
        callType: isVideoCall ? 'video' : 'audio',
        sessionKind: isConference ? 'conference' : 'call',
      });
      dbCallId = call.id;
      console.log('[Call] Created DB call record:', dbCallId, 'in room', roomId);

      // Add initiator as participant
      await queries.calls.addParticipant(call.id, organizerUserId);

      // Track in activeCalls using the mediasoup room ID
      const groupActive = {
        _attemptId: createCallAttemptId(),
        callId: call.id,
        dbRoomId: roomId,
        initiatorUserId: organizerUserId,
        initiatorSocketId: socket.id,
        startedAt: Date.now(),
        callType: isVideoCall ? 'video' : 'audio',
        // callType may later become "video" for recording/history when an
        // audio meeting presents a screen. Joining that meeting must still use
        // its original camera mode instead of unexpectedly requesting camera.
        joinCallType: isVideoCall ? 'video' : 'audio',
        isConference: !!isConference,
        groupRoomName: groupRoomName || backingRoom?.name || 'Conference',
        callerName: callerName || user.username || 'Someone',
        targetUserIds: targets.map(target => target.userId),
        // Filled from authoritative SFU joins, including the organizer.
        joinedUserIds: new Set(),
      };
      // This media-room key is deterministic per chat room. A completed or
      // rolled-back predecessor must not remain the recording-recovery owner
      // when a fresh conference starts under the same key.
      finalizedCalls.delete(mediasoupRoomId);
      activeCalls.set(mediasoupRoomId, groupActive);
      rememberCallForRecording(mediasoupRoomId, groupActive);

      // The acknowledgement admits the organizer to media. If that client
      // crashes or loses the ack before joining, reclaim the ringing call so
      // invitees are never left with an unanswerable conference panel.
      groupActive.startupTimer = setTimeout(async () => {
        const current = activeCalls.get(mediasoupRoomId);
        if (!current || String(current.callId) !== String(call.id) || current.answeredAt) return;
        if (isUserInMediaRoom(mediasoupRoomId, organizerUserId, null, getCallAttemptId(current))) {
          current.startupTimer = null;
          return;
        }
        await rollbackGroupCallStart(mediasoupRoomId, call.id, 'organizer_join_timeout');
      }, 20_000);

      // Create a "started" event message in the group chat
      createCallEventMessage(roomId, organizerUserId, isVideoCall ? 'video' : 'audio', 'started', 0, { isGroup: true });

      // Broadcast active call status to all room members
      broadcastGroupCallStatus(roomId, mediasoupRoomId, true, isVideoCall ? 'video' : 'audio');
    } catch (err) {
      console.error('[Call] DB create error:', err && err.message ? err.message : err);
      failStart('Unable to start this conference. Please try again.');
      return;
    }

    // The organizer must not enter the SFU room until this acknowledgement.
    // At this point activeCalls + DB identity are authoritative; ringing can
    // continue asynchronously while the caller joins media.
    callback?.({
      success: true,
      callId: String(dbCallId),
      mediasoupRoomId,
      isConference: !!isConference,
      conferenceRoomId: isConference ? roomId : null,
      reused: false,
    });

    const isCurrentGroupStart = () => {
      const current = activeCalls.get(mediasoupRoomId);
      return !!current?.callId && String(current.callId) === String(dbCallId);
    };
    // Add each target as participant and ring them
    for (const target of targets) {
      if (!isCurrentGroupStart()) break;
      const targetUserId = target.userId;
      if (!targetUserId) continue;

      if (isUserBusyInActiveCall(targetUserId, mediasoupRoomId)) {
        console.log(`[Call] Group target ${targetUserId} is busy in another active call — skipping ring`);
        continue;
      }

      // Add as participant in DB
      if (dbCallId) {
        try {
          await queries.calls.addParticipant(dbCallId, targetUserId);
        } catch (err) {
          console.error('[Call] DB addParticipant error:', err.message);
        }
      }
      if (!isCurrentGroupStart()) break;

      // Resolve target socketId — pick the LAST live socket to avoid
      // emitting to stale entries that haven't fired disconnect yet.
      let targetSocketId = null;
      for (const [sid, u] of connectedUsers.entries()) {
        if (sameUserId(u.userId, targetUserId) && io.sockets.sockets.get(sid)) {
          targetSocketId = sid; // last live match = most recent
        }
      }

      if (targetSocketId) {
        // Multi-device: ring EVERY one of the target's devices, not just the
        // most-recent socket. Answering on any one cancels the ring on the rest
        // (see answer_call → 'call_cancelled' to the user room).
        emitToUser(targetUserId, 'incoming_call', {
          signal: { type: 'offer', roomId: mediasoupRoomId, isGroupCall: true, groupRoomName, groupRoomId: roomId, isConference: !!isConference },
          from: socket.id,
          callerId: user.userId,
          callerName,
          isVideoCall,
          roomId: mediasoupRoomId,
          isGroupCall: true,
          groupRoomName,
          groupRoomId: roomId,
          isConference: !!isConference,
        });
        console.log(`[Call] Ringing ${targetUserId} on all devices`);
      } else {
        console.log(`[Call] Target ${targetUserId} is offline — cannot ring without push`);
      }
    }

    if (!isCurrentGroupStart()) return;
    socket.emit('call_ringing');

    // ── Ring timeout: auto-end unanswered group call after 45 seconds ──
    if (mediasoupRoomId && activeCalls.has(mediasoupRoomId)) {
      clearRingTimeout(mediasoupRoomId);
      const callerSocketId = socket.id;
      ringTimeouts.set(mediasoupRoomId, setTimeout(async () => {
        ringTimeouts.delete(mediasoupRoomId);
        const active = activeCalls.get(mediasoupRoomId);
        if (!active) return; // already answered/ended
        if (String(active.callId) !== String(dbCallId)) return; // newer call owns this room
        if (active.answeredAt) return; // accepted/joined; media may still be connecting
        // Belt-and-suspenders (#3): the initiator joins during ringing, so >= 2 peers means
        // an invitee joined too — the group call connected and must not be marked missed.
        const groupPeerCount = mediaServer.getPeerCount(mediasoupRoomId);
        if (groupPeerCount >= 2) {
          console.log(`[Call] Group ring timeout fired for ${mediasoupRoomId} but ${groupPeerCount} media peers present — connected, not missed`);
          return;
        }
        const callRecord = await queries.calls.findById(active.callId).catch(() => null);
        if (callRecord && (callRecord.status === 'ringing' || callRecord.status === 'initiated')) {
          console.log(`[Call] Group ring timeout (45s) — marking call ${active.callId} as missed`);
          
          const finalized = await finalizeCall(mediasoupRoomId, {
            reason: 'missed',
            actorUserId: null,
            isGroupCall: false,
            expectedActive: active,
          });
          if (!finalized) return;
          if (hasSupersedingCallAttempt(mediasoupRoomId, active)) return;
          // Note: for a group call timeout that NOBODY answered, we treat it as a whole-call missed (isGroupCall: false for finalizeCall so it ends the whole call).
          // Broadcast that the group call is no longer active
          broadcastGroupCallStatus(roomId, mediasoupRoomId, false, isVideoCall ? 'video' : 'audio');
          // Notify the caller
          if (connectedUsers.has(callerSocketId)) {
            io.to(callerSocketId).emit('call_not_answered', { roomId: mediasoupRoomId, reason: 'not_answered' });
          }
          // Dismiss ringing panels for all targets
          for (const target of targets) {
            if (target.userId && isValidUserId(target.userId)) {
              try { io.to('user:' + target.userId).emit('call_ended', { roomId: mediasoupRoomId, reason: 'ended' }); } catch (_) {}
              queueCallEndedForUser(target.userId, mediasoupRoomId);
            }
          }
        }
      }, 45000));
    }
  });

  // Organizer-only compensation for failures that happen after the server has
  // acknowledged start_group_call but before another participant joins media.
  socket.on('cancel_group_call_start', async ({ roomId, mediasoupRoomId, callId }, callback) => {
    const actor = resolveCallActor(socket);
    const expectedMediaRoomId = `group_call_${roomId}`;
    if (!actor?.userId) {
      return callback?.({ success: false, error: 'Not authenticated' });
    }
    if (!roomId || mediasoupRoomId !== expectedMediaRoomId || !callId) {
      return callback?.({ success: false, error: 'Invalid group call identity' });
    }

    const active = activeCalls.get(mediasoupRoomId);
    if (!active?.callId || String(active.callId) !== String(callId)) {
      const finalized = finalizedCalls.get(mediasoupRoomId);
      if (finalized?.callId && String(finalized.callId) === String(callId)) {
        return callback?.({ success: true, alreadyFinalized: true });
      }
      return callback?.({ success: false, error: 'This group call is no longer active' });
    }
    if (
      String(active.dbRoomId) !== String(roomId) ||
      !sameUserId(active.initiatorUserId, actor.userId)
    ) {
      console.warn(`[Call] Unauthorized group-start rollback by ${actor.userId} for ${mediasoupRoomId}`);
      return callback?.({ success: false, error: 'Only the organizer can cancel this start' });
    }
    if (active.answeredAt) {
      return callback?.({ success: false, error: 'The conference is already live' });
    }

    try {
      const cancelled = await rollbackGroupCallStart(
        mediasoupRoomId,
        callId,
        'organizer_setup_failed',
      );
      callback?.({
        success: cancelled,
        error: cancelled ? undefined : 'The conference could not be rolled back',
      });
    } catch (error) {
      console.error('[Call] cancel_group_call_start error:', error?.message || error);
      callback?.({ success: false, error: 'Unable to cancel the conference start' });
    }
  });

  // Add people to an already-live conference. The media room id is derived on
  // the server so a client cannot pair one conference's membership with
  // another conference's SFU room.
  socket.on('invite_to_conference', async ({ roomId, targetUserIds } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'invite_to_conference')) {
      reply({ success: false, invitedUserIds: [], error: 'Too many invitations. Please wait.' });
      return;
    }

    const actor = resolveCallActor(socket);
    const conferenceRoomId = roomId === null || roomId === undefined ? '' : String(roomId);
    const mediasoupRoomId = `group_call_${conferenceRoomId}`;
    if (!actor?.userId) {
      reply({ success: false, invitedUserIds: [], error: 'Not authenticated' });
      return;
    }
    if (!conferenceRoomId || !Array.isArray(targetUserIds) || targetUserIds.length === 0) {
      reply({ success: false, invitedUserIds: [], error: 'Conference and target users are required' });
      return;
    }
    if (!(await queries.users.hasCapability(actor.userId, 'conferences'))) {
      reply({ success: false, invitedUserIds: [], error: 'Conferences are not enabled for this account' });
      return;
    }
    if (targetUserIds.length > 50) {
      reply({ success: false, invitedUserIds: [], error: 'Invite at most 50 people at once' });
      return;
    }

    const active = activeCalls.get(mediasoupRoomId);
    if (
      !active?.callId
      || !active.isConference
      || !sameUserId(active.dbRoomId, conferenceRoomId)
    ) {
      reply({ success: false, invitedUserIds: [], error: 'This conference is no longer active' });
      return;
    }
    if (!mediaServer.hasPeer(mediasoupRoomId, socket.id)) {
      reply({ success: false, invitedUserIds: [], error: 'Join the conference before inviting people' });
      return;
    }

    const expectedCallId = String(active.callId);
    const isCurrentConference = () => {
      const current = activeCalls.get(mediasoupRoomId);
      return !!current?.callId
        && String(current.callId) === expectedCallId
        && !!current.isConference
        && sameUserId(current.dbRoomId, conferenceRoomId);
    };

    try {
      const [backingRoom, members, actorUser] = await Promise.all([
        queries.rooms.findById(conferenceRoomId),
        queries.rooms.getParticipants(conferenceRoomId),
        queries.users.findById(actor.userId),
      ]);
      if (!isCurrentConference()) {
        reply({ success: false, invitedUserIds: [], error: 'This conference is no longer active' });
        return;
      }
      if (!backingRoom?.is_ephemeral) {
        reply({ success: false, invitedUserIds: [], error: 'Live invitations are only available for conferences' });
        return;
      }

      const actorMember = members.find(member => sameUserId(member.id, actor.userId));
      const actorIsOrganizer = sameUserId(active.initiatorUserId, actor.userId);
      if (!actorMember || (!actorIsOrganizer && actorMember.role !== 'admin')) {
        console.warn(`[Conference] Unauthorized live invite by ${actor.userId} for ${mediasoupRoomId}`);
        reply({ success: false, invitedUserIds: [], error: 'Only the organizer or a conference admin can invite people' });
        return;
      }

      const existingMemberIds = new Set(members.map(member => String(member.id)));
      const existingTargetIds = new Set(
        (Array.isArray(active.targetUserIds) ? active.targetUserIds : []).map(String),
      );
      if (!(active._conferenceInviteInFlight instanceof Set)) {
        active._conferenceInviteInFlight = new Set();
      }

      const candidates = [];
      const seenInput = new Set();
      const skippedUserIds = [];
      const errors = [];
      for (const rawTargetId of targetUserIds) {
        const targetUserId = (typeof rawTargetId === 'string' || typeof rawTargetId === 'number')
          ? String(rawTargetId)
          : '';
        if (!isValidUserId(targetUserId)) {
          errors.push({ userId: targetUserId || null, error: 'Invalid user ID' });
          continue;
        }
        if (
          seenInput.has(targetUserId)
          || sameUserId(targetUserId, actor.userId)
          || existingMemberIds.has(targetUserId)
          || existingTargetIds.has(targetUserId)
          || active._conferenceInviteInFlight.has(targetUserId)
        ) {
          skippedUserIds.push(targetUserId);
          continue;
        }
        seenInput.add(targetUserId);
        active._conferenceInviteInFlight.add(targetUserId);
        candidates.push(targetUserId);
      }

      const invitedUserIds = [];
      const conferenceTitle = backingRoom.name || active.groupRoomName || 'Conference';
      const inviterName = actorUser?.full_name || actorUser?.username || actor.username || 'Someone';
      const isVideoCall = (active.joinCallType || active.callType) === 'video';

      for (const targetUserId of candidates) {
        try {
          const targetUser = await queries.users.findById(targetUserId);
          if (!targetUser || targetUser.status !== 'active' ||
              (targetUser.role !== 'superadmin' && targetUser.can_conference !== true)) {
            errors.push({ userId: targetUserId, error: 'User is not available' });
            continue;
          }
          if (!(await canUsersCommunicate(actor.userId, targetUserId))) {
            errors.push({ userId: targetUserId, error: 'User is not in your contacts' });
            continue;
          }
          if (await isUserSuspended(targetUserId)) {
            errors.push({ userId: targetUserId, error: 'User is suspended' });
            continue;
          }
          if (isUserBusyInActiveCall(targetUserId, mediasoupRoomId)) {
            errors.push({ userId: targetUserId, error: 'User is busy in another call' });
            continue;
          }
          if (!isCurrentConference()) {
            errors.push({ userId: targetUserId, error: 'Conference ended before the invitation was sent' });
            continue;
          }

          // Membership and call history must agree: commit both or neither.
          await db.transaction(async client => {
            await client.query(
              `INSERT INTO room_participants (room_id, user_id, role)
               VALUES ($1, $2, 'member')
               ON CONFLICT (room_id, user_id)
               DO UPDATE SET left_at = NULL, role = 'member'`,
              [conferenceRoomId, targetUserId],
            );
            await client.query(
              `INSERT INTO call_participants (call_id, user_id, answered)
               SELECT $1, $2, FALSE
               WHERE NOT EXISTS (
                 SELECT 1 FROM call_participants WHERE call_id = $1 AND user_id = $2
               )`,
              [expectedCallId, targetUserId],
            );
          });

          if (!isCurrentConference()) {
            errors.push({ userId: targetUserId, error: 'Conference ended before the invitation was sent' });
            continue;
          }

          const current = activeCalls.get(mediasoupRoomId);
          current.targetUserIds = [
            ...new Set([...(Array.isArray(current.targetUserIds) ? current.targetUserIds : []), targetUserId].map(String)),
          ];
          invitedUserIds.push(targetUserId);

          // Existing attendees can render this member immediately as waiting,
          // before a mediasoup producer exists for them.
          io.to(mediasoupRoomId).emit('conference_participant_invited', {
            roomId: mediasoupRoomId,
            conferenceRoomId,
            userId: targetUserId,
            username: targetUser.username,
          });

          const incomingPayload = {
            signal: {
              type: 'offer',
              roomId: mediasoupRoomId,
              isGroupCall: true,
              groupRoomName: conferenceTitle,
              groupRoomId: conferenceRoomId,
              isConference: true,
            },
            from: String(actor.userId),
            callerId: String(actor.userId),
            callerName: inviterName,
            isVideoCall,
            roomId: mediasoupRoomId,
            isGroupCall: true,
            groupRoomName: conferenceTitle,
            groupRoomId: conferenceRoomId,
            isConference: true,
            conferenceRoomId,
            timestamp: Date.now(),
          };
          const targetSocketId = resolveSocketId(targetUserId);

          if (targetSocketId) {
            emitToUser(targetUserId, 'incoming_call', incomingPayload);
          }
          // No live socket and no push infrastructure to reach an offline
          // target — the invite is recorded in the DB; they'll see it next
          // time they connect.
        } catch (error) {
          console.error(`[Conference] Failed to invite ${targetUserId}:`, error?.message || error);
          errors.push({ userId: targetUserId, error: 'Unable to send invitation' });
        } finally {
          active._conferenceInviteInFlight.delete(targetUserId);
        }
      }

      const success = invitedUserIds.length > 0 || errors.length === 0;
      reply({
        success,
        invitedUserIds,
        skippedUserIds: [...new Set(skippedUserIds)],
        errors,
        error: success ? undefined : 'No invitations were sent',
      });
    } catch (error) {
      console.error('[Conference] invite_to_conference error:', error?.message || error);
      reply({ success: false, invitedUserIds: [], error: 'Unable to invite people right now' });
    }
  });

  /**
   * Shared gate for every host-only conference control below. Resolves the live
   * conference, confirms the caller is actually inside it, and confirms they are
   * the organizer or a room admin — the same verdict `conference_permissions`
   * hands the client on join, re-derived here because that flag is a UI hint,
   * never authority. Returns `{ error }` on refusal so each caller can reply in
   * its own shape.
   */
  const authorizeConferenceHost = async (roomId) => {
    const actor = resolveCallActor(socket);
    const conferenceRoomId = roomId === null || roomId === undefined ? '' : String(roomId);
    const mediasoupRoomId = `group_call_${conferenceRoomId}`;
    if (!actor?.userId) return { error: 'Not authenticated' };
    if (!conferenceRoomId) return { error: 'Conference is required' };

    const active = activeCalls.get(mediasoupRoomId);
    if (
      !active?.callId
      || !active.isConference
      || !sameUserId(active.dbRoomId, conferenceRoomId)
    ) {
      return { error: 'This conference is no longer active' };
    }
    if (!mediaServer.hasPeer(mediasoupRoomId, socket.id)) {
      return { error: 'Join the conference before managing it' };
    }

    const members = await queries.rooms.getParticipants(conferenceRoomId);
    const actorMember = members.find(member => sameUserId(member.id, actor.userId));
    const actorIsOrganizer = sameUserId(active.initiatorUserId, actor.userId);
    if (!actorMember || (!actorIsOrganizer && actorMember.role !== 'admin')) {
      console.warn(`[Conference] Unauthorized host action by ${actor.userId} on ${mediasoupRoomId}`);
      return { error: 'Only the organizer can manage this conference' };
    }
    return { actor, active, members, mediasoupRoomId, conferenceRoomId };
  };

  /** Every live socket for a user that is currently a peer in this conference. */
  const conferenceSocketsForUser = (mediasoupRoomId, userId) => {
    const sockets = [];
    for (const [sid, u] of connectedUsers.entries()) {
      if (!sameUserId(u?.userId, userId)) continue;
      if (!mediaServer.hasPeer(mediasoupRoomId, sid)) continue;
      sockets.push(sid);
    }
    return sockets;
  };

  /**
   * Host mute. Deliberately a *request* the target's client honours, not a
   * server-side producer pause: the product decision is a soft mute, so the
   * person can immediately unmute themselves when they do need to speak. The
   * client mutes and then broadcasts its normal audio-state change, so every
   * other participant's UI updates through the existing path rather than a
   * second, parallel notion of who is muted.
   */
  socket.on('conference_mute', async ({ roomId, targetUserId } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_host_action')) {
      reply({ success: false, error: 'Too many requests. Please wait.' });
      return;
    }
    try {
      const gate = await authorizeConferenceHost(roomId);
      if (gate.error) { reply({ success: false, error: gate.error }); return; }
      const { actor, members, mediasoupRoomId } = gate;

      // No target = "mute everyone else". Never mute the host who asked.
      const targets = targetUserId != null
        ? members.filter(m => sameUserId(m.id, targetUserId))
        : members.filter(m => !sameUserId(m.id, actor.userId));
      if (targetUserId != null && targets.length === 0) {
        reply({ success: false, error: 'That person is not in this conference' });
        return;
      }
      if (targetUserId != null && sameUserId(targetUserId, actor.userId)) {
        reply({ success: false, error: 'Use the mic button to mute yourself' });
        return;
      }

      let notified = 0;
      for (const target of targets) {
        for (const sid of conferenceSocketsForUser(mediasoupRoomId, target.id)) {
          io.to(sid).emit('conference_host_muted', {
            roomId: mediasoupRoomId,
            conferenceRoomId: String(gate.conferenceRoomId),
            byUsername: actor.username || 'The host',
            all: targetUserId == null,
          });
          notified += 1;
        }
      }
      console.log(`[Conference] ${actor.userId} muted ${targetUserId != null ? targetUserId : 'everyone'} on ${mediasoupRoomId} (${notified} socket(s))`);
      reply({ success: true, mutedCount: notified });
    } catch (error) {
      console.error('[Conference] conference_mute error:', error?.message || error);
      reply({ success: false, error: 'Unable to mute right now' });
    }
  });

  /** Host removes one participant. Reuses the ordinary call_ended teardown the
   *  clients already handle, so the removed peer cleans up exactly as it would
   *  on any other end — no special-case client path to keep in sync. */
  socket.on('conference_remove_participant', async ({ roomId, targetUserId } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_host_action')) {
      reply({ success: false, error: 'Too many requests. Please wait.' });
      return;
    }
    try {
      const gate = await authorizeConferenceHost(roomId);
      if (gate.error) { reply({ success: false, error: gate.error }); return; }
      const { actor, active, mediasoupRoomId } = gate;

      if (targetUserId == null) { reply({ success: false, error: 'Target is required' }); return; }
      if (sameUserId(targetUserId, actor.userId)) {
        reply({ success: false, error: 'Leave the meeting instead of removing yourself' });
        return;
      }
      // The organizer owns the meeting; a co-admin cannot evict them from it.
      if (sameUserId(active.initiatorUserId, targetUserId)) {
        reply({ success: false, error: 'The organizer cannot be removed' });
        return;
      }

      const sockets = conferenceSocketsForUser(mediasoupRoomId, targetUserId);
      for (const sid of sockets) {
        io.to(sid).emit('call_ended', { roomId: mediasoupRoomId, reason: 'removed_by_host' });
        try { mediaServer.removePeer(sid); } catch (_) { }
      }
      clearRaisedHand(mediasoupRoomId, active, targetUserId);
      io.to(mediasoupRoomId).emit('conference_participant_removed', {
        roomId: mediasoupRoomId,
        conferenceRoomId: String(gate.conferenceRoomId),
        userId: String(targetUserId),
      });
      console.log(`[Conference] ${actor.userId} removed ${targetUserId} from ${mediasoupRoomId} (${sockets.length} socket(s))`);
      reply({ success: true, removedSockets: sockets.length });
    } catch (error) {
      console.error('[Conference] conference_remove_participant error:', error?.message || error);
      reply({ success: false, error: 'Unable to remove that person right now' });
    }
  });

  /** Host ends the meeting for everyone, rather than today's default where
   *  leaving only drops you and the room lives on until it empties. */
  socket.on('conference_end_for_all', async ({ roomId } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_host_action')) {
      reply({ success: false, error: 'Too many requests. Please wait.' });
      return;
    }
    try {
      const gate = await authorizeConferenceHost(roomId);
      if (gate.error) { reply({ success: false, error: gate.error }); return; }
      const { actor, members, mediasoupRoomId } = gate;

      let notified = 0;
      for (const member of members) {
        for (const sid of conferenceSocketsForUser(mediasoupRoomId, member.id)) {
          io.to(sid).emit('call_ended', { roomId: mediasoupRoomId, reason: 'ended_by_host' });
          notified += 1;
        }
      }
      console.log(`[Conference] ${actor.userId} ended ${mediasoupRoomId} for everyone (${notified} socket(s))`);
      reply({ success: true, endedSockets: notified });
    } catch (error) {
      console.error('[Conference] conference_end_for_all error:', error?.message || error);
      reply({ success: false, error: 'Unable to end the meeting right now' });
    }
  });

  /**
   * Host lowers one raised hand, or every hand when no target is given.
   * Unlike mute this is state the server owns, so the queue updates for
   * everyone at once; the people affected also get a direct notice.
   */
  socket.on('conference_lower_hand', async ({ roomId, targetUserId } = {}, callback) => {
    const reply = typeof callback === 'function' ? callback : () => { };
    if (!socketRateLimiter.isAllowed(socket.id, 'conference_host_action')) {
      reply({ success: false, error: 'Too many requests. Please wait.' });
      return;
    }
    try {
      const gate = await authorizeConferenceHost(roomId);
      if (gate.error) { reply({ success: false, error: gate.error }); return; }
      const { actor, active, mediasoupRoomId } = gate;
      const hands = active.raisedHands instanceof Map ? active.raisedHands : new Map();
      const targets = targetUserId != null
        ? [String(targetUserId)].filter(userId => hands.has(userId))
        : [...hands.keys()];

      for (const userId of targets) {
        hands.delete(userId);
        queries.conferenceArchives.addEntry({
          callId: active.callId,
          userId,
          entryType: 'hand_lowered',
          metadata: { byUserId: String(actor.userId), byUsername: actor.username || null },
        }).catch(error => console.error('[Conference] archive host lower failed:', error.message));
        for (const sid of conferenceSocketsForUser(mediasoupRoomId, userId)) {
          io.to(sid).emit('conference_hand_lowered', {
            roomId: mediasoupRoomId,
            conferenceRoomId: String(gate.conferenceRoomId),
            byUsername: actor.username || 'The host',
            all: targetUserId == null,
          });
          // Older clients only understand the per-peer relay.
          io.to(mediasoupRoomId).emit('hand_raised', {
            peerId: sid,
            userId,
            username: null,
            raised: false,
            raisedAt: null,
          });
        }
      }
      if (targets.length) broadcastRaisedHands(mediasoupRoomId, active);
      console.log(`[Conference] ${actor.userId} lowered ${targetUserId != null ? targetUserId : 'all'} hand(s) on ${mediasoupRoomId} (${targets.length})`);
      reply({ success: true, loweredCount: targets.length });
    } catch (error) {
      console.error('[Conference] conference_lower_hand error:', error?.message || error);
      reply({ success: false, error: 'Unable to lower that hand right now' });
    }
  });

  socket.on('call_user', async ({ userToCall, signalData, from, callerName, isVideoCall, roomId }) => {
    // ✅ SECURITY: Rate limit (prevent call spam)
    if (!socketRateLimiter.isAllowed(socket.id, 'call_user')) {
      return socket.emit('call_error', { message: 'Too many calls. Please wait.' });
    }

    const user = connectedUsers.get(socket.id);

    // Fallback: extract roomId from signalData if not sent at the top level
    if (!roomId && signalData?.roomId) {
      roomId = signalData.roomId;
    }

    logger.info('Call', `${callerName || nameForUser(from)} → ${userToCall ? nameForUser(userToCall) : '(no target)'} (${isVideoCall ? 'video' : 'audio'}) — ringing`, { ip: ipForSocket(socket) });

    if (!userToCall) {
      console.error('[Call] userToCall is empty — aborting');
      socket.emit('call_error', { message: 'No target user specified' });
      return;
    }

    // Resolve target userId (might be a socketId or DB userId)
    let resolvedTargetUserId = null;
    let targetSocketId = userToCall;
    if (!connectedUsers.has(userToCall)) {
      resolvedTargetUserId = userToCall; // assume it's a DB userId
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.userId === userToCall) {
          targetSocketId = sid;
          break;
        }
      }
    } else {
      resolvedTargetUserId = connectedUsers.get(userToCall)?.userId || userToCall;
    }

    const callMediaKey = roomId;
    const callType = isVideoCall ? 'video' : 'audio';

    if (!user?.userId || !(await queries.users.hasCapability(user.userId, 'calls'))) {
      socket.emit('call_error', { message: 'Calls are not enabled for this account' });
      return;
    }
    if (resolvedTargetUserId && !(await queries.users.hasCapability(resolvedTargetUserId, 'calls'))) {
      socket.emit('call_rejected', { roomId, reason: 'unavailable' });
      return;
    }

    // Workspace/contact isolation is an authorization boundary, so validate it
    // before the ring is emitted. The previous fast path rang first and
    // cancelled later, which still exposed an unrelated account to a brief
    // incoming-call interruption.
    if (resolvedTargetUserId) {
      const permission = await checkCallPermission(user.userId, resolvedTargetUserId);
      if (!permission.allowed) {
        logger.warn('Call', `Blocked call ${nameForUser(user.userId)} → ${nameForUser(resolvedTargetUserId)} (not permitted)`);
        socket.emit('call_error', { message: permission.reason || 'You cannot call this user' });
        return;
      }
    }

    if (isUserBusyInActiveCall(user?.userId)) {
      // Loud on purpose: a silent reject here is exactly what made every prior
      // leaked-activeCalls-entry incident look like "can't call, no error
      // anywhere" (see STALE_CALL_TTL_MS's comment in callAttempt.js). If this
      // fires for a user who isn't actually on another call right now, it
      // means some activeCalls entry naming them as initiator/target never
      // got released — that's the bug to chase, not this rejection itself.
      console.warn(`[Call] call_user rejected: ${user?.username || user?.userId} already busy in an active call`);
      socket.emit('call_error', { message: 'You are already in a call' });
      return;
    }

    if (resolvedTargetUserId && isUserBusyInActiveCall(resolvedTargetUserId)) {
      console.log(`[Call] Target ${resolvedTargetUserId} is busy in another active call — rejecting quietly`);
      socket.emit('call_rejected', { roomId, reason: 'busy' });
      return;
    }

    // A call may be ringing before either side has joined media, so the
    // peer-based busy check above cannot see it yet. Never overwrite an active
    // attempt at the same deterministic room key; its eventual teardown would
    // otherwise race the replacement.
    if (activeCalls.has(callMediaKey)) {
      socket.emit('call_error', { message: 'A call is already active' });
      return;
    }

    // ── ONLINE PATH ──
    // Authorization has already completed above. Keep the remaining DB writes
    // off the ringing path so creating the private room/call record does not
    // delay the incoming-call UI.
    if (connectedUsers.has(targetSocketId)) {
      // Publish the attempt before either signaling path can observe it. This
      // is an in-memory write (no latency), and gives every delayed timer a
      // stable identity to validate when it eventually fires.
      const callAttemptId = createCallAttemptId();
      const callAttempt = {
        callId: null,
        dbRoomId: null,
        startedAt: Date.now(),
        callType,
        _dbPending: true,
        _attemptId: callAttemptId,
        initiatorUserId: user?.userId ?? null,
        targetUserId: resolvedTargetUserId ?? null,
      };
      finalizedCalls.delete(callMediaKey);
      activeCalls.set(callMediaKey, callAttempt);

      // Multi-device: ring every device the callee is signed in on. Whichever
      // answers first cancels the ring on the others (answer_call broadcasts
      // 'call_cancelled' to the callee's user room, minus the answering socket).
      emitToUser(resolvedTargetUserId, 'incoming_call', {
        signal: signalData,
        from: socket.id,
        callerId: user?.userId,
        callerName,
        isVideoCall,
        roomId,
      });
      socket.emit('call_ringing');

      // Run DB writes in the background; authorization was completed before
      // the ring was emitted.
      if (user?.userId && resolvedTargetUserId) {
        callAttempt._dbPromise = (async () => {
          try {
            const { room } = await queries.rooms.findOrCreatePrivate(
              user.userId,
              resolvedTargetUserId,
              user.userId,
            );
            const bgDbRoomId = room.id;
            const call = await queries.calls.create({
              roomId: bgDbRoomId,
              initiatorId: user.userId,
              callType,
            });
            console.log('[Call] Created DB call record:', call.id, 'in room', bgDbRoomId);
            await queries.calls.addParticipant(call.id, user.userId);
            // Add the target too, even though they haven't answered yet — otherwise
            // a call that ends up missed/rejected has no resolvable "other party" in
            // call_participants, and admin tooling that joins on that table (e.g. the
            // Admin Calls panel) silently drops the call entirely.
            await queries.calls.addParticipant(call.id, resolvedTargetUserId);

            // Always link the captured object. finalizeCall/leave handlers may
            // already hold this exact attempt even if the shared room key has
            // since moved on to a redial.
            callAttempt.callId = call.id;
            callAttempt.dbRoomId = bgDbRoomId;
            delete callAttempt._dbPending;

            // Update the placeholder with real callId and dbRoomId — but only
            // if the entry at this key is still THIS attempt. 1:1 room ids are
            // deterministic per user-pair, so if this call already ended and a
            // new call between the same two users started before this DB
            // write landed, `existing` would be that newer attempt's
            // placeholder — mutating it would attach this stale call's
            // callId/dbRoomId onto the live one, corrupting its DB linkage.
            const existing = activeCalls.get(callMediaKey);
            if (isSameCallAttempt(existing, callAttempt)) {
              if (callAttempt.answeredAt) {
                queries.calls.updateStatus(call.id, 'ongoing').catch(() => { });
              }
              rememberCallForRecording(callMediaKey, callAttempt);
              console.log(`[Call] DB linked to activeCalls "${callMediaKey}" (callId: ${call.id})`);
            } else {
              // The attempt ended (or a redial replaced the room key) before
              // DB linking completed. Never resurrect it into activeCalls.
              const terminal = finalizedCalls.get(callMediaKey);
              if (terminal && isSameCallAttempt(terminal, callAttempt)) {
                terminal.callId = call.id;
                terminal.dbRoomId = bgDbRoomId;
              }
              console.log(`[Call] Late DB link for "${callMediaKey}" (callId: ${call.id}) — captured attempt updated without reclaiming the room key`);
            }
            return call;
          } catch (err) {
            console.error('[Call] DB background error:', err && err.message ? err.message : err);
            return null;
          }
        })();
      }
    } else {
      // Target is offline. Without a push provider there is no way to reach
      // them for a live ring, so the call is recorded and immediately marked
      // missed — the same DB/history outcome as a call nobody answered.
      const targetUserId = resolvedTargetUserId || userToCall;

      if (!isValidUserId(targetUserId)) {
        console.error(`[Call] Cannot record offline call attempt — targetUserId is not a valid user ID: "${targetUserId}"`);
        socket.emit('call_not_reachable');
        return;
      }

      const offlineActive = {
        _attemptId: createCallAttemptId(),
        callId: null,
        dbRoomId: null,
        startedAt: Date.now(),
        callType,
        _dbPending: true,
        initiatorUserId: user?.userId ?? null,
        targetUserId,
      };
      finalizedCalls.delete(callMediaKey);
      activeCalls.set(callMediaKey, offlineActive);

      if (user?.userId && resolvedTargetUserId) {
        try {
          const { room } = await queries.rooms.findOrCreatePrivate(
            user.userId,
            resolvedTargetUserId,
            user.userId,
          );
          const offlineDbRoomId = room.id;
          const call = await queries.calls.create({
            roomId: offlineDbRoomId,
            initiatorId: user.userId,
            callType,
          });
          console.log('[Call] Created DB call record (offline):', call.id, 'in room', offlineDbRoomId);
          await queries.calls.addParticipant(call.id, user.userId);
          // Add the target too — see comment on the online 1:1 path above.
          await queries.calls.addParticipant(call.id, resolvedTargetUserId);
          offlineActive.callId = call.id;
          offlineActive.dbRoomId = offlineDbRoomId;
          delete offlineActive._dbPending;

          createCallEventMessage(offlineDbRoomId, user.userId, callType, 'missed');
          await queries.calls.updateStatus(call.id, 'missed').catch(() => { });
          clearActiveCallIfCurrent(callMediaKey, offlineActive);
        } catch (err) {
          console.error('[Call] DB error (offline path):', err && err.message ? err.message : err);
          clearActiveCallIfCurrent(callMediaKey, offlineActive);
          socket.emit('call_error', { message: 'Unable to start this call. Please try again.' });
          return;
        }
      } else {
        clearActiveCallIfCurrent(callMediaKey, offlineActive);
      }

      socket.emit('call_not_reachable');
    }

    // ── Ring timeout: auto-end unanswered private call after 30 seconds ──
    if (roomId && activeCalls.has(roomId)) {
      clearRingTimeout(roomId); // safety — clear any pre-existing timer
      const callerSocketId = socket.id;
      const scheduledActive = activeCalls.get(roomId);
      const ringTimer = setTimeout(async () => {
        // An old callback may already be executing when a redial installs its
        // timer under the reused room id. Never delete that newer timer entry.
        if (ringTimeouts.get(roomId) === ringTimer) ringTimeouts.delete(roomId);
        const active = activeCalls.get(roomId);
        if (!isSameCallAttempt(active, scheduledActive)) return;
        if (scheduledActive.answeredAt) return; // accepted via native/JS; media may still be connecting
        // Belt-and-suspenders (#3): media state ⟂ signaling state. If both parties are
        // already in the SFU room (caller joins during ringing, so >= 2 means the callee
        // joined too), the call CONNECTED — never record a ghost missed call even if
        // answeredAt wasn't stamped due to a clock race.
        const peerCount = mediaServer.getPeerCount(roomId);
        if (peerCount >= 2) {
          console.log(`[Call] Ring timeout fired for ${roomId} but ${peerCount} media peers present — call is connected, not missed`);
          return;
        }
        // Check if call is still unanswered
        const callRecord = scheduledActive.callId
          ? await queries.calls.findById(scheduledActive.callId).catch(() => null)
          : null;
        if (!isSameCallAttempt(activeCalls.get(roomId), scheduledActive)) return;
        if (
          !scheduledActive.callId ||
          (callRecord && (callRecord.status === 'ringing' || callRecord.status === 'initiated'))
        ) {
          console.log(`[Call] Ring timeout (30s) — finalizing ${scheduledActive.callId || 'DB-unlinked attempt'} as missed`);
          
          const finalized = await finalizeCall(roomId, {
            reason: 'missed',
            actorUserId: null,
            isGroupCall: false,
            expectedActive: scheduledActive,
          });
          if (!finalized) return;
          if (hasSupersedingCallAttempt(roomId, scheduledActive)) return;

          // Notify the caller
          // Notify the caller
          if (connectedUsers.has(callerSocketId)) {
            io.to(callerSocketId).emit('call_not_answered', { roomId, reason: 'not_answered' });
          }
          
          const missedTargetId = resolvedTargetUserId || userToCall;
          if (isValidUserId(missedTargetId)) {
            try { io.to('user:' + missedTargetId).emit('call_ended', { roomId, reason: 'ended' }); } catch (_) {}
            queueCallEndedForUser(missedTargetId, roomId);
          }
        }
      }, 30000);
      ringTimeouts.set(roomId, ringTimer);
    }
  });

  socket.on('answer_call', async ({ signal, to, roomId }) => {
    const user = connectedUsers.get(socket.id);
    // Fallback: extract roomId from signal if not at top level
    if (!roomId && signal?.roomId) {
      roomId = signal.roomId;
    }
    console.log(`[Call] Answered by ${user?.username || socket.id}, roomId=${roomId || 'none'}`);
    const isGroupRoom = !!roomId && roomId.startsWith('group_call_');
    const answererUserId = user?.userId || socket.userId || socket.authUserId;
    const answeringCall = roomId ? activeCalls.get(roomId) : null;
    const requiredCapability = answeringCall?.isConference ? 'conferences' : 'calls';
    if (!answererUserId || !(await queries.users.hasCapability(answererUserId, requiredCapability))) {
      socket.emit('call_ended', {roomId, reason: 'access_revoked'});
      return;
    }

    // Resolve the caller's socketId up front — BOTH the dedup and normal paths need it
    // to deliver call_timer_sync.
    let targetSocketId = to;
    if (to && !connectedUsers.has(to)) {
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.userId === to) {
          targetSocketId = sid;
          break;
        }
      }
    }

    // ── Dedup: the answerer already has a peer in the media room (e.g. it joined via
    // prewarm before answer_call fired). Skip the duplicate media join + call_accepted
    // re-emit, but STILL start the timer — otherwise neither side's call clock ever
    // starts (this was the "timer never starts" bug when both are in-app). ──
    if (roomId && mediaServer.hasPeer(roomId, socket.id)) {
      console.log(`[Call] ${user?.username || socket.id} already in media room ${roomId} — duplicate answer, syncing timer only`);
      markCallAnswered(roomId, 'socket-answer-call-dedup'); // idempotent: clears ring timeout, ensures answeredAt
      if (isGroupRoom) syncGroupCallTimer(roomId);
      else syncCallTimer(roomId, targetSocketId, socket.id);
      return;
    }

    // 1:1 calls lock on explicit acceptance. A conference/group acceptance is
    // only an intent signal; it becomes answered from join_media_room once the
    // participant is genuinely present in the SFU room.
    const active = isGroupRoom
      ? activeCalls.get(roomId)
      : markCallAnswered(roomId, 'socket-answer-call');

    // Server-gate this the same way /api/call/accept (the REST accept path
    // used by Android's native panel) already is — it correctly 409s on a
    // stale call. This in-app socket path didn't have the equivalent check:
    // a ring that already timed out / was ended moments earlier would still
    // tell the caller "accepted" and let the callee try to join a media room
    // nobody else is in, stuck on a "connecting" screen with no way out.
    if (!isGroupRoom && !active) {
      console.log(`[Call] Rejecting stale answer_call for ${roomId} — no active call entry (already ended/rejected/timed out)`);
      socket.emit('call_ended', { roomId, reason: 'expired' });
      return;
    }

    if (answererUserId) {
      // Multi-device: this user may be ringing on several devices. Now that one
      // answered, tell the OTHERS to stop. socket.to(room) targets the whole
      // user room EXCEPT this answering socket, so the answerer is unaffected.
      try {
        socket.to('user:' + answererUserId).emit('call_cancelled', { roomId, reason: 'answered_elsewhere' });
      } catch (_) { /* best-effort */ }
    }

    // ── Tell the caller the call was accepted IMMEDIATELY ──
    // Media setup can begin on both sides right away; DB bookkeeping below
    // must never delay the connect path.
    io.to(targetSocketId).emit('call_accepted', { signal });

    // Start a 1:1 clock on acceptance. Group/conference clocks start from the
    // authoritative media join and are broadcast by syncGroupCallTimer.
    if (!isGroupRoom) syncCallTimer(roomId, targetSocketId, socket.id);

    // ── DB bookkeeping in the background — never blocks the connect path ──
    if (!isGroupRoom && active?.callId && user?.userId) {
      (async () => {
        try {
          await queries.calls.addParticipant(active.callId, user.userId);
          await queries.calls.answerParticipant(active.callId, user.userId);
          await queries.calls.updateStatus(active.callId, 'ongoing');

          // For group calls, create a "joined" event message
          const callRecord = await queries.calls.findById(active.callId).catch(() => null);
          if (active.dbRoomId && callRecord) {
            const room = await queries.rooms.findById(active.dbRoomId).catch(() => null);
            if (room && room.type === 'group') {
              createCallEventMessage(
                active.dbRoomId,
                callRecord.initiator_id,
                callRecord.call_type,
                'joined',
                0,
                { isGroup: true, joinedUserId: user.userId, joinedUserName: user.username },
              );
            }
          }
        } catch (err) {
          console.error('[Call] DB answer error:', err.message);
        }
      })();
    }
  });

  socket.on('ice_candidate', ({ candidate, to }) => {
    io.to(to).emit('ice_candidate', { candidate, from: socket.id });
  });

  // Receiver acknowledges the incoming call — NOW we can tell the caller it's ringing.
  // This is emitted by the client when it receives an incoming_call (either via
  // socket or via FCM background handler opening the app).
  socket.on('call_ack', ({ callerId, roomId }) => {
    const user = connectedUsers.get(socket.id);
    console.log(`[Call] Receiver ${user?.userId || socket.id} acknowledged incoming call from ${callerId}`);

    // Track ack so we can skip the delayed FCM backup push
    if (roomId && user?.userId) {
      if (!callAcks.has(roomId)) callAcks.set(roomId, new Set());
      callAcks.get(roomId).add(String(user.userId));
    }

    const callerSocketId = resolveSocketId(callerId);
    if (callerSocketId) {
      io.to(callerSocketId).emit('call_ringing');
    }
  });

  socket.on('reject_call', async ({ to, roomId, isGroupCall, reason }) => {
    const user = connectedUsers.get(socket.id);
    const rejecterUserId = user?.userId || socket.userId || socket.authUserId;
    console.log(`[Call] reject_call: roomId=${roomId || 'none'}, by ${user?.username || socket.id} (${rejecterUserId || 'unknown'})${isGroupCall ? ' (group call)' : ''}${reason ? `, reason=${reason}` : ''}, notifying caller=${to}`);

    // ── Self-room guard ──
    // If this socket (or ANY sibling device of the same user — a 1:1 call
    // rings every device they're signed into) already has a media peer in the
    // room, the user is actively IN this call. A reject_call for it is a
    // stale/duplicate decline (e.g. dismissing a still-ringing phone after
    // already answering on desktop) — honoring it would tear down the live
    // call on the device that actually answered.
    if (roomId && !isGroupCall && isUserActivePeerInRoom(rejecterUserId, roomId)) {
      console.log(`[Call] Ignoring reject_call for room ${roomId} — user ${rejecterUserId} is already an active peer via another device (stale/sibling-device decline)`);
      return;
    }

    if (roomId) {
      const rejectingActive = activeCalls.get(roomId);
      const finalized = await finalizeCall(roomId, {
        reason: 'rejected',
        actorUserId: rejecterUserId,
        isGroupCall,
        expectedActive: rejectingActive,
      });
      if (!finalized) return;
      if (hasSupersedingCallAttempt(roomId, rejectingActive)) return;
      
      // Fast-path: dismiss this call on the rejecter's OTHER devices
      if (!isGroupCall && rejecterUserId) {
        notifyCallEndedToUserDevices(rejecterUserId, roomId, 'rejected');
      }
    }

    // For 1:1 calls, notify the caller; for group calls the caller ignores this
    let targetSocketId = to;
    if (!connectedUsers.has(to)) {
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.userId === to) { targetSocketId = sid; break; }
      }
    }
    // Forward the reason so the caller can show "User is busy" vs a plain decline.
    io.to(targetSocketId).emit('call_rejected', { roomId, reason: reason || 'declined' });
    console.log(`[Call] reject_call: → call_rejected sent to socket=${targetSocketId || 'not-found'} (user=${to})`);
  });

  // ── Companion / FaceTime handoff (Layer 3 signaling) ──────────────────────
  // A device already in a call asks THIS user's OTHER devices to join the same
  // mediasoup room as a send-only camera (mic muted). `socket.to(user room)`
  // reaches the user's other devices only (not the requester). The receiving
  // device then does the normal mediasoup join as a video-only producer — that
  // media path lives in the client's call service.
  socket.on('companion_request', ({ roomId, callType }) => {
    const u = connectedUsers.get(socket.id);
    if (!u?.userId || !roomId) return;
    socket.to('user:' + u.userId).emit('companion_available', {
      roomId,
      callType: callType || 'video',
      requestedBy: socket.id,
    });
    console.log(`[Companion] ${u.username} asked their other devices to join ${roomId} as camera`);
  });

  // The companion device tells its primary device it has joined (so the primary
  // can switch its own outgoing video off and show the phone's feed instead).
  socket.on('companion_joined', ({ roomId }) => {
    const u = connectedUsers.get(socket.id);
    if (!u?.userId || !roomId) return;
    socket.to('user:' + u.userId).emit('companion_joined', { roomId, deviceSocket: socket.id });
  });

  socket.on('end_call', async ({ to, roomId, timelineReport }) => {
    const endUser = connectedUsers.get(socket.id);
    if (timelineReport && roomId) {
      try {
        mediaServer.ingestClientTimeline(roomId, socket.id, endUser?.userId || null, timelineReport);
      } catch (_) { }
    }


    console.log(`[Call] end_call: roomId=${roomId || 'none'}, by ${endUser?.username || socket.id} (${endUser?.userId || 'unknown'}), notifying to=${to || 'none'}`);
    
    if (roomId) {
      const isGroupRoom = roomId.startsWith('group_call_');
      if (isGroupRoom) {
        // Group calls are cleaned up from leave_media_room / disconnect based
        // on real room emptiness. One participant hanging up must not nuke the
        // shared call for everyone else.
        console.log(`[Call] Ignoring group end_call for ${roomId}; leave_media_room will decide when the call truly ends`);
        return;
      }

      const active = activeCalls.get(roomId);
      let callRecord = null;
      if (active?.callId) {
        callRecord = await queries.calls.findById(active.callId).catch(() => null);
      }

      const wasAnswered = !!active?.answeredAt || (callRecord && callRecord.status === 'ongoing');
      
      const finalized = await finalizeCall(roomId, {
        reason: wasAnswered ? 'completed' : 'missed',
        actorUserId: endUser?.userId,
        isGroupCall: false,
        expectedActive: active,
      });
      if (!finalized) return;
      if (hasSupersedingCallAttempt(roomId, active)) return;
    }

    let targetSocketId = to;
    let targetUserId = isValidUserId(to) ? to : null;
    if (!connectedUsers.has(to)) {
      for (const [sid, u] of connectedUsers.entries()) {
        if (u.userId === to) { targetSocketId = sid; targetUserId = u.userId; break; }
      }
    } else {
      targetUserId = connectedUsers.get(to)?.userId || targetUserId;
    }
    // Queue for reconnect if the target is offline so they don't get stuck
    if (targetUserId && targetSocketId === to && !connectedUsers.has(targetSocketId)) {
      queueCallEndedForUser(targetUserId, roomId);
    }
    io.to(targetSocketId).emit('call_ended', { roomId, reason: 'ended' });
  });

  // ── Check if a group room has an active call ─────────────────────────
  socket.on('check_active_group_call', async ({ roomId }, callback) => {
    if (!roomId) return callback?.({ active: false });
    const user = resolveCallActor(socket);
    if (!user?.userId) return callback?.({ active: false, error: 'Not authenticated' });
    const mediasoupRoomId = `group_call_${roomId}`;
    const active = activeCalls.get(mediasoupRoomId);
    // Live sockets only — see liveMediaPeerCount. A room whose peers are all
    // dead sockets is a call nobody is in, and offering to join it is how the
    // client ends up timing out on create_transport.
    const livePeerCount = liveMediaPeerCount(mediasoupRoomId);
    if (active && livePeerCount > 0) {
      try {
        const members = await queries.rooms.getParticipants(active.dbRoomId || roomId);
        if (!members.some(member => sameUserId(member.id, user.userId))) {
          return callback?.({ active: false, error: 'Not a member of this call' });
        }
      } catch (error) {
        return callback?.({ active: false, error: 'Unable to validate call membership' });
      }
      // Use the original join mode. `active.callType`/DB history may have been
      // promoted to video solely because an audio conference shared a screen.
      const callType = active.joinCallType || active.callType || 'audio';
      const callElapsedSeconds = active.answeredAt
        ? Math.floor((Date.now() - active.answeredAt) / 1000)
        : 0;
      callback?.({
        active: true,
        mediasoupRoomId,
        callType,
        participantCount: livePeerCount,
        callElapsedSeconds,
        isConference: !!active.isConference,
        conferenceRoomId: active.isConference ? active.dbRoomId : null,
      });
    } else {
      callback?.({ active: false });
    }
  });

  // ── Discover live conferences the authenticated user may join ────────
  // Ephemeral conference rooms are deliberately hidden from the normal room
  // list. Without this authenticated discovery path, dismissing an incoming
  // ring would make an otherwise live meeting impossible to find again.
  socket.on('list_active_conferences', async (_payload, callback) => {
    const user = resolveCallActor(socket);
    if (!user?.userId) {
      return callback?.({ success: false, conferences: [], error: 'Not authenticated' });
    }
    if (!(await queries.users.hasCapability(user.userId, 'conferences'))) {
      return callback?.({ success: false, conferences: [], error: 'Conferences are not enabled for this account' });
    }

    try {
      const conferences = [];
      for (const [mediasoupRoomId, active] of activeCalls.entries()) {
        if (!active?.callId || !active.isConference || !active.dbRoomId) continue;

        // Only advertise a room that has actually reached the SFU AND still
        // has somebody live in it. The short ACK-to-organizer-join window is
        // guarded separately by startupTimer; see liveMediaPeerCount for why
        // the raw peer count outlives the people it is counting.
        const livePeerCount = liveMediaPeerCount(mediasoupRoomId);
        if (livePeerCount < 1) continue;

        const members = await queries.rooms.getParticipants(active.dbRoomId);
        if (!members.some(member => sameUserId(member.id, user.userId))) continue;

        const backingRoom = await queries.rooms.findById(active.dbRoomId).catch(() => null);
        conferences.push({
          roomId: String(active.dbRoomId),
          mediasoupRoomId,
          title: backingRoom?.name || active.groupRoomName || 'Conference',
          callType: (active.joinCallType || active.callType) === 'video' ? 'video' : 'audio',
          organizerName: active.callerName || 'Organizer',
          participantCount: livePeerCount,
          callElapsedSeconds: active.answeredAt
            ? Math.max(0, Math.floor((Date.now() - active.answeredAt) / 1000))
            : 0,
          startedAt: active.startedAt || Date.now(),
        });
      }

      conferences.sort((left, right) => right.startedAt - left.startedAt);
      callback?.({ success: true, conferences });
    } catch (error) {
      console.error('[Conference] list_active_conferences error:', error?.message || error);
      callback?.({ success: false, conferences: [], error: 'Unable to load live conferences' });
    }
  });

  // ── Late-join a group call that is already in progress ───────────────
  socket.on('join_group_call', async ({ roomId }, callback) => {
    const user = connectedUsers.get(socket.id);
    if (!user?.userId) return callback?.({ success: false, error: 'Not authenticated' });

    const mediasoupRoomId = `group_call_${roomId}`;
    const active = activeCalls.get(mediasoupRoomId);
    if (!active?.callId) return callback?.({ success: false, error: 'No active call' });

    // This request is authorization/discovery only. It must not mark the call
    // answered: the client may still deny permissions or fail media setup.
    // join_media_room performs the actual lifecycle transition.
    try {
      const members = await queries.rooms.getParticipants(roomId);
      if (!members.some(member => sameUserId(member.id, user.userId))) {
        return callback?.({ success: false, error: 'Not a member of this call' });
      }

      // Keep presentation video separate from the attendee's join mode. An
      // audio conference with a shared screen must not turn on a late joiner's
      // camera or request camera permission unexpectedly.
      const callType = active.joinCallType || active.callType || 'audio';
      const callElapsedSeconds = active.answeredAt
        ? Math.floor((Date.now() - active.answeredAt) / 1000)
        : 0;

      callback?.({
        success: true,
        mediasoupRoomId,
        callType,
        callElapsedSeconds,
        isConference: !!active.isConference,
        conferenceRoomId: active.isConference ? active.dbRoomId : null,
      });
    } catch (err) {
      console.error('[Call] join_group_call error:', err.message);
      callback?.({ success: false, error: err.message });
    }
  });

  // ========================================================================
  // Call history and recordings
  // ========================================================================

  socket.on('get_call_history', async ({ roomId, limit, offset }, callback) => {
    try {
      const calls = roomId
        ? await queries.calls.listByRoom(roomId, { limit, offset })
        : [];
      callback({ success: true, calls });
    } catch (err) {
      callback({ success: false, error: err.message });
    }
  });

  socket.on('get_recordings', async ({ callId }, callback) => {
    try {
      const recordings = await queries.recordings.findByCallId(callId);
      callback({ success: true, recordings });
    } catch (err) {
      callback({ success: false, error: err.message });
    }
  });

  // ========================================================================

  // ========================================================================

  socket.on('disconnect', async () => {
    const user = connectedUsers.get(socket.id);
    socketVLog('[Socket] Disconnected:', user?.username || socket.id);

    // ✅ SECURITY: Clean up rate limiter for this socket
    socketRateLimiter.removeSocket(socket.id);

    // Clean up per-user resource counters
    userTransportCount.delete(socket.id);
    userProducerCount.delete(socket.id);

    // Get the peer's media room BEFORE removing (so we can finalize the call)
    const peerInfo = mediaServer.peers?.get(socket.id);
    const peerMediaRoomId = peerInfo?.roomId || null;
    const peerAttemptId = peerInfo?.peer?.callAttemptId || null;
    // Remove peer FIRST (synchronous) to prevent race conditions — same
    // rationale as leave_media_room. On disconnect the socket is gone so
    // a rapid rejoin from the same socketId is impossible, but keeping the
    // order consistent avoids any future surprises.
    mediaServer.removePeer(socket.id);

    const newStats = peerMediaRoomId ? mediaServer.getRoomStats(peerMediaRoomId) : null;
    const roomIsEmpty = !!peerMediaRoomId && (!newStats || newStats.peerCount === 0);
    // Prefer the live call entry, but fall back to the recording-recovery entry
    // in finalizedCalls so a captured recording is never orphaned when activeCalls
    // was already cleared (end_call, race) before this socket dropped.
    let active = peerMediaRoomId ? activeCalls.get(peerMediaRoomId) : null;
    if (peerAttemptId && !isCallAttemptId(active, peerAttemptId)) {
      active = null;
    }
    if (!active && peerMediaRoomId) {
      active = finalizedCalls.get(peerMediaRoomId) || null;
      if (peerAttemptId && !isCallAttemptId(active, peerAttemptId)) {
        active = null;
      }
      if (active?.callId && roomIsEmpty) {
        console.log(`[disconnect] Recovered call ${active.callId} for ${peerMediaRoomId} from finalizedCalls — finalizing orphaned recording`);
      }
    }
    const isGroupRoom = !!peerMediaRoomId && peerMediaRoomId.startsWith('group_call_');

    // Notify remaining peers that this peer left — but for a LIVE mid-call drop,
    // hold a RECONNECT_GRACE_MS window first so a brief network blip doesn't end
    // the call. If the user already reconnected on a fresh socket, the old
    // socket's exit is silent.
    if (peerMediaRoomId) {
      // An ANSWERED call is held even when this drop empties the room: on a
      // flaky link every participant is routinely disconnected at the same
      // instant, and tearing down then is what left reconnecting users seeing
      // "Not a member of this call". A still-ringing call keeps the old
      // behavior — the callee must learn it was missed immediately, not in 25s.
      const liveMidCallDrop =
        !!active?.callId &&
        !active?.terminalState &&
        !!user?.userId &&
        (!roomIsEmpty || !!active.answeredAt);
      if (
        liveMidCallDrop &&
        isUserInMediaRoom(
          peerMediaRoomId,
          user.userId,
          socket.id,
          getCallAttemptId(active),
        )
      ) {
        console.log(`[Reconnect] ${user.username || user.userId} old socket closed but already rejoined ${peerMediaRoomId} — no peer_left`);
      } else if (liveMidCallDrop) {
        io.to(peerMediaRoomId).emit('peer_reconnecting', {
          peerId: socket.id,
          userId: user.userId,
          username: user.username || null,
        });
        scheduleGracefulPeerLeave(peerMediaRoomId, socket.id, user.userId, user.username, active);
      } else {
        io.to(peerMediaRoomId).emit('peer_left', {
          peerId: socket.id,
          userId: user?.userId || null,
          username: user?.username || null,
        });
        if (roomIsEmpty) clearReconnectGraceForRoom(peerMediaRoomId, active);
      }
    }

    // Captured at drop time, not at teardown time — the teardown below may be
    // held for the grace window, and the call's duration ends when the last
    // participant actually dropped.
    const disconnectEndedAt = Date.now();

    // Everything from here to the media-room cleanup permanently ends the call
    // (deletes its activeCalls entry, finalizes the DB row, stops recording,
    // closes the router). It is deliberately NOT re-indented so this hotfix
    // stays reviewable — only the wrapper and the hold/run decision are new.
    const finalizeDroppedCall = async () => {
    // Release the room key independent of callId — see clearCurrentActiveCall.
    if (roomIsEmpty) {
      clearCurrentActiveCall(peerMediaRoomId, active, { broadcastInactive: isGroupRoom });
    }

    // Detach the old capture before the first DB await. Private/group room ids
    // are reusable, and a redial must be free to start a fresh recording while
    // the prior FFmpeg processes finish flushing in the background.
    const rawDisconnectPromise = roomIsEmpty && active?.callId
      ? mediaServer.stopRecordingRaw(peerMediaRoomId).catch((e) => {
          console.error(`[Call] ⚠️ Raw recording stop error on disconnect for call ${active.callId}:`, e?.message || e);
          console.error('[Call] Raw files may exist on disk but recording will not be processed — check recordings/ dir');
          return null;
        })
      : null;

    let callRecord = null;

    // Finalize call status in DB first for immediate visibility.
    if (active?.callId && roomIsEmpty) {
      callRecord = await queries.calls.findById(active.callId).catch(() => null);
      if (
        callRecord &&
        !active.terminalState &&
        callRecord.status !== 'completed' &&
        callRecord.status !== 'missed' &&
        callRecord.status !== 'rejected'
      ) {
        const wasAnswered = !!active.answeredAt || callRecord.status === 'ongoing';
        if (wasAnswered) {
          await queries.calls.end(active.callId).catch(() => { });
          if (active.dbRoomId) {
            const durationSec = active.answeredAt
              ? Math.round((disconnectEndedAt - active.answeredAt) / 1000)
              : 0;
            createCallEventMessage(active.dbRoomId, callRecord.initiator_id, callRecord.call_type, 'completed', durationSec);
          }
        } else {
          await queries.calls.updateStatus(active.callId, 'missed').catch(() => { });
          if (active.dbRoomId) {
            createCallEventMessage(active.dbRoomId, callRecord.initiator_id, callRecord.call_type, 'missed');
          }
        }
      }
    }

    if (roomIsEmpty && active?.callId) {
      // Phase 1: raw capture — synchronous, tears down mediasoup room
      const rawDisconnect = await rawDisconnectPromise;
      // Phase 2: transcoding — queued in background
      if (rawDisconnect) {
        const capturedCallId = active.callId;
        const capturedDbRoomId = active.dbRoomId;
        if (shouldDiscardShortRecording(rawDisconnect, active.callType)) {
          const minDurationMs = getMinimumRecordingDurationMs(active.callType);
          console.log(
            `[Recording] Skipping short disconnected ${active.callType} call ${capturedCallId}: ` +
            `${Math.round(rawDisconnect.duration)}ms < ${minDurationMs}ms`
          );
          await discardRecordingArtifacts(capturedCallId, rawDisconnect, 'short-disconnect-call');
        } else {
          recordingQueue.add(
            () => mediaServer.extractFromRaw(rawDisconnect, capturedCallId),
            capturedCallId,
            capturedDbRoomId,
            mediaServer.buildResumeSnapshot(rawDisconnect)
          );
          console.log(`[RecordingQueue] Enqueued transcoding for disconnected call ${capturedCallId} — queue depth: ${recordingQueue.size}`);
        }
      }
    }

    // Finalize group call if media room is now empty
    if (peerMediaRoomId) {
      if (active?.callId && roomIsEmpty) {
        if (isGroupRoom && active.dbRoomId) {
          if (hasSupersedingActiveCall(peerMediaRoomId, active.callId)) {
            console.log(`[Call] Skipping stale disconnect notifications for ${peerMediaRoomId} because a newer call is already active`);
          } else {
            try {
              const callerUserId = user?.userId || callRecord?.initiator_id;
              const participants = await queries.rooms.getParticipants(active.dbRoomId);
              for (const p of participants) {
                if (sameUserId(p.id, callerUserId)) continue;
                for (const [sid, u] of connectedUsers.entries()) {
                  if (u.userId === p.id) {
                    io.to(sid).emit('call_ended', { roomId: peerMediaRoomId, reason: 'ended' });
                  }
                }
              }
              console.log(`[Call] disconnect: notified ${participants.length - 1} receiver(s) for ended group call in room ${active.dbRoomId}`);
            } catch (err) {
              console.error('[Call] disconnect group notify error:', err?.message || err);
            }
          }
        }
      }
    }

    // Ephemeral conference: purge its in-call chat now that everyone has left
    // (same rationale as leave_media_room's mirrored block).
    if (roomIsEmpty && active?.isConference && active?.dbRoomId) {
      db.query('DELETE FROM messages WHERE room_id = $1', [active.dbRoomId])
        .then(() => console.log(`[Conference] Purged ephemeral chat for room ${active.dbRoomId}`))
        .catch(err => console.error('[Conference] purge error:', err.message));
    }

    // Reclaim the recording-recovery entry once the room is empty + finalized.
    if (peerMediaRoomId && roomIsEmpty) clearRecordingRecovery(peerMediaRoomId, active);

    // Clean up room if empty and no active recording (same as leave_media_room)
    if (peerMediaRoomId) {
      const roomAfterCleanup = mediaServer.rooms?.get(peerMediaRoomId);
      if (roomAfterCleanup && roomAfterCleanup.peers.size === 0 && !roomAfterCleanup.recording) {
        try { roomAfterCleanup.router.close(); } catch (_) { }
        mediaServer.rooms.delete(peerMediaRoomId);
        console.log(`[Media] Room ${peerMediaRoomId} cleaned up after disconnect + recording stop`);
      }
    }
    };

    // Hold the teardown while anyone can still come back. runRoomFinalizerIfDue
    // (fired when the last grace expires) runs it; a rejoin discards it.
    if (peerMediaRoomId && roomIsEmpty && roomHasPendingGrace(peerMediaRoomId, active)) {
      holdRoomFinalizer(peerMediaRoomId, active, finalizeDroppedCall);
    } else {
      await finalizeDroppedCall();
    }

    if (user?.userId) {
      // Multi-device: only flip the user offline when their LAST device drops.
      // If any other live socket for this user remains, they're still online.
      let hasOtherLiveSocket = false;
      for (const [sid, u] of connectedUsers.entries()) {
        if (sid === socket.id) continue;
        if (u.userId === user.userId && io.sockets.sockets.get(sid)) { hasOtherLiveSocket = true; break; }
      }
      if (!hasOtherLiveSocket) {
        await queries.users.setOnlineStatus(user.userId, false).catch(() => { });
        // Notify all clients that this user went offline
        io.emit('user_status_changed', { userId: user.userId, username: user.username, is_online: false });
      }

      // If this user was a caller with an active (unanswered) call, clean up
      // the pending incoming_call notification for the target so the receiver
      // doesn't get a stale popup.
      for (const [roomId, callInfo] of activeCalls.entries()) {
        if (callInfo.callId) {
          // `shouldClear` is decided once, up front, from data already in memory
          // (no await in between) — so the finally below is guaranteed to run the
          // release exactly when it's owed, regardless of which async step throws.
          // Without this, a transient DB error anywhere in the block below used to
          // jump straight past clearActiveCallIfCurrent, leaving the entry in
          // activeCalls forever (isUserBusyInActiveCall has no TTL/sweeper), which
          // permanently marked the caller "busy" until the process restarted.
          let shouldClear = false;
          try {
            const call = await queries.calls.findById(callInfo.callId);
            shouldClear = !!(call && !callInfo.answeredAt && call.initiator_id === user.userId && (call.status === 'ringing' || call.status === 'initiated'));
            if (shouldClear) {
              clearRingTimeout(roomId);
              // Caller disconnected before the call was answered — mark as missed
              await queries.calls.updateStatus(callInfo.callId, 'missed').catch(() => { });
              // Create a missed call event message
              if (callInfo.dbRoomId) {
                createCallEventMessage(callInfo.dbRoomId, call.initiator_id, call.call_type, 'missed');
              }
              // Find the target user from call participants or room members
              // and notify them + clean up their pending incoming_call notifications
              const participants = await queries.calls.getParticipants(callInfo.callId).catch(() => []);
              for (const p of participants) {
                if (p.user_id !== user.userId) {
                  // Emit call_ended to the callee so their UI dismisses the incoming call
                  let notified = false;
                  for (const [sid, u] of connectedUsers.entries()) {
                    if (u.userId === p.user_id) {
                      io.to(sid).emit('call_ended', { roomId, reason: 'ended' });
                      console.log(`[Call] Sent call_ended to callee ${u.username} (caller disconnected)`);
                      notified = true;
                    }
                  }
                  // Queue for reconnect if callee is offline
                  if (!notified) queueCallEndedForUser(p.user_id, roomId);
                }
              }
              console.log(`[Call] Cleaned up missed call ${callInfo.callId} (caller disconnected)`);
            }
          } catch (err) {
            console.error('[Call] Disconnect cleanup error:', err.message);
          } finally {
            if (shouldClear) clearActiveCallIfCurrent(roomId, callInfo);
          }
        } else if (
          callInfo._dbPending &&
          !callInfo.answeredAt &&
          sameUserId(callInfo.initiatorUserId, user.userId)
        ) {
          // The DB call record (and thus callId) never landed before this
          // disconnect — e.g. the caller closed/backgrounded the app moments
          // after dialing, or the socket dropped mid-setup. The branch above
          // can't see this (it keys off callId), so without this the entry
          // survives with initiatorUserId still pointing at this user, and
          // isUserBusyInActiveCall silently blocks every call they place
          // afterward — with nothing in the logs to explain why — until the
          // 6h STALE_CALL_TTL_MS backstop finally clears it. No DB row exists
          // yet to update; the in-flight _dbPromise already no-ops itself onto
          // finalizedCalls instead of resurrecting this key once it lands (see
          // call_user's background DB-write completion handler).
          console.warn(`[Call] Releasing never-DB-linked call room=${roomId} for ${user.username || user.userId} — caller disconnected before the call record was created`);
          if (callInfo.targetUserId) {
            let notifiedDangling = false;
            for (const [sid, u] of connectedUsers.entries()) {
              if (u.userId === callInfo.targetUserId) {
                io.to(sid).emit('call_ended', { roomId, reason: 'ended' });
                notifiedDangling = true;
              }
            }
            if (!notifiedDangling) queueCallEndedForUser(callInfo.targetUserId, roomId);
          }
          clearActiveCallIfCurrent(roomId, callInfo);
        }
      }
    }

    connectedUsers.delete(socket.id);
    io.emit('users_online', Array.from(connectedUsers.values()));
  });
});

// Centralized upload/multipart error handling to keep client responses JSON.
// Prevents RN clients from choking on default HTML errors and gives actionable messages.

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum size is 100MB.' });
    }
    return res.status(400).json({ error: err.message || 'Upload failed' });
  }

  if (typeof err?.message === 'string' && err.message.startsWith('File type not allowed:')) {
    return res.status(415).json({ error: err.message });
  }

  return next(err);
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
async function startServer() {
  try {
    cleanupStaleRecordingArtifacts();

    const dbOk = await db.testConnection();
    if (!dbOk) {
      console.error('[Server] Database connection failed. Exiting.');
      process.exit(1);
    }

    // Security log retention: purge >90-day login_audit rows now, then daily.
    purgeOldLoginAudit();
    setInterval(purgeOldLoginAudit, 24 * 60 * 60 * 1000);

    // Scheduled-conference "starting soon" reminders — sweep every minute.
    setInterval(sendConferenceReminders, 60 * 1000);
    // Scheduled-conference "starting now" notifications — same cadence.
    setInterval(sendConferenceStartNotifications, 60 * 1000);

    // Backstop for activeCalls entries a teardown path failed to release (see
    // STALE_CALL_TTL_MS). Loud on purpose — every prior instance of this class
    // of bug was invisible because the failure was swallowed inside a `catch`
    // with no log, so the only symptom was "can't call, no error anywhere".
    setInterval(() => {
      for (const [roomId, active] of activeCalls.entries()) {
        if (!isStaleActiveCall(active)) continue;
        console.warn(`[Call] Sweeping stale activeCalls entry room=${roomId} callId=${active?.callId ?? 'n/a'} startedAt=${new Date(active.startedAt).toISOString()} — a teardown path failed to release this call`);
        clearActiveCallIfCurrent(roomId, active);
      }
    }, STALE_CALL_SWEEP_INTERVAL_MS);

    await mediaServer.init();

    // Active-speaker relay: mediaServer owns the mediasoup AudioLevelObserver
    // per room (pure media plumbing) and emits here; server.js owns turning
    // that into a room broadcast (the socket layer), so mediaServer never
    // needs a reference to `io`. One process-lifetime listener — rooms come
    // and go, but this relay doesn't need to.
    mediaServer.on('active_speaker', ({ roomId, peerId, userId, username, volume }) => {
      io.to(roomId).emit('active_speaker', { roomId, peerId, userId, username, volume });
    });

    // A producer this peer was consuming went away (its owner reconnected,
    // closed the camera, or dropped). mediasoup tears down the server-side
    // consumer on its own; this tells the one client that was consuming it so
    // it can evict the dead track instead of rendering its last frame forever.
    // Addressed to the consuming peer only — unlike `close_producer`, which is
    // a room-wide broadcast from the producer's own side.
    mediaServer.on('producer_closed', ({ roomId, peerId, producerId, producerPeerId, kind, appData }) => {
      io.to(peerId).emit('producer_closed', {
        roomId,
        producerId,
        peerId: producerPeerId,
        kind,
        appData: appData || {},
      });
    });

    // Recover any recording jobs interrupted by the last shutdown/crash, then
    // sweep terminal journal rows hourly so the table stays bounded. Fire-and-
    // forget so it never delays the port binding.
    resumeRecordingJobs().catch((e) => console.warn('[RecordingQueue] resume drain error:', e?.message));
    setInterval(() => {
      queries.recordingJobs.sweepTerminal(60).catch(() => { });
    }, 60 * 60 * 1000);

    const PORT = process.env.PORT || 3000;
    // Production traffic must enter through local Nginx. Explicit development
    // may listen on the LAN for direct mobile-device testing; HOST can override
    // either default when the deployment topology intentionally differs.
    const HOST = process.env.HOST
      || (process.env.NODE_ENV === 'development' ? '0.0.0.0' : '127.0.0.1');
    server.listen(PORT, HOST, () => {
      console.log('');
      console.log('='.repeat(40));
      console.log(`  Server running on ${HOST}:${PORT}`);
      console.log(`  Local IP: ${SERVER_IP}`);
      console.log('='.repeat(40));
      console.log('');
      console.log(`Connect your client to: http://${SERVER_IP}:${PORT}`);
      console.log('');

      // ✅ SECURITY: Periodic cleanup of rate limiter (every 5 minutes)
      setInterval(() => {
        socketRateLimiter.cleanup();
      }, 5 * 60 * 1000);
    });
  } catch (error) {
    console.error('[Server] Failed to start:', error);
    process.exit(1);
  }
}

// Graceful shutdown (idempotent)
let isShuttingDown = false;
const gracefulShutdown = async (signal) => {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;

  console.log(`\n[Server] Shutting down... (${signal})`);

  try {
    await mediaServer.close();
  } catch (e) {
    console.error('[Server] mediaServer.close error:', e?.message || e);
  }

  try {
    await db.close();
  } catch (e) {
    console.error('[Server] db.close error:', e?.message || e);
  }

  process.exit(0);
};

process.on('SIGINT', () => {
  gracefulShutdown('SIGINT');
});

process.on('SIGTERM', () => {
  gracefulShutdown('SIGTERM');
});

// ── Last-resort crash guards ──────────────────────────────────────────────
// A single rejected promise or thrown error in any async handler would, by
// Node's defaults (15+), terminate the process — dropping EVERY live call,
// socket, and recording in progress. For a realtime server that's the worst
// possible failure mode for one bad code path. We log loudly and keep serving;
// pm2 still restarts on a genuine hard exit, and these logs surface the bug to
// fix at the source rather than via an outage.
process.on('unhandledRejection', (reason) => {
  console.error('[crash-guard] Unhandled promise rejection — keeping server alive:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[crash-guard] Uncaught exception — keeping server alive:', err);
});

startServer();

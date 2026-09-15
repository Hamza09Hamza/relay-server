/**
 * Shared in-memory state — the single source of truth for volatile,
 * process-local lookups used across HTTP routes and Socket.IO handlers.
 *
 * Every module that `require`s this file receives the SAME Map references,
 * so reads and writes are always consistent regardless of which module
 * performs them. None of this is persisted.
 *
 * (If the server later moves to a clustered / multi-process setup, these are
 * the structures that would be backed by Redis instead.)
 *
 * `activeCalls` already goes through the `CallStateStore` seam: it is a `Map`
 * subclass (in-memory by default, Redis-mirroring when `CALL_STATE_BACKEND=redis`),
 * so the single→multi-instance move is a config flip, not a rewrite. See
 * `callStateStore.js`.
 */

const { createCallStateStore } = require('./callStateStore');

module.exports = {
  // socketId -> { socketId, userId, username }
  connectedUsers: new Map(),

  // roomId -> { callId, dbRoomId, startedAt, answeredAt, callType, ... }
  // CallStateStore (Map subclass): in-memory today, Redis-mirroring when enabled.
  activeCalls: createCallStateStore(),
  // roomId -> { callId, dbRoomId } — kept after end_call deletes from activeCalls
  finalizedCalls: new Map(),
  // userId -> [{ roomId, endedAt }] — call_ended events pending delivery (10 min TTL)
  pendingCallEnded: new Map(),
  // `${roomId}::${userId}` -> { timer, socketId, roomId, userId, username }
  reconnectGrace: new Map(),
  // roomId -> setTimeout id (auto-end unanswered calls)
  ringTimeouts: new Map(),
  // roomId -> Set<userId> (users who acknowledged the incoming call via socket)
  callAcks: new Map(),

  // socketId -> number (per-user DoS guards)
  userTransportCount: new Map(),
  userProducerCount: new Map(),

  // userId -> { isAdmin, expiresAt }
  adminRoleCache: new Map(),
  // userId -> { deleted, status, tokenVersion, expiresAt } — lets
  // authMiddleware reject a deleted/suspended/password-changed account's
  // still-valid JWT without a DB round trip on every single request.
  authStatusCache: new Map(),
  // userId -> password (admin-set resets, cleared on retrieval or after 30 min)
  tempResetPasswords: new Map(),

  // token -> { expiry, userId, fileName }
  uploadAccessTokens: new Map(),
};

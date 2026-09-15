const { randomUUID } = require('crypto');

/**
 * A media-room id is not a call id. Private calls currently reuse the same
 * room id when the same two sockets redial, and group calls intentionally use
 * one deterministic room id. Every lifecycle mutation therefore also needs a
 * per-attempt identity or a late teardown can delete the next call.
 */
function createCallAttemptId() {
  return randomUUID();
}

function getCallAttemptId(call) {
  if (!call) return null;
  if (call._attemptId !== null && call._attemptId !== undefined) {
    return String(call._attemptId);
  }
  // Backward-compatible fallback for state hydrated from before attempt ids
  // were introduced. New calls always receive _attemptId before publication.
  if (call.callId !== null && call.callId !== undefined) {
    return `call:${String(call.callId)}`;
  }
  return null;
}

function isSameCallAttempt(left, right) {
  if (!left || !right) return false;
  if (left === right) return true;

  const leftId = getCallAttemptId(left);
  const rightId = getCallAttemptId(right);
  return leftId !== null && rightId !== null && leftId === rightId;
}

function isCallAttemptId(call, attemptId) {
  if (!call || attemptId === null || attemptId === undefined) return false;
  return getCallAttemptId(call) === String(attemptId);
}

/** Delete only when `expected` still owns the room key. */
function deleteCallIfCurrent(store, roomId, expected) {
  const current = store.get(roomId);
  if (!isSameCallAttempt(current, expected)) return false;
  store.delete(roomId);
  return true;
}

function sameUserId(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) {
    return false;
  }
  return String(left) === String(right);
}

/**
 * Participant ownership that exists before media peers do. This closes the
 * ringing/connecting gap where peer-only busy detection allowed overlapping
 * calls to the same user.
 */
function isUserParticipantInCall(call, userId) {
  if (!call || userId === null || userId === undefined) return false;
  if (sameUserId(call.initiatorUserId, userId)) return true;
  if (sameUserId(call.targetUserId, userId)) return true;

  const collections = [
    call.targetUserIds,
    call.joinedUserIds,
    call.participantUserIds,
  ];
  for (const collection of collections) {
    if (!collection) continue;
    const values = collection instanceof Set
      ? collection.values()
      : (Array.isArray(collection) ? collection : []);
    for (const candidate of values) {
      if (sameUserId(candidate, userId)) return true;
    }
  }
  return false;
}

/**
 * Backstop for activeCalls entries that a teardown path failed to release.
 * Every finalize/disconnect/reject path is expected to release its own entry
 * (see clearActiveCallIfCurrent / clearCurrentActiveCall in server.js) — this
 * TTL is not the primary mechanism, it exists so a single missed path can
 * strand a user "busy" for at most this long instead of until the process
 * restarts. isUserBusyInActiveCall's activeCalls scan otherwise trusts entries
 * unconditionally, and nothing else sweeps that map.
 * 6h is far beyond any real call duration, so it never cuts a live call short.
 */
const STALE_CALL_TTL_MS = 6 * 60 * 60 * 1000;
const STALE_CALL_SWEEP_INTERVAL_MS = 15 * 60 * 1000;

function isStaleActiveCall(active, now = Date.now()) {
  return !!active?.startedAt && (now - active.startedAt) > STALE_CALL_TTL_MS;
}

module.exports = {
  createCallAttemptId,
  getCallAttemptId,
  isSameCallAttempt,
  isCallAttemptId,
  deleteCallIfCurrent,
  isUserParticipantInCall,
  isStaleActiveCall,
  STALE_CALL_TTL_MS,
  STALE_CALL_SWEEP_INTERVAL_MS,
};

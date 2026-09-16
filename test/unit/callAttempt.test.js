'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  createCallAttemptId,
  getCallAttemptId,
  isSameCallAttempt,
  isCallAttemptId,
  deleteCallIfCurrent,
  isUserParticipantInCall,
  isStaleActiveCall,
  STALE_CALL_TTL_MS,
} = require('../../src/app/callAttempt');

test('createCallAttemptId: produces unique ids', () => {
  const a = createCallAttemptId();
  const b = createCallAttemptId();
  assert.notEqual(a, b);
});

test('getCallAttemptId: prefers _attemptId, falls back to callId, else null', () => {
  assert.equal(getCallAttemptId({ _attemptId: 'x' }), 'x');
  assert.equal(getCallAttemptId({ callId: 42 }), 'call:42');
  assert.equal(getCallAttemptId({}), null);
  assert.equal(getCallAttemptId(null), null);
});

test('isSameCallAttempt: two objects with the same _attemptId are the same attempt', () => {
  const a = { _attemptId: 'abc' };
  const b = { _attemptId: 'abc' };
  assert.equal(isSameCallAttempt(a, b), true);
});

test('isSameCallAttempt: a redial gets a new attempt id, so it is not the same attempt', () => {
  const original = { _attemptId: 'abc', callId: 1 };
  const redial = { _attemptId: 'def', callId: 2 };
  assert.equal(isSameCallAttempt(original, redial), false);
});

test('isSameCallAttempt: null/undefined never match', () => {
  assert.equal(isSameCallAttempt(null, { _attemptId: 'x' }), false);
  assert.equal(isSameCallAttempt({ _attemptId: 'x' }, undefined), false);
});

test('isCallAttemptId: compares against a specific attempt id string', () => {
  const call = { _attemptId: 'abc' };
  assert.equal(isCallAttemptId(call, 'abc'), true);
  assert.equal(isCallAttemptId(call, 'xyz'), false);
  assert.equal(isCallAttemptId(null, 'abc'), false);
});

test('deleteCallIfCurrent: only deletes when the store still holds the expected attempt', () => {
  const store = new Map();
  const attempt = { _attemptId: 'abc' };
  store.set('room1', attempt);

  // A stale caller holding an older attempt object must not delete the live one.
  const stale = { _attemptId: 'old' };
  assert.equal(deleteCallIfCurrent(store, 'room1', stale), false);
  assert.equal(store.has('room1'), true);

  assert.equal(deleteCallIfCurrent(store, 'room1', attempt), true);
  assert.equal(store.has('room1'), false);
});

test('isUserParticipantInCall: matches initiator, target, and each collection field', () => {
  assert.equal(isUserParticipantInCall({ initiatorUserId: 'u1' }, 'u1'), true);
  assert.equal(isUserParticipantInCall({ targetUserId: 'u2' }, 'u2'), true);
  assert.equal(isUserParticipantInCall({ targetUserIds: ['u3'] }, 'u3'), true);
  assert.equal(isUserParticipantInCall({ joinedUserIds: new Set(['u4']) }, 'u4'), true);
  assert.equal(isUserParticipantInCall({ initiatorUserId: 'u1' }, 'nobody'), false);
  assert.equal(isUserParticipantInCall(null, 'u1'), false);
});

test('isUserParticipantInCall: compares userIds as strings (UUID vs numeric-id tolerant)', () => {
  assert.equal(isUserParticipantInCall({ initiatorUserId: 1 }, '1'), true);
});

test('isStaleActiveCall: false for a fresh call, true once past the TTL', () => {
  const now = Date.now();
  assert.equal(isStaleActiveCall({ startedAt: now }, now), false);
  assert.equal(isStaleActiveCall({ startedAt: now - STALE_CALL_TTL_MS - 1 }, now), true);
  assert.equal(isStaleActiveCall({}, now), false);
});

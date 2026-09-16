'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const rateLimiter = require('../../socketRateLimiter');

// The module exports a singleton, so every test uses its own socketId to
// avoid cross-test interference.
let counter = 0;
function socketId() {
  return `test-socket-${++counter}`;
}

test('isAllowed: stays allowed up to the configured per-event limit', () => {
  const sid = socketId();
  const limit = rateLimiter.getLimit('typing_start').maxPerMinute;
  for (let i = 0; i < limit; i++) {
    assert.equal(rateLimiter.isAllowed(sid, 'typing_start'), true, `call ${i + 1} should be allowed`);
  }
  assert.equal(rateLimiter.isAllowed(sid, 'typing_start'), false, 'one past the limit should be refused');
});

test('isAllowed: unmapped events fall back to the default limit', () => {
  const sid = socketId();
  const def = rateLimiter.getLimit('some_unknown_event');
  assert.equal(def.maxPerMinute, rateLimiter.getLimit('default').maxPerMinute);
});

test('isAllowed: limits are tracked independently per event name', () => {
  const sid = socketId();
  const limit = rateLimiter.getLimit('call_user').maxPerMinute;
  for (let i = 0; i < limit; i++) rateLimiter.isAllowed(sid, 'call_user');
  assert.equal(rateLimiter.isAllowed(sid, 'call_user'), false);
  // A different event on the same socket is unaffected.
  assert.equal(rateLimiter.isAllowed(sid, 'typing_start'), true);
});

test('isAllowed: limits are tracked independently per socket', () => {
  const sidA = socketId();
  const sidB = socketId();
  const limit = rateLimiter.getLimit('kick_member').maxPerMinute;
  for (let i = 0; i < limit; i++) rateLimiter.isAllowed(sidA, 'kick_member');
  assert.equal(rateLimiter.isAllowed(sidA, 'kick_member'), false);
  assert.equal(rateLimiter.isAllowed(sidB, 'kick_member'), true);
});

test('removeSocket: clears a socket\'s history so a rejoin starts fresh', () => {
  const sid = socketId();
  const limit = rateLimiter.getLimit('camera_on').maxPerMinute;
  for (let i = 0; i < limit; i++) rateLimiter.isAllowed(sid, 'camera_on');
  assert.equal(rateLimiter.isAllowed(sid, 'camera_on'), false);

  rateLimiter.removeSocket(sid);
  assert.equal(rateLimiter.isAllowed(sid, 'camera_on'), true);
});

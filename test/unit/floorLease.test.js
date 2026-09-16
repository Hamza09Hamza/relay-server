'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { FloorLease } = require('../../src/modules/ptt/floorLease');

test('acquire: a free channel is granted to the first requester', () => {
  const floors = new FloorLease();
  const result = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  assert.equal(result.ok, true);
  assert.equal(result.floor.userId, 'u1');
  assert.equal(floors.get('ch1').userId, 'u1');
});

test('acquire: a held channel refuses a different user at equal priority', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  const result = floors.acquire('ch1', { userId: 'u2', username: 'Bob', socketId: 's2' });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'floor_busy');
  assert.equal(result.holder.userId, 'u1');
});

test('acquire: re-pressing while already holding is idempotent (reacquired)', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  const result = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  assert.equal(result.ok, true);
  assert.equal(result.reacquired, true);
});

test('acquire: one socket cannot transmit on two channels at once', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  const result = floors.acquire('ch2', { userId: 'u1', username: 'Alice', socketId: 's1' });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'already_transmitting');
  assert.equal(result.holder.channelId, 'ch1');
});

test('acquire: strictly higher priority preempts the current holder', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1', priority: 0 });
  const result = floors.acquire('ch1', { userId: 'admin', username: 'Admin', socketId: 's2', priority: 10 });
  assert.equal(result.ok, true);
  assert.equal(result.preempted.userId, 'u1');
  assert.equal(floors.get('ch1').userId, 'admin');
});

test('acquire: equal priority never preempts, even from a second requester', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1', priority: 5 });
  const result = floors.acquire('ch1', { userId: 'u2', username: 'Bob', socketId: 's2', priority: 5 });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'floor_busy');
});

test('renew: only the exact holder (user+socket+transmission) can extend the lease', () => {
  const floors = new FloorLease({ ttlMs: 1000 });
  const { floor } = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });

  const wrongUser = floors.renew('ch1', { userId: 'u2', socketId: 's1', transmissionId: floor.transmissionId });
  assert.equal(wrongUser.ok, false);
  assert.equal(wrongUser.reason, 'not_holder');

  const ok = floors.renew('ch1', { userId: 'u1', socketId: 's1', transmissionId: floor.transmissionId });
  assert.equal(ok.ok, true);
  // Same-millisecond synchronous calls can tie under Date.now()'s resolution;
  // what matters is renew() never shortens the lease.
  assert.ok(ok.floor.expiresAt >= floor.expiresAt);
});

test('renew: refused past the hard transmission-length cap', () => {
  const floors = new FloorLease({ ttlMs: 100000, maxMs: 50 });
  const { floor } = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  // Backdate acquiredAt to simulate a transmission that has run past maxMs.
  floor.acquiredAt = Date.now() - 1000;
  const result = floors.renew('ch1', { userId: 'u1', socketId: 's1', transmissionId: floor.transmissionId });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'max_length');
  assert.equal(floors.get('ch1'), null);
});

test('release: a stale transmissionId cannot cut off a newer holder', () => {
  const floors = new FloorLease();
  const first = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  // Simulate the first transmission's floor lapsing and a new one starting.
  floors.release('ch1', { userId: 'u1', socketId: 's1', transmissionId: first.floor.transmissionId });
  floors.acquire('ch1', { userId: 'u2', username: 'Bob', socketId: 's2' });

  const lateRelease = floors.release('ch1', {
    userId: 'u1', socketId: 's1', transmissionId: first.floor.transmissionId,
  });
  assert.equal(lateRelease.ok, false);
  assert.equal(floors.get('ch1').userId, 'u2'); // Bob still holds the floor
});

test('release: requires user+socket+transmission to all match the current holder', () => {
  const floors = new FloorLease();
  const { floor } = floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  const wrongSocket = floors.release('ch1', { userId: 'u1', socketId: 's2', transmissionId: floor.transmissionId });
  assert.equal(wrongSocket.ok, false);
  assert.equal(wrongSocket.reason, 'not_holder');

  const ok = floors.release('ch1', { userId: 'u1', socketId: 's1', transmissionId: floor.transmissionId });
  assert.equal(ok.ok, true);
  assert.equal(floors.get('ch1'), null);
});

test('get: a lapsed lease is never returned even if not yet swept', () => {
  const floors = new FloorLease({ ttlMs: 1 });
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  // Force-expire without waiting on the wall clock.
  floors._floors.get('ch1').expiresAt = Date.now() - 1;
  assert.equal(floors.get('ch1'), null);
});

test('acquire: a new requester can take an already-lapsed floor immediately', () => {
  const floors = new FloorLease({ ttlMs: 1 });
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  floors._floors.get('ch1').expiresAt = Date.now() - 1;

  const result = floors.acquire('ch1', { userId: 'u2', username: 'Bob', socketId: 's2' });
  assert.equal(result.ok, true);
  assert.equal(result.floor.userId, 'u2');
});

test('releaseAllForSocket: drops every channel a socket holds, and no others', () => {
  const floors = new FloorLease();
  floors.acquire('ch1', { userId: 'u1', username: 'Alice', socketId: 's1' });
  floors.acquire('ch2', { userId: 'u2', username: 'Bob', socketId: 's2' });

  const released = floors.releaseAllForSocket('s1');
  assert.equal(released.length, 1);
  assert.equal(released[0].channelId, 'ch1');
  assert.equal(floors.get('ch1'), null);
  assert.equal(floors.get('ch2').userId, 'u2');
});

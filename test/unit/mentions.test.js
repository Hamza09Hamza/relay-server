'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  detectsEveryone,
  normalizeMentions,
  shouldNotifyForMode,
} = require('../../src/app/mentions');

test('detectsEveryone: matches @everyone and its translated tokens', () => {
  assert.equal(detectsEveryone('hey @everyone check this'), true);
  assert.equal(detectsEveryone('attention @tous svp'), true);
  assert.equal(detectsEveryone('@الجميع مرحبا'), true);
});

test('detectsEveryone: does not match a substring or unrelated text', () => {
  assert.equal(detectsEveryone('nothing here'), false);
  assert.equal(detectsEveryone('@everyonesomething'), false); // no word boundary
  assert.equal(detectsEveryone(null), false);
});

test('normalizeMentions: keeps a mention only when the room member is genuinely named in the text', () => {
  const participants = [
    { id: '1', username: 'alice', full_name: 'Alice A' },
    { id: '2', username: 'bob', full_name: 'Bob B' },
  ];
  const result = normalizeMentions([{ id: '2' }], participants, '1', 'hey @Bob B how are you');
  assert.deepEqual(result, [{ id: '2', name: 'Bob B' }]);
});

test('normalizeMentions: drops a mention whose name is not actually present in the text', () => {
  const participants = [{ id: '2', username: 'bob', full_name: 'Bob B' }];
  const result = normalizeMentions([{ id: '2' }], participants, '1', 'no name here');
  assert.deepEqual(result, []);
});

test('normalizeMentions: a client cannot mention someone outside the room', () => {
  const participants = [{ id: '2', username: 'bob', full_name: 'Bob B' }];
  const result = normalizeMentions([{ id: '999' }], participants, '1', 'hey @Ghost');
  assert.deepEqual(result, []);
});

test('normalizeMentions: a sender cannot mention themselves', () => {
  const participants = [{ id: '1', username: 'alice', full_name: 'Alice A' }];
  const result = normalizeMentions([{ id: '1' }], participants, '1', '@Alice A hi');
  assert.deepEqual(result, []);
});

test('normalizeMentions: duplicate ids in the raw list are deduplicated', () => {
  const participants = [{ id: '2', username: 'bob', full_name: 'Bob B' }];
  const result = normalizeMentions([{ id: '2' }, { id: '2' }], participants, '1', '@Bob B @Bob B');
  assert.equal(result.length, 1);
});

test('shouldNotifyForMode: "none" never notifies, "all" always does', () => {
  assert.equal(shouldNotifyForMode('none', true), false);
  assert.equal(shouldNotifyForMode('none', false), false);
  assert.equal(shouldNotifyForMode('all', false), true);
});

test('shouldNotifyForMode: "mentions" only notifies when actually mentioned', () => {
  assert.equal(shouldNotifyForMode('mentions', true), true);
  assert.equal(shouldNotifyForMode('mentions', false), false);
});

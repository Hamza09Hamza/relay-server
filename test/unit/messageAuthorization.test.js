'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  resolvePrivateRecipient,
  isAuthorizedMessageRecipient,
} = require('../../src/app/messageAuthorization');

const members = [{ id: '1' }, { id: '2' }];

test('resolvePrivateRecipient: resolves the other member of a 2-person room', () => {
  const result = resolvePrivateRecipient(members, '1', null);
  assert.equal(result.ok, true);
  assert.equal(result.recipientId, '2');
});

test('resolvePrivateRecipient: a client-supplied recipient must match the actual other member', () => {
  const ok = resolvePrivateRecipient(members, '1', '2');
  assert.equal(ok.ok, true);

  const mismatched = resolvePrivateRecipient(members, '1', '999');
  assert.equal(mismatched.ok, false);
  assert.equal(mismatched.error, 'Recipient does not belong to this room');
});

test('resolvePrivateRecipient: refuses a sender who is not actually in the room', () => {
  const result = resolvePrivateRecipient(members, '999', null);
  assert.equal(result.ok, false);
  assert.equal(result.error, 'Not a member of this room');
});

test('resolvePrivateRecipient: refuses a room that is not exactly 2 people', () => {
  const result = resolvePrivateRecipient([{ id: '1' }, { id: '2' }, { id: '3' }], '1', null);
  assert.equal(result.ok, false);
  assert.equal(result.error, 'Invalid private room membership');
});

test('isAuthorizedMessageRecipient: true only for a different room member', () => {
  assert.equal(isAuthorizedMessageRecipient(members, '2', '1'), true);
  assert.equal(isAuthorizedMessageRecipient(members, '1', '1'), false); // can't be your own recipient
  assert.equal(isAuthorizedMessageRecipient(members, '999', '1'), false); // not in the room
});

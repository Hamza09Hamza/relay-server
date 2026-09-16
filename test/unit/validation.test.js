'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isValidUserId } = require('../../src/shared/validation');

test('isValidUserId: accepts a well-formed UUID', () => {
  assert.equal(isValidUserId('550e8400-e29b-41d4-a716-446655440000'), true);
});

test('isValidUserId: accepts a positive integer id (legacy numeric ids)', () => {
  assert.equal(isValidUserId('42'), true);
  assert.equal(isValidUserId(42), true);
});

test('isValidUserId: rejects zero, negatives, and non-numeric junk', () => {
  assert.equal(isValidUserId('0'), false);
  assert.equal(isValidUserId('-1'), false);
  assert.equal(isValidUserId('not-an-id'), false);
});

test('isValidUserId: rejects null/undefined', () => {
  assert.equal(isValidUserId(null), false);
  assert.equal(isValidUserId(undefined), false);
});

test('isValidUserId: rejects a malformed UUID', () => {
  assert.equal(isValidUserId('550e8400-e29b-41d4-a716'), false);
});

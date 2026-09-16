'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  deriveServerSegments,
  getServerDurationMs,
  subtractPauses,
} = require('../../recordingTimeline');

test('subtractPauses: no pauses returns the whole track as one window', () => {
  const windows = subtractPauses(0, 1000, []);
  assert.deepEqual(windows, [{ startMs: 0, endMs: 1000 }]);
});

test('subtractPauses: a closed pause splits the track around it', () => {
  const windows = subtractPauses(0, 1000, [{ pausedAtMs: 300, resumedAtMs: 600 }]);
  assert.deepEqual(windows, [
    { startMs: 0, endMs: 300 },
    { startMs: 600, endMs: 1000 },
  ]);
});

test('subtractPauses: an open pause (never resumed) lasts until endMs', () => {
  const windows = subtractPauses(0, 1000, [{ pausedAtMs: 400, resumedAtMs: null }]);
  assert.deepEqual(windows, [{ startMs: 0, endMs: 400 }]);
});

test('deriveServerSegments: one continuous track with no pauses yields one segment', () => {
  const segments = deriveServerSegments([{ file: 'a.mkv', startMs: 0, endMs: 5000 }]);
  assert.equal(segments.length, 1);
  assert.equal(segments[0].startMs, 0);
  assert.equal(segments[0].endMs, 5000);
  assert.equal(segments[0].file, 'a.mkv');
  assert.equal(segments[0].index, 0);
});

test('deriveServerSegments: camera pause/resume produces two on-windows', () => {
  const segments = deriveServerSegments([{
    file: 'a.mkv',
    startMs: 0,
    endMs: 10000,
    pauseEvents: [{ pausedAtMs: 3000, resumedAtMs: 7000 }],
  }]);
  assert.equal(segments.length, 2);
  assert.deepEqual(segments.map(s => [s.startMs, s.endMs]), [[0, 3000], [7000, 10000]]);
});

test('deriveServerSegments: on-windows closer than the coalesce window are merged', () => {
  // Two pauses that leave a 200ms gap between windows — below the 500ms default.
  const segments = deriveServerSegments([{
    file: 'a.mkv',
    startMs: 0,
    endMs: 10000,
    pauseEvents: [
      { pausedAtMs: 3000, resumedAtMs: 3200 },
    ],
  }]);
  // The pause itself is only 200ms, well under the coalesce threshold, so the
  // resulting single on-window should span the whole track uninterrupted.
  assert.equal(segments.length, 1);
  assert.equal(segments[0].startMs, 0);
  assert.equal(segments[0].endMs, 10000);
});

test('deriveServerSegments: windows shorter than the minimum are dropped as noise', () => {
  const segments = deriveServerSegments(
    [{ file: 'a.mkv', startMs: 0, endMs: 10000, pauseEvents: [{ pausedAtMs: 100, resumedAtMs: 9950 }] }],
    { coalesceMs: 0 }, // disable coalescing so the tiny trailing window survives to the length filter
  );
  // Remaining windows: [0,100) and [9950,10000) — both under the 300ms default minimum.
  assert.equal(segments.length, 0);
});

test('deriveServerSegments: rotation change splits a window at the event boundary', () => {
  const segments = deriveServerSegments([{
    file: 'a.mkv',
    startMs: 0,
    endMs: 10000,
    rotation: 0,
    rotationEvents: [{ atMs: 4000, rotation: 90 }],
  }]);
  assert.equal(segments.length, 2);
  assert.equal(segments[0].rotation, 0);
  assert.equal(segments[0].endMs, 4000);
  assert.equal(segments[1].rotation, 90);
  assert.equal(segments[1].startMs, 4000);
  assert.equal(segments[1].rotationChangedAtStart, true);
});

test('deriveServerSegments: multiple tracks are sorted by start time and index-numbered', () => {
  const segments = deriveServerSegments([
    { file: 'second.mkv', startMs: 5000, endMs: 8000 },
    { file: 'first.mkv', startMs: 0, endMs: 3000 },
  ]);
  assert.equal(segments.length, 2);
  assert.equal(segments[0].file, 'first.mkv');
  assert.equal(segments[0].index, 0);
  assert.equal(segments[1].file, 'second.mkv');
  assert.equal(segments[1].index, 1);
});

test('deriveServerSegments: invalid tracks (endMs <= startMs, non-finite) are dropped', () => {
  const segments = deriveServerSegments([
    { file: 'bad.mkv', startMs: 1000, endMs: 500 },
    { file: 'nan.mkv', startMs: NaN, endMs: 2000 },
    { file: 'good.mkv', startMs: 0, endMs: 1000 },
  ]);
  assert.equal(segments.length, 1);
  assert.equal(segments[0].file, 'good.mkv');
});

test('getServerDurationMs: returns the latest endMs across all tracks', () => {
  const duration = getServerDurationMs([
    { startMs: 0, endMs: 3000 },
    { startMs: 1000, endMs: 9000 },
    { startMs: 500, endMs: 4000 },
  ]);
  assert.equal(duration, 9000);
});

test('getServerDurationMs: empty/invalid input returns 0', () => {
  assert.equal(getServerDurationMs([]), 0);
  assert.equal(getServerDurationMs(null), 0);
});

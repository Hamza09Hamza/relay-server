/**
 * recordingTimeline.js — server-authoritative recording-segment derivation.
 *
 * PRINCIPLE: the recording timeline is defined by the bytes the SFU actually
 * received, NOT by client-reported camera events. Each captured video producer
 * ("track") carries server-stamped `startMs`/`endMs` (locked at consumer.resume
 * → producerclose, on the `recording.startTime` clock) plus server-stamped
 * `pauseEvents` (camera pause/resume observed via producer_video_state). A
 * camera-ON window is [startMs,endMs] minus the paused ranges.
 *
 * This module is PURE (no I/O) so its math can be unit-verified in isolation —
 * see scripts/verify-recordingTimeline (run with plain `node`). It replaces the
 * old client-event path (`extractCameraSegments(events)` + `rebaseEvents`/
 * `pickPreferredEvents`) as the authoritative source of segment ranges.
 *
 * Coalescing happens ONLY within a single track (same file). Windows from
 * different producers (e.g. a reconnect that creates a new producer) are never
 * merged, because downstream extraction cuts each segment from exactly one
 * source file (selectTrackForSegment maps a segment → one track by overlap).
 */

const DEFAULT_COALESCE_MS = 500;   // merge on-windows of the SAME track closer than this (toggle-storm smoothing)
const DEFAULT_MIN_SEGMENT_MS = 300; // drop on-windows shorter than this (rapid open/close noise)

/**
 * Subtract paused ranges from a track's [startMs,endMs] → array of on-windows.
 * An open pause (resumedAtMs == null) is treated as lasting until endMs.
 */
function subtractPauses(startMs, endMs, pauseEvents) {
  const pauses = (Array.isArray(pauseEvents) ? pauseEvents : [])
    .map((p) => ({
      from: Number(p.pausedAtMs),
      to: p.resumedAtMs == null ? endMs : Number(p.resumedAtMs),
    }))
    .filter((p) => Number.isFinite(p.from) && Number.isFinite(p.to) && p.to > p.from)
    .sort((a, b) => a.from - b.from);

  const windows = [];
  let cursor = startMs;
  for (const p of pauses) {
    const onStart = cursor;
    const onEnd = Math.min(p.from, endMs);
    if (onEnd > onStart) windows.push({ startMs: onStart, endMs: onEnd });
    cursor = Math.max(cursor, p.to);
  }
  if (cursor < endMs) windows.push({ startMs: cursor, endMs });
  return windows;
}

/** Merge windows of one track separated by <= coalesceMs (same file, safe). */
function coalesceWithin(windows, coalesceMs) {
  const merged = [];
  for (const w of windows) {
    const last = merged[merged.length - 1];
    if (last && w.startMs - last.endMs <= coalesceMs) {
      last.endMs = Math.max(last.endMs, w.endMs);
    } else {
      merged.push({ startMs: w.startMs, endMs: w.endMs });
    }
  }
  return merged;
}

function normalizeRotation(value) {
  const rotation = Number(value);
  return [0, 90, 180, 270].includes(rotation) ? rotation : 0;
}

/** Split camera-on windows whenever the server observed an orientation change. */
function splitByRotation(windows, initialRotation, rotationEvents) {
  const events = (Array.isArray(rotationEvents) ? rotationEvents : [])
    .map((event) => ({
      atMs: Number(event?.atMs),
      rotation: normalizeRotation(event?.rotation),
    }))
    .filter((event) => Number.isFinite(event.atMs))
    .sort((a, b) => a.atMs - b.atMs);

  const pieces = [];
  for (const window of windows) {
    let rotation = normalizeRotation(initialRotation);
    let changedAtStart = false;
    for (const event of events) {
      if (event.atMs > window.startMs) break;
      if (event.rotation !== rotation && event.atMs === window.startMs) changedAtStart = true;
      rotation = event.rotation;
    }

    let cursor = window.startMs;
    for (const event of events) {
      if (event.atMs <= window.startMs || event.atMs >= window.endMs) continue;
      if (event.rotation === rotation) continue;
      pieces.push({
        startMs: cursor,
        endMs: event.atMs,
        rotation,
        rotationChangedAtStart: changedAtStart,
      });
      cursor = event.atMs;
      rotation = event.rotation;
      changedAtStart = true;
    }
    if (cursor < window.endMs) {
      pieces.push({
        startMs: cursor,
        endMs: window.endMs,
        rotation,
        rotationChangedAtStart: changedAtStart,
      });
    }
  }
  return pieces;
}

/**
 * Derive authoritative recording segments from server-stamped tracks.
 *
 * @param {Array<{file?:string,startMs:number,endMs:number,pauseEvents?:Array,rotation?:number,rotationEvents?:Array}>} tracks
 * @param {{coalesceMs?:number,minSegmentMs?:number}} [opts]
 * @returns {Array<{index:number,startMs:number,endMs:number,file?:string,rotation:number,rotationChangedAtStart:boolean}>}
 *          camera-on segments, sorted, index-numbered, each within one track.
 */
function deriveServerSegments(tracks, opts = {}) {
  const coalesceMs = Number.isFinite(opts.coalesceMs) ? opts.coalesceMs : DEFAULT_COALESCE_MS;
  const minSegmentMs = Number.isFinite(opts.minSegmentMs) ? opts.minSegmentMs : DEFAULT_MIN_SEGMENT_MS;

  const valid = (Array.isArray(tracks) ? tracks : [])
    .map((t) => ({
      file: t && t.file,
      startMs: Number(t && t.startMs),
      endMs: Number(t && t.endMs),
      pauseEvents: t && t.pauseEvents,
      rotation: normalizeRotation(t && t.rotation),
      rotationEvents: t && t.rotationEvents,
    }))
    .filter((t) => Number.isFinite(t.startMs) && Number.isFinite(t.endMs) && t.endMs > t.startMs)
    .sort((a, b) => a.startMs - b.startMs);

  const out = [];
  for (const t of valid) {
    let windows = subtractPauses(t.startMs, t.endMs, t.pauseEvents);
    windows = coalesceWithin(windows, coalesceMs);
    windows = windows.filter((w) => w.endMs - w.startMs >= minSegmentMs);
    const orientedWindows = splitByRotation(windows, t.rotation, t.rotationEvents);
    for (const w of orientedWindows) out.push({ ...w, file: t.file });
  }

  out.sort((a, b) => a.startMs - b.startMs || a.endMs - b.endMs);
  return out.map((w, i) => ({
    index: i,
    startMs: Math.round(w.startMs),
    endMs: Math.round(w.endMs),
    file: w.file,
    rotation: w.rotation,
    rotationChangedAtStart: !!w.rotationChangedAtStart,
  }));
}

/** Total presence extent (ms) on the server clock — replaces client getCallDuration. */
function getServerDurationMs(tracks) {
  let max = 0;
  for (const t of (Array.isArray(tracks) ? tracks : [])) {
    const e = Number(t && t.endMs);
    if (Number.isFinite(e) && e > max) max = e;
  }
  return max;
}

module.exports = {
  deriveServerSegments,
  getServerDurationMs,
  subtractPauses,
  splitByRotation,
  DEFAULT_COALESCE_MS,
  DEFAULT_MIN_SEGMENT_MS,
};

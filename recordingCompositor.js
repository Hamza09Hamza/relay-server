/**
 * recordingCompositor.js — compose ONE playable file per call.
 *
 * WHY THIS EXISTS
 * ---------------
 * The old playback model streamed N per-participant segment files and tried to
 * keep N hardware video decoders in lockstep on the phone with a JS wall clock +
 * gap timers. Android ExoPlayer only handles ~2–3 simultaneous hardware decoders,
 * so a 3-person group call starved decoders → "stuck / buggy" playback. No amount
 * of better RTP timing fixes that, because it is a playback (decoder) problem.
 *
 * THE FIX: the server already has every participant on ONE shared clock
 * (recording.startTime). So at transcode time we lay each participant onto that
 * timeline — camera-off / absent stretches filled with black — and composite
 * them into a SINGLE grid video + ONE mixed audio track. The admin app then plays
 * one ordinary MP4: one decoder, one timeline, one scrubber. Sync can't drift,
 * gaps are baked, a corrupt/missing track is just a black tile (the rest plays).
 *
 * This is NOT a headless-WebRTC compositor (which would re-capture the call in a
 * browser). It composites the per-user segment files already extracted, with a
 * small number of FFmpeg passes, on the existing server-authoritative timeline.
 *
 * STRUCTURE
 * ---------
 * The grid/layout/filtergraph math is split into PURE functions (computeGrid,
 * computeCellLayout, buildLaneFilterComplex, buildAudioMixFilter) so it can be
 * unit-verified without spawning FFmpeg — see scripts/verify-recordingCompositor.
 * composeCall() is the impure orchestrator that runs FFmpeg and writes the DB row.
 */

const fs = require('fs');
const path = require('path');
const db = require('./src/infrastructure/db');
const { hashFile } = require('./src/shared/files/hash');
const {
  runFFmpegCommand,
  probeMediaDurationMs,
  probeVideoFormat,
} = require('./recordingSegmentExtractor');

const RECORDINGS_DIR = path.join(__dirname, 'recordings');

// Grid cell geometry. This is a PHONE call app: camera video, after the
// orientation bake (transpose), is portrait. So cells are PORTRAIT (9:16) —
// a portrait clip fills its cell instead of pillarboxing to a thin strip in a
// landscape cell. A rare genuinely-landscape capture letterboxes instead
// (acceptable; portrait is the overwhelming case). Even dimensions are required
// by yuv420p/H.264. Final output is (cols*CELL_W) x (rows*CELL_H), and the
// player sizes its container to those real dimensions (no outer letterbox).
const CELL_W = 540;
const CELL_H = 960;
// Conference cells are LANDSCAPE, not portrait — conferences are reviewed more
// like a gallery-view screen share than a phone call, and can have far more
// participants than a typical 1:1/group call, so the grid also biases toward
// more columns (see computeGrid's `wide` option) instead of a near-square grid.
const CELL_W_CONFERENCE = 960;
const CELL_H_CONFERENCE = 540;
const FPS = 30;
const LANE_CRF = 18;   // per-user lane quality (near-lossless; it gets re-encoded once by xstack)
const FINAL_CRF = 20;  // final grid quality

// Composite output budget. Source camera video is now full 1080p (hardware
// H.264), so without a cap a grid would balloon: 1 tile would be 1080×1920 and a
// 3×3 would be 3240×5760. This is an ADMIN REVIEW artifact, not a broadcast — a
// ~1080p portrait canvas shows every face clearly at a fraction of the bytes.
// Cells stay 540×960 for the common 1–4 person calls (unchanged) and only shrink
// to fit once the grid would exceed the budget. Keeps file size sane for any N.
const MAX_CANVAS_W = 1080;
const MAX_CANVAS_H = 1920;

// ── PURE: grid + layout math ────────────────────────────────────────────────

/**
 * Choose a grid for n video tiles. Regular calls get a near-square grid
 * (matches the portrait phone-call cell). Conferences (`wide: true`) bias
 * toward more columns for a flatter, gallery-style canvas better suited to
 * both landscape cells and higher participant counts.
 */
function computeGrid(n, { wide = false } = {}) {
  const tiles = Math.max(1, Math.floor(n));
  const cols = Math.max(1, Math.ceil(Math.sqrt(tiles * (wide ? 16 / 9 : 1))));
  const rows = Math.ceil(tiles / cols);
  return { cols, rows, cells: cols * rows };
}

/**
 * Cell size for a given grid. Keeps the base 540×960 portrait cell, but scales
 * every cell DOWN uniformly if the grid would exceed the MAX_CANVAS budget, so
 * the composite never balloons regardless of participant count. Dimensions are
 * forced even (yuv420p/H.264 requirement).
 */
function computeCellSize(cols, rows, baseW = CELL_W, baseH = CELL_H) {
  const scale = Math.min(
    1,
    MAX_CANVAS_W / (cols * baseW),
    MAX_CANVAS_H / (rows * baseH),
  );
  const even = (v) => Math.max(2, Math.floor(v / 2) * 2);
  return { cellW: even(baseW * scale), cellH: even(baseH * scale) };
}

/**
 * Pixel position of every grid cell, row-major (cell c → {x,y}).
 * Returns the xstack `layout` token list ("x_y") in cell order.
 */
function computeCellLayout(cols, rows, cellW = CELL_W, cellH = CELL_H) {
  const layout = [];
  for (let c = 0; c < cols * rows; c++) {
    const col = c % cols;
    const row = Math.floor(c / cols);
    layout.push(`${col * cellW}_${row * cellH}`);
  }
  return layout;
}

/**
 * Build the filter_complex for ONE participant lane.
 *
 * Input 0 is a black base of the full call length; inputs 1..M are this user's
 * extracted segment files (each carries call-clock startMs/endMs). Each segment
 * is scaled+letterboxed into the cell, time-shifted to its real call offset, and
 * overlaid onto the running base only during its [start,end] window. Everywhere
 * else the black base shows through → camera-off / absent = clean black.
 *
 * @returns {{ filter: string, outLabel: string }}
 */
function buildLaneFilterComplex(segments, cellW = CELL_W, cellH = CELL_H) {
  const parts = [`[0:v]format=yuv420p,fps=${FPS},scale=${cellW}:${cellH},setsar=1[base]`];
  let prev = 'base';
  segments.forEach((seg, i) => {
    const inIdx = i + 1;
    const s = (Number(seg.startMs) / 1000);
    const e = (Number(seg.endMs) / 1000);
    const S = s.toFixed(3);
    const E = e.toFixed(3);
    parts.push(
      `[${inIdx}:v]scale=${cellW}:${cellH}:force_original_aspect_ratio=decrease,` +
      `pad=${cellW}:${cellH}:(ow-iw)/2:(oh-ih)/2:black,setsar=1,fps=${FPS},` +
      `setpts=PTS-STARTPTS+${S}/TB[s${i}]`
    );
    parts.push(
      `[${prev}][s${i}]overlay=eof_action=pass:enable='between(t,${S},${E})'[t${i}]`
    );
    prev = `t${i}`;
  });
  return { filter: parts.join(';'), outLabel: prev };
}

/**
 * Build the audio-mix filter. Each audio input is delayed to its call-clock
 * start so voices land at the right point on the shared timeline, then summed
 * (normalize=0 keeps each voice at full level instead of ducking by speaker
 * count). Input ffmpeg indices start at `firstAudioInputIndex`.
 *
 * @param {Array<{delayMs:number}>} audioInputs
 * @returns {{ filter: string, outLabel: string }|null} null if no audio
 */
function buildAudioMixFilter(audioInputs, firstAudioInputIndex) {
  if (!Array.isArray(audioInputs) || audioInputs.length === 0) return null;
  const parts = [];
  audioInputs.forEach((a, j) => {
    const idx = firstAudioInputIndex + j;
    const delay = Math.max(0, Math.round(Number(a.delayMs) || 0));
    parts.push(`[${idx}:a]aresample=async=1,adelay=${delay}:all=1[a${j}]`);
  });
  if (audioInputs.length === 1) {
    return { filter: parts.join(';'), outLabel: 'a0' };
  }
  const ins = audioInputs.map((_, j) => `[a${j}]`).join('');
  parts.push(`${ins}amix=inputs=${audioInputs.length}:normalize=0:dropout_transition=0[aout]`);
  return { filter: parts.join(';'), outLabel: 'aout' };
}

/** Total call length (ms) implied by the per-user extracted outputs. */
function computeTotalDurationMs(users) {
  let max = 0;
  for (const u of (Array.isArray(users) ? users : [])) {
    const ae = Number(u.audioEndMs) || 0;
    if (ae > max) max = ae;
    for (const seg of (u.videoSegments || [])) {
      const e = Number(seg.endMs) || 0;
      if (e > max) max = e;
    }
  }
  return max;
}

// ── IMPURE: orchestration ─────────────────────────────────────────────────────

/** color=black lavfi input args for one padding cell / base of given length. */
function blackInputArgs(durationSec, w = CELL_W, h = CELL_H) {
  return ['-f', 'lavfi', '-i', `color=c=black:s=${w}x${h}:r=${FPS}:d=${durationSec.toFixed(3)}`];
}

/**
 * Render one participant's full-length lane (black + their segments).
 * Returns the lane file path, or null on failure (caller substitutes black).
 */
async function buildLane(callId, user, totalSec, outDir, cellW = CELL_W, cellH = CELL_H) {
  const segs = (user.videoSegments || [])
    .filter((s) => s.filePath && fs.existsSync(s.filePath) && (s.fileSize == null || s.fileSize > 0))
    .sort((a, b) => a.startMs - b.startMs);
  if (segs.length === 0) return null;

  const lanePath = path.join(outDir, `lane_${user.userId}.mp4`);
  const { filter, outLabel } = buildLaneFilterComplex(segs, cellW, cellH);

  const args = [...blackInputArgs(totalSec, cellW, cellH)];
  for (const seg of segs) args.push('-i', seg.filePath);
  args.push(
    '-filter_complex', filter,
    '-map', `[${outLabel}]`,
    '-t', totalSec.toFixed(3),
    '-c:v', 'libx264', '-preset', 'fast', '-crf', String(LANE_CRF),
    '-pix_fmt', 'yuv420p', '-r', String(FPS),
    '-an', '-movflags', '+faststart', '-y', lanePath,
  );

  const res = await runFFmpegCommand(args, { label: `compose lane ${user.username}` });
  if (res.status !== 0 || !fs.existsSync(lanePath) || fs.statSync(lanePath).size === 0) {
    console.warn(`[Compositor] Lane build failed for ${user.username} — tile will be black. ${(res.stderr || '').slice(-300)}`);
    try { if (fs.existsSync(lanePath)) fs.unlinkSync(lanePath); } catch (_) {}
    return null;
  }
  return lanePath;
}

/** Look up whether this call is a conference — drives the wide/landscape grid below. */
async function getSessionKind(callId) {
  try {
    const { rows } = await db.query('SELECT session_kind FROM calls WHERE id = $1', [callId]);
    return rows[0]?.session_kind || 'call';
  } catch (_) {
    return 'call';
  }
}

/**
 * Compose a single playable artifact for a whole call.
 *
 * @param {string} callId
 * @param {Array} users  per-user outputs from processCallRecordings:
 *   { userId, username, videoSegments:[{startMs,endMs,filePath,fileSize}],
 *     audioFile:{filePath}|null, audioStartMs, audioEndMs }
 * @param {object} [opts]
 * @returns {object|null} composite summary (also persisted to recording_composites)
 */
async function composeCall(callId, users, opts = {}) {
  const list = (Array.isArray(users) ? users : []).filter(Boolean);
  const totalMs = Number(opts.totalDurationMs) || computeTotalDurationMs(list);
  if (!totalMs || totalMs < 200) {
    console.warn(`[Compositor] Call ${callId}: no usable duration (${totalMs}ms) — skipping composite`);
    return null;
  }
  const totalSec = totalMs / 1000;

  const outDir = path.join(RECORDINGS_DIR, callId, 'composite');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // Audio inputs: every participant who captured audio, delayed to their join.
  const audioInputs = list
    .filter((u) => u.audioFile && u.audioFile.filePath && fs.existsSync(u.audioFile.filePath))
    .map((u) => ({ filePath: u.audioFile.filePath, delayMs: Math.max(0, Number(u.audioStartMs) || 0) }));

  // Video users: those with at least one real segment file on disk.
  const videoUsers = list.filter((u) =>
    (u.videoSegments || []).some((s) => s.filePath && fs.existsSync(s.filePath)));

  const compositePath = path.join(outDir, 'call.mp4');
  const tempArtifacts = [];

  try {
    // ── AUDIO-ONLY CALL → single mixed audio file ────────────────────────────
    if (videoUsers.length === 0) {
      if (audioInputs.length === 0) {
        console.warn(`[Compositor] Call ${callId}: no audio and no video — nothing to compose`);
        return null;
      }
      const mix = buildAudioMixFilter(audioInputs, 0);
      const args = [];
      for (const a of audioInputs) args.push('-i', a.filePath);
      args.push(
        '-filter_complex', mix.filter,
        '-map', `[${mix.outLabel}]`,
        '-t', totalSec.toFixed(3),
        '-c:a', 'aac', '-b:a', '192k',
        '-movflags', '+faststart', '-y', compositePath,
      );
      const res = await runFFmpegCommand(args, { label: `compose audio ${callId}` });
      if (res.status !== 0 || !fs.existsSync(compositePath)) {
        console.error(`[Compositor] Audio-only compose failed for ${callId}: ${(res.stderr || '').slice(-400)}`);
        return null;
      }
      return await persistComposite(callId, compositePath, {
        // This is AAC in an MP4 container (call.mp4), not an MP3. Persist the
        // container truth so browser clients choose the correct demuxer.
        width: null, height: null, layout: 'audio', hasVideo: false, format: 'mp4',
      });
    }

    // ── VIDEO CALL → per-user lanes → grid + mixed audio ─────────────────────
    // Grid first, so we know the cell size (capped to MAX_CANVAS) before building
    // lanes — a big group shrinks cells instead of producing a huge canvas.
    const isConference = (await getSessionKind(callId)) === 'conference';
    const { cols, rows, cells } = computeGrid(videoUsers.length, { wide: isConference });
    const { cellW, cellH } = computeCellSize(
      cols, rows,
      isConference ? CELL_W_CONFERENCE : CELL_W,
      isConference ? CELL_H_CONFERENCE : CELL_H,
    );
    const layoutTokens = computeCellLayout(cols, rows, cellW, cellH);

    const lanes = [];
    for (const u of videoUsers) {
      lanes.push(await buildLane(callId, u, totalSec, outDir, cellW, cellH));
    }
    const realLanes = lanes.filter(Boolean);
    realLanes.forEach((p) => tempArtifacts.push(p));
    if (realLanes.length === 0) {
      console.warn(`[Compositor] Call ${callId}: all lanes failed — falling back to audio-only`);
      // Recurse into the audio-only path by faking no video users.
      return await composeCall(callId, list.map((u) => ({ ...u, videoSegments: [] })), opts);
    }

    // Final command: K video cells (lanes, then black pads) + audio inputs.
    const args = [];
    const filters = [];
    const cellLabels = [];
    let inputIdx = 0;
    for (let c = 0; c < cells; c++) {
      const lane = c < lanes.length ? lanes[c] : null;
      if (lane) {
        args.push('-i', lane);
      } else {
        // Missing/failed lane or trailing empty grid cell → black filler.
        args.push(...blackInputArgs(totalSec, cellW, cellH));
      }
      // Normalize EVERY cell to identical geometry/format/SAR/fps — xstack
      // refuses to stack inputs that disagree, and the lavfi black pads would
      // otherwise differ from the libx264 lanes.
      filters.push(`[${inputIdx}:v]format=yuv420p,scale=${cellW}:${cellH},setsar=1,fps=${FPS}[vc${c}]`);
      cellLabels.push(`[vc${c}]`);
      inputIdx += 1;
    }
    const firstAudioInputIndex = inputIdx;
    for (const a of audioInputs) { args.push('-i', a.filePath); inputIdx += 1; }

    let vmap;
    if (cells === 1) {
      vmap = '[vc0]';
    } else {
      filters.push(
        `${cellLabels.join('')}xstack=inputs=${cells}:layout=${layoutTokens.join('|')}[vout]`
      );
      vmap = '[vout]';
    }

    const mix = buildAudioMixFilter(audioInputs, firstAudioInputIndex);
    if (mix) filters.push(mix.filter);

    args.push('-filter_complex', filters.join(';'));
    args.push('-map', vmap);
    if (mix) args.push('-map', `[${mix.outLabel}]`);
    args.push(
      '-t', totalSec.toFixed(3),
      '-c:v', 'libx264', '-preset', 'fast', '-crf', String(FINAL_CRF),
      '-profile:v', 'high', '-pix_fmt', 'yuv420p', '-r', String(FPS),
    );
    if (mix) args.push('-c:a', 'aac', '-b:a', '192k');
    args.push('-movflags', '+faststart', '-y', compositePath);

    const res = await runFFmpegCommand(args, { label: `compose grid ${callId}` });
    if (res.status !== 0 || !fs.existsSync(compositePath) || fs.statSync(compositePath).size === 0) {
      console.error(`[Compositor] Grid compose failed for ${callId}: ${(res.stderr || '').slice(-500)}`);
      return null;
    }

    // Cell → participant map in xstack (row-major) order, video tiles only, so
    // the admin player can label who is in which tile.
    const cellUsers = videoUsers.map((u) => ({
      userId: u.userId != null ? String(u.userId) : null,
      username: u.username || 'Unknown',
    }));

    return await persistComposite(callId, compositePath, {
      width: cols * cellW, height: rows * cellH,
      layout: `${cols}x${rows}`, hasVideo: true, format: 'mp4', cellUsers,
    });
  } finally {
    // Lanes are intermediates — the grid bakes them in. Keep nothing extra.
    for (const f of tempArtifacts) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
    }
  }
}

/** Probe, hash, and upsert the composite into recording_composites. */
async function persistComposite(callId, filePath, meta) {
  const fileSize = fs.statSync(filePath).size;
  const durationMs = (await probeMediaDurationMs(filePath)) || 0;
  let { width, height } = meta;
  if (meta.hasVideo && (!width || !height)) {
    const probed = await probeVideoFormat(filePath);
    if (probed) { width = probed.width; height = probed.height; }
  }
  const fileHash = hashFile(filePath);
  const cellUsers = Array.isArray(meta.cellUsers) ? JSON.stringify(meta.cellUsers) : null;

  await db.query(
    `INSERT INTO recording_composites
       (call_id, file_path, file_size, duration_ms, width, height, layout, format, has_video, file_hash, cell_users)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     ON CONFLICT (call_id) DO UPDATE
       SET file_path = EXCLUDED.file_path, file_size = EXCLUDED.file_size,
           duration_ms = EXCLUDED.duration_ms, width = EXCLUDED.width, height = EXCLUDED.height,
           layout = EXCLUDED.layout, format = EXCLUDED.format, has_video = EXCLUDED.has_video,
           file_hash = EXCLUDED.file_hash, cell_users = EXCLUDED.cell_users, created_at = NOW()`,
    [callId, filePath, fileSize, durationMs, width || null, height || null,
     meta.layout, meta.format, !!meta.hasVideo, fileHash, cellUsers]
  );

  console.log(
    `[Compositor] ✅ Call ${callId} → ${path.basename(filePath)} ` +
    `(${(fileSize / 1024 / 1024).toFixed(2)}MB, ${(durationMs / 1000).toFixed(1)}s, ${meta.layout})`
  );
  return { callId, filePath, fileSize, durationMs, width, height, ...meta, fileHash };
}

module.exports = {
  composeCall,
  // pure helpers (unit-verifiable)
  computeGrid,
  computeCellSize,
  computeCellLayout,
  buildLaneFilterComplex,
  buildAudioMixFilter,
  computeTotalDurationMs,
  CELL_W,
  CELL_H,
};

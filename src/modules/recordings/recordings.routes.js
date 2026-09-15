/**
 * Recordings — admin listing/streaming, per-segment streaming, and the
 * participant-facing segment list for playback.
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const db = require('../../infrastructure/db');
const queries = require('../../infrastructure/db/queries');
const encryption = require('../../infrastructure/encryption/encryption');
const { RECORDINGS_DIR } = require('../../app/paths');
const { hashFile } = require('../../shared/files/hash');
const { parseLimit, parseOffset } = require('../../shared/http/pagination');
const {
  authMiddleware, superadminMiddleware,
} = require('../auth/auth.middleware');

const router = express.Router();

// Legacy extracted audio segments use an MP4 container, so their extension is
// not enough to describe the stream. Their stable storage convention is the
// call's `audio/` directory. Correct media typing is essential for browser and
// native audio players to choose an audio decoder rather than a black video UI.
function recordingContentType(filePath) {
  const normalized = path.normalize(String(filePath || ''));
  if (normalized.includes(`${path.sep}audio${path.sep}`)) return 'audio/mp4';
  if (path.extname(normalized).toLowerCase() === '.mp3') return 'audio/mpeg';
  return 'video/mp4';
}

// List all recordings
router.get('/api/admin/recordings', authMiddleware, superadminMiddleware, async (req, res) => {
  try {
    const limit = parseLimit(req.query.limit, { def: 50, max: 200 });
    const offset = parseOffset(req.query.offset);
    const { rows } = await db.query(
      `SELECT r.*,
              r.user_id AS recording_user_id,
              r.username AS recording_username,
              c.call_type, c.started_at AS call_started_at, c.ended_at AS call_ended_at,
              c.status AS call_status, c.session_kind,
              u.username AS initiator_username,
              COALESCE(
                (SELECT json_agg(json_build_object('user_id', cp2.user_id, 'username', u2.username))
                 FROM call_participants cp2
                 JOIN users u2 ON u2.id = cp2.user_id
                 WHERE cp2.call_id = c.id),
                '[]'::json
              ) AS participants
       FROM recordings r
       JOIN calls c ON c.id = r.call_id
       JOIN users u ON u.id = c.initiator_id
       ORDER BY r.created_at DESC
       LIMIT $1 OFFSET $2`,
      [limit, offset],
    );
    res.json({ recordings: rows });
  } catch (err) {
    console.error('[Admin] List recordings error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete ALL recording media for a single call (superadmin only).
//
// Removes the recording_segments + recording_metadata + recordings rows for the
// call AND their files on disk. The `calls` row and the "call event" chat
// message are deliberately preserved — only the recorded media is purged, so
// call history/metadata stays intact.
router.delete('/api/admin/recordings/call/:callId', authMiddleware, superadminMiddleware, async (req, res) => {
  const { callId } = req.params;
  if (!callId) return res.status(400).json({ error: 'callId required' });

  // Only unlink files that resolve INSIDE the recordings dir — never follow a
  // path that escapes it (defense against a tampered/relative file_path row).
  const safeUnlink = (filePath) => {
    if (!filePath) return;
    try {
      const resolved = path.resolve(filePath);
      if (resolved !== RECORDINGS_DIR && !resolved.startsWith(RECORDINGS_DIR + path.sep)) {
        console.warn('[Admin] Skipping unlink outside recordings dir:', filePath);
        return;
      }
      if (fs.existsSync(resolved)) fs.unlinkSync(resolved);
    } catch (err) {
      console.error('[Admin] Failed to delete recording file:', err.message);
    }
  };

  try {
    // Confirm the call exists so a bogus id returns 404 (and we never touch
    // anything but this call's media).
    const call = await queries.calls.findById(callId);
    if (!call) return res.status(404).json({ error: 'Call not found' });

    // 1) Segment files + rows (the new segment-based recordings).
    const { rows: segs } = await db.query(
      'SELECT id, file_path FROM recording_segments WHERE call_id = $1',
      [callId],
    );
    segs.forEach((s) => safeUnlink(s.file_path));
    await db.query('DELETE FROM recording_segments WHERE call_id = $1', [callId]);

    // 1b) Call-level composite (single grid/audio artifact) + its file.
    const { rows: comps } = await db.query(
      'SELECT file_path FROM recording_composites WHERE call_id = $1',
      [callId],
    );
    comps.forEach((c) => safeUnlink(c.file_path));
    await db.query('DELETE FROM recording_composites WHERE call_id = $1', [callId]);

    // 2) Per-call recording metadata (speaker/presence events).
    await db.query('DELETE FROM recording_metadata WHERE call_id = $1', [callId]);

    // 3) Old-format recordings rows (each removes its own file on disk).
    const recs = await queries.recordings.findByCallId(callId);
    for (const r of recs) {
      await queries.recordings.remove(r.id);
    }

    console.log(`[Admin] Recordings for call ${callId} deleted by superadmin ${req.userId} — ${segs.length} segment(s), ${recs.length} recording(s)`);
    res.json({ ok: true, deletedSegments: segs.length, deletedRecordings: recs.length });
  } catch (err) {
    console.error('[Admin] Delete call recordings error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Stream a recording file
router.get('/api/admin/recordings/:id/stream', authMiddleware, superadminMiddleware, async (req, res) => {
  try {
    const recording = await queries.recordings.findById(req.params.id);
    if (!recording) {
      return res.status(404).json({ error: 'Recording not found' });
    }
    const filePath = recording.file_path;
    // Path traversal protection: ensure the resolved path is inside the recordings dir
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(RECORDINGS_DIR + path.sep) && resolved !== RECORDINGS_DIR) {
      console.error('[Admin] Path traversal attempt blocked:', filePath);
      return res.status(403).json({ error: 'Access denied' });
    }

    // Integrity check: verify SHA-256 hash matches what was stored at save time
    if (recording.file_hash && fs.existsSync(filePath)) {
      const currentHash = hashFile(filePath);
      if (currentHash !== recording.file_hash) {
        console.error(`[Admin] Recording integrity check FAILED for ${req.params.id}: expected ${recording.file_hash}, got ${currentHash}`);
        return res.status(409).json({ error: 'Recording integrity check failed — file may have been tampered with' });
      }
    }

    // Handle encrypted recording files
    if (encryption.isInitialized() && filePath.endsWith('.enc') && fs.existsSync(filePath)) {
      const originalName = path.basename(filePath, '.enc');
      const decrypted = encryption.decryptFile(filePath, originalName);
      const ext = path.extname(originalName).toLowerCase();
      const mimeTypes = { '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.webm': 'audio/webm', '.ogg': 'audio/ogg' };
      const contentType = mimeTypes[ext] || 'application/octet-stream';
      const totalSize = decrypted.length;

      // Support range requests for encrypted files (required by iOS AVPlayer for video)
      const range = req.headers.range;
      if (range) {
        const parts = range.replace(/bytes=/, '').split('-');
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;
        const chunkSize = end - start + 1;
        res.writeHead(206, {
          'Content-Range': `bytes ${start}-${end}/${totalSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunkSize,
          'Content-Type': contentType,
        });
        return res.end(decrypted.subarray(start, end + 1));
      }

      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Length', totalSize);
      res.setHeader('Accept-Ranges', 'bytes');
      return res.send(decrypted);
    }

    if (!filePath || !fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Recording file not found on disk' });
    }
    const stat = fs.statSync(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = { '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.webm': 'audio/webm', '.ogg': 'audio/ogg' };
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    // Support range requests for seeking
    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${stat.size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': end - start + 1,
        'Content-Type': contentType,
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': stat.size,
        'Content-Type': contentType,
        'Accept-Ranges': 'bytes',
      });
      fs.createReadStream(filePath).pipe(res);
    }
  } catch (err) {
    console.error('[Admin] Stream recording error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Recordings are superadmin-only — regular admins must never see call media.
router.get('/api/admin/recording-segments', authMiddleware, superadminMiddleware, async (req, res) => {
  try {
    const limit = parseLimit(req.query.limit, { def: 50, max: 200 });
    const offset = parseOffset(req.query.offset);
    const callIdFilter = req.query.callId ? String(req.query.callId) : null;

    const { rows: segments } = await db.query(
      `SELECT
         rs.id,
         rs.call_id,
         rs.user_id,
         u.username,
         rs.segment_index,
         rs.start_ms,
         rs.end_ms,
         rs.file_path,
         rs.file_size,
         rs.duration_ms,
         c.call_type,
         c.started_at,
         c.ended_at,
         c.status AS call_status,
         c.session_kind,
         ui.username AS initiator_username,
         rm.events AS metadata_events,
         rm.created_at AS metadata_stored_at
       FROM recording_segments rs
       JOIN calls c ON c.id = rs.call_id
       JOIN users u ON u.id = rs.user_id
       LEFT JOIN users ui ON ui.id = c.initiator_id
       LEFT JOIN recording_metadata rm ON rm.call_id = rs.call_id AND rm.user_id = rs.user_id
       WHERE rs.file_path IS NOT NULL
       AND ($3::text IS NULL OR c.id::text = $3::text)
       ORDER BY c.started_at DESC, rs.user_id, rs.segment_index
       LIMIT $1 OFFSET $2`,
      [limit, offset, callIdFilter],
    );

    // Group by call for cleaner response
    const groupedByCall = {};
    segments.forEach(seg => {
      if (!groupedByCall[seg.call_id]) {
        groupedByCall[seg.call_id] = {
          callId: seg.call_id,
          callType: seg.call_type,
          sessionKind: seg.session_kind || 'call',
          startedAt: seg.started_at,
          endedAt: seg.ended_at,
          status: seg.call_status,
          initiatorUsername: seg.initiator_username || '',
          participants: new Map(),
        };
      }
      if (!groupedByCall[seg.call_id].participants.has(seg.user_id)) {
        groupedByCall[seg.call_id].participants.set(seg.user_id, {
          userId: seg.user_id,
          username: seg.username,
          metadataEvents: seg.metadata_events,
          segments: [],
        });
      }
      groupedByCall[seg.call_id].participants.get(seg.user_id).segments.push({
        segmentId: seg.id,
        segmentIndex: seg.segment_index,
        startMs: seg.start_ms,
        endMs: seg.end_ms,
        filePath: seg.file_path,
        fileSize: seg.file_size,
        durationMs: seg.duration_ms,
        streamUrl: `/api/admin/recording-segments/${seg.id}/stream`,
      });
    });

    // Convert Map to array
    const result = Object.values(groupedByCall).map(call => ({
      ...call,
      participants: Array.from(call.participants.values()),
    }));

    // Attach the server-side voice-activity timeline. This is generated by
    // FFmpeg per participant, so the clients can show who was speaking at a
    // given point instead of treating a participant's whole segment as speech.
    if (result.length > 0) {
      try {
        const { rows: timelines } = await db.query(
          `SELECT call_id, user_id, speaker_timeline
             FROM recordings
            WHERE call_id = ANY($1::uuid[])`,
          [result.map(call => String(call.callId))],
        );
        const byParticipant = new Map(
          timelines.map(row => [`${row.call_id}:${row.user_id}`, row.speaker_timeline || []]),
        );
        for (const call of result) {
          for (const participant of call.participants) {
            participant.speakerTimeline = byParticipant.get(`${call.callId}:${participant.userId}`) || [];
          }
        }
      } catch (timelineErr) {
        // Keep the recording calendar usable on installations predating the
        // speaker-timeline column; the UI falls back to participant segments.
        console.warn('[Admin] speaker timeline lookup skipped:', timelineErr.message);
      }
    }

    // Attach the call-level composite (primary playback surface) when present.
    // The per-user `segments` remain for solo review / fallback, but the client
    // prefers `composite` so it plays ONE file instead of N synchronized players.
    const callIds = result.map(c => String(c.callId));
    if (callIds.length > 0) {
      // Resilient to a not-yet-migrated DB: if recording_composites doesn't
      // exist (migration 041 not run), every call just gets composite:null and
      // the list still works (falls back to per-user players). This removes the
      // deploy-ordering footgun between server code and the migration.
      try {
        // Prefer the richer query (with cell_users for tile labels). If that
        // column doesn't exist yet (migration 042 not run), fall back to the
        // base columns so composite playback still works — labels just won't show.
        const baseCols =
          'call_id, duration_ms, width, height, layout, format, has_video, file_size';
        let comps;
        try {
          ({ rows: comps } = await db.query(
            `SELECT ${baseCols}, cell_users
             FROM recording_composites WHERE call_id = ANY($1::uuid[])`,
            [callIds],
          ));
        } catch (cellErr) {
          ({ rows: comps } = await db.query(
            `SELECT ${baseCols}
             FROM recording_composites WHERE call_id = ANY($1::uuid[])`,
            [callIds],
          ));
        }
        const byCall = new Map(comps.map(c => [String(c.call_id), c]));
        for (const call of result) {
          const c = byCall.get(String(call.callId));
          call.composite = c
            ? {
                streamUrl: `/api/admin/recording-composites/${call.callId}/stream`,
                durationMs: c.duration_ms,
                width: c.width,
                height: c.height,
                layout: c.layout,
                format: c.format,
                hasVideo: c.has_video,
                fileSize: c.file_size,
                // Row-major cell → participant map for tile identity overlays.
                cellUsers: c.cell_users || null,
              }
            : null;
        }
      } catch (compErr) {
        console.warn('[Admin] composite lookup skipped (table missing?):', compErr.message);
        for (const call of result) call.composite = null;
      }
    }

    res.json({ calls: result, count: segments.length });
  } catch (err) {
    console.error('[Admin] List recording segments error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Superadmin-only: stream a specific recording segment
router.get('/api/admin/recording-segments/:segmentId/stream', authMiddleware, superadminMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT rs.*, u.username FROM recording_segments rs
       JOIN users u ON u.id = rs.user_id
       WHERE rs.id = $1`,
      [req.params.segmentId],
    );

    if (!rows.length) {
      return res.status(404).json({ error: 'Segment not found' });
    }

    const segment = rows[0];
    if (!segment.file_path) {
      return res.status(400).json({ error: 'Segment file not yet available (extraction in progress)' });
    }

    // Check file exists
    if (!fs.existsSync(segment.file_path)) {
      console.warn(`[Admin] Segment file missing: ${segment.file_path}`);
      return res.status(410).json({ error: 'Segment file has been deleted' });
    }

    const filePath = segment.file_path;
    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const contentType = recordingContentType(filePath);
    const range = req.headers.range;

    // Media players (including react-native-video) rely on byte-range support
    // for progressive playback and seek bar updates.
    if (range) {
      const parts = String(range).replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

      if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= fileSize) {
        res.status(416).set({
          'Content-Range': `bytes */${fileSize}`,
        }).end();
        return;
      }

      const chunkSize = (end - start) + 1;
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': contentType,
        'Cache-Control': 'private, max-age=3600',
      });

      fs.createReadStream(filePath, { start, end }).pipe(res);
      return;
    }

    // Full-file stream fallback
    res.writeHead(200, {
      'Content-Length': fileSize,
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'private, max-age=3600',
    });
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    console.error('[Admin] Get segment error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Superadmin-only: stream the call-level COMPOSITE (single grid/audio artifact).
// This is the primary playback surface — one file, one decoder, one timeline.
router.get('/api/admin/recording-composites/:callId/stream', authMiddleware, superadminMiddleware, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT file_path, file_hash, format, has_video FROM recording_composites WHERE call_id = $1',
      [req.params.callId],
    );
    if (!rows.length) {
      return res.status(404).json({ error: 'Composite not found' });
    }
    const composite = rows[0];
    const filePath = composite.file_path;

    // Path traversal protection: resolved path must live inside recordings dir.
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(RECORDINGS_DIR + path.sep) && resolved !== RECORDINGS_DIR) {
      console.error('[Admin] Composite path traversal blocked:', filePath);
      return res.status(403).json({ error: 'Access denied' });
    }
    if (!fs.existsSync(filePath)) {
      return res.status(410).json({ error: 'Composite file has been deleted' });
    }

    // Integrity: verify SHA-256 matches what was stored at compose time. A range
    // request only checks once (the first, range-less probe most players issue is
    // cheap); per-chunk hashing would be prohibitive, and tamper detection at open
    // is the meaningful guarantee here.
    if (composite.file_hash && !req.headers.range) {
      const currentHash = hashFile(filePath);
      if (currentHash !== composite.file_hash) {
        console.error(`[Admin] Composite integrity FAILED for call ${req.params.callId}`);
        return res.status(409).json({ error: 'Composite integrity check failed — file may have been tampered with' });
      }
    }

    const stat = fs.statSync(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const contentType = ext === '.mp3'
      ? 'audio/mpeg'
      : composite.has_video
        ? 'video/mp4'
        : 'audio/mp4';
    const range = req.headers.range;

    if (range) {
      const parts = String(range).replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
      if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= stat.size) {
        return res.status(416).set({ 'Content-Range': `bytes */${stat.size}` }).end();
      }
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${stat.size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': end - start + 1,
        'Content-Type': contentType,
        'Cache-Control': 'private, max-age=3600',
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
      return;
    }

    res.writeHead(200, {
      'Content-Length': stat.size,
      'Content-Type': contentType,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'private, max-age=3600',
    });
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    console.error('[Admin] Stream composite error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get recording segments for playback (simple segment list)
router.get('/api/calls/:callId/recording-segments', authMiddleware, async (req, res) => {
  try {
    const { callId } = req.params;
    const userId = req.userId;

    // Verify user was a participant in this call
    const callRecord = await queries.calls.findById(callId).catch(() => null);
    if (!callRecord) {
      return res.status(404).json({ error: 'Call not found' });
    }

    // Check user was a participant
    const participants = await queries.calls.getParticipants(callId).catch(() => []);
    const isParticipant = participants.some(p => p.user_id === userId);
    if (!isParticipant) {
      return res.status(403).json({ error: 'Not a participant of this call' });
    }

    // Get all recording metadata and segments for this call
    const metadata = await db.query(
      `SELECT
         rm.user_id,
         rm.events,
         json_agg(json_build_object(
           'index', rs.segment_index,
           'startMs', rs.start_ms,
           'endMs', rs.end_ms,
           'filePath', rs.file_path,
           'fileSize', rs.file_size,
           'durationMs', rs.duration_ms
         ) ORDER BY rs.segment_index) as segments
       FROM recording_metadata rm
       LEFT JOIN recording_segments rs ON rm.call_id = rs.call_id AND rm.user_id = rs.user_id
       WHERE rm.call_id = $1
       GROUP BY rm.user_id, rm.events`,
      [callId]
    );

    if (!metadata || metadata.rows.length === 0) {
      return res.status(404).json({
        error: 'No recording metadata found for this call',
        callId
      });
    }

    // Format response with proper URLs
    const result = metadata.rows.map(entry => ({
      userId: entry.user_id,
      metadata: entry.events,
      segments: (entry.segments || [])
        .filter(seg => seg.filePath) // Only include segments with extracted files
        .map(seg => ({
          index: seg.index,
          startMs: seg.startMs,
          endMs: seg.endMs,
          durationMs: seg.durationMs,
          fileSize: seg.fileSize,
          url: `/api/recording-segment/${callId}/${entry.user_id}/${seg.index}.mp4`
        }))
    }));

    res.json({
      callId,
      duration: callRecord.duration,
      data: result,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error('[RecordingSegments] Get metadata error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Stream recording segment file
router.get('/api/recording-segment/:callId/:userId/:segmentIndex.mp4', authMiddleware, async (req, res) => {
  try {
    const { callId, userId, segmentIndex } = req.params;

    // Authorization: only the segment owner or a superadmin can access it
    const requester = await queries.users.findById(req.userId);
    if (!requester) return res.status(401).json({ error: 'Unauthorized' });
    const isOwner = requester.id === userId;
    const isSuperadmin = requester.role === 'superadmin';
    if (!isOwner && !isSuperadmin) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // Get segment file path from DB
    const result = await db.query(
      `SELECT file_path FROM recording_segments
       WHERE call_id = $1 AND user_id = $2 AND segment_index = $3`,
      [callId, userId, parseInt(segmentIndex)]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Segment not found' });
    }

    const filePath = result.rows[0].file_path;

    // Security: verify path is within recordings directory
    const resolved = path.resolve(filePath);
    if (!resolved.startsWith(RECORDINGS_DIR + path.sep)) {
      console.error('[RecordingSegment] Path traversal attempt:', filePath);
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const stat = fs.statSync(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const contentType = ext === '.mp4' ? 'video/mp4' : 'application/octet-stream';

    // Support range requests
    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${stat.size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': end - start + 1,
        'Content-Type': contentType,
      });
      fs.createReadStream(filePath, { start, end }).pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': stat.size,
        'Content-Type': contentType,
        'Accept-Ranges': 'bytes',
      });
      fs.createReadStream(filePath).pipe(res);
    }

  } catch (err) {
    console.error('[RecordingSegment] Stream error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

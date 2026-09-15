/**
 * Recording Segment Extractor
 *
 * Extracts clean video/audio segments from RTP recordings based on the
 * SERVER-AUTHORITATIVE timeline (deriveServerSegments) — the camera-on windows
 * the SFU actually observed, derived from each producer's server-stamped
 * start/end + pauseEvents. Client camera events are no longer used to cut; they
 * survive only as non-authoritative labels in recording_metadata.
 *
 * NO MERGING, NO BLACK FRAMES, NO OVERLAYS
 * Just FFmpeg stream copy for each segment
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const db = require('./src/infrastructure/db');
const { deriveServerSegments, getServerDurationMs } = require('./recordingTimeline');

const RECORDINGS_DIR = path.join(__dirname, 'recordings');

// ── Transcoding throttle settings ───────────────────────────────────────────
// Limit peak CPU during Phase 2 (VP8 → H.264 transcoding).  By default FFmpeg
// uses ALL available cores which pins the server at 100 % for the entire encode
// the event loop, drops socket connections, and can crash the process.
//
// TRANSCODING_THREADS: max threads FFmpeg may use per invocation (default 2).
// TRANSCODING_PRESET:  libx264 speed/quality tradeoff.  'fast' is ~40 % faster
//   per thread vs 'medium' with virtually identical quality at the same CRF.
// TRANSCODING_NICE:    Unix nice level (0-19) for FFmpeg child processes so
//   real-time media traffic and the Node event loop keep scheduling priority.
// TRANSCODING_MAX_CORES: max CPU cores FFmpeg may use (enforced via taskset on
//   Linux).  Pins the process to cores 0..N-1 so the rest of the machine stays
//   responsive for real-time media and the Node event loop.
// TRANSCODING_CRF: libx264 CRF value (0-51). Lower = better quality, bigger
//   files.  Default 17 is near-visually-lossless.
const TRANSCODING_THREADS   = parseInt(process.env.TRANSCODING_THREADS, 10) || 2;
const TRANSCODING_PRESET    = process.env.TRANSCODING_PRESET || 'fast';
const TRANSCODING_NICE      = parseInt(process.env.TRANSCODING_NICE, 10) || 10;
const TRANSCODING_MAX_CORES = parseInt(process.env.TRANSCODING_MAX_CORES, 10) || 3;
const TRANSCODING_CRF       = parseInt(process.env.TRANSCODING_CRF, 10) || 17;

/**
 * Extract video segments from raw RTP file based on metadata
 * Returns array of {index, startMs, endMs, filePath, fileSize, durationMs}
 */
async function extractVideoSegments(
  callId,
  userId,
  username,
  rawVideoSource,
  segments,  // [{startMs, endMs, index}, ...]
  rawAudioFile  // optional: raw .ogg audio file to mux into each segment
) {
  const videoTracks = normalizeVideoTracks(rawVideoSource);
  if (videoTracks.length === 0) {
    console.error(`[SegmentExtractor] No usable video source for user ${userId}`);
    return [];
  }

  const SEGMENT_DIR = path.join(RECORDINGS_DIR, callId, 'videos');
  if (!fs.existsSync(SEGMENT_DIR)) {
    fs.mkdirSync(SEGMENT_DIR, { recursive: true });
  }

  const extractedSegments = [];

  // Probe the raw audio file ONCE, up front, rather than per segment.
  // A non-zero byte count is not sufficient to call it usable: the
  // late-producer recording path (addProducerToRecording in mediaServer.js)
  // can leave a *non-empty* but corrupt .mka behind when its FFmpeg process
  // hits -rw_timeout before the mediasoup consumer is resumed — the file has
  // a valid-looking Matroska header but no readable clusters. A size check
  // alone reports "has audio", so every segment for this user then fails
  // outright when FFmpeg can't actually open the file — losing the video
  // too, not just the audio. Probing the duration is the same read ffmpeg
  // would attempt, so the corruption is caught here and the extraction
  // degrades to video-only instead of dropping the whole segment.
  let hasAudio = false;
  if (rawAudioFile && fs.existsSync(rawAudioFile)) {
    try {
      if (fs.statSync(rawAudioFile).size > 0) {
        const audioDurationMs = await probeMediaDurationMs(rawAudioFile);
        hasAudio = audioDurationMs != null && audioDurationMs > 0;
        if (!hasAudio) {
          console.warn(
            `[SegmentExtractor] Raw audio for user ${userId} exists but is unreadable/corrupt ` +
            `(${rawAudioFile}) — extracting video-only`
          );
        }
      }
    } catch (_) {}
  }

  // Cache actual file durations (probed via ffprobe) so we don't re-probe the
  // same raw MKV for every segment.  This is the ground-truth cap: the server-
  // side endOffsetMs is stamped when transports close, which happens BEFORE the
  // 10 s SIGKILL deadline fires.  SIGKILL'd files therefore always contain more
  // data than endOffsetMs suggests, and using endOffsetMs as the cap silently
  // truncates the last ~10 s of those recordings.
  const trackActualDurationCache = new Map(); // file path → actual duration ms

  const getActualTrackDurationMs = async (track) => {
    if (trackActualDurationCache.has(track.file)) {
      return trackActualDurationCache.get(track.file);
    }
    const probed = await probeMediaDurationMs(track.file);
    // probeMediaDurationMs returns null on error; fall back to endMs-startMs so
    // the behaviour is identical to the old code when ffprobe is unavailable.
    const actual = probed != null ? probed : Math.max(0, track.endMs - track.startMs);
    trackActualDurationCache.set(track.file, actual);
    return actual;
  };

  for (const segment of segments) {
    const segmentPath = path.join(
      SEGMENT_DIR,
      `${userId}_seg_${segment.index}.mp4`
    );

    const selectedTrack = selectTrackForSegment(videoTracks, segment);
    if (!selectedTrack) {
      console.warn(
        `[SegmentExtractor] No matching raw video track for segment ${segment.index} (${segment.startMs}-${segment.endMs}) user ${userId}`
      );
      continue;
    }

    // Pre-roll: start slightly before the client-reported camera_opened to
    // ensure we land AFTER a keyframe and don't lose the first visible frames.
    // A camera-orientation boundary must be frame-accurate: including frames
    // from before the switch and rotating them with the new camera's value
    // produces a short upside-down flash. Ordinary camera-open segments keep
    // the keyframe-friendly pre-roll.
    const PRE_ROLL_MS = segment.rotationChangedAtStart ? 0 : 300;
    const rawLocalStart = segment.startMs - selectedTrack.startMs;
    const localStartMs = Math.max(0, rawLocalStart - PRE_ROLL_MS);

    // Use the actual file duration (from ffprobe) as the cap — NOT endOffsetMs.
    // endOffsetMs is stamped when mediasoup transports close, but SIGKILL'd
    // FFmpeg processes keep writing for up to 10 more seconds.  Using the
    // server-side endOffsetMs silently truncates those extra seconds.
    const actualTrackDurationMs = await getActualTrackDurationMs(selectedTrack);
    const localEndMs = Math.min(
      Math.max(localStartMs, segment.endMs - selectedTrack.startMs),
      actualTrackDurationMs
    );

    const videoStartSec = (localStartMs / 1000).toFixed(3);
    const durationSec = ((localEndMs - localStartMs) / 1000).toFixed(3);
    // hasAudio was probed once, above, for the whole call rather than per
    // segment — see the comment there for why a size check alone isn't enough.
    // Audio seek: aligned with the video pre-roll so A/V stay in sync
    const audioStartSec = (Math.max(0, segment.startMs - PRE_ROLL_MS) / 1000).toFixed(3);

    console.log(
      `[SegmentExtractor] Extracting video segment ${segment.index}: ` +
      `${segment.startMs}ms-${segment.endMs}ms to ${segmentPath}` +
      (hasAudio ? ' (with audio)' : ' (video only)') +
      ` (seekV=${videoStartSec}s, seekA=${audioStartSec}s, dur=${durationSec}s, trackDur=${actualTrackDurationMs}ms)`
    );

    try {
      // FFmpeg: extract segment and transcode VP8 → H.264
      // Video is VP8 in MKV, audio is Opus in OGG (separate file)
      //
      // Raw MKV files from RTP capture are typically unfinalized (FFmpeg is
      // SIGTERM/SIGKILL'd when the call ends) — no Cue entries, no duration
      // in the header.  This makes byte-level seeking unreliable.
      //
      // Strategy:
      //   1. Try input seeking first (fast, works for properly-timestamped MKVs)
      //   2. If the output is suspiciously small (< MIN_SEGMENT_BYTES), retry
      //      with output seeking (reads from start — reliable but slower)

      // Bake the client-reported display rotation (CVO is lost by codec-copy).
      // rotation = degrees clockwise the receiver must rotate to display upright.
      // RECORDING_TRANSPOSE_OVERRIDE (0|90|180|270) lets an operator correct the
      // direction per device without an app rebuild; else use the client value.
      const overrideRot = Number(process.env.RECORDING_TRANSPOSE_OVERRIDE);
      const rotation = [0, 90, 180, 270].includes(overrideRot)
        ? overrideRot
        : ([0, 90, 180, 270].includes(Number(segment.rotation))
            ? Number(segment.rotation)
            : Number(selectedTrack.rotation || 0));
      let rotateVf = null;
      if (rotation === 90) rotateVf = 'transpose=1';            // 90° clockwise
      else if (rotation === 270) rotateVf = 'transpose=2';      // 90° counter-clockwise
      else if (rotation === 180) rotateVf = 'transpose=1,transpose=1';

      const videoEncArgs = [];
      if (rotateVf) videoEncArgs.push('-vf', rotateVf);
      videoEncArgs.push(
        '-c:v', 'libx264',
        '-preset', TRANSCODING_PRESET,
        '-crf', String(TRANSCODING_CRF),
        '-profile:v', 'high',
        '-level', '4.1',
        '-maxrate', '5M',
        '-bufsize', '10M',
        '-pix_fmt', 'yuv420p',
        '-g', '60',
        '-bf', '2',
        '-r', '30',
        '-vsync', 'cfr',
      );

      // ── Attempt 1: input seeking (fast) with generous probe settings ──
      const ffmpegArgs = [
        '-threads', String(TRANSCODING_THREADS),
        '-analyzeduration', '10000000',   // 10 s — handles unfinalized MKV with gaps
        '-probesize', '10000000',          // 10 MB
        '-err_detect', 'ignore_err',
        '-fflags', '+discardcorrupt+genpts',
        '-ss', videoStartSec,
        '-i', selectedTrack.file,
      ];
      if (hasAudio) {
        ffmpegArgs.push('-ss', audioStartSec, '-i', rawAudioFile);
      }
      ffmpegArgs.push(
        '-t', durationSec,
        '-map', '0:v',
      );
      if (hasAudio) {
        ffmpegArgs.push('-map', '1:a');
      }
      ffmpegArgs.push(...videoEncArgs);
      if (hasAudio) {
        ffmpegArgs.push('-c:a', 'aac', '-b:a', '192k');
      }
      ffmpegArgs.push(
        '-movflags', '+faststart',
        '-y',
        segmentPath
      );

      let result = await runFFmpegCommand(ffmpegArgs, {
        label: `${username} seg${segment.index}`
      });

      // ── Attempt 2: output seeking (reliable fallback) ──
      // If input seeking produced a suspiciously small file (or failed), retry
      // by reading the raw MKV from the beginning and using filter-level trim
      // + output -ss.  This handles unfinalized MKVs with missing Cue entries.
      const MIN_SEGMENT_BYTES = 50 * 1024; // 50 KB — well below any real segment
      const expectedDurationSec = parseFloat(durationSec);
      let needsRetry = result.status !== 0;
      if (!needsRetry && fs.existsSync(segmentPath)) {
        const firstSize = fs.statSync(segmentPath).size;
        // Heuristic: any real video+audio segment of 1+ seconds should exceed 50 KB
        needsRetry = firstSize < MIN_SEGMENT_BYTES && expectedDurationSec >= 1;
      }

      if (needsRetry) {
        console.warn(
          `[SegmentExtractor] Input-seek produced empty/tiny output for seg ${segment.index}; ` +
          `retrying with output seeking (slow but reliable)`
        );

        // Build filter graph: read full video, trim to the target window,
        // then re-timestamp from 0.  Audio uses per-input -ss (OGG is seekable).
        const retryArgs = [
          '-threads', String(TRANSCODING_THREADS),
          '-analyzeduration', '10000000',
          '-probesize', '10000000',
          '-err_detect', 'ignore_err',
          '-fflags', '+discardcorrupt+genpts',
          '-i', selectedTrack.file,       // no -ss: read from beginning
        ];
        if (hasAudio) {
          retryArgs.push('-ss', audioStartSec, '-i', rawAudioFile);
        }
        retryArgs.push(
          '-map', '0:v',
        );
        if (hasAudio) {
          retryArgs.push('-map', '1:a');
        }
        // Output seeking: -ss after inputs trims the combined output
        retryArgs.push(
          '-ss', videoStartSec,
          '-t', durationSec,
        );
        retryArgs.push(...videoEncArgs);
        if (hasAudio) {
          retryArgs.push('-c:a', 'aac', '-b:a', '192k');
        }
        retryArgs.push(
          '-movflags', '+faststart',
          '-y',
          segmentPath
        );

        result = await runFFmpegCommand(retryArgs, {
          label: `${username} seg${segment.index} (retry-output-seek)`
        });
      }

      if (result.status !== 0) {
        console.error(
          `[SegmentExtractor] Failed to extract segment ${segment.index}: ${result.stderr}`
        );
        continue;
      }

      if (!fs.existsSync(segmentPath)) {
        console.error(`[SegmentExtractor] Segment file not created: ${segmentPath}`);
        continue;
      }

      const fileSize = fs.statSync(segmentPath).size;
      console.log(`[SegmentExtractor] ✅ Segment ${segment.index}: ${(fileSize / 1024 / 1024).toFixed(2)}MB`);

      const actualDurationMs = await probeMediaDurationMs(segmentPath) || (segment.endMs - segment.startMs);

      // Correct the segment endMs in DB to match actual extracted content.
      // The metadata-derived endMs can overshoot when the rebased client
      // timeline extends beyond the raw file's actual recorded content.
      const actualEndMs = segment.startMs + actualDurationMs;
      const correctedEndMs = Math.min(segment.endMs, actualEndMs);

      extractedSegments.push({
        index: segment.index,
        startMs: segment.startMs,
        endMs: correctedEndMs,
        filePath: segmentPath,
        relativeUrl: `/recordings/${callId}/videos/${userId}_seg_${segment.index}.mp4`,
        fileSize,
        durationMs: actualDurationMs
      });

      // Upsert: INSERT for fallback users (no pre-existing row) and UPDATE for normal
      // users whose row was created by recordingMetadataHandler. ON CONFLICT ensures
      // both paths land in a consistent state without a double-write.
      await db.query(
        `INSERT INTO recording_segments
           (call_id, user_id, segment_index, start_ms, end_ms, file_path, file_size, duration_ms)
         VALUES ($5, $6, $7, $8, $4, $1, $2, $3)
         ON CONFLICT (call_id, user_id, segment_index) DO UPDATE
           SET file_path   = EXCLUDED.file_path,
               file_size   = EXCLUDED.file_size,
               duration_ms = EXCLUDED.duration_ms,
               end_ms      = EXCLUDED.end_ms`,
        [segmentPath, fileSize, actualDurationMs, correctedEndMs, callId, userId, segment.index, segment.startMs]
      );

    } catch (error) {
      console.error(`[SegmentExtractor] Error extracting segment ${segment.index}:`, error.message);
    }
  }

  return extractedSegments;
}

/**
 * Extract audio once for entire call duration
 * Audio plays continuously regardless of camera state
 */
async function extractAudio(
  callId,
  userId,
  username,
  rawAudioFile,
  startMs,
  endMs
) {
  if (!fs.existsSync(rawAudioFile)) {
    console.error(`[SegmentExtractor] Audio file not found: ${rawAudioFile}`);
    return null;
  }
  try {
    if (fs.statSync(rawAudioFile).size === 0) {
      console.error(`[SegmentExtractor] Audio file is empty (0 bytes): ${rawAudioFile}`);
      return null;
    }
  } catch (_) {}

  const AUDIO_DIR = path.join(RECORDINGS_DIR, callId, 'audio');
  if (!fs.existsSync(AUDIO_DIR)) {
    fs.mkdirSync(AUDIO_DIR, { recursive: true });
  }

  const audioPath = path.join(AUDIO_DIR, `${userId}_audio.mp4`);
  const startSec = (startMs / 1000).toFixed(3);

  // Cap at the shorter of the client-reported call duration and the probed
  // raw file duration. The raw MKA file can continue to grow during RTP
  // timeout / shutdown, while the client metadata can also overshoot when the
  // app's timer outlives the actual media. Using the smaller value keeps the
  // extracted audio aligned with real content.
  const actualFileDurationMs = await probeMediaDurationMs(rawAudioFile);
  const effectiveEndMs = actualFileDurationMs != null
    ? Math.min(endMs, actualFileDurationMs)  // cap at call duration
    : endMs;
  const durationSec = ((effectiveEndMs - startMs) / 1000).toFixed(3);

  console.log(
    `[SegmentExtractor] Extracting audio: ${startMs}ms-${effectiveEndMs}ms to ${audioPath}` +
    (actualFileDurationMs != null && effectiveEndMs < endMs
      ? ` (clamped from ${endMs}ms → ${effectiveEndMs}ms by ffprobe)` : '')
  );

  try {
    const result = await runFFmpegCommand([
      '-i', rawAudioFile,
      '-ss', startSec,
      '-t', durationSec,
      '-c:a', 'aac',        // Transcode Opus → AAC for broad player compatibility
      '-b:a', '192k',
      '-movflags', '+faststart',
      '-y',
      audioPath
    ], { label: `${username} audio` });

    if (result.status !== 0) {
      console.error(`[SegmentExtractor] Failed to extract audio: ${result.stderr}`);
      return null;
    }

    if (!fs.existsSync(audioPath)) {
      console.error(`[SegmentExtractor] Audio file not created: ${audioPath}`);
      return null;
    }

    const fileSize = fs.statSync(audioPath).size;
    const actualOutputDurationMs = await probeMediaDurationMs(audioPath) || Math.max(0, effectiveEndMs - startMs);
    console.log(`[SegmentExtractor] ✅ Audio: ${(fileSize / 1024 / 1024).toFixed(2)}MB`);

    return {
      filePath: audioPath,
      relativeUrl: `/recordings/${callId}/audio/${userId}_audio.mp4`,
      fileSize,
      durationMs: actualOutputDurationMs
    };

  } catch (error) {
    console.error('[SegmentExtractor] Error extracting audio:', error.message);
    return null;
  }
}

/**
 * Process entire call: extract all segments + audio for all users.
 *
 * Iterates rawRecordings (every user who has actual files on disk) rather than
 * metadata.rows so that users who crashed or disconnected before sending their
 * recording metadata are not silently dropped and their raw files deleted.
 *
 * For users WITH metadata  → existing DB-driven segment path (unchanged).
 * For users WITHOUT metadata → synthesize one full-duration segment from the
 *   raw track timestamps and insert a minimal recording_metadata row so the
 *   admin panel can display the recording.
 */
async function processCallRecordings(callId, rawRecordings) {
  try {
    const callProcessStart = Date.now();
    console.log(
      `\n[SegmentExtractor] Processing call ${callId}...` +
      ` (threads=${TRANSCODING_THREADS}, preset=${TRANSCODING_PRESET}, nice=${TRANSCODING_NICE}, cores=${TRANSCODING_MAX_CORES}, crf=${TRANSCODING_CRF})`
    );

    // Index existing metadata by userId for O(1) lookup.
    const metadataResult = await db.query(
      `SELECT user_id, events FROM recording_metadata WHERE call_id = $1`,
      [callId]
    );
    const metaByUserId = new Map();
    for (const row of metadataResult.rows) {
      metaByUserId.set(String(row.user_id), row.events);
    }

    if (metaByUserId.size === 0) {
      console.warn(
        `[SegmentExtractor] No metadata found for call ${callId} — ` +
        `will use fallback extraction for all ${rawRecordings.length} user(s) with raw files`
      );
    }

    const result = [];

    for (const userRawFiles of rawRecordings) {
      const userId    = userRawFiles.userId;
      const userIdStr = String(userId);
      const userProcessStart = Date.now();
      console.log(`\n[SegmentExtractor] Processing user ${userId} (${userRawFiles.username})...`);

      const hasMetadata = metaByUserId.has(userIdStr);

      // ── SERVER-AUTHORITATIVE TIMELINE ───────────────────────────────────
      // The timeline is defined by the bytes the SFU received, NOT by client
      // camera events. Each captured video producer carries server-stamped
      // startMs/endMs (+ pauseEvents); deriveServerSegments turns those into the
      // camera-on windows we cut. Client `events` survive only as labels and are
      // used ONLY as a last-resort fallback when the server captured no video at
      // all (legacy data / audio-only edge cases).
      const rawVideoTracks = Array.isArray(userRawFiles.videoTracks) ? userRawFiles.videoTracks : [];
      const serverAudioTracks = Array.isArray(userRawFiles.audioTracks) ? userRawFiles.audioTracks : [];

      // Drop unreadable/corrupt video tracks (e.g. a 1-2s rejoin producer whose
      // container header never got written before teardown). Their camera-on
      // window is simply not cut → it becomes a clean gap, never a hard failure.
      const serverVideoTracks = [];
      for (const t of rawVideoTracks) {
        if (await probeVideoReadable(t.file)) {
          serverVideoTracks.push(t);
        } else {
          console.warn(
            `[SegmentExtractor] Dropping unreadable video track for user ${userId}: ${t.file} ` +
            `(corrupt/empty container — its window renders as a gap)`
          );
        }
      }

      const serverSegments = deriveServerSegments(serverVideoTracks);
      const serverDurationMs = getServerDurationMs([...serverVideoTracks, ...serverAudioTracks]);
      // Call-clock offset where this user's audio actually began (late joiners
      // start > 0). The compositor adelays each user's audio by this so voices
      // land at the right point on the shared timeline.
      const audioStartMs = serverAudioTracks.length > 0
        ? Math.max(0, Number(serverAudioTracks[0].startMs || 0))
        : 0;

      let segments = [];
      let audioEndMs = serverDurationMs; // server presence extent on the recording clock

      if (serverSegments.length > 0) {
        // Authoritative: RTP-observed camera-on windows.
        segments = serverSegments;
        console.log(`[SegmentExtractor] Server timeline: ${segments.length} camera-on window(s) for user ${userId}`);
      } else if (serverVideoTracks.length === 0 && hasMetadata) {
        // No server video captured but client reported camera events — legacy fallback.
        const events = metaByUserId.get(userIdStr);
        segments = extractCameraSegments(events);
        if (!audioEndMs) audioEndMs = getCallDuration(events);
        console.warn(`[SegmentExtractor] No server video for user ${userId} — falling back to client camera events (${segments.length} segment(s))`);
      }
      // else: audio-only (segments stays []) → continuous audio row inserted below.

      if (!audioEndMs && hasMetadata) {
        audioEndMs = getCallDuration(metaByUserId.get(userIdStr));
      }

      // Nothing usable for this user (no server media and no fallback audio).
      if (segments.length === 0 && !(userRawFiles.audioFile && audioEndMs > 0)) {
        console.warn(
          `[SegmentExtractor] No usable server windows or audio for user ${userId} in call ${callId} — skipping`
        );
        continue;
      }

      // Persist a synthetic metadata row when the client never sent one, so the
      // admin panel can still JOIN recording_metadata for this user.
      if (!hasMetadata && serverDurationMs > 0) {
        try {
          await db.query(
            `INSERT INTO recording_metadata (call_id, user_id, events)
             VALUES ($1, $2, $3::jsonb)
             ON CONFLICT (call_id, user_id) DO NOTHING`,
            [
              callId,
              userId,
              JSON.stringify([
                { type: 'camera_opened', timestampMs: serverSegments[0]?.startMs ?? 0 },
                { type: 'call_ended',    timestampMs: serverDurationMs },
              ]),
            ]
          );
        } catch (dbErr) {
          console.warn(
            `[SegmentExtractor] Could not insert synthetic metadata for user ${userId}: ${dbErr.message}`
          );
        }
      }

      // ── Extract video segments ────────────────────────────────────────────
      let videoSegments = [];
      if ((userRawFiles.videoFile || userRawFiles.videoTracks?.length > 0) && segments.length > 0) {
        videoSegments = await extractVideoSegments(
          callId,
          userId,
          userRawFiles.username,
          userRawFiles.videoTracks?.length ? userRawFiles.videoTracks : userRawFiles.videoFile,
          segments,
          userRawFiles.audioFile  // mux audio into video segments
        );
      }

      // ── Extract audio (continuous for entire presence window) ─────────────
      let audioFile = null;
      if (userRawFiles.audioFile && audioEndMs > 0) {
        audioFile = await extractAudio(
          callId,
          userId,
          userRawFiles.username,
          userRawFiles.audioFile,
          0,
          audioEndMs
        );
      }

      // ── Persist audio-only segment row ──────────────────────────────────
      // For audio-only calls (no video segments), recording_segments has no
      // rows yet because extractCameraSegments returns [] and video extraction
      // is skipped.  Insert one row so the admin panel can find and stream it.
      if (audioFile && videoSegments.length === 0) {
        try {
          await db.query(
            `INSERT INTO recording_segments
               (call_id, user_id, segment_index, start_ms, end_ms, file_path, file_size, duration_ms)
             VALUES ($1, $2, 0, 0, $3, $4, $5, $6)
             ON CONFLICT (call_id, user_id, segment_index) DO UPDATE
               SET file_path   = EXCLUDED.file_path,
                   file_size   = EXCLUDED.file_size,
                   duration_ms = EXCLUDED.duration_ms,
                   end_ms      = EXCLUDED.end_ms`,
            [callId, userId, audioFile.durationMs, audioFile.filePath, audioFile.fileSize, audioFile.durationMs]
          );
        } catch (dbErr) {
          console.warn(`[SegmentExtractor] Could not insert audio segment for user ${userId}: ${dbErr.message}`);
        }
      }

      // ── Stitch segments into one continuous timeline MP4 ───────────────
      // Fills camera-off gaps with black frames so the admin panel can play
      // a single seamless file per user instead of managing segment gaps.
      let stitchedFile = null;
      if (videoSegments.length > 0 && audioEndMs > 0) {
        try {
          stitchedFile = await stitchUserTimeline(
            callId, userId, userRawFiles.username, videoSegments, audioEndMs
          );
        } catch (stitchErr) {
          console.warn(`[SegmentExtractor] Stitch failed for ${userRawFiles.username}: ${stitchErr.message}`);
        }
      }

      const userElapsedSec = ((Date.now() - userProcessStart) / 1000).toFixed(1);
      console.log(`[SegmentExtractor] User ${userRawFiles.username} completed in ${userElapsedSec}s`);

      result.push({
        userId,
        username: userRawFiles.username,
        videoSegments,
        audioFile,
        stitchedFile,
        // Timeline anchors for the call compositor (server clock, ms).
        audioStartMs,
        audioEndMs,
      });
    }

    const callElapsedSec = ((Date.now() - callProcessStart) / 1000).toFixed(1);
    console.log(`\n[SegmentExtractor] ✅ Call ${callId} processing complete (${callElapsedSec}s elapsed)`);
    return result;

  } catch (error) {
    console.error('[SegmentExtractor] Error processing call:', error);
    throw error;
  }
}

function normalizeVideoTracks(rawVideoSource) {
  if (Array.isArray(rawVideoSource)) {
    return rawVideoSource
      .map((t) => ({
        file: t?.file,
        startMs: Number(t?.startMs || 0),
        endMs: Number(t?.endMs || 0),
        rotation: Number(t?.rotation || 0),  // client-reported display rotation (deg cw)
        rotationEvents: Array.isArray(t?.rotationEvents) ? t.rotationEvents : [],
      }))
      .filter((t) => t.file && fs.existsSync(t.file) && Number.isFinite(t.startMs) && Number.isFinite(t.endMs) && t.endMs > t.startMs)
      .sort((a, b) => a.startMs - b.startMs);
  }

  if (typeof rawVideoSource === 'string' && rawVideoSource && fs.existsSync(rawVideoSource)) {
    return [{ file: rawVideoSource, startMs: 0, endMs: Number.MAX_SAFE_INTEGER }];
  }

  return [];
}

function selectTrackForSegment(videoTracks, segment) {
  const segStart = Number(segment?.startMs || 0);
  const segEnd = Number(segment?.endMs || 0);

  const fullyContaining = videoTracks.find((t) => segStart >= t.startMs - 200 && segEnd <= t.endMs + 200);
  if (fullyContaining) return fullyContaining;

  let best = null;
  let bestOverlap = 0;
  for (const t of videoTracks) {
    const overlap = Math.max(0, Math.min(segEnd, t.endMs) - Math.max(segStart, t.startMs));
    if (overlap > bestOverlap) {
      bestOverlap = overlap;
      best = t;
    }
  }
  return best;
}

/**
 * Extract camera on/off segments from metadata events
 */
function extractCameraSegments(events) {
  const segments = [];
  let currentStart = null;
  let segmentIndex = 0;

  for (const event of events) {
    if (event.type === 'camera_opened') {
      // If we already have an open segment, close it first (duplicate camera_opened)
      if (currentStart !== null) {
        segments.push({ startMs: currentStart, endMs: event.timestampMs, index: segmentIndex++ });
      }
      currentStart = event.timestampMs;
    } else if (event.type === 'camera_closed' && currentStart !== null) {
      segments.push({
        startMs: currentStart,
        endMs: event.timestampMs,
        index: segmentIndex++
      });
      currentStart = null;
    } else if (event.type === 'call_ended' && currentStart !== null) {
      segments.push({
        startMs: currentStart,
        endMs: event.timestampMs,
        index: segmentIndex++
      });
      currentStart = null;
    }
  }

  return segments;
}

/**
 * Get total call duration from events
 */
function getCallDuration(events) {
  const callEndEvent = events.find(e => e.type === 'call_ended');
  return callEndEvent ? callEndEvent.timestampMs : 0;
}

/**
 * Run FFmpeg command and return result.
 *
 * Spawns FFmpeg behind `nice` to lower its scheduling priority so real-time
 * media and the Node event loop are not starved during long transcodes.
 *
 * @param {string[]} args   FFmpeg arguments
 * @param {object}   [opts]
 * @param {string}   [opts.label]  Human-readable label for 30-second progress logs
 */
function runFFmpegCommand(args, { label = '' } = {}) {
  return new Promise((resolve) => {
    // On Linux, pin FFmpeg to a limited set of CPU cores via taskset and
    // lower its I/O priority via ionice so the rest of the server (real-time
    // media, Node event loop) stays responsive during long transcodes.
    const isLinux = process.platform === 'linux';
    const cpuList = Array.from({ length: TRANSCODING_MAX_CORES }, (_, i) => i).join(',');

    let cmd, cmdArgs;
    if (isLinux) {
      // taskset -c 0,1 ionice -c2 -n7 nice -n 10 ffmpeg ...
      cmd = 'taskset';
      cmdArgs = [
        '-c', cpuList,
        'ionice', '-c2', '-n7',
        'nice', '-n', String(TRANSCODING_NICE),
        'ffmpeg', ...args,
      ];
    } else {
      cmd = 'nice';
      cmdArgs = ['-n', String(TRANSCODING_NICE), 'ffmpeg', ...args];
    }

    const proc = spawn(cmd, cmdArgs, {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stderr = '';
    let lastProgressLog = Date.now();
    const PROGRESS_INTERVAL_MS = 30_000; // log progress every 30 s

    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      stderr += chunk;
      // Cap accumulated stderr at 64 KB to avoid runaway memory during long
      // encodes (FFmpeg emits a carriage-return progress line every frame).
      if (stderr.length > 65536) stderr = stderr.slice(-32768);

      // Periodic progress logging so operators can track long transcodes.
      if (label) {
        const now = Date.now();
        if (now - lastProgressLog >= PROGRESS_INTERVAL_MS) {
          const m = chunk.match(/frame=\s*(\d+).*?time=(\S+).*?speed=\s*(\S+)/);
          if (m) {
            lastProgressLog = now;
            console.log(
              `[SegmentExtractor] [${label}] progress — frame=${m[1]} time=${m[2]} speed=${m[3]}`
            );
          }
        }
      }
    });

    proc.on('close', (status) => {
      resolve({ status, stderr });
    });

    proc.on('error', (error) => {
      resolve({ status: 1, stderr: error.message });
    });
  });
}

/**
 * Probe actual media duration in milliseconds using ffprobe.
 */
function probeMediaDurationMs(filePath) {
  return new Promise((resolve) => {
    const proc = spawn('ffprobe', [
      '-v', 'error',
      '-show_entries', 'format=duration',
      '-of', 'default=noprint_wrappers=1:nokey=1',
      filePath,
    ], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    proc.stdout.on('data', (d) => {
      stdout += d.toString();
    });

    proc.on('close', (status) => {
      if (status !== 0) return resolve(null);
      const sec = parseFloat((stdout || '').trim());
      if (!Number.isFinite(sec) || sec <= 0) return resolve(null);
      resolve(Math.round(sec * 1000));
    });

    proc.on('error', () => resolve(null));
  });
}

/**
 * Probe whether a raw capture file contains a DECODABLE video stream.
 *
 * Used to drop corrupt tracks BEFORE they reach segment extraction. A rejoin
 * mid-call spawns a fresh per-producer FFmpeg; if that producer lived only a
 * second or two and was hard-killed at teardown, its container header may never
 * have been written → "EBML header parsing failed / Invalid data". Such a file
 * is unrecoverable, so we exclude it: the corresponding camera-on window simply
 * never gets cut and renders as a black gap in the composite, instead of
 * failing the whole user's extraction.
 *
 * IMPORTANT: we probe for a video STREAM, not duration. Valid-but-unfinalized
 * MKVs (the normal case — FFmpeg is SIGKILL'd at call end) legitimately have no
 * duration tag in the header, so a duration probe would wrongly reject good
 * files. A stream probe only fails when the container itself is unparseable.
 */
function probeVideoReadable(filePath) {
  return new Promise((resolve) => {
    if (!filePath || !fs.existsSync(filePath)) return resolve(false);
    try { if (fs.statSync(filePath).size === 0) return resolve(false); } catch (_) { return resolve(false); }
    const proc = spawn('ffprobe', [
      '-v', 'error',
      '-select_streams', 'v:0',
      '-show_entries', 'stream=codec_type',
      '-of', 'default=noprint_wrappers=1:nokey=1',
      filePath,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.on('close', (code) => resolve(code === 0 && out.trim() === 'video'));
    proc.on('error', () => resolve(false));
  });
}

/**
 * Probe video dimensions and detect audio presence in a media file.
 */
function probeVideoFormat(filePath) {
  return new Promise((resolve) => {
    const proc = spawn('ffprobe', [
      '-v', 'error',
      '-show_entries', 'stream=width,height,codec_type',
      '-of', 'json',
      filePath,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });

    let stdout = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });

    proc.on('close', (code) => {
      if (code !== 0) return resolve(null);
      try {
        const data = JSON.parse(stdout);
        const streams = data?.streams || [];
        const videoStream = streams.find((s) => s.codec_type === 'video');
        const hasAudio = streams.some((s) => s.codec_type === 'audio');
        resolve({
          width: videoStream?.width || 640,
          height: videoStream?.height || 480,
          hasAudio,
        });
      } catch (_) {
        resolve(null);
      }
    });

    proc.on('error', () => resolve(null));
  });
}

/**
 * Generate a black + silent video piece for gap filling.
 * Codec settings match extractVideoSegments output for clean concat.
 */
async function createBlackPiece(outPath, width, height, durationSec, includeAudio) {
  if (durationSec < 0.01) return false;

  const args = [
    '-y',
    '-f', 'lavfi', '-i', `color=c=black:s=${width}x${height}:r=30:d=${durationSec.toFixed(3)}`,
  ];
  if (includeAudio) {
    args.push('-f', 'lavfi', '-i', 'anullsrc=r=48000:cl=stereo');
    args.push('-map', '0:v', '-map', '1:a');
  }
  // Match extractVideoSegments encoding params EXACTLY so concat demuxer
  // can use stream copy without SPS/PPS mismatches.
  args.push(
    '-t', durationSec.toFixed(3),
    '-c:v', 'libx264',
    '-preset', TRANSCODING_PRESET,
    '-crf', String(TRANSCODING_CRF),
    '-profile:v', 'high',
    '-level', '4.1',
    '-maxrate', '5M',
    '-bufsize', '10M',
    '-pix_fmt', 'yuv420p',
    '-r', '30', '-vsync', 'cfr',
    '-g', '60',
    '-bf', '2',
  );
  if (includeAudio) {
    args.push('-c:a', 'aac', '-b:a', '192k');
  }
  args.push('-movflags', '+faststart', outPath);

  const result = await runFFmpegCommand(args, { label: 'gap-fill' });
  return result.status === 0 && fs.existsSync(outPath) && fs.statSync(outPath).size > 0;
}

/**
 * Stitch extracted video segments into a single continuous timeline MP4.
 *
 * Fills camera-off gaps with black + silence so the output is one seamless
 * file that plays from 0 to totalDurationMs.  This replaces the old
 * buildNormalizedPeerVideoTimeline approach which read from raw MKVs.
 *
 * Approach: generate black-frame pieces for gaps, then concat-demux all
 * pieces and re-encode to ensure uniform format (handles any minor codec
 * param mismatches between segments and generated pieces).
 *
 * @param {string} callId
 * @param {string} userId
 * @param {string} username
 * @param {Array}  videoSegments - [{index, startMs, endMs, filePath, fileSize, durationMs}]
 * @param {number} totalDurationMs - full call duration
 * @returns {object|null} {filePath, relativeUrl, fileSize, durationMs} or null
 */
async function stitchUserTimeline(callId, userId, username, videoSegments, totalDurationMs) {
  if (!videoSegments || videoSegments.length === 0 || !totalDurationMs) return null;

  const sorted = [...videoSegments]
    .filter((s) => s.filePath && fs.existsSync(s.filePath) && s.fileSize > 0)
    .sort((a, b) => a.startMs - b.startMs);
  if (sorted.length === 0) return null;

  // If there's only one segment covering most of the call, skip stitching
  const singleSegCoverage = sorted.length === 1
    ? (sorted[0].endMs - sorted[0].startMs) / totalDurationMs
    : 0;
  if (singleSegCoverage > 0.9) {
    console.log(`[SegmentExtractor] Single segment covers ${(singleSegCoverage * 100).toFixed(0)}% of call — skipping stitch for ${username}`);
    return null;
  }

  const STITCH_DIR = path.join(RECORDINGS_DIR, callId, 'stitched');
  if (!fs.existsSync(STITCH_DIR)) fs.mkdirSync(STITCH_DIR, { recursive: true });

  // Probe first segment for dimensions and audio presence
  const probe = await probeVideoFormat(sorted[0].filePath);
  const width = probe?.width || 640;
  const height = probe?.height || 480;
  const hasAudio = probe?.hasAudio ?? false;

  const pieces = [];
  const tempArtifacts = [];
  let cursor = 0; // timeline position in ms

  console.log(
    `[SegmentExtractor] Stitching ${sorted.length} segments for ${username} ` +
    `(${width}x${height}, audio=${hasAudio}, totalDuration=${(totalDurationMs / 1000).toFixed(1)}s)`
  );

  for (const seg of sorted) {
    // Gap before this segment
    const gap = seg.startMs - cursor;
    if (gap > 100) { // >100ms gap worth filling
      const gapFile = path.join(STITCH_DIR, `${userId}_gap_${pieces.length}.mp4`);
      const ok = await createBlackPiece(gapFile, width, height, gap / 1000, hasAudio);
      if (ok) {
        pieces.push(gapFile);
        tempArtifacts.push(gapFile);
      } else {
        console.warn(`[SegmentExtractor] Failed to create gap piece (${(gap / 1000).toFixed(1)}s) for ${username}`);
      }
    }

    // Add the actual segment
    pieces.push(seg.filePath);
    cursor = seg.endMs;
  }

  // Trailing black to fill to total call duration
  if (totalDurationMs - cursor > 100) {
    const gapFile = path.join(STITCH_DIR, `${userId}_gap_${pieces.length}.mp4`);
    const ok = await createBlackPiece(gapFile, width, height, (totalDurationMs - cursor) / 1000, hasAudio);
    if (ok) {
      pieces.push(gapFile);
      tempArtifacts.push(gapFile);
    }
  }

  if (pieces.length <= 1) {
    // Cleanup any temp artifacts
    for (const f of tempArtifacts) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
    }
    return null;
  }

  // Write concat list
  const concatList = path.join(STITCH_DIR, `${userId}_concat.txt`);
  const listContent = pieces.map((p) => `file '${p.replace(/'/g, "'\\''")}'`).join('\n');
  fs.writeFileSync(concatList, listContent + '\n');
  tempArtifacts.push(concatList);

  // Stream copy the concat — all pieces are already H.264 with matching params.
  // This avoids a double-encode which causes quality loss, bloated file size,
  // and stuttery playback (2-3 fps) on mobile devices.
  const stitchedPath = path.join(STITCH_DIR, `${userId}_timeline.mp4`);
  const ffmpegCopyArgs = [
    '-threads', String(TRANSCODING_THREADS),
    '-f', 'concat', '-safe', '0', '-i', concatList,
    '-c', 'copy',
    '-movflags', '+faststart',
    '-y', stitchedPath,
  ];

  let result = await runFFmpegCommand(ffmpegCopyArgs, { label: `${username} stitch (copy)` });

  // Fallback: re-encode if stream copy fails (e.g., SPS/PPS mismatch between pieces)
  if (result.status !== 0 || !fs.existsSync(stitchedPath) ||
      (fs.existsSync(stitchedPath) && fs.statSync(stitchedPath).size < 1024)) {
    console.warn(`[SegmentExtractor] Stream-copy stitch failed for ${username}, falling back to re-encode`);
    const ffmpegReencodeArgs = [
      '-threads', String(TRANSCODING_THREADS),
      '-f', 'concat', '-safe', '0', '-i', concatList,
      '-c:v', 'libx264',
      '-preset', TRANSCODING_PRESET,
      '-crf', '23',    // lighter than CRF 17 — source is already encoded
      '-profile:v', 'high',
      '-pix_fmt', 'yuv420p',
      '-r', '30', '-vsync', 'cfr',
      '-g', '30', '-bf', '0',   // short GOP, no B-frames → simpler decode
    ];
    if (hasAudio) {
      ffmpegReencodeArgs.push('-c:a', 'aac', '-b:a', '192k');
    }
    ffmpegReencodeArgs.push('-movflags', '+faststart', '-y', stitchedPath);
    result = await runFFmpegCommand(ffmpegReencodeArgs, { label: `${username} stitch (re-encode)` });
  }

  // Cleanup temp gap pieces and concat list
  for (const f of tempArtifacts) {
    try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
  }

  if (result.status !== 0 || !fs.existsSync(stitchedPath)) {
    console.warn(`[SegmentExtractor] Stitching failed for ${username}: ${result.stderr?.substring(0, 200)}`);
    try { if (fs.existsSync(stitchedPath)) fs.unlinkSync(stitchedPath); } catch (_) {}
    return null;
  }

  const fileSize = fs.statSync(stitchedPath).size;
  const durationMs = await probeMediaDurationMs(stitchedPath) || totalDurationMs;
  console.log(`[SegmentExtractor] ✅ Stitched ${username}: ${(fileSize / 1024 / 1024).toFixed(2)}MB, ${(durationMs / 1000).toFixed(1)}s`);

  return {
    filePath: stitchedPath,
    relativeUrl: `/recordings/${callId}/stitched/${userId}_timeline.mp4`,
    fileSize,
    durationMs,
  };
}

module.exports = {
  extractVideoSegments,
  extractAudio,
  processCallRecordings,
  extractCameraSegments,
  getCallDuration,
  stitchUserTimeline,
  // Shared FFmpeg/ffprobe helpers reused by recordingCompositor.js so the call
  // compositor inherits the same CPU throttling (taskset/ionice/nice).
  runFFmpegCommand,
  probeMediaDurationMs,
  probeVideoFormat,
  probeVideoReadable,
};

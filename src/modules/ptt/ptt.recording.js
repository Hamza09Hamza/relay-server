'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const db = require('../../infrastructure/db');
const encryption = require('../../infrastructure/encryption/encryption');
const { RECORDINGS_DIR } = require('../../app/paths');
const { hashFile } = require('../../shared/files/hash');

const PTT_RECORDINGS_DIR = path.join(RECORDINGS_DIR, 'ptt');
const MIN_RETAINED_DURATION_MS = 400;
// A press killed before any RTP packet arrives still leaves a Matroska header
// shell on disk (observed ~1KB) with zero frames muxed into it. Real Opus
// voice audio (this router negotiates no explicit maxaveragebitrate, so
// clients float in the ~24-40kbps range) clears a couple KB within well
// under a second, so anything under this size is "no audio captured" —
// skip the second ffmpeg pass instead of letting it fail on a guaranteed-
// empty input.
const MIN_RAW_AUDIO_BYTES = 2_048;
const DEFAULT_RETENTION_DAYS = 1;
const RTP_PORT_MIN = 29_000;
const RTP_PORT_PAIRS = 1_000;
const reservedPorts = new Set();
const RECORDER_DRAIN_MS = 300;
// FFmpeg's seekable Matroska default is a five-second cluster. If its RTP/UDP
// input stalls during shutdown and the process has to be terminated, the open
// cluster is not finalized — producing the observed exact 5s/10s/15s files.
// Keep clusters short so even a blocked FFmpeg exit cannot discard a
// human-noticeable tail.
const MATROSKA_CLUSTER_MS = 250;

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function isPttRecordingEnabled(env = process.env) {
  return String(env.NODE_ENV || '').trim().toLowerCase() === 'production' &&
    String(env.PTT_AUDIO_RECORDING_ENABLED || '').trim().toLowerCase() === 'true';
}

function retentionDays(env = process.env) {
  const parsed = Number.parseInt(String(env.PTT_AUDIO_RETENTION_DAYS || ''), 10);
  if (!Number.isFinite(parsed)) return DEFAULT_RETENTION_DAYS;
  return Math.max(1, Math.min(365, parsed));
}

function isRetainableDuration(durationMs) {
  return Number.isFinite(durationMs) && durationMs > MIN_RETAINED_DURATION_MS;
}

function pruneExpiredCompleted(cache, now = Date.now()) {
  for (const [transmissionId, entry] of cache) {
    if (!entry || entry.expiresAt <= now) cache.delete(transmissionId);
  }
  return cache.size;
}

function allocatePortPair() {
  for (let i = 0; i < RTP_PORT_PAIRS; i++) {
    const rtp = RTP_PORT_MIN + Math.floor(Math.random() * RTP_PORT_PAIRS) * 2;
    const rtcp = rtp + 1;
    if (reservedPorts.has(rtp) || reservedPorts.has(rtcp)) continue;
    reservedPorts.add(rtp);
    reservedPorts.add(rtcp);
    return { rtp, rtcp };
  }
  throw new Error('No PTT recording RTP ports available');
}

function releasePortPair(pair) {
  if (!pair) return;
  reservedPorts.delete(pair.rtp);
  reservedPorts.delete(pair.rtcp);
}

function safePttPath(candidate) {
  if (!candidate) return null;
  const resolved = path.resolve(candidate);
  return resolved === PTT_RECORDINGS_DIR || resolved.startsWith(`${PTT_RECORDINGS_DIR}${path.sep}`)
    ? resolved
    : null;
}

function unlinkSafe(candidate) {
  const resolved = safePttPath(candidate);
  if (!resolved || resolved === PTT_RECORDINGS_DIR) return false;
  try {
    if (fs.existsSync(resolved)) fs.unlinkSync(resolved);
    return true;
  } catch (error) {
    console.warn('[PTT Recording] Cleanup failed:', error.message);
    return false;
  }
}

function run(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeoutMs);
    timer.unref?.();
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve({
        code,
        timedOut,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
      });
    });
  });
}

function waitForRecorderReady(child, timeoutMs = 1_500) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.stderr.off('data', onData);
      child.off('error', onError);
      child.off('close', onClose);
      if (error) reject(error);
      else resolve();
    };
    const onData = chunk => {
      const text = chunk.toString();
      if (/Output #0|Press \[q\]/.test(text)) finish();
    };
    const onError = error => finish(error);
    const onClose = code => finish(new Error(`FFmpeg exited during startup (${code})`));
    const timer = setTimeout(() => finish(), timeoutMs);
    timer.unref?.();
    child.stderr.on('data', onData);
    child.once('error', onError);
    child.once('close', onClose);
  });
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode) return;
  const closed = new Promise(resolve => child.once('close', resolve));
  try { child.stdin.write('q\n'); } catch (_) {}
  let timer = setTimeout(() => {
    // SIGINT is FFmpeg's graceful interrupt path: it breaks a blocked network
    // read and gives the muxer a chance to close its current cluster/trailer.
    // SIGTERM produced "Immediate exit requested" on the affected server and
    // is exactly where the open five-second cluster was being discarded.
    try { child.kill('SIGINT'); } catch (_) {}
  }, 2_000);
  timer.unref?.();
  await Promise.race([closed, new Promise(resolve => setTimeout(resolve, 3_000))]);
  clearTimeout(timer);
  if (child.exitCode === null && !child.signalCode) {
    try { child.kill('SIGKILL'); } catch (_) {}
    await Promise.race([closed, new Promise(resolve => setTimeout(resolve, 500))]);
  }
}

function buildRecorderArgs(sdpPath, rawPath) {
  return [
    '-hide_banner', '-loglevel', 'info', '-y',
    '-protocol_whitelist', 'file,udp,rtp',
    '-fflags', '+genpts+igndts',
    '-thread_queue_size', '2048',
    '-f', 'sdp', '-i', sdpPath,
    '-vn', '-c:a', 'copy',
    '-flush_packets', '1',
    '-cluster_time_limit', String(MATROSKA_CLUSTER_MS),
    '-cluster_size_limit', '32768',
    '-f', 'matroska', rawPath,
  ];
}

function buildAudioSdp(consumer, portPair, transmissionId) {
  const codec = consumer.rtpParameters?.codecs?.[0];
  const ssrc = consumer.rtpParameters?.encodings?.[0]?.ssrc;
  if (!codec || !ssrc) throw new Error('Recorder did not receive valid Opus RTP parameters');
  const payloadType = codec.payloadType;
  const channels = codec.channels || 2;
  return [
    'v=0',
    'o=- 0 0 IN IP4 127.0.0.1',
    's=Relay PTT transmission',
    't=0 0',
    `m=audio ${portPair.rtp} RTP/AVP ${payloadType}`,
    'c=IN IP4 127.0.0.1',
    `a=rtcp:${portPair.rtcp}`,
    `a=rtpmap:${payloadType} opus/${codec.clockRate}/${channels}`,
    `a=fmtp:${payloadType} minptime=10;useinbandfec=1`,
    'a=recvonly',
    `a=ssrc:${ssrc} cname:ptt-${transmissionId}`,
    '',
  ].join('\n');
}

// Device names aren't tracked in this demo (no device-management subsystem),
// so diagnostics fall back to the bare deviceId — see describeState below.
async function lookupDeviceName(_userId, _deviceId) {
  return null;
}

// Finds the caller's live socket(s) for (userId, deviceId) the same way
// ptt.socket.js's health-probe path does — kept local rather than shared
// since this is the only other place recording diagnostics need it.
function socketsForDevice(io, connectedUsers, userId, deviceId) {
  const matches = [];
  if (!io || !connectedUsers) return matches;
  for (const [socketId, user] of connectedUsers.entries()) {
    if (String(user?.userId) !== String(userId)) continue;
    if (String(user?.deviceId || '') !== String(deviceId || '')) continue;
    const socket = io.sockets.sockets.get(socketId);
    if (socket?.connected) matches.push(socket);
  }
  return matches;
}

/**
 * Tags a recording-diagnostic log line with who/what it happened to, so a
 * network-vs-device question can actually be answered from the logs instead
 * of just a bare FFmpeg error with no identity attached.
 */
function describeState(state) {
  const parts = [`tx=${String(state.transmissionId || '').slice(0, 8)}`];
  parts.push(`user=${state.username || 'unknown'}`);
  parts.push(`device=${state.deviceName || 'unknown'}(${String(state.deviceId || '').slice(0, 8)})`);
  return parts.join(' ');
}

// Whether the socket looks alive right now, and for how long it's been up —
// a socket that reconnected seconds ago points at a network problem; one
// that's been stable for minutes points away from the network and toward
// the device/media path. Available immediately, no round trip, works even
// on app builds that predate the health-probe ack below.
function socketStateFor(io, connectedUsers, userId, deviceId) {
  const sockets = socketsForDevice(io, connectedUsers, userId, deviceId);
  if (sockets.length === 0) return 'no-live-socket';
  const issuedAt = sockets[0].handshake?.issued;
  if (!issuedAt) return 'connected(age unknown)';
  return `connected(${Math.round((Date.now() - issuedAt) / 1000)}s old)`;
}

// Real round-trip time to the device, measured at the moment of the error.
// Requires the client to have the 'ptt:health_probe' no-op-ack listener
// (added alongside this); older, not-yet-updated app builds simply won't
// ack in time and this reports that explicitly rather than guessing.
async function measurePingMs(io, connectedUsers, userId, deviceId, timeoutMs = 2000) {
  const sockets = socketsForDevice(io, connectedUsers, userId, deviceId);
  if (sockets.length === 0) return null;
  const startedAt = Date.now();
  try {
    await sockets[0].timeout(timeoutMs).emitWithAck('ptt:health_probe');
    return Date.now() - startedAt;
  } catch (_) {
    return -1;
  }
}

function formatPing(ms) {
  if (ms === null) return 'no live socket (device offline)';
  if (ms < 0) return 'connected but did not respond to probe (stalled or pre-update app build)';
  return `${ms}ms`;
}

function logRecordingDiagnostic(prefix, state, io, connectedUsers, line) {
  const tag = describeState(state);
  const socketState = socketStateFor(io, connectedUsers, state.userId, state.deviceId);
  console.warn(`[PTT Recording] ${tag} socket=${socketState} ${prefix}`, line);
  measurePingMs(io, connectedUsers, state.userId, state.deviceId)
    .then(ms => console.warn(`[PTT Recording] ${tag} ping=${formatPing(ms)}`))
    .catch(() => {});
}

function createPttRecorder({ mediaServer, io, connectedUsers }) {
  const active = new Map();
  const starting = new Map();
  const stopping = new Map();
  const completed = new Map();
  const enabled = isPttRecordingEnabled();
  const days = retentionDays();

  console.log(
    enabled
      ? `[PTT Recording] ENABLED (production, retention ${days} day(s), minimum > ${MIN_RETAINED_DURATION_MS}ms)`
      : '[PTT Recording] DISABLED (requires NODE_ENV=production and PTT_AUDIO_RECORDING_ENABLED=true; no PTT files will be created)',
  );

  async function startInternal({
    roomId, peerId, producerId, transmissionId, userId, username, deviceId,
  }) {
    if (!enabled) return { enabled: false };
    if (!/^[0-9a-f-]{36}$/i.test(String(transmissionId || ''))) {
      throw new Error('Invalid PTT transmission id');
    }
    if (active.has(transmissionId)) return { enabled: true, started: true };

    const room = mediaServer.rooms.get(roomId);
    const producer = room?.peers.get(peerId)?.producers.get(producerId);
    if (!room || !producer || producer.closed || producer.kind !== 'audio') {
      throw new Error('PTT audio producer is not available for recording');
    }

    // This is the first filesystem mutation in the PTT recorder and it is
    // reachable only after the exact production+opt-in gate above.
    fs.mkdirSync(PTT_RECORDINGS_DIR, { recursive: true });
    const portPair = allocatePortPair();
    const rawPath = path.join(PTT_RECORDINGS_DIR, `${transmissionId}.raw.mka.part`);
    const sdpPath = path.join(PTT_RECORDINGS_DIR, `${transmissionId}.sdp`);
    let transport = null;
    let consumer = null;
    let child = null;

    try {
      transport = await room.router.createPlainTransport({
        listenIp: { ip: '127.0.0.1', announcedIp: null },
        rtcpMux: false,
        comedia: false,
      });
      await transport.connect({ ip: '127.0.0.1', port: portPair.rtp, rtcpPort: portPair.rtcp });
      consumer = await transport.consume({
        producerId,
        rtpCapabilities: room.router.rtpCapabilities,
        paused: true,
        appData: { pttTransmissionId: transmissionId },
      });
      fs.writeFileSync(sdpPath, buildAudioSdp(consumer, portPair, transmissionId), { mode: 0o600 });

      const deviceName = await lookupDeviceName(userId, deviceId);

      child = spawn(
        'ffmpeg',
        buildRecorderArgs(sdpPath, rawPath),
        { stdio: ['pipe', 'ignore', 'pipe'] },
      );

      const state = {
        transmissionId, roomId, peerId, producerId,
        userId, username, deviceId, deviceName,
        producer, transport, consumer, child, portPair, rawPath, sdpPath,
        startedAt: null,
      };
      active.set(transmissionId, state);

      child.stderr.on('data', chunk => {
        const line = chunk.toString();
        if (/\b(error|invalid|failed)\b/i.test(line)) {
          logRecordingDiagnostic('FFmpeg:', state, io, connectedUsers, line.trim().slice(0, 300));
        }
      });
      child.on('error', error => {
        logRecordingDiagnostic('FFmpeg spawn error:', state, io, connectedUsers, error.message);
      });
      // FFmpeg cannot finish opening an RTP input until it sees packets. Resume
      // the mediasoup consumer first, while the readiness listeners are already
      // installed, so the first ~1.5 seconds of every press are not clipped by
      // the readiness timeout (which would make valid 4+ second clips vanish).
      const ready = waitForRecorderReady(child);
      await consumer.resume();
      state.startedAt = Date.now();
      await ready;
      if (child.exitCode !== null || child.signalCode) throw new Error('PTT recorder failed to remain running');
      consumer.once('producerclose', () => {
        // Diagnostic: recordings have been observed finalizing with real
        // content noticeably shorter than the actual floor hold (exact 5s/
        // 10s/15s multiples vs. a longer wall-clock press) — i.e. something
        // closes the underlying audio Producer well before the user actually
        // releases. This pins down whether it's this path firing early.
        const elapsedMs = state.startedAt ? Date.now() - state.startedAt : -1;
        console.log(`[PTT Recording] ${transmissionId}: producer closed after ${elapsedMs}ms — finalizing now`);
        stop(transmissionId).catch(error =>
          console.warn('[PTT Recording] Producer-close finalization failed:', error.message));
      });
      return { enabled: true, started: true };
    } catch (error) {
      active.delete(transmissionId);
      try { consumer?.close(); } catch (_) {}
      try { transport?.close(); } catch (_) {}
      try { await stopChild(child); } catch (_) {}
      releasePortPair(portPair);
      unlinkSafe(sdpPath);
      unlinkSafe(rawPath);
      throw error;
    }
  }

  function start(options) {
    if (!enabled) return Promise.resolve({ enabled: false });
    const transmissionId = options?.transmissionId;
    if (starting.has(transmissionId)) return starting.get(transmissionId);

    // Install the flight synchronously but defer every filesystem/mediasoup/
    // FFmpeg step. The caller can announce the live Producer immediately, and
    // stop() can still observe and await this flight if the press ends quickly.
    let promise;
    promise = Promise.resolve()
      .then(() => startInternal(options))
      .finally(() => {
        if (starting.get(transmissionId) === promise) starting.delete(transmissionId);
      });
    starting.set(transmissionId, promise);
    return promise;
  }

  async function finalize(transmissionId) {
    const state = active.get(transmissionId);
    if (!state) return null;
    active.delete(transmissionId);

    const finalPath = path.join(PTT_RECORDINGS_DIR, `${transmissionId}.m4a`);
    const finalPartPath = `${finalPath}.part`;
    const encryptedPath = `${finalPath}.enc`;
    try {
      // Floor release and socket disconnect can arrive immediately after the
      // final RTP packets. Keep the plain consumer alive briefly so mediasoup,
      // UDP and FFmpeg can drain those already-received packets before we ask
      // the muxer to write its trailer. Without this window, valid presses can
      // collapse into a header-only Matroska file under load.
      await delay(RECORDER_DRAIN_MS);
      try { state.consumer?.close(); } catch (_) {}
      try { state.transport?.close(); } catch (_) {}
      await stopChild(state.child);
      releasePortPair(state.portPair);
      unlinkSafe(state.sdpPath);

      if (!state.startedAt || !fs.existsSync(state.rawPath) || fs.statSync(state.rawPath).size < MIN_RAW_AUDIO_BYTES) {
        console.log(`[PTT Recording] ${transmissionId}: press too short to capture audio, discarding`);
        unlinkSafe(state.rawPath);
        return null;
      }

      const converted = await run('ffmpeg', [
        '-hide_banner', '-loglevel', 'error', '-y',
        '-i', state.rawPath, '-vn', '-c:a', 'aac', '-b:a', '96k',
        '-movflags', '+faststart', '-f', 'mp4', finalPartPath,
      ], 30_000);
      if (converted.code !== 0 || converted.timedOut || !fs.existsSync(finalPartPath) || fs.statSync(finalPartPath).size === 0) {
        throw new Error(`PTT audio finalization failed (${converted.code}): ${converted.stderr.slice(0, 240)}`);
      }
      const probe = await run('ffprobe', [
        '-v', 'error', '-show_entries', 'format=duration',
        '-of', 'default=noprint_wrappers=1:nokey=1', finalPartPath,
      ], 8_000);
      const durationMs = Math.round(Number.parseFloat(probe.stdout.trim()) * 1_000);
      // Strictly greater than two seconds, based on the successfully converted
      // final media artifact rather than the lease clock or client input.
      if (probe.code !== 0 || !isRetainableDuration(durationMs)) {
        unlinkSafe(state.rawPath);
        unlinkSafe(finalPartPath);
        return null;
      }
      fs.renameSync(finalPartPath, finalPath);
      const plainSize = fs.statSync(finalPath).size;

      let storedPath = finalPath;
      let encrypted = false;
      if (encryption.isInitialized()) {
        encryption.encryptFile(finalPath, encryptedPath);
        unlinkSafe(finalPath);
        storedPath = encryptedPath;
        encrypted = true;
      }
      const fileHash = hashFile(storedPath);
      unlinkSafe(state.rawPath);
      return {
        filePath: storedPath,
        durationMs,
        mimeType: 'audio/mp4',
        fileSize: plainSize,
        fileHash,
        encrypted,
        originalName: path.basename(finalPath),
      };
    } catch (error) {
      logRecordingDiagnostic('Finalization failed:', state, io, connectedUsers, error.message);
      unlinkSafe(state.rawPath);
      unlinkSafe(state.sdpPath);
      unlinkSafe(finalPartPath);
      unlinkSafe(finalPath);
      unlinkSafe(encryptedPath);
      return null;
    } finally {
      try { state.consumer?.close(); } catch (_) {}
      try { state.transport?.close(); } catch (_) {}
      releasePortPair(state.portPair);
    }
  }

  function stop(transmissionId) {
    if (!enabled) return Promise.resolve(null);
    // Transmission ids are unique, so an expired result will normally never
    // be requested again. Sweep the whole tiny TTL cache on every stop rather
    // than leaking one entry per broadcast for the lifetime of the process.
    pruneExpiredCompleted(completed);
    const startFlight = starting.get(transmissionId);
    if (startFlight) {
      return startFlight
        .catch(() => null)
        .then(() => stop(transmissionId));
    }
    const cached = completed.get(transmissionId);
    if (cached && cached.expiresAt > Date.now()) return Promise.resolve(cached.result);
    if (cached) completed.delete(transmissionId);
    if (stopping.has(transmissionId)) return stopping.get(transmissionId);
    // A release can beat recorder.start's first async setup step. Do not cache
    // that absence: if start subsequently installs state, the post-start floor
    // re-check will call stop again and must be able to finalize it.
    if (!active.has(transmissionId)) return Promise.resolve(null);
    const promise = finalize(transmissionId)
      .then(result => {
        completed.set(transmissionId, { result, expiresAt: Date.now() + 5 * 60_000 });
        return result;
      })
      .finally(() => stopping.delete(transmissionId));
    stopping.set(transmissionId, promise);
    return promise;
  }

  function discard(audio) {
    if (audio?.filePath) unlinkSafe(audio.filePath);
  }

  async function prune() {
    if (!enabled) return;
    fs.mkdirSync(PTT_RECORDINGS_DIR, { recursive: true });
    const { rows: expired } = await db.query(
      `SELECT id, audio_file_path
       FROM ptt_transmissions
       WHERE audio_file_path IS NOT NULL
         AND NOT pinned
         AND audio_recorded_at < NOW() - ($1::text || ' days')::interval`,
      [days],
    );
    for (const row of expired) unlinkSafe(row.audio_file_path);
    if (expired.length) {
      await db.query(
        `UPDATE ptt_transmissions
         SET audio_file_path = NULL, audio_duration_ms = NULL,
             audio_mime_type = NULL, audio_file_size = NULL,
             audio_file_hash = NULL, audio_encrypted = FALSE,
             audio_original_name = NULL, audio_recorded_at = NULL
         WHERE id = ANY($1::uuid[])`,
        [expired.map(row => row.id)],
      );
    }

    const { rows: retained } = await db.query(
      'SELECT audio_file_path FROM ptt_transmissions WHERE audio_file_path IS NOT NULL',
    );
    const retainedPaths = new Set(retained.map(row => safePttPath(row.audio_file_path)).filter(Boolean));
    const now = Date.now();
    for (const name of fs.readdirSync(PTT_RECORDINGS_DIR)) {
      const candidate = safePttPath(path.join(PTT_RECORDINGS_DIR, name));
      if (!candidate || !fs.statSync(candidate).isFile()) continue;
      const age = now - fs.statSync(candidate).mtimeMs;
      const isTemp = name.endsWith('.part') || name.endsWith('.sdp') || name.includes('.raw.');
      if ((isTemp && age > 60 * 60 * 1_000) || (!isTemp && age > 24 * 60 * 60 * 1_000 && !retainedPaths.has(candidate))) {
        unlinkSafe(candidate);
      }
    }
  }

  function scheduleMaintenance() {
    if (!enabled) return;
    const runPrune = () => prune().catch(error =>
      console.warn('[PTT Recording] Retention cleanup failed:', error.message));
    const first = setTimeout(runPrune, 30_000);
    first.unref?.();
    const interval = setInterval(runPrune, 6 * 60 * 60 * 1_000);
    interval.unref?.();
  }

  scheduleMaintenance();
  return { enabled, start, stop, discard, prune };
}

module.exports = {
  createPttRecorder,
  isPttRecordingEnabled,
  retentionDays,
  isRetainableDuration,
  safePttPath,
  PTT_RECORDINGS_DIR,
  MIN_RETAINED_DURATION_MS,
  MIN_RAW_AUDIO_BYTES,
  RECORDER_DRAIN_MS,
  MATROSKA_CLUSTER_MS,
  buildRecorderArgs,
  stopChild,
  pruneExpiredCompleted,
};

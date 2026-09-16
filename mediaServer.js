/**
 * Mediasoup Media Server Configuration
 * Handles WebRTC media routing and recording
 */

const mediasoup = require('mediasoup');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

// Ensure recordings directory exists
const RECORDINGS_DIR = path.join(__dirname, 'recordings');
if (!fs.existsSync(RECORDINGS_DIR)) {
  fs.mkdirSync(RECORDINGS_DIR, { recursive: true });
}

// ── Global FFmpeg recording port allocator ───────────────────────────────
// Each recording stream needs a dedicated UDP RTP/RTCP port pair for FFmpeg.
// Previously each call's recording kept its OWN reservedPorts Set, so two
// calls recording at the same time could independently pick the same pair
// and FFmpeg would fail to bind (port collision). This registry reserves
// ports across the WHOLE process so concurrent calls never overlap.
const RECORDING_PORT_MIN = 20000;            // even RTP base
const RECORDING_PORT_SPAN = 4500;            // pairs available (RTCP = RTP+1)
const _globalReservedPorts = new Set();

function allocateRecordingPortPair() {
  for (let attempt = 0; attempt < 5000; attempt++) {
    const rtp = RECORDING_PORT_MIN + Math.floor(Math.random() * RECORDING_PORT_SPAN) * 2;
    const rtcp = rtp + 1;
    if (_globalReservedPorts.has(rtp) || _globalReservedPorts.has(rtcp)) continue;
    _globalReservedPorts.add(rtp);
    _globalReservedPorts.add(rtcp);
    return { rtp, rtcp };
  }
  throw new Error('[Recording] No free FFmpeg port pair available (registry exhausted)');
}

function releaseRecordingPortPair(rtp, rtcp) {
  if (rtp != null) _globalReservedPorts.delete(rtp);
  if (rtcp != null) _globalReservedPorts.delete(rtcp);
}

// Recording combine optimization flags (CPU control)
// Hard-disabled for now to avoid expensive multi-pass ffmpeg processing.
const ENABLE_VIDEO_TIMELINE_STITCHING = false;
const ENABLE_AVATAR_OVERLAY = false;
const USE_HW_VIDEO_ENCODER = process.platform === 'darwin';
const USE_NORMALIZED_CONCAT_COMBINE = String(process.env.RECORDING_COMBINE_NORMALIZED || 'false').toLowerCase() === 'true';
const USE_CLIENT_TIMELINE_METADATA = String(process.env.RECORDING_USE_CLIENT_TIMELINE || 'true').toLowerCase() === 'true';
const WRITE_COMBINE_DEBUG_ARTIFACT = String(process.env.RECORDING_WRITE_COMBINE_DEBUG || 'false').toLowerCase() === 'true';
const VERBOSE_MEDIA_LOGS = String(process.env.VERBOSE_MEDIA_LOGS || 'false').toLowerCase() === 'true';
const VERBOSE_RECORDING_LOGS = String(process.env.RECORDING_VERBOSE_LOGS || 'false').toLowerCase() === 'true';

const mediaVLog = (...args) => {
  if (VERBOSE_MEDIA_LOGS) console.log(...args);
};

const recordingVLog = (...args) => {
  if (VERBOSE_RECORDING_LOGS) console.log(...args);
};

// PTT has a dedicated, per-transmission recorder. It must never enter the
// generic call recorder, especially now that one PTT shard can contain many
// simultaneous logical channels.
const isPttMediaRoom = roomId => typeof roomId === 'string' &&
  (roomId.startsWith('ptt:') || roomId.startsWith('ptt-shard:'));

// Mediasoup configuration
const config = {
  // Worker settings
  worker: {
    rtcMinPort: 10000,
    rtcMaxPort: 10500,
    logLevel: 'warn',
    logTags: ['info', 'ice', 'dtls', 'rtp', 'srtp', 'rtcp'],
  },
  // Router settings (media codecs)
  router: {
    mediaCodecs: [
      {
        kind: 'audio',
        mimeType: 'audio/opus',
        clockRate: 48000,
        channels: 2,
      },
      {
        kind: 'video',
        mimeType: 'video/VP8',
        clockRate: 90000,
        parameters: {
          // Start low so GCC bandwidth estimation ramps up gracefully.
          'x-google-start-bitrate': 1000,
        },
      },
      {
        kind: 'video',
        mimeType: 'video/H264',
        clockRate: 90000,
        parameters: {
          'packetization-mode': 1,
          // Constrained Baseline level 4.2 — supports 1080p up to 60fps. The old
          // 42e01f (level 3.1) capped the encoder at 720p. Same profile as most
          // mobile encoders advertise, and level-asymmetry-allowed lets each
          // direction pick its own level, so negotiation stays compatible.
          'profile-level-id': '42e02a',
          'level-asymmetry-allowed': 1,
        },
      },
    ],
  },
  // WebRTC transport settings
  webRtcTransport: {
    listenIps: [
      {
        ip: '0.0.0.0',
        announcedIp: null, // Will be set dynamically
      },
    ],
    maxIncomingBitrate: 0,               // 0 = unlimited — let BWE manage it
    initialAvailableOutgoingBitrate: 10000000,  // 10 Mbps — ramp up faster
    enableUdp: true,
    enableTcp: true,
    preferUdp: true,
  },
  // Plain transport for recording (RTP to FFmpeg)
  plainTransport: {
    listenIp: { ip: '127.0.0.1', announcedIp: null },
    rtcpMux: false,
    comedia: false,
  },
};

class MediaServer extends EventEmitter {
  constructor() {
    super();
    this.workers = [];
    this.nextWorkerIndex = 0;
    this.rooms = new Map(); // roomId -> Room
    // roomId -> Promise<Room>. Router creation is asynchronous; without a
    // single-flight, simultaneous Radio restores can create two routers for
    // the same shard and strand every peer attached to the losing instance.
    this.roomCreationFlights = new Map();
    this.peers = new Map(); // peerId -> Peer
    // socketId -> Set<peerId>. A single socket used to own exactly one peerId
    // (peerId === socket.id everywhere). PTT multi-channel listening broke
    // that: one socket can now hold several peers at once (one per joined
    // channel, keyed by a synthetic id), so cleanup and cross-peer ownership
    // checks need a way to enumerate them. See getPeerIdsForSocket().
    this.socketPeers = new Map();
  }

  /**
   * Async process runner to avoid blocking the Node.js event loop.
   */
  runCommand(command, args, { timeout = 0, cwd } = {}) {
    return new Promise((resolve, reject) => {
      const proc = spawn(command, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd,
      });

      const stdoutChunks = [];
      const stderrChunks = [];
      let timedOut = false;
      let timer = null;

      if (timeout > 0) {
        timer = setTimeout(() => {
          timedOut = true;
          try { proc.kill('SIGKILL'); } catch (_) {}
        }, timeout);
      }

      proc.stdout.on('data', d => stdoutChunks.push(d));
      proc.stderr.on('data', d => stderrChunks.push(d));
      proc.on('error', reject);
      proc.on('close', (code) => {
        if (timer) clearTimeout(timer);
        resolve({
          status: code,
          stdout: Buffer.concat(stdoutChunks).toString(),
          stderr: Buffer.concat(stderrChunks).toString(),
          timedOut,
        });
      });
    });
  }

  /**
   * Check available disk space for recordings directory.
   */
  async hasSufficientRecordingDiskSpace(minBytes = 500 * 1024 * 1024) {
    try {
      const result = await this.runCommand('df', ['-k', RECORDINGS_DIR], { timeout: 3000 });
      const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
      if (lines.length < 2) return true;
      const cols = lines[lines.length - 1].trim().split(/\s+/);
      // POSIX df -k: Filesystem 1024-blocks Used Available Capacity Mounted on
      const availableKb = Number(cols[3]);
      if (!Number.isFinite(availableKb)) return true;
      const availableBytes = availableKb * 1024;
      return availableBytes >= minBytes;
    } catch (_) {
      // Fail-open: do not block recording if df parsing fails.
      return true;
    }
  }

  /**
   * Initialize Mediasoup workers
   */
  async init() {
    const numWorkers = require('os').cpus().length;
    console.log(`[MediaServer] Creating ${numWorkers} workers...`);

    for (let i = 0; i < numWorkers; i++) {
      const worker = await mediasoup.createWorker({
        logLevel: config.worker.logLevel,
        logTags: config.worker.logTags,
        rtcMinPort: config.worker.rtcMinPort,
        rtcMaxPort: config.worker.rtcMaxPort,
      });

      worker.on('died', () => {
        console.error(`[MediaServer] Worker ${i} died, exiting...`);
        setTimeout(() => process.exit(1), 2000);
      });

      this.workers.push(worker);
      console.log(`  Worker ${i} created (PID: ${worker.pid})`);
    }

    console.log('[MediaServer] Initialized successfully');
  }

  /**
   * Close all workers gracefully
   */
  async close() {
    console.log(`[MediaServer] Closing ${this.workers.length} workers...`);
    for (const worker of this.workers) {
      try {
        worker.close();
      } catch (e) {
        // ignore
      }
    }
    this.workers = [];
    console.log('[MediaServer] All workers closed');
  }

  /**
   * Get next worker (round-robin)
   */
  getNextWorker() {
    const worker = this.workers[this.nextWorkerIndex];
    this.nextWorkerIndex = (this.nextWorkerIndex + 1) % this.workers.length;
    return worker;
  }

  /**
   * Create or get a room
   */
  async getOrCreateRoom(roomId, announcedIp) {
    const current = this.rooms.get(roomId);
    if (current && !current.router.closed) return current;
    if (current?.router.closed) this.rooms.delete(roomId);
    const existingFlight = this.roomCreationFlights.get(roomId);
    if (existingFlight) return existingFlight;

    let creation;
    creation = (async () => {
      // Recheck inside the flight in case a canonical room was installed just
      // before this task began.
      const existing = this.rooms.get(roomId);
      if (existing && !existing.router.closed) return existing;

      const worker = this.getNextWorker();
      const router = await worker.createRouter({
        mediaCodecs: config.router.mediaCodecs,
      });

      // Active-speaker detection: mediasoup reads the standard WebRTC
      // ssrc-audio-level RTP header extension that every browser/react-native-webrtc
      // sender already includes, so no client-side change is needed to produce it.
      // threshold/interval mirror what Zoom/Meet feel like in practice — -60dBvo
      // catches normal speech without lighting up on keyboard/breathing noise,
      // 300ms is fast enough to feel live without emitting on every voice pause.
      // Closed automatically when the router closes (mediasoup closes every
      // RtpObserver it owns), so there is no separate teardown to do here.
      let audioLevelObserver;
      try {
        audioLevelObserver = await router.createAudioLevelObserver({
          maxEntries: 1,
          threshold: -60,
          interval: 300,
        });
      } catch (error) {
        try { router.close(); } catch (_) {}
        throw error;
      }

      const room = {
        id: roomId,
        router,
        audioLevelObserver,
        peers: new Map(),
        recording: null,
        createdAt: Date.now(),
      };

      audioLevelObserver.on('volumes', (volumes) => {
        const entry = volumes[0];
        const peerId = entry?.producer?.appData?.peerId;
        const peer = peerId ? room.peers.get(peerId) : null;
        if (!peer) return;
        this.emit('active_speaker', {
          roomId,
          peerId,
          userId: peer.userId,
          username: peer.username,
          volume: entry.volume,
        });
      });
      audioLevelObserver.on('silence', () => {
        this.emit('active_speaker', { roomId, peerId: null, userId: null, username: null, volume: null });
      });

      this.rooms.set(roomId, room);
      mediaVLog(`[MediaServer] Room created: ${roomId}`);
      return room;
    })().finally(() => {
      if (this.roomCreationFlights.get(roomId) === creation) {
        this.roomCreationFlights.delete(roomId);
      }
    });
    this.roomCreationFlights.set(roomId, creation);
    return creation;
  }

  /**
   * Create WebRTC transport for a peer
   */
  async createWebRtcTransport(roomId, peerId, announcedIp) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const transportOptions = {
      ...config.webRtcTransport,
      listenIps: [
        {
          ip: '0.0.0.0',
          announcedIp: announcedIp || this.getLocalIp(),
        },
      ],
    };

    const transport = await room.router.createWebRtcTransport(transportOptions);

    transport.on('dtlsstatechange', (dtlsState) => {
      if (dtlsState === 'closed') {
        transport.close();
      }
    });

    transport.on('close', () => {
      mediaVLog(`[MediaServer] Transport closed for peer ${peerId}`);
    });

    return {
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dtlsParameters,
      transport,
    };
  }

  /**
   * Connect transport (DTLS handshake)
   */
  async connectTransport(roomId, transportId, dtlsParameters) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    // Find transport in all peers
    for (const [peerId, peer] of room.peers) {
      if (peer.sendTransport?.id === transportId) {
        await peer.sendTransport.connect({ dtlsParameters });
        return;
      }
      if (peer.recvTransport?.id === transportId) {
        await peer.recvTransport.connect({ dtlsParameters });
        return;
      }
    }

    throw new Error(`Transport ${transportId} not found`);
  }

  /** Connect only a transport owned by the named peer. Dedicated PTT
   * signalling uses this instead of the legacy room-wide transport scan. */
  async connectPeerTransport(roomId, peerId, transportId, dtlsParameters) {
    const peer = this.rooms.get(roomId)?.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);
    const transport = [peer.sendTransport, peer.recvTransport]
      .find(candidate => candidate?.id === transportId);
    if (!transport) throw new Error(`Transport ${transportId} is not owned by this peer`);
    await transport.connect({ dtlsParameters });
  }

  getPeerTransport(roomId, peerId, direction) {
    const peer = this.rooms.get(roomId)?.peers.get(peerId);
    return direction === 'send' ? peer?.sendTransport || null : peer?.recvTransport || null;
  }

  /**
   * Create a producer (send media to server)
   * AUTO-RECORDING: Starts recording automatically when call is established
   */
  async produce(roomId, peerId, transportId, kind, rtpParameters, appData = {}) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const peer = room.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);
    if (!peer.sendTransport || peer.sendTransport.id !== transportId) {
      throw new Error('Send transport is not owned by this peer');
    }

    const producer = await peer.sendTransport.produce({
      kind,
      rtpParameters,
      appData: { ...appData, peerId },
    });

    producer.on('transportclose', () => {
      producer.close();
    });

    peer.producers.set(producer.id, producer);
    mediaVLog(`[MediaServer] Producer created: ${kind} from ${peerId}`);

    if (kind === 'audio' && room.audioLevelObserver) {
      // No matching removeProducer call needed — mediasoup's RtpObserver drops
      // a producer automatically when that producer closes.
      room.audioLevelObserver.addProducer({ producerId: producer.id }).catch((err) => {
        console.error(`[MediaServer] audioLevelObserver.addProducer failed for ${peerId}:`, err.message);
      });
    }

    // Always log the negotiated VIDEO codec so the live encoder path is visible
    // in production logs (H.264 = hardware single-stream; VP8 = software
    // simulcast). encodings count: 1 = single H.264 stream, 3 = VP8 simulcast.
    if (kind === 'video') {
      const c = producer.rtpParameters?.codecs?.[0] || {};
      const nEnc = (producer.rtpParameters?.encodings || []).length;
      console.log(
        `[MediaServer] 🎥 Video producer from ${peerId} → codec=${c.mimeType || '?'} ` +
        `pt=${c.payloadType ?? '?'} encodings=${nEnc}` +
        (c.parameters && c.parameters['profile-level-id'] ? ` profile-level-id=${c.parameters['profile-level-id']}` : ''),
      );
    }

    // Snapshot recording state BEFORE firing checkAndStartAutoRecording.
    // This is critical: checkAndStartAutoRecording is fire-and-forget, but
    // its async body runs SYNCHRONOUSLY until the first `await` inside
    // startRecording — which sets room.recording before yielding.  If we
    // check room.recording AFTER the fire-and-forget call, it may already
    // be non-null even though startRecording hasn't finished processing all
    // existing producers yet — leading to addProducerToRecording duplicating
    // a producer that startRecording's for-loop will also pick up.
    const wasAlreadyRecording = !isPttMediaRoom(roomId) && !!room.recording;

    // AUTO-RECORDING: Fire-and-forget — do NOT await so that produce()
    // returns immediately and the call connects faster for the client.
    if (!isPttMediaRoom(roomId)) {
      this.checkAndStartAutoRecording(roomId).catch(err =>
        console.error(`[Recording] Auto-start error for room ${roomId}:`, err.message),
      );
    }

    // Only add to an EXISTING recording — not one that was just kicked off
    // by checkAndStartAutoRecording above (that one's for-loop already
    // iterates all current producers including this one).
    if (wasAlreadyRecording) {
      const rec = room.recording;
      if (rec?.initializing) {
        if (!(rec.queuedLateProducers instanceof Map)) {
          rec.queuedLateProducers = new Map();
        }
        if (!rec.queuedLateProducers.has(producer.id)) {
          rec.queuedLateProducers.set(producer.id, { producer, peerId });
        }
        recordingVLog(`  [Recording] Queued late producer ${producer.kind} from ${peerId} while recorder initializes`);
      } else {
        this.addProducerToRecording(room, producer, peerId).catch(err =>
          console.error(`[Recording] Add-producer error for room ${roomId}:`, err.message),
        );
      }
    }

    return { id: producer.id, producerId: producer.id };
  }

  /**
   * Check if we should auto-start recording.
   * Starts immediately when 2+ peers have producers (no debounce).
   */
  async checkAndStartAutoRecording(roomId) {
    if (isPttMediaRoom(roomId)) return;
    const room = this.rooms.get(roomId);
    if (!room) return;

    // Already recording — nothing to do
    if (room.recording) return;

    // Count peers with at least one producer
    let peersWithProducers = 0;
    for (const [, peer] of room.peers) {
      if (peer.producers.size > 0) {
        peersWithProducers++;
      }
    }

    if (peersWithProducers >= 2) {
      console.log(`[Recording] Call established in room ${roomId} — starting recording immediately`);
      try {
        await this.startRecording(roomId);
      } catch (err) {
        console.error(`[Recording] Auto-start error for room ${roomId}:`, err.message);
      }
    }
  }

  /**
   * Create a consumer (receive media from server)
   * IMPORTANT: Prevents users from consuming their own media (no echo)
   */
  async consume(roomId, peerId, producerId) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const peer = room.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);

    // Find the producer and its owner
    let producer = null;
    let producerOwnerId = null;
    for (const [ownerId, p] of room.peers) {
      if (p.producers.has(producerId)) {
        producer = p.producers.get(producerId);
        producerOwnerId = ownerId;
        break;
      }
    }

    if (!producer) throw new Error(`Producer ${producerId} not found`);

    // PREVENT ECHO: Don't let a user consume their own producer
    if (producerOwnerId === peerId) {
      console.log(`[MediaServer] Preventing ${peerId} from consuming own ${producer.kind}`);
      throw new Error('Cannot consume own producer');
    }

    // Check if router can consume
    if (!room.router.canConsume({ producerId, rtpCapabilities: peer.rtpCapabilities })) {
      throw new Error('Cannot consume this producer');
    }

    if (!peer.recvTransport) throw new Error('Receive transport not created');
    const consumer = await peer.recvTransport.consume({
      producerId,
      rtpCapabilities: peer.rtpCapabilities,
      paused: true, // Start paused, resume after client is ready
      appData: {
        pttChannelId: producer.appData?.pttChannelId || null,
        pttTransmissionId: producer.appData?.pttTransmissionId || null,
      },
    });

    consumer.on('transportclose', () => {
      consumer.close();
      peer.consumers.delete(consumer.id);
    });

    consumer.on('producerclose', () => {
      consumer.close();
      peer.consumers.delete(consumer.id);
      // Tell the consuming client too. Without this the server quietly drops
      // its side while the client keeps a closed consumer and, worse, keeps
      // the dead track in its remote stream — so the peer's video renders the
      // last frame forever after their producer goes away (e.g. a reconnect
      // replacing it with a fresh producer). `close_producer` only covers the
      // explicit screen-share path; camera/mic producers die through here.
      this.emit('producer_closed', {
        roomId,
        peerId,
        producerId,
        producerPeerId: producerOwnerId,
        kind: consumer.kind,
        appData: producer.appData || {},
      });
    });

    peer.consumers.set(consumer.id, consumer);

    // For simulcast video producers, request the highest spatial layer.
    // The SFU will automatically downgrade the layer if the consumer's
    // available bandwidth drops — fully adaptive without any extra signalling.
    if (consumer.kind === 'video') {
      try {
        await consumer.setPreferredLayers({ spatialLayer: 2, temporalLayer: 2 });
      } catch {
        // Not a simulcast consumer (e.g. screen-share) — harmless.
      }
    }

    return {
      id: consumer.id,
      producerId,
      kind: consumer.kind,
      rtpParameters: consumer.rtpParameters,
      producerPaused: !!producer.paused,
      appData: producer.appData,
    };
  }

  closeProducer(roomId, peerId, producerId) {
    const peer = this.rooms.get(roomId)?.peers.get(peerId);
    const producer = peer?.producers.get(producerId);
    if (!peer || !producer) return null;
    const result = {appData: producer.appData || {}, kind: producer.kind};
    producer.close();
    peer.producers.delete(producerId);
    return result;
  }

  getProducerInfo(roomId, producerId) {
    const room = this.rooms.get(roomId);
    if (!room) return null;
    for (const [peerId, peer] of room.peers) {
      const producer = peer.producers.get(producerId);
      if (producer && !producer.closed) {
        return {
          producer,
          producerId,
          peerId,
          userId: peer.userId,
          username: peer.username,
          kind: producer.kind,
          paused: !!producer.paused,
          appData: producer.appData || {},
        };
      }
    }
    return null;
  }

  closeConsumersForPttChannel(roomId, peerId, channelId) {
    const peer = this.rooms.get(roomId)?.peers.get(peerId);
    if (!peer) return 0;
    let closed = 0;
    for (const [consumerId, consumer] of peer.consumers) {
      if (String(consumer.appData?.pttChannelId || '') !== String(channelId)) continue;
      try { consumer.close(); } catch (_) {}
      peer.consumers.delete(consumerId);
      closed++;
    }
    return closed;
  }

  /**
   * Check for an active producer source. Passing peerId limits the lookup to
   * that peer; null checks the whole room (used to enforce one presentation).
   */
  hasProducerSource(roomId, source, peerId = null) {
    const room = this.rooms.get(roomId);
    if (!room) return false;
    for (const [candidatePeerId, peer] of room.peers) {
      if (peerId && candidatePeerId !== peerId) continue;
      for (const [, producer] of peer.producers) {
        const producerSource = producer.appData?.source ||
          (producer.kind === 'audio' ? 'microphone' : 'camera');
        if (!producer.closed && producerSource === source) return true;
      }
    }
    return false;
  }

  /**
   * Pause or resume the authoritative server-side producer for one media
   * source. Clients also pause their local Producer, but that state is not
   * automatically reflected on mediasoup's server Producer; keeping both in
   * sync makes late-join roster state and bandwidth usage accurate.
   */
  async setProducerSourcePaused(roomId, peerId, source, paused) {
    const peer = this.rooms.get(roomId)?.peers.get(peerId);
    if (!peer) return false;

    for (const [, producer] of peer.producers) {
      const producerSource = producer.appData?.source ||
        (producer.kind === 'audio' ? 'microphone' : 'camera');
      if (producer.closed || producerSource !== source) continue;
      if (paused && !producer.paused) await producer.pause();
      if (!paused && producer.paused) await producer.resume();
      return true;
    }

    return false;
  }

  /**
   * Resume consumer
   */
  async resumeConsumer(roomId, peerId, consumerId) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const peer = room.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);

    const consumer = peer.consumers.get(consumerId);
    if (!consumer) throw new Error(`Consumer ${consumerId} not found`);

    await consumer.resume();
  }

  /**
   * Request keyframes on all consumers that are receiving video from a
   * specific peer's producer. Called after a camera switch so the remote
   * decoder gets a fresh I-frame from the new camera immediately.
   *
   * Iterates every OTHER peer in the room, checks their consumers for
   * ones backed by our peer's video producer, and fires requestKeyFrame().
   * Also refreshes recording consumers for the same producer.
   */
  async requestKeyFramesForPeer(roomId, producerPeerId) {
    const room = this.rooms.get(roomId);
    if (!room) return;

    const producerPeer = room.peers.get(producerPeerId);
    if (!producerPeer) return;

    // Collect this peer's video producer IDs
    const videoProducerIds = new Set();
    for (const [id, producer] of producerPeer.producers) {
      if (producer.kind === 'video') videoProducerIds.add(id);
    }
    if (videoProducerIds.size === 0) return;

    let requested = 0;

    // Request keyframes on all remote peers' consumers fed by our producer
    for (const [peerId, peer] of room.peers) {
      if (peerId === producerPeerId) continue;
      for (const [, consumer] of peer.consumers) {
        if (consumer.kind === 'video' && videoProducerIds.has(consumer.producerId) && !consumer.closed) {
          try {
            await consumer.requestKeyFrame();
            requested++;
          } catch (_) { /* consumer may have just closed */ }
        }
      }
    }

    // Also request keyframes on recording consumers for this producer
    if (room.recording) {
      for (const input of (room.recording.consumers || [])) {
        if (input.kind === 'video' && videoProducerIds.has(input.consumer?.producerId) && !input.consumer?.closed) {
          try {
            await input.consumer.requestKeyFrame();
            requested++;
          } catch (_) {}
        }
      }
      // Recording inputs may be in the .inputs array instead
      for (const input of (room.recording.inputs || [])) {
        if (input.kind === 'video' && input.peerId === producerPeerId && input.consumer && !input.consumer.closed) {
          try {
            await input.consumer.requestKeyFrame();
            requested++;
          } catch (_) {}
        }
      }
    }

    // Follow-up burst — mobile encoders can be slow to respond to PLI
    if (requested > 0) {
      console.log(`[Media] Requested ${requested} keyframe(s) after camera switch by ${producerPeerId}`);
      for (let burst = 0; burst < 2; burst++) {
        await new Promise(resolve => setTimeout(resolve, 300));
        for (const [peerId, peer] of room.peers) {
          if (peerId === producerPeerId) continue;
          for (const [, consumer] of peer.consumers) {
            if (consumer.kind === 'video' && videoProducerIds.has(consumer.producerId) && !consumer.closed) {
              try { await consumer.requestKeyFrame(); } catch (_) {}
            }
          }
        }
      }
    }
  }

  /**
   * Update the orientation of a peer's live camera producer and timestamp it
   * on the active recording. Camera switching uses replaceTrack(), so no new
   * server Producer is created and appData would otherwise remain stale for
   * the rest of the call.
   */
  updateCameraOrientation(roomId, peerId, rawRotation) {
    const rotation = Number(rawRotation);
    if (![0, 90, 180, 270].includes(rotation)) return false;

    const room = this.rooms.get(roomId);
    const peer = room?.peers.get(peerId);
    if (!room || !peer) return false;

    const cameraProducerIds = new Set();
    for (const [producerId, producer] of peer.producers) {
      const source = producer.appData?.source ||
        (producer.kind === 'video' ? 'camera' : 'microphone');
      if (producer.closed || producer.kind !== 'video' || source !== 'camera') continue;
      producer.appData.rotation = rotation;
      cameraProducerIds.add(producerId);
    }

    const recording = room.recording;
    if (!recording || cameraProducerIds.size === 0) return cameraProducerIds.size > 0;

    const atMs = Math.max(0, Date.now() - recording.startTime);
    for (const input of recording.inputs || []) {
      const isMatchingCamera = input.kind === 'video' &&
        (input.source || 'camera') === 'camera' &&
        input.peerId === peerId &&
        input.endOffsetMs === null &&
        (!input.producerId || cameraProducerIds.has(input.producerId));
      if (!isMatchingCamera) continue;

      const events = Array.isArray(input.rotationEvents)
        ? input.rotationEvents
        : (input.rotationEvents = []);
      const previous = events.length > 0
        ? events[events.length - 1].rotation
        : input.rotation;
      if (Number(previous) === rotation) continue;
      events.push({ atMs, rotation });
      console.log(`  [Recording] Camera rotation for ${peerId}: ${rotation}° at ${atMs}ms`);
    }
    return true;
  }

  /**
   * Start recording a room.
   * Saves individual per-producer streams with timeline metadata
   * (startOffsetMs / endOffsetMs) so the combine phase can align
   * and fill gaps with user avatars.
   */
  async startRecording(roomId) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    if (room.recording) {
      console.log(`[Recording] Already in progress for room ${roomId}`);
      return room.recording;
    }

    const hasDisk = await this.hasSufficientRecordingDiskSpace();
    if (!hasDisk) {
      console.warn(`[Recording] Skipping start for room ${roomId}: low disk space in recordings directory`);
      return null;
    }

    const timestamp = Date.now();
    const recordingId = `${roomId}_${timestamp}`;
    
    // Determine if this is a video call (any peer has video producer)
    let hasVideo = false;
    for (const [, peer] of room.peers) {
      for (const [, producer] of peer.producers) {
        if (producer.kind === 'video') {
          hasVideo = true;
          break;
        }
      }
      if (hasVideo) break;
    }

    const outputFile = path.join(RECORDINGS_DIR, `${recordingId}.${hasVideo ? 'mp4' : 'mp3'}`);

    room.recording = {
      id: recordingId,
      startTime: timestamp,
      outputFile,
      hasVideo,
      stopped: false,
      reservedPorts: new Set(),
      initializing: true,
      queuedLateProducers: new Map(),
      ffmpegProcesses: [],  // one per stream
      tempFiles: [],         // individual stream files
      sdpFiles: [],          // individual .sdp files per stream
      transports: [],
      consumers: [],
      inputs: [],            // each input: { ..., startOffsetMs, endOffsetMs, peerId, username, profilePicture }
      peerMeta: new Map(),   // peerId -> { username, profilePicture }
      clientTimelineReports: new Map(), // stableIdentity(userId|peerId) -> [report]
      nextStreamIdx: { audio: 0, video: 0 },
    };

    // Collect peer metadata
    for (const [peerId, peer] of room.peers) {
      room.recording.peerMeta.set(peerId, {
        username: peer.username,
        userId: peer.userId,
        profilePicture: peer.profilePicture,
      });
    }

    // Collect all producers and create recording consumers
    for (const [peerId, peer] of room.peers) {
      for (const [producerId, producer] of peer.producers) {
        const input = await this.createRecordingInput(room, producer, peerId);
        if (input) {
          input.isInitialStream = true;
        }
      }
    }

    // Start individual FFmpeg processes (one per stream, codec copy)
    await this.startIndividualRecordings(room);

    // Startup ready: drain any producers that arrived while we were initializing.
    room.recording.initializing = false;
    const queued = Array.from(room.recording.queuedLateProducers?.values() || []);
    room.recording.queuedLateProducers = new Map();
    for (const item of queued) {
      if (!item?.producer || item.producer.closed) continue;
      await this.addProducerToRecording(room, item.producer, item.peerId);
    }

    console.log(`[Recording] Started for room ${roomId} -> ${outputFile}`);
    return room.recording;
  }

  /**
   * Create a recording input for a producer.
   * Allocates a dedicated FFmpeg port pair (RTP + RTCP) and tells
   * the PlainTransport to send RTP there.
   *
   * Timeline: stores `startOffsetMs` = now - recording.startTime.
   * `endOffsetMs` is set when the producer closes or the recording stops.
   */
  async createRecordingInput(room, producer, peerId) {
    let ffmpegRtpPort = null;
    let ffmpegRtcpPort = null;
    let portsReserved = false;

    try {
      const recording = room.recording;

      // Race guard: same producer can be observed by initial bootstrap loop and
      // late-producer path concurrently. Reuse existing input if already present.
      const existingInput = (recording.inputs || []).find(
        (inp) => inp?.consumer?.producerId === producer.id
      );
      if (existingInput) {
        recordingVLog(`  [Recording] Reusing existing input for producer ${producer.id} (${producer.kind} from ${peerId})`);
        return existingInput;
      }

      // Pick an even port for FFmpeg RTP, odd for RTCP — reserved PROCESS-WIDE.
      // Reserve synchronously before the first await to avoid concurrent
      // late-producer collisions in group calls AND collisions between
      // simultaneous calls (the global registry guarantees uniqueness).
      if (!(recording.reservedPorts instanceof Set)) {
        recording.reservedPorts = new Set();
      }
      const _portPair = allocateRecordingPortPair();
      ffmpegRtpPort = _portPair.rtp;
      ffmpegRtcpPort = _portPair.rtcp;
      recording.reservedPorts.add(ffmpegRtpPort);
      recording.reservedPorts.add(ffmpegRtcpPort);
      portsReserved = true;

      // Create plain transport — mediasoup picks its own ports
      const transport = await room.router.createPlainTransport({
        listenIp: { ip: '127.0.0.1', announcedIp: null },
        rtcpMux: false,   // separate RTP and RTCP ports
        comedia: false,   // we will manually connect to FFmpeg ports
      });

      // Tell the transport to send RTP/RTCP TO FFmpeg's ports
      await transport.connect({
        ip: '127.0.0.1',
        port: ffmpegRtpPort,
        rtcpPort: ffmpegRtcpPort,
      });

      // Create consumer on the plain transport
      const consumer = await transport.consume({
        producerId: producer.id,
        rtpCapabilities: room.router.rtpCapabilities,
        paused: true, // Will resume AFTER FFmpeg binds to the ports
      });

      // For simulcast video producers, request the HIGHEST spatial layer
      // so the recording captures full-resolution video (not the default
      // lowest layer which is typically 180p / 120kbps).
      if (producer.kind === 'video') {
        try {
          await consumer.setPreferredLayers({ spatialLayer: 2, temporalLayer: 2 });
        } catch (_) {
          // Not a simulcast producer — harmless
        }
      }

      // Provisional timeline start — will be overwritten after consumer.resume()
      // when RTP actually starts flowing to FFmpeg.  Do NOT use this value for
      // combine alignment: effectiveStartLocked guards the real value.
      const provisionalStartOffsetMs = Date.now() - recording.startTime;

      const inputEntry = {
        ffmpegRtpPort,
        ffmpegRtcpPort,
        kind: producer.kind,
        producerId: producer.id,
        source: producer.appData?.source ||
          (producer.kind === 'audio' ? 'microphone' : 'camera'),
        peerId,
        consumer,
        codec: consumer.rtpParameters.codecs[0],
        ssrc: consumer.rtpParameters.encodings?.[0]?.ssrc,
        startOffsetMs: provisionalStartOffsetMs,
        effectiveStartLocked: false,
        endOffsetMs: null,   // set when producer closes or recording stops
        pauseEvents: [],     // [{pausedAtMs, resumedAtMs}] for camera toggles
        // Display rotation (deg clockwise) the client reported at produce time
        // via producer appData. Codec-copying VP8 RTP drops the WebRTC CVO
        // orientation header, so we re-apply this rotation at transcode to bake
        // upright video. 0 (or unknown) → no transpose.
        rotation: producer.kind === 'video'
          ? ([0, 90, 180, 270].includes(Number(producer.appData?.rotation)) ? Number(producer.appData.rotation) : 0)
          : 0,
        // A camera switch reuses the same WebRTC producer. Keep a server-clock
        // history so each portion of the raw track is normalized with the
        // orientation that was actually active at that time.
        rotationEvents: [],  // [{atMs, rotation}]
      };

      // Listen for producer close → mark endOffsetMs only.
      // We do NOT kill the FFmpeg process here — stopRecording handles
      // all process shutdown to avoid race conditions where producerclose
      // and stopRecording both try to kill the same process, leading to
      // corrupted / empty output files.
      consumer.on('producerclose', () => {
        if (recording && inputEntry.endOffsetMs === null) {
          inputEntry.endOffsetMs = Date.now() - recording.startTime;
          console.log(`  [Recording] Producer closed for ${producer.kind} from ${peerId} — endOffset ${inputEntry.endOffsetMs}ms`);
        }
      });

      recording.transports.push(transport);
      recording.consumers.push({ consumer, producerId: producer.id, kind: producer.kind });
      recording.inputs.push(inputEntry);

      // Also track peer metadata if not yet known
      if (!recording.peerMeta.has(peerId)) {
        const peer = room.peers.get(peerId);
        if (peer) {
          recording.peerMeta.set(peerId, {
            username: peer.username,
            userId: peer.userId,
            profilePicture: peer.profilePicture,
          });
        }
      }

      recordingVLog(`  [Recording] Input: ${producer.kind} from ${peerId} → FFmpeg port ${ffmpegRtpPort}/${ffmpegRtcpPort} (ssrc: ${consumer.rtpParameters.encodings?.[0]?.ssrc}, offset: ${provisionalStartOffsetMs}ms)`);
      return inputEntry;

    } catch (error) {
      if (portsReserved) {
        try {
          releaseRecordingPortPair(ffmpegRtpPort, ffmpegRtcpPort);
          const reserved = room?.recording?.reservedPorts;
          if (reserved instanceof Set) {
            if (ffmpegRtpPort != null) reserved.delete(ffmpegRtpPort);
            if (ffmpegRtcpPort != null) reserved.delete(ffmpegRtcpPort);
          }
        } catch (_) {
          // ignore cleanup errors
        }
      }
      console.error(`  [Recording] Failed to create recording input:`, error.message);
      return null;
    }
  }

  /**
   * Build an SDP file for a SINGLE recording stream (one m= line).
   * Each stream gets its own FFmpeg process to avoid multi-stream timing
   * issues and enables codec-copy recording.
   */
  buildStreamSdp(input) {
    const codec = input.codec;
    const pt = codec.payloadType;
    // Use AVPF profile so FFmpeg honours RTCP feedback (PLI / FIR).
    // Without AVPF the sender ignores keyframe requests and black frames
    // accumulate whenever a keyframe is missed.
    const profile = input.kind === 'video' ? 'RTP/AVPF' : 'RTP/AVP';
    let sdp = `v=0\no=- 0 0 IN IP4 127.0.0.1\ns=MediasoupStream\nt=0 0\n`;

    if (input.kind === 'audio') {
      const channels = codec.channels || 2;
      sdp += `m=audio ${input.ffmpegRtpPort} ${profile} ${pt}\n`;
      sdp += `c=IN IP4 127.0.0.1\n`;
      sdp += `a=rtcp:${input.ffmpegRtcpPort}\n`;
      sdp += `a=rtpmap:${pt} opus/${codec.clockRate}/${channels}\n`;
      sdp += `a=fmtp:${pt} minptime=10;useinbandfec=1\n`;
    } else {
      sdp += `m=video ${input.ffmpegRtpPort} ${profile} ${pt}\n`;
      sdp += `c=IN IP4 127.0.0.1\n`;
      sdp += `a=rtcp:${input.ffmpegRtcpPort}\n`;

      // Codec-aware rtpmap/fmtp from the ACTUAL negotiated codec, so recording
      // works whether the client sends H.264 (hardware) or VP8. FFmpeg codec-
      // copies either into Matroska; SPS/PPS arrive in-band (the keyframe burst
      // on open guarantees an early one), so no sprop-parameter-sets is required.
      const mime = (codec.mimeType || '').toLowerCase();
      if (mime === 'video/h264') {
        sdp += `a=rtpmap:${pt} H264/${codec.clockRate}\n`;
        const p = codec.parameters || {};
        const fmtp = [
          `packetization-mode=${p['packetization-mode'] != null ? p['packetization-mode'] : 1}`,
        ];
        if (p['profile-level-id']) fmtp.push(`profile-level-id=${p['profile-level-id']}`);
        if (p['sprop-parameter-sets']) fmtp.push(`sprop-parameter-sets=${p['sprop-parameter-sets']}`);
        sdp += `a=fmtp:${pt} ${fmtp.join(';')}\n`;
      } else {
        sdp += `a=rtpmap:${pt} VP8/${codec.clockRate}\n`;
      }

      // RTCP feedback — critical: tells the encoder to honour PLI (keyframe
      // requests). Without these lines requestKeyFrame() is silently ignored
      // and black frames accumulate after every keyframe miss.
      sdp += `a=rtcp-fb:${pt} nack\n`;
      sdp += `a=rtcp-fb:${pt} nack pli\n`;
      sdp += `a=rtcp-fb:${pt} ccm fir\n`;
      sdp += `a=rtcp-fb:${pt} goog-remb\n`;
    }

    sdp += `a=recvonly\n`;
    if (input.ssrc) {
      sdp += `a=ssrc:${input.ssrc} cname:recording-${input.peerId}\n`;
    }

    return sdp;
  }

  /**
   * Phase 1: Start individual FFmpeg processes for each stream.
   * Each process records a single RTP stream using codec copy (no
   * transcoding).  This completely bypasses the VP8 decoder.
   *
   * - Audio → .mka  (Matroska Audio — incremental cluster writes survive SIGKILL;
   *                    unlike OGG which buffers in-memory and produces 0 bytes on
   *                    any forced exit before clean shutdown)
   * - Video → .mkv  (Matroska — more lenient than WebM about keyframe starts)
   *
   * Phase 2 (in stopRecording/combineRecordings) will merge all files
   * into the final side-by-side MP4.
   */
  async startIndividualRecordings(room) {
    const recording = room.recording;
    const inputs = recording.inputs;
    recording.ffmpegProcesses = [];
    recording.tempFiles = [];
    recording.sdpFiles = [];

    if (!recording.nextStreamIdx) {
      recording.nextStreamIdx = { audio: 0, video: 0 };
    }

    for (const input of inputs) {
      // If this input was already started by late-producer flow, skip it here
      // to avoid duplicate FFmpeg processes and timing lock races.
      if (input.tempFile || input.sdpFile || input.ffmpegStarted) {
        continue;
      }

      const idx = recording.nextStreamIdx[input.kind]++;
      const suffix = `${input.kind}_${idx}`;

      // Both audio and video use Matroska: MKV for video, MKA for audio.
      // Matroska writes data in clusters incrementally to disk, so even a
      // SIGKILL loses at most the in-flight cluster (~0.5 s) rather than
      // the entire file.  OGG buffers all Opus pages in RAM and only flushes
      // on a clean exit, making any signal a complete data loss.
      const ext = input.kind === 'audio' ? 'mka' : 'mkv';
      const fmt = 'matroska'; // covers both MKA and MKV
      const tempFile = path.join(RECORDINGS_DIR, `${recording.id}_${suffix}.${ext}`);
      const sdpFile = path.join(RECORDINGS_DIR, `${recording.id}_${suffix}.sdp`);

      input.tempFile = tempFile;
      input.sdpFile = sdpFile;

      // Write a single-stream SDP
      const sdpContent = this.buildStreamSdp(input);
      fs.writeFileSync(sdpFile, sdpContent);
      recordingVLog(`  [Recording] Stream SDP (${suffix}): ${sdpFile}`);

      // FFmpeg args — codec copy, one stream → container
      // Key flags:
      //   +genpts+igndts  — regenerate PTS and ignore broken DTS; prevents
      //                     timestamp gaps (camera pause/rejoin) from causing
      //                     FFmpeg to drop frames and go black.
      //   -max_delay      — cap jitter buffer to avoid frozen/black segments
      //                     caused by packets that arrive wildly out-of-order.
      //   -avoid_negative_ts make_zero — rebase timestamps so FFmpeg never
      //                     sees negative PTS which causes immediate black.
      const ffmpegArgs = [
        '-y',
        '-protocol_whitelist', 'file,udp,rtp',
        '-analyzeduration', '5000000',
        '-probesize', '5000000',
        '-max_delay', '500000',
        '-reorder_queue_size', '4096',
        '-fflags', '+genpts+igndts',
        '-thread_queue_size', '4096',
        '-rw_timeout', '6000000',
        '-f', 'sdp',
        '-i', sdpFile,
        '-avoid_negative_ts', 'make_zero',
        '-c', 'copy',
        '-flush_packets', '1',
        '-f', fmt,
        tempFile,
      ];

      recordingVLog(`  [FFmpeg] Spawning (${suffix}): ffmpeg ${ffmpegArgs.join(' ')}`);

      const ffmpeg = spawn('ffmpeg', ffmpegArgs, {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      ffmpeg.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && (msg.includes('Error') || msg.includes('error') ||
                    msg.includes('Invalid') || msg.includes('failed'))) {
          console.error(`  [FFmpeg ${suffix}] ${msg.substring(0, 300)}`);
        }
      });

      ffmpeg.on('error', (err) => {
        console.error(`  [FFmpeg ${suffix}] Spawn error: ${err.message}`);
      });

      ffmpeg.on('close', (code) => {
        if (code === 0) {
          console.log(`  [FFmpeg ${suffix}] Finished OK → ${tempFile}`);
        } else {
          console.log(`  [FFmpeg ${suffix}] Exited with code ${code}`);
        }
      });

      recording.ffmpegProcesses.push({ process: ffmpeg, suffix, tempFile });
      recording.tempFiles.push(tempFile);
      recording.sdpFiles.push(sdpFile);
      input.ffmpegStarted = true;
    }

    // Wait for each FFmpeg process to actually bind its UDP socket before
    // resuming consumers. A fixed sleep races on loaded systems — instead
    // we poll the process's stderr for the "bound to" confirmation line,
    // with a 6 s hard deadline to avoid hanging forever.
    const waitForFfmpegReady = (proc, suffix, deadlineMs = 3000) =>
      new Promise((resolve) => {
        let ready = false;
        const finish = () => { if (!ready) { ready = true; resolve(); } };

        // FFmpeg prints "bind(... port NNN)" or "Opening ... for reading"
        // once the UDP socket is up and it's reading the SDP.
        proc.stderr.on('data', (chunk) => {
          const s = chunk.toString();
          if (!ready && (s.includes('bind(') || s.includes('for reading') || s.includes('opening'))) {
            recordingVLog(`  [FFmpeg ${suffix}] UDP socket ready`);
            finish();
          }
        });

        setTimeout(finish, deadlineMs);
      });

    // Wait for ALL FFmpeg processes to be socket-ready before resuming any consumer.
    await Promise.all(
      recording.ffmpegProcesses.map(({ process: proc, suffix }) =>
        waitForFfmpegReady(proc, suffix),
      ),
    );
    // Extra 200 ms settle so the OS receive buffer is primed.
    await new Promise(resolve => setTimeout(resolve, 200));

    // Resume all consumers — RTP data starts flowing to each FFmpeg
    for (const { consumer, kind } of recording.consumers) {
      const input = recording.inputs.find(i => i.consumer === consumer);
      try {
        // Only the initial batch is controlled from this startup path.
        // Late producers are resumed/locked by addProducerToRecording.
        if (!input || !input.isInitialStream) {
          continue;
        }

        if (!consumer.closed && consumer.paused) {
          await consumer.resume();
          recordingVLog(`  [Recording] Consumer resumed: ${kind}`);
        }
        if (input && !input.effectiveStartLocked) {
          input.startOffsetMs = Date.now() - recording.startTime;
          input.effectiveStartLocked = true;
          recordingVLog(`  [Recording] Effective start: ${kind} from ${input.peerId} at ${input.startOffsetMs}ms`);
        }
      } catch (e) {
        // A producer may close during startup delay; do not fail whole recording startup.
        if (input && input.endOffsetMs === null) {
          input.endOffsetMs = Date.now() - recording.startTime;
        }
        console.warn(`  [Recording] Consumer resume skipped (${kind}): ${e.message}`);
      }
    }

    // Immediate keyframe request right after resume — minimises the window
    // where FFmpeg receives P-frames without a reference keyframe, which
    // would decode to black/green garbage during segment extraction.
    for (const { consumer, kind } of recording.consumers) {
      if (kind === 'video') {
        try {
          await consumer.requestKeyFrame();
          recordingVLog(`  [Recording] Immediate post-resume keyframe requested`);
        } catch (_) { /* ignore */ }
      }
    }

    // Follow-up keyframe burst — 3 rounds at 200 ms spacing for reliability.
    // Mobile VP8 encoders can be slow to respond to PLI; multiple rounds
    // ensure FFmpeg gets a reference frame ASAP.
    for (let burst = 0; burst < 3; burst++) {
      await new Promise(resolve => setTimeout(resolve, 200));
      for (const { consumer, kind } of recording.consumers) {
        if (kind === 'video') {
          try {
            await consumer.requestKeyFrame();
            recordingVLog(`  [Recording] Keyframe burst ${burst + 1} requested`);
          } catch (e) {
            console.warn(`  [Recording] Keyframe request failed: ${e.message}`);
          }
        }
      }
    }

    // Periodic keyframe requesting for the ENTIRE recording duration.
    // 2 s interval (down from 4 s) — shrinks the worst-case black window
    // after a keyframe miss. VP8 on mobile can be slow to respond to PLI;
    // sending frequently ensures FFmpeg always has a recent reference frame.
    recording._keyframeInterval = setInterval(async () => {
      for (const { consumer, kind } of (recording.consumers || [])) {
        if (kind === 'video') {
          try { await consumer.requestKeyFrame(); } catch (e) { /* ignore */ }
        }
      }
    }, 2000);
  }

  /**
   * Generate an avatar image for a peer (used to fill video gaps).
   * If the peer has a profile picture, scales it to fit.
   * Otherwise, draws a colored circle with their initial letter.
   *
   * @param {string} peerId
   * @param {{ username: string, profilePicture: string|null }} meta
   * @param {number} width - cell width
   * @param {number} height - cell height
   * @param {string} recordingId - for naming the file
   * @returns {string|null} path to the generated avatar PNG
   */
  async generateAvatarImage(peerId, meta, width, height, recordingId) {
    const avatarFile = path.join(RECORDINGS_DIR, `${recordingId}_avatar_${peerId.substring(0, 8)}.png`);

    const username = meta?.username || 'User';
    const initial = username.charAt(0).toUpperCase();

    // Deterministic color based on peerId
    const colors = ['#4A90D9', '#E74C3C', '#27AE60', '#F39C12', '#8E44AD', '#1ABC9C', '#E67E22', '#2980B9'];
    let hash = 0;
    for (let i = 0; i < peerId.length; i++) hash = ((hash << 5) - hash + peerId.charCodeAt(i)) | 0;
    const bgColor = colors[Math.abs(hash) % colors.length];

    // Check if profile picture exists on disk
    const profilePicPath = meta?.profilePicture
      ? path.join(__dirname, meta.profilePicture)
      : null;
    const hasProfilePic = profilePicPath && fs.existsSync(profilePicPath);

    try {
      if (hasProfilePic) {
        // Scale profile picture to fill the cell with letterbox/pillarbox
        const vf = `scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:color=${bgColor}`;
        await this.runCommand('ffmpeg', [
          '-y',
          '-i', profilePicPath,
          '-vf', vf,
          '-frames:v', '1',
          '-update', '1',
          avatarFile,
        ], { timeout: 10000 });
      } else {
        // Generate avatar with initial letter using Python/Pillow
        // Write a temp Python script (avoids shell quoting issues with inline -c)
        // Produces a colored background with a semi-transparent circle
        // and a large centered initial letter (e.g. "A" for Alex)
        const fontSize = Math.floor(Math.min(width, height) * 0.35);
        const circleR = Math.floor(Math.min(width, height) * 0.25);
        const cx = Math.floor(width / 2);
        const cy = Math.floor(height / 2);

        const pyFile = path.join(RECORDINGS_DIR, `${recordingId}_gen_avatar_${peerId.substring(0, 8)}.py`);
        const pyScript = [
          'from PIL import Image, ImageDraw, ImageFont',
          `img = Image.new("RGB", (${width}, ${height}), "${bgColor}")`,
          'draw = ImageDraw.Draw(img)',
          `overlay = Image.new("RGBA", (${width}, ${height}), (0,0,0,0))`,
          'od = ImageDraw.Draw(overlay)',
          `od.ellipse([${cx - circleR},${cy - circleR},${cx + circleR},${cy + circleR}], fill=(255,255,255,50))`,
          `img.paste(Image.alpha_composite(Image.new("RGBA", img.size, (0,0,0,0)), overlay).convert("RGB"), mask=overlay.split()[3])`,
          'try:',
          `    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", ${fontSize})`,
          'except:',
          '    font = ImageFont.load_default()',
          `bbox = draw.textbbox((0,0), "${initial}", font=font)`,
          'tw, th = bbox[2]-bbox[0], bbox[3]-bbox[1]',
          `draw.text(((${width}-tw)/2, (${height}-th)/2 - bbox[1]), "${initial}", fill="white", font=font)`,
          `img.save("${avatarFile}")`,
        ].join('\n');

        fs.writeFileSync(pyFile, pyScript);
        try {
          await this.runCommand('python3', [pyFile], { timeout: 15000 });
        } finally {
          try { fs.unlinkSync(pyFile); } catch (_) {}
        }
      }

      if (fs.existsSync(avatarFile)) {
        console.log(`  [Combine] Avatar generated for ${username}: ${avatarFile}`);
        return avatarFile;
      }
    } catch (e) {
      console.warn(`  [Combine] Avatar generation failed for ${username}: ${e.message}`);
    }

    return null;
  }

  /**
   * Track a producer pause/resume event for recording timeline.
   * Called when `producer_video_state` fires (camera toggle).
   *
   * When paused:
   *  - Records the pause timestamp.
   *  - Pauses the recording consumer so FFmpeg receives no RTP
   *    data for this period (clean gap in the MKV container).
   *
   * When resumed:
   *  - Records the resume timestamp.
   *  - Resumes the recording consumer.
   *  - Requests a keyframe (so FFmpeg can decode immediately).
   */
  async trackProducerPause(roomId, peerId, paused) {
    const room = this.rooms.get(roomId);
    if (!room || !room.recording) return;

    const recording = room.recording;
    const now = Date.now();
    const offsetMs = now - recording.startTime;

    // Find video inputs for this peer
    const videoInputs = recording.inputs.filter(
      (inp) => inp.peerId === peerId && inp.kind === 'video' &&
        (inp.source || 'camera') === 'camera' && inp.endOffsetMs === null
    );

    for (const input of videoInputs) {
      if (paused) {
        // Mark pause start
        input.pauseEvents.push({ pausedAtMs: offsetMs, resumedAtMs: null });
        console.log(`  [Recording] Video paused for ${peerId} at ${offsetMs}ms`);
        // Pause the mediasoup consumer so FFmpeg receives no RTP during the
        // camera-off window.  Without this, the sender may emit frozen/black
        // frames that land in the MKV container and corrupt the normalized-
        // concat timeline for this segment.
        try {
          if (!input.consumer.closed && !input.consumer.paused) {
            await input.consumer.pause();
          }
        } catch (e) {
          console.warn(`  [Recording] Consumer pause failed for ${peerId}: ${e.message}`);
        }
      } else {
        // Mark resume on the last open pause event
        const lastPause = input.pauseEvents[input.pauseEvents.length - 1];
        if (lastPause && lastPause.resumedAtMs === null) {
          lastPause.resumedAtMs = offsetMs;
        }
        console.log(`  [Recording] Video resumed for ${peerId} at ${offsetMs}ms`);
        // Resume consumer before requesting keyframe so FFmpeg is ready to
        // decode the incoming keyframe packet.
        try {
          if (!input.consumer.closed && input.consumer.paused) {
            await input.consumer.resume();
          }
        } catch (e) {
          console.warn(`  [Recording] Consumer resume failed for ${peerId}: ${e.message}`);
        }

        // Request keyframe so FFmpeg can decode immediately after gap
        try { await input.consumer.requestKeyFrame(); } catch (e) {}
        setTimeout(async () => {
          try { await input.consumer.requestKeyFrame(); } catch (e) {}
        }, 500);
      }
    }
  }

  /**
   * Detect whether a rendered video is mostly black using ffmpeg blackdetect.
   * Returns true if black coverage is >= 90% of total duration.
   */
  async isMostlyBlackVideo(filePath, totalDurationSec) {
    if (!filePath || !fs.existsSync(filePath)) return false;

    const duration = Math.max(0.001, Number(totalDurationSec || 0));
    if (!Number.isFinite(duration) || duration <= 0) return false;

    try {
      const result = await this.runCommand('ffmpeg', [
        '-hide_banner',
        '-nostats',
        '-i', filePath,
        '-vf', 'blackdetect=d=0.30:pix_th=0.10',
        '-an',
        '-f', 'null',
        '-',
      ], { timeout: 30000 });

      const stderr = result?.stderr || '';
      if (!stderr) return false;

      const re = /black_duration:([0-9.]+)/g;
      let blackSec = 0;
      let m;
      while ((m = re.exec(stderr)) !== null) {
        blackSec += Number(m[1] || 0);
      }

      const ratio = blackSec / duration;
      return ratio >= 0.9;
    } catch (_) {
      return false;
    }
  }

  /**
   * Ingest optional client-side timeline report for higher-fidelity camera/mic state.
   * Report is merged during combine and clipped by server-observed presence.
   */
  ingestClientTimeline(roomId, peerId, userId, report = {}) {
    const room = this.rooms.get(roomId);
    if (!room || !room.recording) return false;

    const recording = room.recording;
    if (!(recording.clientTimelineReports instanceof Map)) {
      recording.clientTimelineReports = new Map();
    }

    const stableIdentity = userId ? String(userId) : String(peerId);
    const toSegments = (arr) => this.normalizeTimelineSegments(
      (Array.isArray(arr) ? arr : []).map((s) => ({
        startSec: Number(s?.startSec),
        endSec: Number(s?.endSec),
      }))
    ).map((s) => ({
      startSec: Number(s.startSec.toFixed(3)),
      endSec: Number(s.endSec.toFixed(3)),
    }));

    const normalized = {
      source: report?.source || 'client',
      sessionId: report?.sessionId || null,
      atMs: Date.now(),
      cameraOnSegments: toSegments(report?.cameraOnSegments),
      micOnSegments: toSegments(report?.micOnSegments),
      presenceSegments: toSegments(report?.presenceSegments),
    };

    const existing = recording.clientTimelineReports.get(stableIdentity) || [];
    existing.push(normalized);
    recording.clientTimelineReports.set(stableIdentity, existing);
    recordingVLog(`  [Recording] Client timeline report captured for ${stableIdentity} (${normalized.cameraOnSegments.length} camera segments)`);
    return true;
  }

  /**
   * Probe a video file and return { width, height }.
   * Returns null on error.
   */
  async probeVideoSize(filePath) {
    try {
      // Get coded dimensions
      const sizeResult = await this.runCommand('ffprobe', [
        '-v', 'error',
        '-select_streams', 'v:0',
        '-show_entries', 'stream=width,height',
        '-of', 'csv=s=x:p=0',
        filePath,
      ], { timeout: 5000 });
      const raw = (sizeResult.stdout || '').trim();
      let [w, h] = raw.split('x').map(Number);
      if (!(w > 0 && h > 0)) return null;

      // Check for rotation metadata — mobile cameras often record with a
      // rotation tag (90° or 270°) meaning the coded w×h is transposed
      // relative to the actual displayed orientation.
      let rotation = 0;
      try {
        // Try side_data displaymatrix (newer FFmpeg / VP8+MKV)
        const sideDataRes = await this.runCommand('ffprobe', [
          '-v', 'error',
          '-select_streams', 'v:0',
          '-show_entries', 'side_data=rotation',
          '-of', 'default=nw=1:nk=1',
          filePath,
        ], { timeout: 5000 });
        const sideData = (sideDataRes.stdout || '').trim();
        if (sideData) rotation = Math.abs(parseFloat(sideData)) || 0;
      } catch (_) {}

      if (rotation === 0) {
        try {
          // Try stream tags rotation (common in MP4/MKV from mobile)
          const tagRotRes = await this.runCommand('ffprobe', [
            '-v', 'error',
            '-select_streams', 'v:0',
            '-show_entries', 'stream_tags=rotate',
            '-of', 'default=nw=1:nk=1',
            filePath,
          ], { timeout: 5000 });
          const tagRot = (tagRotRes.stdout || '').trim();
          if (tagRot) rotation = Math.abs(parseInt(tagRot, 10)) || 0;
        } catch (_) {}
      }

      if (rotation === 0) {
        try {
          // Try format tags rotation
          const fmtRotRes = await this.runCommand('ffprobe', [
            '-v', 'error',
            '-show_entries', 'format_tags=rotate',
            '-of', 'default=nw=1:nk=1',
            filePath,
          ], { timeout: 5000 });
          const fmtRot = (fmtRotRes.stdout || '').trim();
          if (fmtRot) rotation = Math.abs(parseInt(fmtRot, 10)) || 0;
        } catch (_) {}
      }

      // If rotated 90° or 270°, swap dimensions to get the DISPLAYED size
      if (rotation === 90 || rotation === 270) {
        console.log(`  [Combine] Detected rotation=${rotation}° for ${filePath} — swapping ${w}x${h} → ${h}x${w}`);
        [w, h] = [h, w];
      }

      return { width: w, height: h, rotation };
    } catch (e) {
      console.warn(`  [Combine] ffprobe failed for ${filePath}: ${e.message}`);
    }
    return null;
  }

  /**
   * Normalize timeline segments to valid sorted non-empty ranges.
   */
  normalizeTimelineSegments(segments = [], maxSec = null) {
    const normalized = (Array.isArray(segments) ? segments : [])
      .map(seg => ({
        startSec: Number(seg?.startSec),
        endSec: Number(seg?.endSec),
      }))
      .filter(seg => Number.isFinite(seg.startSec) && Number.isFinite(seg.endSec) && seg.endSec > seg.startSec)
      .map(seg => {
        let s = Math.max(0, seg.startSec);
        let e = seg.endSec;
        if (Number.isFinite(maxSec) && maxSec != null) {
          e = Math.min(maxSec, e);
          s = Math.min(maxSec, s);
        }
        return { startSec: s, endSec: e };
      })
      .filter(seg => seg.endSec > seg.startSec)
      .sort((a, b) => a.startSec - b.startSec);

    // merge overlaps
    const merged = [];
    for (const seg of normalized) {
      const last = merged[merged.length - 1];
      if (last && seg.startSec <= last.endSec) {
        last.endSec = Math.max(last.endSec, seg.endSec);
      } else {
        merged.push({ ...seg });
      }
    }
    return merged;
  }

  /**
   * Subtract B segments from A segments: A - B.
   */
  subtractTimelineSegments(baseSegments = [], subtractSegments = []) {
    let result = this.normalizeTimelineSegments(baseSegments);
    const subtract = this.normalizeTimelineSegments(subtractSegments);

    for (const cut of subtract) {
      const next = [];
      for (const seg of result) {
        if (cut.endSec <= seg.startSec || cut.startSec >= seg.endSec) {
          next.push(seg);
          continue;
        }

        if (cut.startSec > seg.startSec) {
          next.push({ startSec: seg.startSec, endSec: cut.startSec });
        }
        if (cut.endSec < seg.endSec) {
          next.push({ startSec: cut.endSec, endSec: seg.endSec });
        }
      }
      result = next;
    }

    return this.normalizeTimelineSegments(result);
  }

  /**
   * Compose multiple per-peer video segments into one timeline-aligned file.
   * Gaps show avatar/black background, and camera-off ranges overlay avatar.
   */
  async composePeerVideoTimeline(videoInputs, totalDurationSec, recordingId, peerId, meta) {
    if (!Array.isArray(videoInputs) || videoInputs.length === 0) return null;

    const firstProbe = await this.probeVideoSize(videoInputs[0].tempFile);
    const width = firstProbe?.width || 640;
    const height = firstProbe?.height || 480;
    const outFile = path.join(RECORDINGS_DIR, `${recordingId}_video_timeline_${peerId.substring(0, 8)}.mp4`);

    const avatarFile = await this.generateAvatarImage(peerId, meta, width, height, recordingId);

    const ffmpegArgs = ['-y'];
    // Base canvas
    ffmpegArgs.push('-f', 'lavfi', '-i', `color=c=black:s=${width}x${height}:r=30:d=${totalDurationSec.toFixed(3)}`);

    let avatarIdx = -1;
    if (avatarFile && fs.existsSync(avatarFile)) {
      avatarIdx = ffmpegArgs.filter(a => a === '-i').length;
      ffmpegArgs.push('-loop', '1', '-i', avatarFile);
    }

    const segmentInputIndexes = [];
    for (const seg of videoInputs) {
      const idx = ffmpegArgs.filter(a => a === '-i').length;
      segmentInputIndexes.push(idx);
      ffmpegArgs.push('-err_detect', 'ignore_err', '-fflags', '+discardcorrupt+genpts', '-i', seg.tempFile);
    }

    const filterParts = [];
    let baseLabel = 'base0';
    if (avatarIdx >= 0) {
      filterParts.push(`[0:v][${avatarIdx}:v]overlay=0:0[${baseLabel}]`);
    } else {
      filterParts.push(`[0:v]setpts=PTS-STARTPTS[${baseLabel}]`);
    }

    for (let i = 0; i < videoInputs.length; i++) {
      const seg = videoInputs[i];
      const inIdx = segmentInputIndexes[i];
      const segLabel = `segv${i}`;
      const nextBase = `base${i + 1}`;
      const startSec = Math.max(0, Number(((seg.startOffsetMs || 0) / 1000).toFixed(3)));
      const endSec = Math.max(startSec, Number((((seg.endOffsetMs ?? (totalDurationSec * 1000)) || 0) / 1000).toFixed(3)));

      const segProbe = await this.probeVideoSize(seg.tempFile);
      let rotateVf = '';
      if (segProbe?.rotation === 90) rotateVf = 'transpose=1,';
      else if (segProbe?.rotation === 270) rotateVf = 'transpose=2,';
      else if (segProbe?.rotation === 180) rotateVf = 'transpose=1,transpose=1,';

      filterParts.push(
        `[${inIdx}:v]${rotateVf}scale=${width}:${height}:force_original_aspect_ratio=decrease,pad=${width}:${height}:(ow-iw)/2:(oh-ih)/2:color=black,setpts=PTS-STARTPTS+${startSec}/TB[${segLabel}]`
      );
      filterParts.push(`[${baseLabel}][${segLabel}]overlay=0:0:enable='between(t,${startSec},${endSec})'[${nextBase}]`);
      baseLabel = nextBase;
    }

    // Camera pause windows overlay avatar (if available)
    const pauseSegments = this.normalizeTimelineSegments(
      videoInputs.flatMap(seg => (seg.pauseEvents || [])
        .filter(pe => pe?.pausedAtMs != null && pe?.resumedAtMs != null)
        .map(pe => ({
          startSec: Number(pe.pausedAtMs) / 1000,
          endSec: Number(pe.resumedAtMs) / 1000,
        }))),
      totalDurationSec,
    );

    let finalLabel = baseLabel;
    if (avatarIdx >= 0 && pauseSegments.length > 0) {
      const expr = pauseSegments
        .map(seg => `between(t,${seg.startSec.toFixed(3)},${seg.endSec.toFixed(3)})`)
        .join('+');
      const pausedLabel = 'vpaused';
      filterParts.push(`[${baseLabel}][${avatarIdx}:v]overlay=0:0:enable='${expr}'[${pausedLabel}]`);
      finalLabel = pausedLabel;
    }

    ffmpegArgs.push('-filter_complex', filterParts.join(';'));
    ffmpegArgs.push('-map', `[${finalLabel}]`);
    ffmpegArgs.push(
      '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23',
      '-r', '30', '-vsync', 'cfr', '-g', '60',
      '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
      outFile,
    );

    try {
      const result = await this.runCommand('ffmpeg', ffmpegArgs, { timeout: 180000 });

      if (result.status === 0 && fs.existsSync(outFile) && fs.statSync(outFile).size > 0) {
        console.log(`  [Combine] Built stitched video timeline for ${meta?.username || peerId}: ${outFile}`);
        return outFile;
      }

      const stderr = result.stderr ? result.stderr.toString().substring(0, 500) : '';
      console.warn(`  [Combine] Stitched video timeline failed for ${meta?.username || peerId} (exit ${result.status}): ${stderr}`);
      return null;
    } finally {
      if (avatarFile) {
        try { if (fs.existsSync(avatarFile)) fs.unlinkSync(avatarFile); } catch (_) {}
      }
    }
  }

  /**
   * Detect speaking segments from a rendered file audio track using ffmpeg
   * silencedetect (voice activity approximation based on audio energy).
   *
   * Returns array: [{ startSec, endSec }]
   */
  async detectSpeakingTimeline(filePath, durationSec) {
    if (!filePath || !fs.existsSync(filePath)) return [];

    const totalSec = Math.max(0, Number(durationSec || 0));
    if (!Number.isFinite(totalSec) || totalSec <= 0) return [];

    try {
      const args = [
        '-hide_banner',
        '-nostats',
        '-i', filePath,
        '-af', 'silencedetect=noise=-36dB:d=0.20',
        '-f', 'null',
        '-',
      ];

      const result = await this.runCommand('ffmpeg', args, { timeout: 30000 });

      const stderr = result.stderr || '';
      if (!stderr) {
        return [{ startSec: 0, endSec: Number(totalSec.toFixed(3)) }];
      }

      const events = [];
      const eventRegex = /silence_start:\s*([0-9.]+)|silence_end:\s*([0-9.]+)/g;
      let match;
      while ((match = eventRegex.exec(stderr)) !== null) {
        if (match[1] != null) {
          events.push({ type: 'silence_start', t: Number(match[1]) });
        } else if (match[2] != null) {
          events.push({ type: 'silence_end', t: Number(match[2]) });
        }
      }

      // No silence markers => treat full file as speech activity
      if (events.length === 0) {
        return [{ startSec: 0, endSec: Number(totalSec.toFixed(3)) }];
      }

      const rawSegments = [];
      let speechStart = 0;

      for (const ev of events) {
        const t = Math.max(0, Math.min(totalSec, Number(ev.t || 0)));
        if (ev.type === 'silence_start') {
          if (speechStart !== null && t > speechStart) {
            rawSegments.push({ startSec: speechStart, endSec: t });
          }
          speechStart = null;
        } else if (ev.type === 'silence_end') {
          speechStart = t;
        }
      }

      if (speechStart !== null && speechStart < totalSec) {
        rawSegments.push({ startSec: speechStart, endSec: totalSec });
      }

      // Cleanup: remove tiny spikes and merge near-adjacent segments
      const minTalkSec = 0.12;
      const mergeGapSec = 0.10;
      const cleaned = [];
      for (const seg of rawSegments) {
        const s = Math.max(0, Number(seg.startSec || 0));
        const e = Math.min(totalSec, Number(seg.endSec || 0));
        if (!Number.isFinite(s) || !Number.isFinite(e) || e - s < minTalkSec) continue;

        const last = cleaned[cleaned.length - 1];
        if (last && s - last.endSec <= mergeGapSec) {
          last.endSec = Math.max(last.endSec, e);
        } else {
          cleaned.push({ startSec: s, endSec: e });
        }
      }

      return cleaned.map(seg => ({
        startSec: Number(seg.startSec.toFixed(3)),
        endSec: Number(seg.endSec.toFixed(3)),
      }));
    } catch (e) {
      console.warn(`  [Combine] VAD/silencedetect failed for ${filePath}: ${e.message}`);
      return [];
    }
  }

  /**
   * Alternative video assembly path:
   * 1) Build exact-duration timeline pieces (black gaps + active segments)
   * 2) Concatenate pieces into one continuous per-peer timeline video.
   *
   * This avoids long overlay chains that can cause held-frame artifacts on
   * lossy RTP segments.
   */
  async buildNormalizedPeerVideoTimeline({ recordingId, peer, peerKey, videoInputs, activeTimelineSegments, totalDurationSec, totalDurationMs, targetW, targetH }) {
    const safeName = (peer?.username || 'peer').replace(/[^a-zA-Z0-9_-]/g, '_');
    const shortKey = String(peer?.userId || peerKey).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 12) || 'peer';
    const prefix = `${recordingId}_${safeName}_${shortKey}`;

    const pieceFiles = [];
    const tempArtifacts = [];
    let pieceIdx = 0;

    const pushBlackPiece = async (durationSec) => {
      if (!(durationSec > 0.001)) return;
      const out = path.join(RECORDINGS_DIR, `${prefix}_norm_piece_${pieceIdx++}_black.mp4`);
      const args = [
        '-y',
        '-f', 'lavfi',
        '-i', `color=c=black:s=${targetW}x${targetH}:r=24:d=${Number(durationSec.toFixed(3))}`,
        '-t', Number(durationSec.toFixed(3)).toString(),
        '-c:v', 'libx264',
        '-preset', 'veryfast',
        '-crf', '23',
        '-r', '24',
        '-g', '48',
        '-pix_fmt', 'yuv420p',
        '-an',
        '-movflags', '+faststart',
        out,
      ];
      const r = await this.runCommand('ffmpeg', args, { timeout: 90000 });
      if (r.status !== 0 || !fs.existsSync(out) || fs.statSync(out).size === 0) {
        throw new Error(`Failed to generate black timeline piece (${durationSec.toFixed(3)}s)`);
      }
      pieceFiles.push(out);
      tempArtifacts.push(out);
    };

    const pushActivePiece = async (segment, durationSec, sourceOffsetSec = 0) => {
      if (!(durationSec > 0.001)) return;

      const probe = await this.probeVideoSize(segment.tempFile);
      let rotateVf = '';
      if (probe?.rotation === 90) rotateVf = 'transpose=1,';
      else if (probe?.rotation === 270) rotateVf = 'transpose=2,';
      else if (probe?.rotation === 180) rotateVf = 'transpose=1,transpose=1,';

      const out = path.join(RECORDINGS_DIR, `${prefix}_norm_piece_${pieceIdx++}_active.mp4`);
      const d = Number(durationSec.toFixed(3));
      const srcStart = Math.max(0, Number(sourceOffsetSec.toFixed(3)));
      const srcEnd = Number((srcStart + d).toFixed(3));
      const args = [
        '-y',
        '-f', 'lavfi',
        '-i', `color=c=black:s=${targetW}x${targetH}:r=24:d=${d}`,
        '-analyzeduration', '10000000',
        '-probesize', '10000000',
        '-err_detect', 'ignore_err',
        '-fflags', '+discardcorrupt+genpts',
        '-i', segment.tempFile,
        '-filter_complex',
        `[1:v]${rotateVf}scale=${targetW}:${targetH}:force_original_aspect_ratio=decrease,pad=${targetW}:${targetH}:(ow-iw)/2:(oh-ih)/2:color=black,trim=start=${srcStart}:end=${srcEnd},setpts=PTS-STARTPTS[vseg];[0:v][vseg]overlay=0:0:eof_action=pass:repeatlast=0[vout]`,
        '-map', '[vout]',
        '-t', d.toString(),
        '-c:v', 'libx264',
        '-preset', 'veryfast',
        '-crf', '23',
        '-r', '24',
        '-g', '48',
        '-pix_fmt', 'yuv420p',
        '-an',
        '-movflags', '+faststart',
        out,
      ];

      const r = await this.runCommand('ffmpeg', args, { timeout: 120000 });
      if (r.status !== 0 || !fs.existsSync(out) || fs.statSync(out).size === 0) {
        throw new Error(`Failed to normalize active segment: ${segment.tempFile}`);
      }

      pieceFiles.push(out);
      tempArtifacts.push(out);
    };

    const sorted = [...(videoInputs || [])].sort((a, b) => (a.startOffsetMs || 0) - (b.startOffsetMs || 0));

    // Build effective camera-on windows.
    // If caller provides activeTimelineSegments (presence minus pauses), use it.
    // Otherwise fallback to raw stream spans.
    const activeWindows = Array.isArray(activeTimelineSegments) && activeTimelineSegments.length > 0
      ? this.normalizeTimelineSegments(activeTimelineSegments, totalDurationSec)
      : this.normalizeTimelineSegments(
          sorted.map(seg => ({
            startSec: (seg.startOffsetMs || 0) / 1000,
            endSec: ((seg.endOffsetMs ?? totalDurationMs) || 0) / 1000,
          })),
          totalDurationSec,
        );

    const activeSlices = [];
    for (const win of activeWindows) {
      let cursor = win.startSec;
      for (const seg of sorted) {
        const segStart = Math.max(0, (seg.startOffsetMs || 0) / 1000);
        const segEnd = Math.min(totalDurationSec, ((seg.endOffsetMs ?? totalDurationMs) || 0) / 1000);

        // Skip segments that end entirely before the current cursor position.
        // Without this guard, a segment that precedes the current window window
        // can stall the cursor and cause the next segment's ovStart to be
        // computed against the wrong baseline, producing a dropped slice.
        if (segEnd <= cursor + 0.0005) continue;

        const ovStart = Math.max(cursor, segStart);
        const ovEnd = Math.min(win.endSec, segEnd);
        if (ovEnd > ovStart + 0.0005) {
          activeSlices.push({
            segment: seg,
            timelineStartSec: ovStart,
            timelineEndSec: ovEnd,
            sourceOffsetSec: ovStart - segStart,
          });
          cursor = ovEnd;
          if (cursor >= win.endSec - 0.0005) break;
        }
      }
    }

    let cursorSec = 0;

    for (const slice of activeSlices) {
      const startSec = Math.max(0, Number(slice.timelineStartSec.toFixed(3)));
      const endSec = Math.min(totalDurationSec, Math.max(startSec, Number(slice.timelineEndSec.toFixed(3))));

      if (startSec > cursorSec + 0.001) {
        await pushBlackPiece(startSec - cursorSec);
        cursorSec = startSec;
      }

      const activeDur = Math.max(0, endSec - cursorSec);
      if (activeDur > 0.001) {
        await pushActivePiece(slice.segment, activeDur, Math.max(0, slice.sourceOffsetSec));
        cursorSec = endSec;
      }
    }

    if (cursorSec < totalDurationSec - 0.001) {
      await pushBlackPiece(totalDurationSec - cursorSec);
      cursorSec = totalDurationSec;
    }

    if (pieceFiles.length === 0) {
      await pushBlackPiece(totalDurationSec);
    }

    const concatList = path.join(RECORDINGS_DIR, `${prefix}_norm_concat.txt`);
    const escaped = pieceFiles
      .map(f => `file '${f.replace(/'/g, `'\\''`)}'`)
      .join('\n');
    fs.writeFileSync(concatList, `${escaped}\n`);
    tempArtifacts.push(concatList);

    const timelineOut = path.join(RECORDINGS_DIR, `${recordingId}_${safeName}_${shortKey}_normvideo.mp4`);
    const concatArgs = [
      '-y',
      '-f', 'concat',
      '-safe', '0',
      '-i', concatList,
      '-c:v', 'libx264',
      '-preset', 'veryfast',
      '-crf', '23',
      '-r', '24',
      '-g', '48',
      '-pix_fmt', 'yuv420p',
      '-an',
      '-movflags', '+faststart',
      timelineOut,
    ];

    const cr = await this.runCommand('ffmpeg', concatArgs, { timeout: 180000 });
    for (const f of tempArtifacts) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
    }

    if (cr.status === 0 && fs.existsSync(timelineOut) && fs.statSync(timelineOut).size > 0) {
      return timelineOut;
    }

    try { if (fs.existsSync(timelineOut)) fs.unlinkSync(timelineOut); } catch (_) {}
    return null;
  }

  /**
   * Phase 2: Produce one MP4/MP3 per peer from their raw streams.
   *
   * Each peer's video MKV + audio OGG are muxed into a single clean MP4.
   * No avatars, no overlays, no grid — just the raw re-encoded media.
   *
   * Returns an array of { file, peerId, username, format } objects.
   */
  async combineRecordings(recording) {
    const useNormalizedCombine = USE_NORMALIZED_CONCAT_COMBINE;
    // Calculate total recording duration from call lifecycle stop moment.
    // IMPORTANT: do NOT rely on longest stream/user because users can leave
    // and rejoin while the call continues.
    const maxEndOffset = Math.max(...recording.inputs.map(i => i.endOffsetMs || 0));
    const stopOffsetMs = Number(recording.stopOffsetMs || 0);
    const totalDurationMs = stopOffsetMs > 0
      ? stopOffsetMs
      : (maxEndOffset > 0 ? maxEndOffset : (Date.now() - recording.startTime));
    for (const input of recording.inputs) {
      if (input.endOffsetMs === null) {
        input.endOffsetMs = totalDurationMs;
      }
    }

    // Filter valid (non-empty, existing) inputs
    const validInputs = [];
    for (const input of recording.inputs) {
      if (!input.tempFile || !fs.existsSync(input.tempFile)) continue;
      const stat = fs.statSync(input.tempFile);
      if (stat.size === 0) {
        console.warn(`  [Combine] Skipping empty file: ${input.tempFile}`);
        continue;
      }
      validInputs.push(input);
    }

    if (validInputs.length === 0) {
      console.error('  [Combine] No valid stream files to combine');
      return [];
    }

    const totalDurationSec = totalDurationMs / 1000;
    console.log(`  [Combine] Total duration: ${totalDurationSec.toFixed(1)}s, valid streams: ${validInputs.length}`);
    console.log(`  [Combine] Strategy: ${useNormalizedCombine ? 'normalized-concat' : 'legacy-overlay'}`);

    // Log each stream
    for (const input of validInputs) {
      const meta = recording.peerMeta?.get(input.peerId);
      console.log(`  [Combine] Stream: ${input.kind} from ${meta?.username || input.peerId} — offset ${input.startOffsetMs}ms → ${input.endOffsetMs}ms (file: ${input.tempFile})`);
    }

    // Group by stable participant identity (userId when available, otherwise peerId)
    // so reconnects/rejoins from a new socket are merged into one final recording.
    const peerMap = new Map();
    const clientTimelineMap = recording.clientTimelineEntries
      ? new Map(recording.clientTimelineEntries)
      : (recording.clientTimelineReports instanceof Map ? recording.clientTimelineReports : new Map());

    const combineDebug = {
      recordingId: recording.id,
      totalDurationSec: Number(totalDurationSec.toFixed(3)),
      strategy: useNormalizedCombine ? 'normalized-concat' : 'legacy-overlay',
      useClientTimelineMetadata: USE_CLIENT_TIMELINE_METADATA,
      generatedAt: new Date().toISOString(),
      peers: [],
    };
    for (const input of validInputs) {
      const meta = recording.peerMeta?.get(input.peerId);
      const stableUserId = meta?.userId ? String(meta.userId) : null;
      const stableKey = stableUserId || String(input.peerId);

      if (!peerMap.has(stableKey)) {
        peerMap.set(stableKey, {
          audios: [],
          videos: [],
          username: meta?.username || input.peerId,
          userId: stableUserId,
          stableKey,
        });
      }
      const peer = peerMap.get(stableKey);
      if (input.kind === 'audio') peer.audios.push(input);
      else peer.videos.push(input);
    }

    console.log(`  [Combine] Peers: ${peerMap.size} (${[...peerMap.values()].map(p => p.username).join(', ')})`);

    const validateInputFile = async (input, streamSelector) => {
      if (!input?.tempFile || !fs.existsSync(input.tempFile)) return false;
      try {
        const probe = await this.runCommand('ffprobe', [
          '-v', 'error',
          '-select_streams', streamSelector,
          '-show_entries', 'stream=codec_name',
          '-of', 'default=nw=1:nk=1',
          input.tempFile,
        ], { timeout: 5000 });
        return probe.status === 0 && !!(probe.stdout || '').trim();
      } catch {
        return false;
      }
    };

    // Build one output file per peer
    const outputFiles = [];

    for (const [peerKey, peer] of peerMap) {
      const shortKey = String(peer.userId || peerKey).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 12) || 'peer';
      const audioCandidates = (peer.audios || [])
        .filter(i => i && i.tempFile && fs.existsSync(i.tempFile))
        .sort((a, b) => (a.startOffsetMs || 0) - (b.startOffsetMs || 0));
      const videoCandidates = (peer.videos || [])
        .filter(i => i && i.tempFile && fs.existsSync(i.tempFile))
        .sort((a, b) => (a.startOffsetMs || 0) - (b.startOffsetMs || 0));

      const audioInputs = [];
      for (const a of audioCandidates) {
        if (await validateInputFile(a, 'a:0')) {
          audioInputs.push(a);
        } else {
          console.warn(`  [Combine] Skipping unreadable audio segment for ${peer.username}: ${a.tempFile}`);
        }
      }

      const videoInputs = [];
      for (const v of videoCandidates) {
        if (await validateInputFile(v, 'v:0')) {
          videoInputs.push(v);
        } else {
          console.warn(`  [Combine] Skipping unreadable video segment for ${peer.username}: ${v.tempFile}`);
        }
      }

      // Detect suspicious start skew between first audio/video segment.
      let firstAudioStartMs = null;
      let firstVideoStartMs = null;
      let avStartSkewMs = null;
      if (audioInputs.length > 0 && videoInputs.length > 0) {
        firstAudioStartMs = Number(audioInputs[0].startOffsetMs || 0);
        firstVideoStartMs = Number(videoInputs[0].startOffsetMs || 0);
        avStartSkewMs = Math.abs(firstAudioStartMs - firstVideoStartMs);
        if (avStartSkewMs > 500) {
          console.warn(`  [Combine] A/V start skew for ${peer.username}: ${avStartSkewMs}ms (audio=${firstAudioStartMs}ms, video=${firstVideoStartMs}ms)`);
        }
      }

      const videoPresenceSegments = this.normalizeTimelineSegments(
        videoInputs.map(seg => ({
          startSec: (seg.startOffsetMs || 0) / 1000,
          endSec: ((seg.endOffsetMs ?? totalDurationMs) || 0) / 1000,
        })),
        totalDurationSec,
      );

      const presenceTimeline = this.normalizeTimelineSegments(
        [...audioInputs, ...videoInputs].map(seg => ({
          startSec: (seg.startOffsetMs || 0) / 1000,
          endSec: ((seg.endOffsetMs ?? totalDurationMs) || 0) / 1000,
        })),
        totalDurationSec,
      ).map(seg => ({
        startSec: Number(seg.startSec.toFixed(3)),
        endSec: Number(seg.endSec.toFixed(3)),
      }));

      const presenceEvents = presenceTimeline.flatMap(seg => ([
        { type: 'join', atSec: Number(seg.startSec.toFixed(3)) },
        { type: 'leave', atSec: Number(seg.endSec.toFixed(3)) },
      ]));

      const videoPauseSegments = this.normalizeTimelineSegments(
        videoInputs.flatMap(seg => (seg.pauseEvents || [])
          .filter(pe => pe?.pausedAtMs != null && pe?.resumedAtMs != null)
          .map(pe => ({
            startSec: Number(pe.pausedAtMs) / 1000,
            endSec: Number(pe.resumedAtMs) / 1000,
          }))),
        totalDurationSec,
      );

      // Camera-on timeline (presence minus pause windows)
      let timelineSource = 'server-derived';
      let videoTimeline = this.subtractTimelineSegments(videoPresenceSegments, videoPauseSegments)
        .map(seg => ({
          startSec: Number(seg.startSec.toFixed(3)),
          endSec: Number(seg.endSec.toFixed(3)),
        }));

      // Hybrid metadata merge:
      // use client-reported cameraOn segments when available, but ALWAYS clip
      // by server-observed presence windows to avoid out-of-call pollution.
      const reports = clientTimelineMap.get(String(peer.userId || peerKey)) || [];
      if (USE_CLIENT_TIMELINE_METADATA && Array.isArray(reports) && reports.length > 0) {
        const clientCameraOn = this.normalizeTimelineSegments(
          reports.flatMap(r => Array.isArray(r?.cameraOnSegments) ? r.cameraOnSegments : []),
          totalDurationSec,
        );

        if (clientCameraOn.length > 0) {
          const clipped = [];
          for (const c of clientCameraOn) {
            for (const p of presenceTimeline) {
              const s = Math.max(c.startSec, p.startSec);
              const e = Math.min(c.endSec, p.endSec);
              if (e > s) clipped.push({ startSec: s, endSec: e });
            }
          }

          const merged = this.normalizeTimelineSegments(clipped, totalDurationSec).map(seg => ({
            startSec: Number(seg.startSec.toFixed(3)),
            endSec: Number(seg.endSec.toFixed(3)),
          }));

          if (merged.length > 0) {
            const union = this.normalizeTimelineSegments([
              ...videoTimeline,
              ...merged,
            ], totalDurationSec).map(seg => ({
              startSec: Number(seg.startSec.toFixed(3)),
              endSec: Number(seg.endSec.toFixed(3)),
            }));

            videoTimeline = union;
            timelineSource = 'server-plus-client-union';
            console.log(`  [Combine] Merged client camera timeline for ${peer.username} (server ${videoTimeline.length} segments after union)`);
          }
        }
      }

      // If video starts significantly earlier than audio, clamp early video windows.
      // This trims pre-audio head frames that otherwise create apparent black/frozen lead-in
      // and persistent desync in the final MP4.
      if (
        firstAudioStartMs != null &&
        firstVideoStartMs != null &&
        firstVideoStartMs + 500 < firstAudioStartMs &&
        Array.isArray(videoTimeline) &&
        videoTimeline.length > 0
      ) {
        const minStartSec = Number((firstAudioStartMs / 1000).toFixed(3));
        const clampedTimeline = this.normalizeTimelineSegments(
          videoTimeline.map(seg => ({
            startSec: Math.max(minStartSec, Number(seg.startSec || 0)),
            endSec: Number(seg.endSec || 0),
          })),
          totalDurationSec,
        ).map(seg => ({
          startSec: Number(seg.startSec.toFixed(3)),
          endSec: Number(seg.endSec.toFixed(3)),
        }));

        if (clampedTimeline.length > 0) {
          videoTimeline = clampedTimeline;
          timelineSource = `${timelineSource}+av-clamp`;
          console.warn(`  [Combine] Clamped early video lead for ${peer.username} to ${minStartSec}s (audio start)`);
        }
      }

      // Stitch all per-peer video segments (leave/rejoin continuity)
      // HARD-DISABLED for now (CPU hotspot). Keep per-peer raw recordings + metadata.
      let stitchedVideoFile = null;
      // if (ENABLE_VIDEO_TIMELINE_STITCHING && videoInputs.length > 0) {
      //   const meta = recording.peerMeta?.get(peerId);
      //   stitchedVideoFile = this.composePeerVideoTimeline(
      //     videoInputs,
      //     totalDurationSec,
      //     recording.id,
      //     peerId,
      //     meta,
      //   );
      // }

      const isVideoCall = !!recording.hasVideo;
      const hasVideo = videoInputs.length > 0;
      const hasAudio = audioInputs.length > 0;
      const ext = isVideoCall ? 'mp4' : 'mp3';
      const safeName = peer.username.replace(/[^a-zA-Z0-9_-]/g, '_');
      const outputFile = path.join(RECORDINGS_DIR, `${recording.id}_${safeName}_${shortKey}.${ext}`);

      console.log(`  [Combine] Building ${ext} for ${peer.username} (video footage: ${hasVideo ? 'yes' : 'no'}, audio: ${hasAudio ? 'yes' : 'no'})`);

      const ffmpegArgs = ['-y'];
      const audioInputIndices = [];
      const videoInputIndices = [];
      let normalizedTimelineVideoFile = null;
      let usingNormalizedVideo = false;
      let normalizedRejectedMostlyBlack = false;

      const videoEncodeArgs = USE_HW_VIDEO_ENCODER
        ? [
            '-c:v', 'h264_videotoolbox',
            '-allow_sw', '1',
            '-realtime', 'true',
            '-b:v', '3000k',
            '-maxrate', '4500k',
          ]
        : [
            '-c:v', 'libx264',
            '-preset', 'veryfast',
            '-crf', '23',
          ];

      if (isVideoCall) {
        const firstProbe = hasVideo ? await this.probeVideoSize(videoInputs[0].tempFile) : null;
        const targetW = firstProbe?.width || 640;
        const targetH = firstProbe?.height || 480;

        if (useNormalizedCombine && hasVideo) {
          try {
            normalizedTimelineVideoFile = await this.buildNormalizedPeerVideoTimeline({
              recordingId: recording.id,
              peer,
              peerKey,
              videoInputs,
              activeTimelineSegments: videoTimeline,
              totalDurationSec,
              totalDurationMs,
              targetW,
              targetH,
            });
          } catch (e) {
            console.warn(`  [Combine] Normalized timeline build failed for ${peer.username}: ${e.message}`);
            normalizedTimelineVideoFile = null;
          }

          if (normalizedTimelineVideoFile && fs.existsSync(normalizedTimelineVideoFile)) {
            const mostlyBlack = await this.isMostlyBlackVideo(normalizedTimelineVideoFile, totalDurationSec);
            if (mostlyBlack) {
              normalizedRejectedMostlyBlack = true;
              console.warn(`  [Combine] Normalized timeline appears mostly black for ${peer.username}; falling back to legacy overlay`);
              try { if (fs.existsSync(normalizedTimelineVideoFile)) fs.unlinkSync(normalizedTimelineVideoFile); } catch (_) {}
              normalizedTimelineVideoFile = null;
            } else {
              ffmpegArgs.push('-i', normalizedTimelineVideoFile);
              usingNormalizedVideo = true;
              console.log(`  [Combine] Using normalized timeline video for ${peer.username}`);
            }
          } else {
            console.warn(`  [Combine] Falling back to legacy overlay for ${peer.username}`);
          }
        }

        if (!usingNormalizedVideo) {
          // Legacy path: full-duration black canvas + overlay timeline
          ffmpegArgs.push('-f', 'lavfi', '-i', `color=c=black:s=${targetW}x${targetH}:r=24:d=${totalDurationSec.toFixed(3)}`);

          for (const v of videoInputs) {
            const idx = ffmpegArgs.filter(a => a === '-i').length;
            videoInputIndices.push(idx);
            ffmpegArgs.push(
              '-analyzeduration', '10000000',
              '-probesize', '10000000',
              '-err_detect', 'ignore_err',
              '-fflags', '+discardcorrupt+genpts',
              '-i', v.tempFile,
            );
          }
        }
      }

      if (hasAudio) {
        for (const audioInput of audioInputs) {
          const idx = ffmpegArgs.filter(a => a === '-i').length;
          audioInputIndices.push(idx);
          ffmpegArgs.push('-i', audioInput.tempFile);
        }
      }

      // Build timeline-aware audio filter when there are multiple segments,
      // when first segment starts later than t=0, or for any video-call output
      // (to guarantee full-length padding with silence).
      const needsAudioTimelineMerge =
        hasAudio && (
          isVideoCall ||
          audioInputs.length > 1 ||
          (audioInputs[0]?.startOffsetMs || 0) > 20
        );

      let audioTimelineGraph = '';
      if (needsAudioTimelineMerge) {
        const parts = [];
        const delayedLabels = [];
        for (let i = 0; i < audioInputs.length; i++) {
          const inIdx = audioInputIndices[i];
          const delayMs = Math.max(0, Math.floor(audioInputs[i].startOffsetMs || 0));
          const label = `ad${i}`;
          delayedLabels.push(`[${label}]`);
          parts.push(`[${inIdx}:a]adelay=${delayMs}|${delayMs},aresample=async=1:first_pts=0[${label}]`);
        }

        if (audioInputs.length === 1) {
          parts.push(
            `${delayedLabels[0]}apad=pad_dur=${totalDurationSec.toFixed(3)},` +
            `atrim=0:${totalDurationSec.toFixed(3)},asetpts=N/SR/TB[aout]`
          );
        } else {
          parts.push(
            `${delayedLabels.join('')}amix=inputs=${audioInputs.length}:duration=longest:dropout_transition=0,` +
            `apad=pad_dur=${totalDurationSec.toFixed(3)},` +
            `atrim=0:${totalDurationSec.toFixed(3)},asetpts=N/SR/TB[aout]`
          );
        }

        audioTimelineGraph = parts.join(';');
      }

      if (isVideoCall && usingNormalizedVideo) {
        if (audioTimelineGraph) {
          ffmpegArgs.push('-filter_complex', audioTimelineGraph);
        }

        ffmpegArgs.push('-map', '0:v');
        if (hasAudio) {
          ffmpegArgs.push('-map', audioTimelineGraph ? '[aout]' : `${audioInputIndices[0]}:a`);
        }
        ffmpegArgs.push('-t', totalDurationSec.toFixed(3));
        ffmpegArgs.push('-c:v', 'copy');
        ffmpegArgs.push('-movflags', '+faststart');
      }

      if (isVideoCall && !usingNormalizedVideo) {
        const firstProbe = hasVideo ? await this.probeVideoSize(videoInputs[0].tempFile) : null;
        const targetW = firstProbe?.width || 640;
        const targetH = firstProbe?.height || 480;

        const videoParts = ['[0:v]setpts=PTS-STARTPTS[vbase0]'];
        let baseLabel = 'vbase0';

        for (let i = 0; i < videoInputs.length; i++) {
          const seg = videoInputs[i];
          const inIdx = videoInputIndices[i];
          const startSec = Math.max(0, Number(((seg.startOffsetMs || 0) / 1000).toFixed(3)));
          const endSec = Math.max(startSec, Number((((seg.endOffsetMs ?? totalDurationMs) || 0) / 1000).toFixed(3)));
          const probe = await this.probeVideoSize(seg.tempFile);
          let rotateVf = '';
          if (probe?.rotation === 90) rotateVf = 'transpose=1,';
          else if (probe?.rotation === 270) rotateVf = 'transpose=2,';
          else if (probe?.rotation === 180) rotateVf = 'transpose=1,transpose=1,';

          const segLabel = `vseg${i}`;
          const nextBase = `vbase${i + 1}`;

          // Intersect this raw stream span with computed camera-on timeline.
          // This preserves black output during camera-off / absent windows.
          const activeWindowsForSeg = (videoTimeline || [])
            .map(win => ({
              startSec: Math.max(startSec, Number(win.startSec || 0)),
              endSec: Math.min(endSec, Number(win.endSec || 0)),
            }))
            .filter(win => win.endSec > win.startSec);

          if (activeWindowsForSeg.length === 0) {
            continue;
          }

          const enableExpr = activeWindowsForSeg
            .map(win => `between(t,${win.startSec.toFixed(3)},${win.endSec.toFixed(3)})`)
            .join('+');

          videoParts.push(
            `[${inIdx}:v]${rotateVf}scale=${targetW}:${targetH}:force_original_aspect_ratio=decrease,pad=${targetW}:${targetH}:(ow-iw)/2:(oh-ih)/2:color=black,setpts=PTS-STARTPTS+${startSec}/TB[${segLabel}]`
          );
          videoParts.push(`[${baseLabel}][${segLabel}]overlay=0:0:enable='${enableExpr}'[${nextBase}]`);
          baseLabel = nextBase;
        }

        const videoGraph =
          `${videoParts.join(';')};` +
          `[${baseLabel}]tpad=stop_mode=add:stop_duration=${totalDurationSec.toFixed(3)},` +
          `trim=0:${totalDurationSec.toFixed(3)},setpts=PTS-STARTPTS[vout]`;
        const fullGraph = audioTimelineGraph ? `${videoGraph};${audioTimelineGraph}` : videoGraph;
        ffmpegArgs.push('-filter_complex', fullGraph);
        ffmpegArgs.push('-map', '[vout]');
        if (hasAudio) {
          ffmpegArgs.push('-map', audioTimelineGraph ? '[aout]' : `${audioInputIndices[0]}:a`);
        }
        ffmpegArgs.push('-t', totalDurationSec.toFixed(3));
        ffmpegArgs.push(
          ...videoEncodeArgs,
          '-r', '24', '-vsync', 'cfr', '-g', '48',
          '-pix_fmt', 'yuv420p', '-movflags', '+faststart',
          '-max_muxing_queue_size', '1024',
        );
      }

      if (!hasVideo && audioTimelineGraph) {
        ffmpegArgs.push('-filter_complex', audioTimelineGraph, '-map', '[aout]');
      }

      if (hasAudio) {
        ffmpegArgs.push('-c:a', hasVideo ? 'aac' : 'libmp3lame', '-b:a', '192k');
      }

      ffmpegArgs.push(outputFile);

        combineDebug.peers.push({
          peerKey,
          userId: peer.userId || null,
          username: peer.username,
          timelineSource,
          avStartSkewMs,
          normalizedVideoSelected: usingNormalizedVideo,
          normalizedRejectedMostlyBlack,
          audioSegments: audioInputs.map(s => ({
            file: s.tempFile,
            startOffsetMs: s.startOffsetMs,
            endOffsetMs: s.endOffsetMs,
          })),
          videoSegments: videoInputs.map(s => ({
            file: s.tempFile,
            startOffsetMs: s.startOffsetMs,
            endOffsetMs: s.endOffsetMs,
          })),
          videoTimeline,
          presenceTimeline,
        });

      console.log(`  [Combine] Running: ffmpeg ${ffmpegArgs.join(' ')}`);

      try {
        const result = await this.runCommand('ffmpeg', ffmpegArgs, { timeout: 120000 });

        if (result.status === 0 && fs.existsSync(outputFile) && fs.statSync(outputFile).size > 0) {
          const sizeKB = (fs.statSync(outputFile).size / 1024).toFixed(0);
          // Probe the actual duration of the output file (most accurate)
          let fileDurationSec = null;
          try {
            const probeDuration = await this.runCommand('ffprobe', [
              '-v', 'error',
              '-show_entries', 'format=duration',
              '-of', 'default=nw=1:nk=1',
              outputFile,
            ], { timeout: 5000 });
            const durStr = (probeDuration.stdout || '').trim();
            if (durStr) fileDurationSec = parseFloat(durStr);
          } catch (_) {}
          if (fileDurationSec != null && Math.abs(fileDurationSec - totalDurationSec) > 1.5) {
            console.warn(
              `  [Combine] Duration mismatch for ${peer.username}: expected ${totalDurationSec.toFixed(1)}s, got ${fileDurationSec.toFixed(1)}s`
            );
          }
          console.log(`  [Combine] ✅ ${peer.username}: ${outputFile} (${sizeKB}KB, ${fileDurationSec ? fileDurationSec.toFixed(1) + 's' : '?'})`);
          const speakerTimeline = hasAudio
            ? await this.detectSpeakingTimeline(outputFile, fileDurationSec || totalDurationSec)
            : [];

          outputFiles.push({
            file: outputFile,
            peerId: peer.userId || peerKey,
            username: peer.username,
            userId: peer.userId,
            format: ext,
            durationSec: fileDurationSec,
            speakerTimeline,
            videoTimeline,
            presenceTimeline,
            presenceEvents,
          });
        } else {
          const stderr = result.stderr ? result.stderr.toString().substring(0, 500) : '';
          console.warn(`  [Combine] ❌ ${peer.username} failed (exit ${result.status}): ${stderr}`);
        }
      } catch (e) {
        console.warn(`  [Combine] ❌ ${peer.username} error: ${e.message}`);
      }

      if (normalizedTimelineVideoFile) {
        try { if (fs.existsSync(normalizedTimelineVideoFile)) fs.unlinkSync(normalizedTimelineVideoFile); } catch (_) {}
      }

      if (stitchedVideoFile) {
        try { if (fs.existsSync(stitchedVideoFile)) fs.unlinkSync(stitchedVideoFile); } catch (_) {}
      }
    }

    if (outputFiles.length > 0) {
      console.log(`  [Combine] Success: ${outputFiles.length} file(s) produced`);
    } else {
      console.error('  [Combine] No output files could be produced');
    }

    if (WRITE_COMBINE_DEBUG_ARTIFACT) {
      try {
        const debugFile = path.join(RECORDINGS_DIR, `${recording.id}_combine_debug.json`);
        fs.writeFileSync(debugFile, JSON.stringify(combineDebug, null, 2));
        console.log(`  [Combine] Debug timeline artifact: ${debugFile}`);
      } catch (e) {
        console.warn(`  [Combine] Failed to write debug artifact: ${e.message}`);
      }
    }

    return outputFiles;
  }

  /**
   * Add a new producer to an ongoing recording.
   * Creates a dedicated PlainTransport + consumer + FFmpeg process for the
   * new stream, exactly like startRecording does for initial producers.
   */
  async addProducerToRecording(room, producer, peerId) {
    if (!room.recording) return;

    const recording = room.recording;
    if (recording.stopped) return;

    // Don't duplicate — check if we already record this producer
    const alreadyRecorded = recording.inputs.some(
      (inp) => inp.consumer && inp.consumer.producerId === producer.id
    );
    if (alreadyRecorded) {
      console.log(`  [Recording] Producer ${producer.id} already being recorded`);
      return;
    }

    console.log(`  [Recording] Adding late producer ${producer.kind} from ${peerId} to ongoing recording`);

    try {
      // 1. Create recording input (PlainTransport + consumer)
      const input = await this.createRecordingInput(room, producer, peerId);
      if (!input) {
        console.error(`  [Recording] createRecordingInput did not add an input`);
        return;
      }

      if (recording.stopped) {
        recordingVLog('  [Recording] Recording stopped while creating late input, aborting');
        return;
      }

      // If startup path already picked this input, don't start a duplicate
      // FFmpeg pipeline in the late-producer path.
      if (input.ffmpegStarted || input.tempFile || input.sdpFile) {
        recordingVLog(`  [Recording] Late producer ${producer.id} already initialized by startup path`);
        return;
      }

      // 2. Allocate a unique stream index atomically
      if (!recording.nextStreamIdx) {
        recording.nextStreamIdx = { audio: 0, video: 0 };
      }
      const idx = recording.nextStreamIdx[input.kind]++;
      const suffix = `${input.kind}_${idx}`;

      if (input.kind === 'video' && !recording.hasVideo) {
        recording.hasVideo = true;
        recordingVLog(`  [Recording] Late video producer added — call upgraded to video`);
      }

      // MKA for audio (Matroska Audio) — incremental cluster writes survive
      // SIGKILL; OGG loses all buffered data instantly on any forced exit.
      const ext = input.kind === 'audio' ? 'mka' : 'mkv';
      const fmt = 'matroska';
      const tempFile = path.join(RECORDINGS_DIR, `${recording.id}_${suffix}.${ext}`);
      const sdpFile = path.join(RECORDINGS_DIR, `${recording.id}_${suffix}.sdp`);

      input.tempFile = tempFile;
      input.sdpFile = sdpFile;

      // 3. Write SDP for the new stream
      const sdpContent = this.buildStreamSdp(input);
      fs.writeFileSync(sdpFile, sdpContent);
      recordingVLog(`  [Recording] Late stream SDP (${suffix}): ${sdpFile}`);

      // 4. Start FFmpeg process for this stream
      const ffmpegArgs = [
        '-y',
        '-protocol_whitelist', 'file,udp,rtp',
        '-analyzeduration', '5000000',
        '-probesize', '5000000',
        '-max_delay', '500000',
        '-reorder_queue_size', '4096',
        '-fflags', '+genpts+igndts',
        '-thread_queue_size', '4096',
        '-rw_timeout', '6000000',
        '-f', 'sdp',
        '-i', sdpFile,
        '-avoid_negative_ts', 'make_zero',
        '-c', 'copy',
        '-flush_packets', '1',
        '-f', fmt,
        tempFile,
      ];

      recordingVLog(`  [FFmpeg] Spawning late (${suffix}): ffmpeg ${ffmpegArgs.join(' ')}`);

      const ffmpeg = spawn('ffmpeg', ffmpegArgs, {
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      ffmpeg.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && (msg.includes('Error') || msg.includes('error') ||
                    msg.includes('Invalid') || msg.includes('failed'))) {
          console.error(`  [FFmpeg ${suffix}] ${msg.substring(0, 300)}`);
        }
      });

      ffmpeg.on('error', (err) => {
        console.error(`  [FFmpeg ${suffix}] Spawn error: ${err.message}`);
      });

      ffmpeg.on('close', (code) => {
        if (code === 0) {
          console.log(`  [FFmpeg ${suffix}] Finished OK → ${tempFile}`);
        } else {
          console.log(`  [FFmpeg ${suffix}] Exited with code ${code}`);
        }
      });

      recording.ffmpegProcesses.push({ process: ffmpeg, suffix, tempFile });
      recording.tempFiles.push(tempFile);
      recording.sdpFiles.push(sdpFile);
      input.ffmpegStarted = true;

      // 5. Wait for FFmpeg to bind its UDP socket, then resume consumer.
      // Use the same readiness probe as startIndividualRecordings — a fixed
      // sleep races on loaded systems and drops early keyframes.
      await new Promise((resolve) => {
        let ready = false;
        const finish = () => { if (!ready) { ready = true; resolve(); } };
        let poll = null;

        const stopPolling = () => {
          if (poll) {
            clearInterval(poll);
            poll = null;
          }
        };

        ffmpeg.stderr.on('data', (chunk) => {
          const s = chunk.toString();
          if (!ready && (s.includes('bind(') || s.includes('for reading') || s.includes('opening'))) {
            finish();
          }
        });
        ffmpeg.on('close', () => {
          stopPolling();
          finish();
        });

        poll = setInterval(() => {
          if (recording.stopped) {
            stopPolling();
            finish();
          }
        }, 200);

        setTimeout(() => {
          stopPolling();
          finish();
        }, 2000); // hard deadline
      });

      if (recording.stopped) {
        // Recording stopped while this late process was still initialising.
        // rw_timeout (6 s) handles the exit; graduated signals as fallback.
        console.log(`  [Recording] Recording stopped during late FFmpeg startup — will exit via rw_timeout (${suffix})`);
        setTimeout(() => {
          if (!ffmpeg.killed && ffmpeg.exitCode === null) {
            console.log(`  [Recording] SIGTERM for late-startup ${suffix}`);
            try { ffmpeg.kill('SIGTERM'); } catch (_) {}
          }
        }, 6000);
        setTimeout(() => {
          if (!ffmpeg.killed && ffmpeg.exitCode === null) {
            console.log(`  [Recording] Emergency SIGKILL for late-startup ${suffix}`);
            try { ffmpeg.kill('SIGKILL'); } catch (_) {}
          }
        }, 10000);
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, 200)); // extra settle
      if (!input.consumer.closed && input.consumer.paused) {
        await input.consumer.resume();
        // Lock the effective start immediately after resume so the timestamp
        // reflects when RTP actually starts arriving at FFmpeg — not when
        // createRecordingInput() allocated the object (seconds earlier).
        if (!input.effectiveStartLocked) {
          input.startOffsetMs = Date.now() - recording.startTime;
          input.effectiveStartLocked = true;
        }
      } else if (!input.effectiveStartLocked) {
        // Consumer already closed (producer disappeared during FFmpeg startup).
        // Mark locked so we don't re-enter; provisional value is the best we have.
        input.effectiveStartLocked = true;
        console.warn(`  [Recording] Late consumer closed before resume (${input.kind} from ${peerId}) — keeping provisional startOffset ${input.startOffsetMs}ms`);
      }
      recordingVLog(`  [Recording] Late consumer resumed: ${input.kind}`);
      recordingVLog(`  [Recording] Effective start: ${input.kind} from ${peerId} at ${input.startOffsetMs}ms`);

      // 6. Request keyframe for video — immediate + 3 bursts at 200 ms
      if (input.kind === 'video') {
        // Immediate keyframe right after resume to minimise black frames
        try {
          await input.consumer.requestKeyFrame();
          recordingVLog(`  [Recording] Late immediate keyframe for ${peerId}`);
        } catch (_) { /* ignore */ }

        for (let burst = 0; burst < 3; burst++) {
          await new Promise((resolve) => setTimeout(resolve, 200));
          try {
            await input.consumer.requestKeyFrame();
            recordingVLog(`  [Recording] Late keyframe burst ${burst + 1} for ${peerId}`);
          } catch (e) {
            console.warn(`  [Recording] Late keyframe request failed: ${e.message}`);
          }
        }
      }
    } catch (error) {
      console.error(`  [Recording] Failed to add late producer to recording:`, error.message);
    }
  }

  /**
   * Stop capture and return raw recording artifacts (no combine yet).
   * This is intended for background/worker combine pipelines.
   */
  async stopRecordingRaw(roomId) {
    const room = this.rooms.get(roomId);
    if (!room || !room.recording) {
      console.log(`[Recording] No active recording for room ${roomId}`);
      return null;
    }

    // ── Grab & clear atomically (before any await) ──
    const recording = room.recording;
    recording.stopped = true;
    room.recording = null;

    // ── Finalize timeline: set endOffsetMs for any stream still recording ──
    // Also close any open pause events (camera was still off at end of call)
    const now = Date.now();
    const stopOffsetMs = Math.max(0, now - recording.startTime);
    recording.stopOffsetMs = stopOffsetMs;
    for (const input of recording.inputs) {
      if (input.endOffsetMs === null) {
        input.endOffsetMs = stopOffsetMs;
      }
      if (input.pauseEvents) {
        for (const pe of input.pauseEvents) {
          if (pe.resumedAtMs === null) {
            pe.resumedAtMs = input.endOffsetMs;
          }
        }
      }
    }

    // Cancel keyframe interval
    if (recording._keyframeInterval) {
      clearInterval(recording._keyframeInterval);
      recording._keyframeInterval = null;
    }

    // ── Phase 1a: Close mediasoup consumers & transports FIRST ──
    // This stops RTP data flow to FFmpeg. Without incoming packets,
    // FFmpeg's RTP reader will time out and exit cleanly, writing
    // a proper container trailer (MKV/OGG). Sending SIGINT/SIGTERM
    // directly causes corrupted files (exit code 255, no trailer).
    console.log('  [Recording] Closing consumers & transports to stop RTP flow…');
    for (const item of recording.consumers) {
      try { (item.consumer || item).close(); } catch (e) {}
    }
    for (const transport of recording.transports) {
      try { transport.close(); } catch (e) {}
    }

    // Release the process-wide FFmpeg port reservations for every input so
    // concurrent and future recordings can reuse them (prevents leak).
    for (const input of recording.inputs) {
      try { releaseRecordingPortPair(input.ffmpegRtpPort, input.ffmpegRtcpPort); } catch (_) {}
    }

    // ── Phase 1b: Wait for FFmpeg processes to exit naturally ──
    // FFmpeg args include -rw_timeout 6000000 (6 s). Once RTP data stops
    // (consumers closed above), the UDP socket will timeout, FFmpeg will
    // write proper container trailers and exit with code 0.
    //
    // rw_timeout was widened from 3 s → 6 s after a race in
    // addProducerToRecording (a late joiner's FFmpeg is spawned, then the
    // mediasoup consumer isn't resumed until an up-to-~2.2 s readiness wait
    // completes) left only ~0.8 s of margin — enough for a single CPU-load
    // blip (a concurrent segment-transcode, another late joiner's keyframe
    // RPCs) to blow the deadline before real RTP ever arrived. FFmpeg then
    // exits with code 0 having read nothing, producing a small-but-nonzero,
    // structurally corrupt Matroska file: "finished OK" in the logs, but
    // unopenable later, which silently failed that user's ENTIRE segment
    // (video included) at extraction time. See also the hasAudio probe in
    // recordingSegmentExtractor.js, which now catches this class of file
    // instead of trusting a nonzero byte count.
    //
    // DO NOT send 'q' to stdin — it triggers a finalization sequence that
    // deadlocks when the RTP socket is already dead (audio_0 hung through
    // SIGTERM, only SIGKILL worked).  Let rw_timeout handle the exit.
    //
    // Timeline:  rw_timeout ~6 s  |  8 s → SIGTERM  |  14 s → SIGKILL

    // ── FFmpeg shutdown wrapped in try/catch: even if FFmpeg processes
    // hang or fail, we STILL return the recording data so raw files on
    // disk can be transcoded.  Losing the return value here is the #1
    // cause of "forgotten" recordings (raw MKA/MKV orphaned forever). ──
    try {
      const stopPromises = (recording.ffmpegProcesses || []).map(({ process: proc, suffix }) => {
        return new Promise((resolve) => {
          let done = false;
          const finish = () => { if (!done) { done = true; resolve(); } };

          proc.on('close', finish);

          // If already dead, resolve immediately
          if (proc.killed || proc.exitCode !== null) {
            finish();
            return;
          }

          recordingVLog(`  [Recording] Waiting for ${suffix} rw_timeout exit…`);

          // After 8 s → SIGTERM (safe for MKA/MKV — writes trailer on exit)
          // Extended from 6 s to give late-joiner FFmpeg processes (spawned by
          // addProducerToRecording mid-call) enough time for rw_timeout to fire.
          setTimeout(() => {
            if (!done && !proc.killed && proc.exitCode === null) {
              console.log(`  [Recording] SIGTERM ${suffix} (rw_timeout did not exit in time)`);
              try { proc.kill('SIGTERM'); } catch (e) {}
            }
          }, 8000);

          // After 14 s → SIGKILL (emergency only)
          setTimeout(() => {
            if (!done) {
              console.log(`  [Recording] SIGKILL ${suffix} (rw_timeout did not exit in time)`);
              try { proc.kill('SIGKILL'); } catch (e) {}
            }
          }, 14000);

          // Hard deadline: resolve after 16 s regardless
          setTimeout(finish, 16000);
        });
      });
      await Promise.all(stopPromises);
      console.log('  [Recording] All stream recorders stopped');

      // Safety net: SIGKILL any FFmpeg processes that may have been appended
      // concurrently after stopPromises was created. Using SIGKILL (not SIGTERM)
      // because SIGTERM/SIGINT cause "Immediate exit requested" which corrupts
      // containers. MKA/MKV can survive SIGKILL by recovering already-written
      // clusters; OGG cannot, but we no longer use OGG.
      for (const { process: proc, suffix } of (recording.ffmpegProcesses || [])) {
        if (!proc.killed && proc.exitCode === null) {
          console.log(`  [Recording] SIGKILL late-added process ${suffix}`);
          try { proc.kill('SIGKILL'); } catch (_) {}
        }
      }
    } catch (ffmpegErr) {
      console.error(`[Recording] ⚠️ FFmpeg shutdown error (salvaging raw files): ${ffmpegErr?.message || ffmpegErr}`);
      // Force-kill all remaining FFmpeg processes so they don't leak
      for (const { process: proc, suffix } of (recording.ffmpegProcesses || [])) {
        if (!proc.killed && proc.exitCode === null) {
          try { proc.kill('SIGKILL'); } catch (_) {}
        }
      }
    }

    // ── Use call stop offset captured BEFORE async FFmpeg shutdown/merge ──
    // This keeps true call length (including rejoin gaps) without including
    // post-call processing time.
    const mediaDuration = stopOffsetMs;
    console.log(`[Recording] Capture stopped: raw artifacts ready (media duration: ${Math.round(mediaDuration / 1000)}s)`);

    return {
      id: recording.id,
      duration: mediaDuration,
      recording,
    };
  }

  /**
   * Build a JSON-serializable snapshot for combine workers.
   */
  createCombineSnapshot(rawRecordingResult) {
    if (!rawRecordingResult?.recording) return null;
    const rec = rawRecordingResult.recording;

    return {
      id: rec.id,
      startTime: rec.startTime,
      stopOffsetMs: rec.stopOffsetMs,
      hasVideo: !!rec.hasVideo,
      inputs: (rec.inputs || []).map(i => ({
        ffmpegRtpPort: i.ffmpegRtpPort,
        ffmpegRtcpPort: i.ffmpegRtcpPort,
        kind: i.kind,
        producerId: i.producerId,
        source: i.source,
        peerId: i.peerId,
        codec: i.codec,
        ssrc: i.ssrc,
        startOffsetMs: i.startOffsetMs,
        endOffsetMs: i.endOffsetMs,
        pauseEvents: Array.isArray(i.pauseEvents) ? i.pauseEvents.map(pe => ({ ...pe })) : [],
        rotation: Number(i.rotation || 0),
        rotationEvents: Array.isArray(i.rotationEvents) ? i.rotationEvents.map(event => ({ ...event })) : [],
        tempFile: i.tempFile,
        sdpFile: i.sdpFile,
      })),
      peerMetaEntries: Array.from((rec.peerMeta || new Map()).entries()),
      clientTimelineEntries: Array.from((rec.clientTimelineReports || new Map()).entries()),
      tempFiles: Array.isArray(rec.tempFiles) ? [...rec.tempFiles] : [],
      sdpFiles: Array.isArray(rec.sdpFiles) ? [...rec.sdpFiles] : [],
      duration: rawRecordingResult.duration,
    };
  }

  /**
   * Cleanup temporary MKV/OGG/SDP artifacts from a snapshot.
   */
  cleanupSnapshotArtifacts(snapshot) {
    if (!snapshot) return;
    for (const f of (snapshot.tempFiles || [])) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
    }
    for (const f of (snapshot.sdpFiles || [])) {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch (_) {}
    }
  }

  /**
   * Build a JSON-serializable snapshot of a raw recording bundle, sufficient to
   * RESUME extractFromRaw() after a process restart. Captures only the fields
   * extractFromRaw reads (raw.id/duration + recording.{id,stopOffsetMs,tempFiles,
   * sdpFiles, inputs (including pause/orientation histories), and peerMeta}).
   * Live RTC handles (consumers, transports, ffmpeg processes) are intentionally
   * dropped — by Phase 2 they're already torn down and the raw files on disk are
   * the only thing that matters. Returns null if the bundle can't be snapshotted.
   */
  buildResumeSnapshot(raw) {
    const rec = raw?.recording;
    if (!rec) return null;
    return {
      id: raw.id ?? rec.id ?? null,
      duration: raw.duration ?? null,
      recording: {
        id: rec.id,
        stopOffsetMs: rec.stopOffsetMs ?? null,
        tempFiles: Array.isArray(rec.tempFiles) ? [...rec.tempFiles] : [],
        sdpFiles: Array.isArray(rec.sdpFiles) ? [...rec.sdpFiles] : [],
        peerMetaEntries: Array.from((rec.peerMeta || new Map()).entries()),
        inputs: (rec.inputs || []).map((i) => ({
          kind: i.kind,
          producerId: i.producerId,
          source: i.source,
          peerId: i.peerId,
          tempFile: i.tempFile,
          startOffsetMs: i.startOffsetMs,
          endOffsetMs: i.endOffsetMs,
          pauseEvents: Array.isArray(i.pauseEvents) ? i.pauseEvents.map(event => ({ ...event })) : [],
          rotation: Number(i.rotation || 0),
          rotationEvents: Array.isArray(i.rotationEvents) ? i.rotationEvents.map(event => ({ ...event })) : [],
        })),
      },
    };
  }

  /**
   * Revive a snapshot from buildResumeSnapshot() into a `raw`-shaped object that
   * extractFromRaw() accepts directly (it reconstructs peerMeta from peerMetaEntries).
   */
  reviveResumeSnapshot(snapshot) {
    if (!snapshot?.recording) return null;
    return {
      id: snapshot.id,
      duration: snapshot.duration,
      recording: { ...snapshot.recording },
    };
  }

  /**
   * True if a resume snapshot's raw capture files still exist on disk. After a
   * crash the raw artifacts are what we resume from; if they're gone (cleaned up,
   * disk wiped) there's nothing to transcode and the job should be abandoned.
   */
  resumeArtifactsExist(snapshot) {
    const temps = snapshot?.recording?.tempFiles || [];
    return temps.some((f) => {
      try { return f && fs.existsSync(f) && fs.statSync(f).size > 0; } catch (_) { return false; }
    });
  }

  /**
   * Phase 2 of recording pipeline: VP8→H.264 transcoding + audio muxing.
   * Takes the raw artifact bundle returned by stopRecordingRaw() and produces
   * the final per-user MP4 segments.  Separated from stopRecordingRaw so the
   * CPU-heavy transcoding can run in a background queue while the room is
   * already torn down.
   *
   * @param {object} raw  Result from stopRecordingRaw()
   * @param {string|null} dbCallId  DB call ID to associate segments with
   */
  async extractFromRaw(raw, dbCallId = null) {
    if (!raw) return null;

    const recording = raw.recording;
    recording.peerMeta = recording.peerMeta instanceof Map
      ? recording.peerMeta
      : new Map(recording.peerMetaEntries || []);

    const effectiveCallId = dbCallId || recording.id;
    console.log(`[RecordingQueue] ▶ Starting transcoding for call ${effectiveCallId}`);
    const phaseStart = Date.now();

    // ── Phase 2: Extract per-segment media files (no merging, no black frames) ──
    console.log('  [Recording] Starting segment extraction phase…');
    const segmentExtractor = require('./recordingSegmentExtractor');

    // Build raw recording files list grouped by user
    const userFilesMap = new Map();

    const pickBestExistingFile = (candidates = [], kind, userId) => {
      if (!Array.isArray(candidates) || candidates.length === 0) return null;

      const existing = candidates
        .map((f) => {
          if (!f || !fs.existsSync(f)) return null;
          try {
            const size = fs.statSync(f).size;
            return { path: f, size };
          } catch (_) {
            return null;
          }
        })
        .filter(e => e && e.size > 0)
        .sort((a, b) => b.size - a.size);

      if (existing.length === 0) {
        console.warn(`[Recording] No existing ${kind} files for user ${userId}; candidates=${JSON.stringify(candidates)}`);
        return null;
      }

      if (existing.length > 1) {
        recordingVLog(`  [Recording] Multiple ${kind} candidates for ${userId}; picked largest ${existing[0].path}`);
      }

      return existing[0].path;
    };

    for (const input of recording.inputs) {
      const meta = recording.peerMeta.get(input.peerId) || { username: input.peerId, userId: null };
      const userId = meta.userId || input.peerId;
      const key = String(userId);

      if (!userFilesMap.has(key)) {
        userFilesMap.set(key, {
          userId,
          username: meta.username,
          peerId: input.peerId,
          videoCandidates: [],
          audioCandidates: [],
          videoTracks: [],
          audioTracks: [],
          videoFile: null,
          audioFile: null
        });
      }

      const userRec = userFilesMap.get(key);
      if (input.kind === 'video') {
        if (input.tempFile) {
          userRec.videoCandidates.push(input.tempFile);
          userRec.videoTracks.push({
            file: input.tempFile,
            startMs: Number(input.startOffsetMs || 0),
            endMs: Number(input.endOffsetMs ?? recording.stopOffsetMs ?? raw.duration ?? 0),
            // Server-stamped camera pause/resume windows (recording.startTime clock).
            // The segment extractor uses these to derive authoritative camera-on
            // windows — no client metadata involved. See recordingTimeline.js.
            pauseEvents: Array.isArray(input.pauseEvents) ? input.pauseEvents : [],
            // Client-reported display rotation, baked at transcode (see extractor).
            rotation: Number(input.rotation || 0),
            rotationEvents: Array.isArray(input.rotationEvents) ? input.rotationEvents : [],
          });
        }
      } else if (input.kind === 'audio') {
        if (input.tempFile) {
          userRec.audioCandidates.push(input.tempFile);
          userRec.audioTracks.push({
            file: input.tempFile,
            startMs: Number(input.startOffsetMs || 0),
            endMs: Number(input.endOffsetMs ?? recording.stopOffsetMs ?? raw.duration ?? 0),
          });
        }
      }
    }

    // Resolve best existing media files per user for backward compatibility.
    // New extractor path can consume videoTracks/audioTracks directly.
    for (const [, userRec] of userFilesMap) {
      userRec.videoFile = pickBestExistingFile(userRec.videoCandidates, 'video', userRec.userId);
      userRec.audioFile = pickBestExistingFile(userRec.audioCandidates, 'audio', userRec.userId);

      userRec.videoTracks = (userRec.videoTracks || [])
        .filter((t) => t?.file && fs.existsSync(t.file))
        .sort((a, b) => (a.startMs || 0) - (b.startMs || 0));
      userRec.audioTracks = (userRec.audioTracks || [])
        .filter((t) => t?.file && fs.existsSync(t.file))
        .sort((a, b) => (a.startMs || 0) - (b.startMs || 0));
    }

    const rawRecordings = Array.from(userFilesMap.values());
    console.log(`[Recording] Found raw files for ${rawRecordings.length} users`);

    // Extract segments for all users
    const outputFiles = [];
    try {
      const extractedByUser = await segmentExtractor.processCallRecordings(effectiveCallId, rawRecordings);

      for (const userResult of extractedByUser) {
        outputFiles.push({
          userId: userResult.userId,
          username: userResult.username,
          videoSegments: userResult.videoSegments || [],
          audioFile: userResult.audioFile || null,
          stitchedFile: userResult.stitchedFile || null
        });
      }

      // ── Compose ONE playable artifact per call ──────────────────────────────
      // Grid video + mixed audio on the shared server clock. This is the primary
      // playback surface (single decoder/timeline/scrubber on the client). Kept in
      // its own try/catch: a compositor failure must never lose the per-user
      // segments already extracted above.
      try {
        const compositor = require('./recordingCompositor');
        await compositor.composeCall(effectiveCallId, extractedByUser);
      } catch (composeError) {
        console.error('[Recording] Composite generation error:', composeError.message);
      }
    } catch (extractError) {
      console.error('[Recording] Segment extraction error:', extractError.message);
    }

    // ── Cleanup raw temp files (MKV/OGG) ──
    // Safety net for crash/disconnect scenarios: if a user had raw files but no
    // processed metadata result, preserve those raw artifacts for recovery.
    const processedIdentities = new Set(
      outputFiles.flatMap((f) => [String(f.userId || ''), String(f.peerId || '')]).filter(Boolean)
    );
    const usersMissingProcessedOutput = rawRecordings.filter((u) => {
      const uid = String(u.userId || '');
      const pid = String(u.peerId || '');
      return !processedIdentities.has(uid) && !processedIdentities.has(pid);
    });

    const preserveTempFiles = new Set();
    for (const userRec of usersMissingProcessedOutput) {
      for (const f of (userRec.videoCandidates || [])) if (f) preserveTempFiles.add(f);
      for (const f of (userRec.audioCandidates || [])) if (f) preserveTempFiles.add(f);
      if (userRec.videoFile) preserveTempFiles.add(userRec.videoFile);
      if (userRec.audioFile) preserveTempFiles.add(userRec.audioFile);
    }

    if (usersMissingProcessedOutput.length > 0) {
      console.warn(
        `[Recording] Preserving raw files for ${usersMissingProcessedOutput.length} user(s) without processed metadata output`
      );
    }

    const tempFilesToDelete = (recording.tempFiles || []).filter((f) => !preserveTempFiles.has(f));
    this.cleanupSnapshotArtifacts({ tempFiles: tempFilesToDelete, sdpFiles: recording.sdpFiles });

    const fileCount = outputFiles.length;
    const elapsedSec = ((Date.now() - phaseStart) / 1000).toFixed(1);
    console.log(`[RecordingQueue] ✓ Transcoding done for call ${effectiveCallId}: ${fileCount} user(s), took ${elapsedSec}s`);

    return {
      id: raw.id,
      duration: raw.duration,
      files: outputFiles, // Array of { userId, username, videoSegments[], audioFile }
    };
  }

  /**
   * Stop recording a room and immediately run extraction.
   * Kept for backward compatibility; prefer stopRecordingRaw + extractFromRaw
   * with a background queue for production use.
   */
  async stopRecording(roomId, dbCallId = null) {
    const raw = await this.stopRecordingRaw(roomId);
    return await this.extractFromRaw(raw, dbCallId);
  }

  /**
   * Add peer to room
   * @param {string} profilePicture - relative URL like '/uploads/abc.jpg' (optional)
   */
  async addPeer(roomId, peerId, username, announcedIp, profilePicture, userId, callAttemptId = null, socketId = peerId) {
    let room = await this.getOrCreateRoom(roomId, announcedIp);
    // Even returning an already-existing room crosses an await boundary. The
    // last old peer can remove/close it during that yield. Re-acquire the
    // canonical open room before the synchronous peer insertion below.
    if (this.rooms.get(roomId) !== room || room.router.closed) {
      room = await this.getOrCreateRoom(roomId, announcedIp);
    }
    if (this.rooms.get(roomId) !== room || room.router.closed) {
      throw new Error(`Room ${roomId} changed while adding peer`);
    }

    // Safeguard: if this peerId already exists in the room (rapid leave+rejoin
    // before the async leave handler finished), clean up the stale entry first.
    if (room.peers.has(peerId)) {
      const oldPeer = room.peers.get(peerId);
      console.log(`[MediaServer] Cleaning up stale peer entry for ${username} (rapid rejoin)`);
      for (const [, producer] of oldPeer.producers) {
        try { producer.close(); } catch (_) {}
      }
      for (const [, consumer] of oldPeer.consumers) {
        try { consumer.close(); } catch (_) {}
      }
      if (oldPeer.sendTransport) try { oldPeer.sendTransport.close(); } catch (_) {}
      if (oldPeer.recvTransport) try { oldPeer.recvTransport.close(); } catch (_) {}
      room.peers.delete(peerId);
      this.peers.delete(peerId);
    }

    const peer = {
      id: peerId,
      username,
      userId: userId || null,
      // Signaling room ids can be reused by an immediate redial. Keep the
      // attempt identity on the media peer so a late disconnect from call A
      // cannot finalize call B merely because both used the same room id.
      callAttemptId: callAttemptId ? String(callAttemptId) : null,
      profilePicture: profilePicture || null,
      sendTransport: null,
      recvTransport: null,
      producers: new Map(),
      consumers: new Map(),
      rtpCapabilities: null,
    };

    room.peers.set(peerId, peer);
    this.peers.set(peerId, { roomId, peer, socketId });
    if (!this.socketPeers.has(socketId)) this.socketPeers.set(socketId, new Set());
    this.socketPeers.get(socketId).add(peerId);

    mediaVLog(`[MediaServer] Peer ${username} joined room ${roomId}`);

    return {
      routerRtpCapabilities: room.router.rtpCapabilities,
    };
  }

  /**
   * Set peer's RTP capabilities
   */
  setPeerRtpCapabilities(roomId, peerId, rtpCapabilities) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const peer = room.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);

    peer.rtpCapabilities = rtpCapabilities;
  }

  /**
   * Check if a peer exists in a room
   */
  hasPeer(roomId, peerId) {
    const room = this.rooms.get(roomId);
    return room ? room.peers.has(peerId) : false;
  }

  /**
   * The media room this peerId occupies, or null.
   *
   * Calls always use `peerId === socket.id`, so `getPeerRoomId(socket.id)` is
   * still exactly "is this socket in a call" — PTT no longer uses the bare
   * socket id as its peerId (see getPeerIdsForSocket), so this can no longer
   * collide with a PTT membership. Callers that need to know about ALL of a
   * socket's peers (a socket can now hold several at once — one call peer XOR
   * several PTT channel peers) want getPeerIdsForSocket instead.
   */
  getPeerRoomId(peerId) {
    return this.peers.get(peerId)?.roomId || null;
  }

  /**
   * Every peerId currently registered under a socket, across every room.
   * Before PTT multi-channel listening, a socket held at most one peerId
   * (itself). Now it can hold one call peer OR several PTT channel peers
   * (`ptt:<socketId>:<channelId>`) simultaneously — this is how disconnect
   * cleanup and call/PTT mutual-exclusion enforcement enumerate them, and how
   * generic handlers verify a client-claimed peerId actually belongs to the
   * socket asserting it (see resolveOwnedPeerId in server.js) rather than
   * trusting an arbitrary client-supplied string.
   */
  getPeerIdsForSocket(socketId) {
    return Array.from(this.socketPeers.get(socketId) || []);
  }

  /**
   * Number of peers currently joined to a room's SFU (0 if the room doesn't exist).
   * Used as a "media established" signal: the caller joins during ringing, so >= 2 peers
   * means BOTH parties are in the room — the call connected and must never be recorded as
   * a missed call, even under a signaling-clock race where answeredAt wasn't stamped yet.
   */
  getPeerCount(roomId) {
    const room = this.rooms.get(roomId);
    return room ? room.peers.size : 0;
  }

  /**
   * Store transport for peer
   */
  storePeerTransport(roomId, peerId, transport, direction) {
    const room = this.rooms.get(roomId);
    if (!room) throw new Error(`Room ${roomId} not found`);

    const peer = room.peers.get(peerId);
    if (!peer) throw new Error(`Peer ${peerId} not found`);

    if (direction === 'send') {
      peer.sendTransport = transport;
    } else {
      peer.recvTransport = transport;
    }
  }

  /**
   * Remove peer from room
   * AUTO-RECORDING: Stops recording when call ends (less than 2 peers with producers)
   */
  removePeer(peerId) {
    const peerInfo = this.peers.get(peerId);
    if (!peerInfo) return;

    const { roomId, peer, socketId = peerId } = peerInfo;
    const room = this.rooms.get(roomId);

    if (room) {
      // Close all producers
      for (const [, producer] of peer.producers) {
        producer.close();
      }

      // Close all consumers
      for (const [, consumer] of peer.consumers) {
        consumer.close();
      }

      // Close transports
      if (peer.sendTransport) peer.sendTransport.close();
      if (peer.recvTransport) peer.recvTransport.close();

      room.peers.delete(peerId);
      mediaVLog(`[MediaServer] Peer ${peer.username} left room ${roomId}`);

      // NOTE: Recording stop is NOT triggered here. The caller
      // (leave_media_room / disconnect handler) is responsible for
      // awaiting stopRecording so it can capture the result and save
      // it to the DB. A fire-and-forget call here would race with
      // the handler's own await and lose the recording result.

      // Clean up empty room — but only if there is no active recording.
      // If a recording is in progress, the room must stay alive until
      // stopRecording finishes (it references room.recording).
      if (room.peers.size === 0 && !room.recording) {
        room.router.close();
        this.rooms.delete(roomId);
        console.log(`[MediaServer] Room ${roomId} closed (empty)`);
      }
    }

    this.peers.delete(peerId);
    const siblingPeers = this.socketPeers.get(socketId);
    if (siblingPeers) {
      siblingPeers.delete(peerId);
      if (siblingPeers.size === 0) this.socketPeers.delete(socketId);
    }
  }

  /**
   * Get all producers in a room (except from the requesting peer)
   */
  getProducers(roomId, excludePeerId) {
    const room = this.rooms.get(roomId);
    if (!room) return [];

    const producers = [];
    for (const [peerId, peer] of room.peers) {
      if (peerId === excludePeerId) continue;
      for (const [producerId, producer] of peer.producers) {
        if (producer.closed) continue;
        producers.push({
          producerId,
          peerId,
          userId: peer.userId,
          username: peer.username,
          kind: producer.kind,
          paused: !!producer.paused,
          appData: producer.appData || {},
        });
      }
    }

    return producers;
  }

  /**
   * Get local IP address
   */
  getLocalIp() {
    const os = require('os');
    const interfaces = os.networkInterfaces();

    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }

    return '127.0.0.1';
  }

  /**
   * Get room stats
   */
  getRoomStats(roomId) {
    const room = this.rooms.get(roomId);
    if (!room) return null;

    return {
      id: roomId,
      peerCount: room.peers.size,
      isRecording: !!room.recording,
      createdAt: room.createdAt,
      peers: Array.from(room.peers.values()).map(p => ({
        id: p.id,
        username: p.username,
        producerCount: p.producers.size,
        consumerCount: p.consumers.size,
      })),
    };
  }

  /**
   * Get best-effort call-relative base offset for a peer's latest recording session.
   * Used to rebase client metadata timestamps on leave/rejoin flows where the
   * client restarts its local call timer from 0.
   *
   * IMPORTANT: Only return a non-zero offset when the peer has MORE THAN ONE
   * recording input of this kind — that signals a rejoin where the client's
   * local timer reset to 0.  For a first-time join the client timestamps
   * already start at 0 relative to their call start and should NOT be shifted.
   */
  getPeerRecordingSessionBaseOffset(roomId, peerId, kind = 'video') {
    const room = this.rooms.get(roomId);
    const recording = room?.recording;
    if (!recording || !Array.isArray(recording.inputs)) return null;

    const matches = recording.inputs
      .filter((i) => i?.peerId === peerId && i?.kind === kind)
      .sort((a, b) => Number(b.startOffsetMs || 0) - Number(a.startOffsetMs || 0));

    if (matches.length === 0) return null;

    // First-time join: only one session → no rebasing needed
    if (matches.length === 1) return 0;

    // Rejoin: return the latest session's start offset
    return Number(matches[0].startOffsetMs || 0);
  }
}

module.exports = { MediaServer, config, isPttMediaRoom };

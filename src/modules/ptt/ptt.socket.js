'use strict';

/**
 * PTT realtime control + dedicated media signalling.
 *
 * Logical channels belonging to one workspace share a mediasoup Router and one
 * socket-owned peer. This lets a phone listen to many channels with one receive
 * transport while authorization stays channel-scoped at every producer and
 * consumer operation. Generic call media events are intentionally not used.
 */
const pttService = require('./ptt.service');
const pttRuntime = require('./ptt.runtime');
const { FloorLease, LEASE_TTL_MS } = require('./floorLease');
const { createPttRecorder } = require('./ptt.recording');
const { userTransportCount, userProducerCount } = require('../../app/state');

const MAX_CHANNELS_PER_SOCKET = 100;
const MAX_SHARDS_PER_SOCKET = 16;

module.exports = function createPttSocket({
  io,
  mediaServer,
  connectedUsers,
  serverIp,
  socketRateLimiter = null,
}) {
  const floors = new FloorLease();
  const recorder = createPttRecorder({ mediaServer, io, connectedUsers });
  const recoveryCutoff = new Date();
  pttService.recoverOpenTransmissions(recoveryCutoff)
    .then(count => {
      if (count > 0) console.log(`[PTT] Recovered ${count} open transmission(s) after restart`);
    })
    .catch(error => console.warn('[PTT] Open-transmission recovery failed:', error.message));

  /** channelId -> Map<socketId, trusted actor> */
  const presence = new Map();
  /** socketId -> Set<channelId> */
  const socketChannels = new Map();
  /** socketId -> Map<workspaceId, shard session> */
  const socketShards = new Map();
  /** producerId -> immutable PTT routing metadata */
  const producerIndex = new Map();
  /** channelId -> {transmissionId, insertPromise, producerId?} */
  const openTransmissions = new Map();
  const joinLocks = new Map();
  const inFlightProducers = new Set();
  const deletingWorkspaces = new Set();

  const channelRoom = channelId => `ptt-presence:${channelId}`;
  const sharedPeerId = (socketId, workspaceId) => `ptt-shard:${socketId}:${workspaceId}`;
  const isWorkspaceDeleting = workspaceId => deletingWorkspaces.has(String(workspaceId));

  function actorOf(socket) {
    // PTT cannot use the JWT-only pre-registration fallback. register_user is
    // where account/workspace suspension is checked; accepting PTT before it
    // would reopen that bypass.
    const registered = connectedUsers.get(socket.id);
    if (!registered?.userId) return null;
    return {
      userId: registered.userId,
      username: registered.username || registered.fullName || 'Unknown',
      fullName: registered.fullName || registered.username || 'Unknown',
      profilePicture: registered.profilePicture || null,
      deviceId: registered.deviceId || socket.deviceId || null,
    };
  }

  function participantsOf(channelId) {
    const byUser = new Map();
    for (const actor of presence.get(channelId)?.values() || []) {
      const key = String(actor.userId);
      const existing = byUser.get(key);
      byUser.set(key, {
        userId: actor.userId,
        username: actor.username,
        fullName: actor.fullName,
        profilePicture: actor.profilePicture || existing?.profilePicture || null,
        deviceCount: (existing?.deviceCount || 0) + 1,
      });
    }
    return Array.from(byUser.values());
  }

  function shardMap(socketId) {
    if (!socketShards.has(socketId)) socketShards.set(socketId, new Map());
    return socketShards.get(socketId);
  }

  function sessionForChannel(socketId, channelId) {
    for (const session of socketShards.get(socketId)?.values() || []) {
      if (session.channels.has(channelId)) return session;
    }
    return null;
  }

  function sessionFromPayload(socket, payload = {}) {
    const byChannel = payload.channelId
      ? sessionForChannel(socket.id, payload.channelId)
      : null;
    const candidates = Array.from(socketShards.get(socket.id)?.values() || []);
    const session = byChannel || candidates.find(item => item.roomId === payload.roomId) || null;
    if (!session) return null;
    if (payload.roomId && payload.roomId !== session.roomId) return null;
    return session;
  }

  function serializeTransport(transport) {
    return {
      success: true,
      id: transport.id,
      iceParameters: transport.iceParameters,
      iceCandidates: transport.iceCandidates,
      dtlsParameters: transport.dtlsParameters,
    };
  }

  function rateAllowed(socket, eventName, respond) {
    if (!socketRateLimiter || socketRateLimiter.isAllowed(socket.id, eventName)) return true;
    respond?.({ success: false, error: 'rate_limited', reason: 'rate_limited' });
    return false;
  }

  async function withJoinLock(socketId, task) {
    const previous = joinLocks.get(socketId) || Promise.resolve();
    const current = previous.catch(() => {}).then(task);
    joinLocks.set(socketId, current);
    try {
      return await current;
    } finally {
      if (joinLocks.get(socketId) === current) joinLocks.delete(socketId);
    }
  }

  function emitFloorEnded(floor, reason) {
    io.to(channelRoom(floor.channelId)).emit('ptt:floor_released', {
      channelId: floor.channelId,
      transmissionId: floor.transmissionId,
      reason,
    });
    io.to(channelRoom(floor.channelId)).emit('ptt:speaker_stopped', {
      channelId: floor.channelId,
      userId: floor.userId,
    });
  }

  function emitProducerClosed(meta, reason = 'closed') {
    const payload = {
      channelId: meta.channelId,
      roomId: meta.roomId,
      peerId: meta.peerId,
      producerId: meta.producerId,
      transmissionId: meta.transmissionId,
      reason,
      appData: {
        pttChannelId: meta.channelId,
        pttTransmissionId: meta.transmissionId,
      },
    };
    io.to(channelRoom(meta.channelId)).emit('ptt:producer_closed', payload);
  }

  function closeIndexedProducer(meta, reason = 'closed') {
    if (!meta) return false;
    producerIndex.delete(meta.producerId);
    const entry = openTransmissions.get(meta.channelId);
    if (entry?.producerId === meta.producerId) entry.producerId = null;
    recorder.stop(meta.transmissionId).catch(error =>
      console.warn('[PTT] recorder stop failed:', error.message));
    const closed = mediaServer.closeProducer(meta.roomId, meta.peerId, meta.producerId);
    if (closed) {
      userProducerCount.set(meta.peerId, Math.max(0, (userProducerCount.get(meta.peerId) || 1) - 1));
      emitProducerClosed(meta, reason);
    }
    return !!closed;
  }

  function closeProducerForTransmission(channelId, transmissionId, reason) {
    const entry = openTransmissions.get(channelId);
    if (!entry || entry.transmissionId !== transmissionId || !entry.producerId) return;
    const meta = producerIndex.get(entry.producerId);
    if (meta) closeIndexedProducer(meta, reason);
  }

  async function closeTransmission(channelId, transmissionId, reason) {
    const entry = openTransmissions.get(channelId);
    if (!entry || entry.transmissionId !== transmissionId) return;
    openTransmissions.delete(channelId);
    let inserted = false;
    try {
      await entry.insertPromise;
      inserted = true;
    } catch (error) {
      console.warn('[PTT] beginTransmission failed:', error.message);
    }
    if (!inserted) {
      const audio = await recorder.stop(transmissionId).catch(() => null);
      recorder.discard(audio);
      return;
    }

    // History state must not depend on optional FFmpeg conversion. Mark the
    // transmission ended as soon as its insert exists; recording finalization
    // may take tens of seconds and attaches audio in a second idempotent update.
    let ended = false;
    try {
      await pttService.endTransmission(transmissionId, reason);
      ended = true;
    } catch (error) {
      console.warn('[PTT] endTransmission failed:', error.message);
    }
    const audio = await recorder.stop(transmissionId).catch(error => {
      console.warn('[PTT] recording finalization failed:', error.message);
      return null;
    });
    if (!audio) {
      if (!ended) {
        pttService.endTransmission(transmissionId, reason).catch(error =>
          console.warn('[PTT] endTransmission retry failed:', error.message));
      }
      return;
    }
    try {
      await pttService.attachTransmissionAudio(transmissionId, reason, audio);
      io.to(channelRoom(channelId)).emit('ptt:recording_ready', {
        channelId,
        transmissionId,
        speakerUserId: entry.userId || null,
      });
    } catch (error) {
      recorder.discard(audio);
      console.warn('[PTT] attachTransmissionAudio failed:', error.message);
    }
  }

  function finishFloor(floor, reason) {
    closeProducerForTransmission(floor.channelId, floor.transmissionId, reason);
    emitFloorEnded(floor, reason);
    closeTransmission(floor.channelId, floor.transmissionId, reason).catch(error =>
      console.warn('[PTT] transmission close failed:', error.message));
  }

  floors.onExpire(({ floor, reason }) => {
    finishFloor(floor, reason);
    console.log(`[PTT] floor ${reason} on ${floor.channelId} (was ${floor.username})`);
  });
  floors.start();

  function removeShardIfEmpty(socket, session) {
    if (session.channels.size > 0) return;
    try { mediaServer.removePeer(session.peerId); } catch (_) {}
    userTransportCount.delete(session.peerId);
    userProducerCount.delete(session.peerId);
    const shards = socketShards.get(socket.id);
    shards?.delete(session.workspaceId);
    if (shards?.size === 0) socketShards.delete(socket.id);
  }

  function leaveChannel(socket, channelId, { notify = true, reason = 'left' } = {}) {
    const session = sessionForChannel(socket.id, channelId);
    const wasPresent = presence.get(channelId)?.has(socket.id) || false;
    const actor = actorOf(socket);

    const floor = floors.get(channelId);
    if (floor?.socketId === socket.id) {
      const released = floors.release(channelId, {
        userId: floor.userId,
        socketId: socket.id,
        transmissionId: floor.transmissionId,
      });
      const terminationReason = reason === 'disconnect'
        ? 'disconnect'
        : [
          'access_revoked',
          'channel_deleted',
          'workspace_access_revoked',
          'workspace_deleted',
          'account_access_revoked',
        ].includes(reason)
          ? 'revoked'
          : 'released';
      if (released.ok) finishFloor(released.floor, terminationReason);
    }

    for (const meta of Array.from(producerIndex.values())) {
      if (meta.socketId === socket.id && meta.channelId === channelId) {
        closeIndexedProducer(meta, reason);
      }
    }

    const members = presence.get(channelId);
    if (members?.delete(socket.id) && members.size === 0) presence.delete(channelId);
    const channels = socketChannels.get(socket.id);
    channels?.delete(channelId);
    if (channels?.size === 0) socketChannels.delete(socket.id);
    socket.leave(channelRoom(channelId));

    if (session) {
      session.channels.delete(channelId);
      mediaServer.closeConsumersForPttChannel(session.roomId, session.peerId, channelId);
      removeShardIfEmpty(socket, session);
    }

    if (notify && wasPresent) {
      io.to(channelRoom(channelId)).emit('ptt:user_left', {
        channelId,
        userId: actor?.userId || null,
        participants: participantsOf(channelId),
        reason,
      });
    }
  }

  function evictForCall(socket) {
    const channels = Array.from(socketChannels.get(socket.id) || []);
    for (const channelId of channels) leaveChannel(socket, channelId, { reason: 'call_started' });
    return channels;
  }

  function socketHoldsFloor(roomId, socketId, channelId = null) {
    const resolvedChannel = channelId || pttService.channelIdFromRoomId(roomId);
    if (!resolvedChannel) return false;
    return floors.get(resolvedChannel)?.socketId === socketId;
  }

  async function ensureShard(socket, actor, access) {
    const workspaceId = access.channel.workspaceId;
    const shards = shardMap(socket.id);
    let session = shards.get(workspaceId);
    if (session && mediaServer.hasPeer(session.roomId, session.peerId)) return session;
    if (session) shards.delete(workspaceId);
    if (shards.size >= MAX_SHARDS_PER_SOCKET) throw new Error('PTT shard limit reached');

    const roomId = pttService.pttShardRoomId(workspaceId);
    const peerId = sharedPeerId(socket.id, workspaceId);
    const result = await mediaServer.addPeer(
      roomId, peerId, actor.username, serverIp, null, actor.userId, null, socket.id,
    );
    session = {
      workspaceId,
      roomId,
      peerId,
      channels: new Set(),
      routerRtpCapabilities: result.routerRtpCapabilities,
    };
    shards.set(workspaceId, session);
    return session;
  }

  async function reauthorizeJoined(socket, channelId) {
    const actor = actorOf(socket);
    if (!actor || !presence.get(channelId)?.has(socket.id)) return null;
    return pttService.resolveAccess(actor.userId, channelId);
  }

  function registerPttHandlers(socket) {
    // Cold/headless clients connect before register_user's DB work has
    // necessarily finished. This explicit readiness probe lets them wait for
    // the trusted connectedUsers entry instead of racing ptt:join and clipping
    // the beginning of a short transmission with a "Not registered" retry.
    socket.on('ptt:registration_ready', (_payload = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      const actor = actorOf(socket);
      respond({
        success: Boolean(actor?.userId),
        ...(actor?.deviceId ? { deviceId: actor.deviceId } : {}),
      });
    });

    socket.on('ptt:join', ({ channelId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_join', respond)) return;
      withJoinLock(socket.id, async () => {
        const actor = actorOf(socket);
        if (!actor) return respond({ success: false, error: 'Not registered' });
        if (typeof channelId !== 'string' || !channelId) {
          return respond({ success: false, error: 'Invalid channel' });
        }
        const access = await pttService.resolveAccess(actor.userId, channelId);
        if (!access) return respond({ success: false, error: 'Channel not found' });
        if (isWorkspaceDeleting(access.channel.workspaceId)) {
          return respond({ success: false, error: 'Channel not found' });
        }
        if (!socket.connected) return;
        if (!socketChannels.get(socket.id)?.has(channelId) &&
            (socketChannels.get(socket.id)?.size || 0) >= MAX_CHANNELS_PER_SOCKET) {
          return respond({ success: false, error: 'PTT channel limit reached' });
        }
        if (mediaServer.getPeerRoomId(socket.id)) {
          return respond({ success: false, error: 'busy_in_call', reason: 'busy_in_call' });
        }

        const session = await ensureShard(socket, actor, access);
        if (!socket.connected) {
          removeShardIfEmpty(socket, session);
          return;
        }
        if (isWorkspaceDeleting(access.channel.workspaceId)) {
          removeShardIfEmpty(socket, session);
          return respond({ success: false, error: 'Channel not found' });
        }
        // ensureShard awaits mediasoup allocation. A regular call can finish
        // joining during that await after the first busy check but before this
        // channel enters presence. Recheck now; if the call won, reclaim the
        // still-empty PTT shard and refuse the join. There is no await between
        // this check and presence insertion, so the inverse interleaving is
        // handled by join_media_room's evictForCall immediately afterward.
        if (mediaServer.getPeerRoomId(socket.id)) {
          removeShardIfEmpty(socket, session);
          return respond({ success: false, error: 'busy_in_call', reason: 'busy_in_call' });
        }
        session.channels.add(channelId);
        if (!presence.has(channelId)) presence.set(channelId, new Map());
        presence.get(channelId).set(socket.id, actor);
        if (!socketChannels.has(socket.id)) socketChannels.set(socket.id, new Set());
        socketChannels.get(socket.id).add(channelId);
        socket.join(channelRoom(channelId));

        const holder = floors.get(channelId);
        const media = {
          shardId: session.workspaceId,
          roomId: session.roomId,
          peerId: session.peerId,
          routerRtpCapabilities: session.routerRtpCapabilities,
        };
        respond({
          success: true,
          media,
          roomId: media.roomId,
          peerId: media.peerId,
          routerRtpCapabilities: media.routerRtpCapabilities,
          channel: access.channel,
          canTransmit: access.canTransmit,
          isModerator: access.isModerator,
          participants: participantsOf(channelId),
          heartbeatMs: Math.floor(LEASE_TTL_MS / 3),
          speaker: holder ? {
            userId: holder.userId,
            username: holder.username,
            transmissionId: holder.transmissionId,
          } : null,
        });
        socket.to(channelRoom(channelId)).emit('ptt:user_joined', {
          channelId,
          participant: {
            userId: actor.userId, username: actor.username, fullName: actor.fullName,
          },
          participants: participantsOf(channelId),
        });
      }).catch(error => {
        console.error('[PTT] join error:', error.message);
        respond({ success: false, error: 'Could not join channel' });
      });
    });

    socket.on('ptt:standby', ({ channelId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        if (typeof channelId !== 'string' || !channelId) {
          return respond({ success: false, error: 'Invalid channel' });
        }
        leaveChannel(socket, channelId, { reason: 'standby' });
        respond({ success: true });
      } catch (_) {
        respond({ success: false, error: 'Could not enter standby' });
      }
    });

    socket.on('ptt:leave', async ({ channelId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const actor = actorOf(socket);
        if (!actor) return respond({ success: false, error: 'Not registered' });
        if (typeof channelId !== 'string' || !channelId) {
          return respond({ success: false, error: 'Invalid channel' });
        }
        leaveChannel(socket, channelId, { reason: 'left' });
        respond({ success: true });
      } catch (error) {
        console.error('[PTT] leave error:', error.message);
        respond({ success: false, error: 'Could not leave channel' });
      }
    });

    socket.on('ptt:set_rtp_capabilities', ({ channelId, roomId, rtpCapabilities } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
        mediaServer.setPeerRtpCapabilities(session.roomId, session.peerId, rtpCapabilities);
        respond({ success: true });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:create_transport', async ({ channelId, roomId, direction } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_create_transport', respond)) return;
      try {
        await withJoinLock(`${socket.id}:transport:${direction}`, async () => {
          if (!['send', 'recv'].includes(direction)) {
            return respond({ success: false, error: 'Invalid transport direction' });
          }
          const session = sessionFromPayload(socket, { channelId, roomId });
          if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
          const existing = mediaServer.getPeerTransport(session.roomId, session.peerId, direction);
          if (existing && !existing.closed) return respond(serializeTransport(existing));
          let count = userTransportCount.get(session.peerId) || 0;
          if (existing?.closed) {
            count = Math.max(0, count - 1);
            userTransportCount.set(session.peerId, count);
          }
          if (count >= 2) return respond({ success: false, error: 'Transport limit reached' });
          const result = await mediaServer.createWebRtcTransport(
            session.roomId, session.peerId, serverIp,
          );
          if (!socket.connected || !mediaServer.hasPeer(session.roomId, session.peerId)) {
            try { result.transport.close(); } catch (_) {}
            return;
          }
          mediaServer.storePeerTransport(session.roomId, session.peerId, result.transport, direction);
          userTransportCount.set(
            session.peerId,
            (userTransportCount.get(session.peerId) || 0) + 1,
          );
          respond(serializeTransport(result.transport));
        });
      } catch (error) {
        console.error('[PTT] create_transport error:', error.message);
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:connect_transport', async ({ channelId, roomId, transportId, dtlsParameters } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
        await mediaServer.connectPeerTransport(
          session.roomId, session.peerId, transportId, dtlsParameters,
        );
        respond({ success: true });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:get_producers', async ({ channelId, roomId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
        const requestedChannels = channelId ? [channelId] : Array.from(session.channels);
        const authorized = new Set();
        for (const candidate of requestedChannels) {
          if (session.channels.has(candidate) && await reauthorizeJoined(socket, candidate)) {
            authorized.add(candidate);
          }
        }
        const producers = mediaServer.getProducers(session.roomId, session.peerId)
          .filter(item => authorized.has(item.appData?.pttChannelId))
          .map(item => ({
            ...item,
            channelId: item.appData.pttChannelId,
            transmissionId: item.appData.pttTransmissionId,
            roomId: session.roomId,
          }));
        respond({ success: true, producers });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:consume', async ({ channelId, roomId, producerId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_consume', respond)) return;
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
        const source = mediaServer.getProducerInfo(session.roomId, producerId);
        const producerChannelId = source?.appData?.pttChannelId;
        if (!source || !producerChannelId ||
            (channelId && String(channelId) !== String(producerChannelId)) ||
            !session.channels.has(producerChannelId)) {
          return respond({ success: false, error: 'Producer is not in an authorized channel' });
        }
        if (!(await reauthorizeJoined(socket, producerChannelId))) {
          return respond({ success: false, error: 'Channel access revoked' });
        }
        const result = await mediaServer.consume(session.roomId, session.peerId, producerId);
        respond({
          success: true,
          id: result.id,
          producerId: result.producerId,
          kind: result.kind,
          rtpParameters: result.rtpParameters,
          producerPaused: result.producerPaused,
          appData: result.appData,
          channelId: producerChannelId,
          roomId: session.roomId,
        });
      } catch (error) {
        console.error('[PTT] consume error:', error.message);
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:resume_consumer', async ({ channelId, roomId, consumerId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session) return respond({ success: false, error: 'Not in this PTT shard' });
        const consumer = mediaServer.rooms.get(session.roomId)?.peers
          .get(session.peerId)?.consumers.get(consumerId);
        const effectiveChannelId = consumer?.appData?.pttChannelId;
        if (!consumer || !session.channels.has(effectiveChannelId) ||
            (channelId && String(channelId) !== String(effectiveChannelId)) ||
            !(await reauthorizeJoined(socket, effectiveChannelId))) {
          return respond({ success: false, error: 'Consumer is not authorized' });
        }
        await mediaServer.resumeConsumer(session.roomId, session.peerId, consumerId);
        respond({ success: true });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:produce', async ({ channelId, roomId, transportId, kind, rtpParameters } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_produce', respond)) return;
      try {
        const actor = actorOf(socket);
        if (!actor) return respond({ success: false, error: 'Not registered' });
        const session = sessionFromPayload(socket, { channelId, roomId });
        if (!session || !channelId || !session.channels.has(channelId)) {
          return respond({ success: false, error: 'Not joined to this channel' });
        }
        const access = await reauthorizeJoined(socket, channelId);
        if (!access) return respond({ success: false, error: 'Channel access revoked' });
        if (!access.canTransmit) return respond({ success: false, error: 'listen_only', reason: 'listen_only' });
        const floor = floors.get(channelId);
        if (!floor || floor.socketId !== socket.id || String(floor.userId) !== String(actor.userId)) {
          return respond({ success: false, error: 'You do not hold the floor' });
        }
        if (kind !== 'audio') return respond({ success: false, error: 'PTT is audio only' });
        if (!rtpParameters || !Array.isArray(rtpParameters.codecs) || !rtpParameters.codecs.length) {
          return respond({ success: false, error: 'Invalid RTP parameters' });
        }
        const sendTransport = mediaServer.getPeerTransport(session.roomId, session.peerId, 'send');
        if (!sendTransport || sendTransport.id !== transportId) {
          return respond({ success: false, error: 'Invalid send transport' });
        }
        for (const meta of producerIndex.values()) {
          if (meta.socketId === socket.id) {
            return respond({ success: false, error: 'A PTT producer is already active' });
          }
        }
        if (inFlightProducers.has(socket.id)) {
          return respond({ success: false, error: 'A PTT producer is already starting' });
        }

        const trustedAppData = {
          source: 'microphone',
          pttChannelId: channelId,
          pttTransmissionId: floor.transmissionId,
          pttUserId: String(actor.userId),
        };
        inFlightProducers.add(socket.id);
        let result;
        try {
          result = await mediaServer.produce(
            session.roomId, session.peerId, transportId, 'audio', rtpParameters, trustedAppData,
          );
        } finally {
          inFlightProducers.delete(socket.id);
        }
        const floorAfterProduce = floors.get(channelId);
        if (!floorAfterProduce || floorAfterProduce.socketId !== socket.id ||
            floorAfterProduce.transmissionId !== floor.transmissionId) {
          mediaServer.closeProducer(session.roomId, session.peerId, result.id);
          return respond({ success: false, error: 'Floor expired while starting microphone' });
        }
        const meta = {
          producerId: result.id,
          channelId,
          roomId: session.roomId,
          peerId: session.peerId,
          socketId: socket.id,
          userId: actor.userId,
          username: actor.username,
          transmissionId: floor.transmissionId,
        };
        producerIndex.set(result.id, meta);
        const entry = openTransmissions.get(channelId);
        if (entry?.transmissionId === floor.transmissionId) entry.producerId = result.id;
        userProducerCount.set(session.peerId, (userProducerCount.get(session.peerId) || 0) + 1);

        recorder.start({
          roomId: session.roomId,
          peerId: session.peerId,
          producerId: result.id,
          transmissionId: floor.transmissionId,
          userId: actor.userId,
          username: actor.username,
          deviceId: actor.deviceId,
        }).catch(error => {
          console.warn('[PTT Recording] Could not capture transmission:', error.message);
        });

        const event = {
          channelId,
          roomId: session.roomId,
          peerId: session.peerId,
          producerId: result.id,
          transmissionId: floor.transmissionId,
          userId: actor.userId,
          username: actor.username,
          kind: 'audio',
          paused: false,
          appData: trustedAppData,
        };
        socket.to(channelRoom(channelId)).emit('ptt:new_producer', event);
        respond({ success: true, id: result.id });
      } catch (error) {
        console.error('[PTT] produce error:', error.message);
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:close_producer', ({ channelId, roomId, producerId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const session = sessionFromPayload(socket, { channelId, roomId });
        const meta = producerIndex.get(producerId);
        if (!session || !meta || meta.socketId !== socket.id || meta.peerId !== session.peerId ||
            String(meta.channelId) !== String(channelId)) {
          return respond({ success: false, error: 'Producer is not owned by this channel' });
        }
        closeIndexedProducer(meta, 'closed');
        respond({ success: true });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:producer_audio_state', async ({ channelId, roomId, producerId, muted } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      try {
        const actor = actorOf(socket);
        const session = sessionFromPayload(socket, { channelId, roomId });
        const meta = producerIndex.get(producerId);
        if (!actor || !session || !meta || meta.socketId !== socket.id ||
            String(meta.channelId) !== String(channelId)) {
          return respond({ success: false, error: 'Producer is not owned by this channel' });
        }
        const floor = floors.get(channelId);
        if (!muted && (!floor || floor.socketId !== socket.id || floor.transmissionId !== meta.transmissionId)) {
          return respond({ success: false, error: 'You do not hold the floor' });
        }
        await mediaServer.setProducerSourcePaused(
          session.roomId, session.peerId, 'microphone', !!muted,
        );
        socket.to(channelRoom(channelId)).emit('ptt:peer_audio_state', {
          channelId,
          roomId: session.roomId,
          peerId: session.peerId,
          producerId,
          muted: !!muted,
        });
        respond({ success: true });
      } catch (error) {
        respond({ success: false, error: error.message });
      }
    });

    socket.on('ptt:floor_request', async ({ channelId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_floor_request', respond)) return;
      try {
        const actor = actorOf(socket);
        if (!actor) return respond({ success: false, error: 'Not registered' });
        if (!presence.get(channelId)?.has(socket.id)) {
          return respond({ success: false, error: 'Not joined to this channel' });
        }
        const access = await pttService.resolveAccess(actor.userId, channelId);
        if (!access) return respond({ success: false, error: 'Channel not found' });
        if (!access.canTransmit) return respond({ success: false, error: 'listen_only', reason: 'listen_only' });
        // Membership, socket liveness, and the call/PTT exclusion can all
        // change while resolveAccess waits on the database. Never grant a
        // floor from that stale pre-await snapshot.
        if (!socket.connected) return;
        if (!presence.get(channelId)?.has(socket.id)) {
          return respond({ success: false, error: 'Not joined to this channel' });
        }
        if (isWorkspaceDeleting(access.channel.workspaceId)) {
          return respond({ success: false, error: 'Channel not found' });
        }
        if (mediaServer.getPeerRoomId(socket.id)) {
          return respond({ success: false, error: 'busy_in_call', reason: 'busy_in_call' });
        }

        const result = floors.acquire(channelId, {
          userId: actor.userId,
          username: actor.username,
          socketId: socket.id,
          priority: access.priority,
        });
        if (!result.ok) {
          return respond({ success: false, reason: result.reason, holder: result.holder });
        }

        if (result.expired) finishFloor(result.expired, 'expired');

        if (result.preempted) {
          finishFloor(result.preempted, 'revoked');
          io.to(result.preempted.socketId).emit('ptt:you_were_preempted', {
            channelId,
            by: { userId: actor.userId, username: actor.username },
          });
        }

        if (!result.reacquired) {
          const transmissionId = result.floor.transmissionId;
          const insertPromise = pttService.beginTransmission({
            transmissionId, channelId, userId: actor.userId,
          });
          openTransmissions.set(channelId, {
            transmissionId,
            insertPromise,
            producerId: null,
            userId: actor.userId,
          });
          socket.to(channelRoom(channelId)).emit('ptt:speaker_started', {
            channelId,
            participant: { userId: actor.userId, username: actor.username },
            transmissionId,
          });
        }

        respond({
          success: true,
          transmissionId: result.floor.transmissionId,
          expiresAt: result.floor.expiresAt,
          heartbeatMs: Math.floor(LEASE_TTL_MS / 3),
        });
      } catch (error) {
        console.error('[PTT] floor_request error:', error.message);
        respond({ success: false, error: 'Floor request failed' });
      }
    });

    socket.on('ptt:floor_heartbeat', ({ channelId, transmissionId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!rateAllowed(socket, 'ptt_floor_heartbeat', respond)) return;
      const actor = actorOf(socket);
      if (!actor) return respond({ success: false, error: 'Not registered' });
      const result = floors.renew(channelId, {
        userId: actor.userId, socketId: socket.id, transmissionId,
      });
      if (!result.ok && result.reason === 'max_length' && result.floor) {
        finishFloor(result.floor, 'max_length');
      }
      respond({ success: result.ok, reason: result.reason, expiresAt: result.floor?.expiresAt });
    });

    socket.on('ptt:floor_release', ({ channelId, transmissionId } = {}, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      const actor = actorOf(socket);
      if (!actor) return respond({ success: false, error: 'Not registered' });
      const result = floors.release(channelId, {
        userId: actor.userId, socketId: socket.id, transmissionId,
      });
      if (!result.ok) return respond({ success: true, stale: true });
      respond({ success: true });
      // Diagnostic: recorded audio has been observed several seconds shorter
      // than the real hold. Logging the client's own release timing here
      // settles whether the client sends floor_release early (a touch/
      // gesture bug) or the recording is what's cutting off a genuinely
      // longer, correctly-timed hold.
      const heldMs = result.floor.acquiredAt ? Date.now() - result.floor.acquiredAt : -1;
      console.log(`[PTT] floor_release for ${result.floor.transmissionId} after ${heldMs}ms held`);
      finishFloor(result.floor, 'released');
    });

    socket.on('disconnect', () => {
      const channels = Array.from(socketChannels.get(socket.id) || []);
      for (const channelId of channels) {
        try { leaveChannel(socket, channelId, { reason: 'disconnect' }); } catch (_) {}
      }
      socketChannels.delete(socket.id);
      socketShards.delete(socket.id);
      inFlightProducers.delete(socket.id);
    });
  }

  function evictUser(channelId, userId, reason = 'access_revoked') {
    for (const [socketId, actor] of Array.from(presence.get(channelId)?.entries() || [])) {
      if (String(actor.userId) !== String(userId)) continue;
      const socket = io.sockets.sockets.get(socketId);
      if (!socket) continue;
      socket.emit('ptt:access_revoked', { channelId, reason });
      leaveChannel(socket, channelId, { reason });
    }
  }

  async function refreshUserAccess(channelId, userId) {
    const access = await pttService.resolveAccess(userId, channelId);
    if (!access) return evictUser(channelId, userId, 'access_revoked');
    for (const [socketId, actor] of presence.get(channelId)?.entries() || []) {
      if (String(actor.userId) !== String(userId)) continue;
      const socket = io.sockets.sockets.get(socketId);
      socket?.emit('ptt:permissions_changed', {
        channelId,
        canTransmit: access.canTransmit,
        isModerator: access.isModerator,
      });
      const floor = floors.get(channelId);
      if (!access.canTransmit && floor?.socketId === socketId) {
        const released = floors.release(channelId, {
          userId: floor.userId, socketId, transmissionId: floor.transmissionId,
        });
        if (released.ok) finishFloor(released.floor, 'revoked');
      }
    }
  }

  function evictChannel(channelId, reason = 'channel_deleted') {
    for (const socketId of Array.from(presence.get(channelId)?.keys() || [])) {
      const socket = io.sockets.sockets.get(socketId);
      if (!socket) continue;
      socket.emit('ptt:access_revoked', { channelId, reason });
      leaveChannel(socket, channelId, { reason });
    }
  }

  function evictUserFromWorkspace(workspaceId, userId, reason = 'workspace_access_revoked') {
    for (const [socketId, shards] of Array.from(socketShards.entries())) {
      const session = Array.from(shards.values())
        .find(candidate => String(candidate.workspaceId) === String(workspaceId));
      if (!session) continue;
      const socket = io.sockets.sockets.get(socketId);
      if (!socket) continue;
      const belongsToUser = Array.from(session.channels)
        .some(channelId => String(presence.get(channelId)?.get(socketId)?.userId) === String(userId));
      if (!belongsToUser) continue;
      for (const channelId of Array.from(session.channels)) {
        socket.emit('ptt:access_revoked', { channelId, reason });
        leaveChannel(socket, channelId, { reason });
      }
    }
  }

  function evictWorkspace(workspaceId, reason = 'workspace_deleted') {
    // The workspace delete cascades its channels in PostgreSQL, but live media
    // state is process-local. Tear every matching shard down first so no floor,
    // producer, consumer, or recorder can outlive the tenant that authorized it.
    deletingWorkspaces.add(String(workspaceId));
    for (const [socketId, shards] of Array.from(socketShards.entries())) {
      const session = Array.from(shards.values())
        .find(candidate => String(candidate.workspaceId) === String(workspaceId));
      if (!session) continue;
      const socket = io.sockets.sockets.get(socketId);
      if (!socket) continue;
      for (const channelId of Array.from(session.channels)) {
        socket.emit('ptt:access_revoked', { channelId, reason });
        leaveChannel(socket, channelId, { reason });
      }
    }
  }

  function cancelWorkspaceDeletion(workspaceId) {
    deletingWorkspaces.delete(String(workspaceId));
  }

  function evictUserEverywhere(userId, reason = 'account_access_revoked') {
    for (const [channelId, members] of Array.from(presence.entries())) {
      if (Array.from(members.values()).some(actor => String(actor.userId) === String(userId))) {
        evictUser(channelId, userId, reason);
      }
    }
  }

  pttRuntime.install({
    evictUser,
    refreshUserAccess,
    evictChannel,
    evictUserFromWorkspace,
    evictWorkspace,
    cancelWorkspaceDeletion,
    evictUserEverywhere,
  });
  return {
    registerPttHandlers,
    socketHoldsFloor,
    evictForCall,
    evictUser,
    evictChannel,
    evictUserFromWorkspace,
    evictWorkspace,
    cancelWorkspaceDeletion,
    evictUserEverywhere,
  };
};

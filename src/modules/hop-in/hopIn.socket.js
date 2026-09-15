const { randomBytes, randomUUID } = require('node:crypto');
const { getCallAttemptId } = require('../../app/callAttempt');

/** Ephemeral, device-bound camera handoffs. Video travels over WebRTC, never Socket.IO. */
function createHopIn({
  io,
  connectedUsers,
  activeCalls,
  mediaServer,
  iceServers = [],
  now = Date.now,
}) {
  const devices = new Map();
  const sessions = new Map();
  const budgets = new Map();
  const identity = (socket) => {
    const user = connectedUsers.get(socket.id);
    return user &&
      socket.deviceId &&
      String(user.userId) === String(socket.authUserId)
      ? { userId: String(socket.authUserId), deviceId: socket.deviceId }
      : null;
  };
  const conference = (socketId, roomId) => {
    const call = activeCalls.get(roomId);
    return call?.isConference &&
      mediaServer.rooms.get(roomId)?.peers.has(socketId)
      ? call
      : null;
  };
  const emit = (id, event, data) => io.to(id).emit(`hop_in:${event}`, data);
  const finish = (session, reason) => {
    if (!sessions.delete(session.id)) return;
    for (const id of [session.desktopId, session.phoneId])
      emit(id, 'ended', { sessionId: session.id, reason });
  };
  const owns = (socket, session) => {
    const actor = identity(socket);
    return (
      actor &&
      session &&
      session.userId === actor.userId &&
      [session.desktopId, session.phoneId].includes(socket.id)
    );
  };
  const valid = (session) => {
    const call = conference(session.desktopId, session.roomId);
    return (
      call &&
      getCallAttemptId(call) === session.attemptId &&
      devices.has(session.phoneId) &&
      devices.has(session.desktopId)
    );
  };
  const sweep = () => {
    for (const session of sessions.values()) {
      if (!valid(session)) finish(session, 'Conference ended');
      else if (now() >= session.expiresAt)
        finish(session, 'Camera request expired');
    }
  };
  const timer = setInterval(sweep, 2000);
  timer.unref?.();

  function register(socket) {
    const handle = (name, action, limit = 30) =>
      socket.on(`hop_in:${name}`, async (data, callback) => {
        const reply = typeof callback === 'function' ? callback : () => {};
        try {
          if (!identity(socket))
            throw new Error('Device registration is not ready');
          const key = `${socket.id}:${name}`;
          let budget = budgets.get(key);
          if (!budget || now() - budget.start >= 60000)
            budgets.set(key, (budget = { start: now(), count: 0 }));
          if (++budget.count > limit)
            throw new Error('Please wait before trying again');
          if (!data || typeof data !== 'object' || Array.isArray(data))
            throw new Error('Invalid request');
          sweep();
          reply({ success: true, ...(await action(data)) });
        } catch (error) {
          reply({
            success: false,
            error: error.message || 'Camera connection failed',
          });
        }
      });
    handle('register', ({ role, name }) => {
      if (!['phone', 'desktop'].includes(role))
        throw new Error('Invalid device type');
      const actor = identity(socket);
      const existing = devices.get(socket.id);
      // Never change roles under a live session.
      if (existing && existing.role !== role)
        throw new Error('Device type already registered');
      const device = {
        ...actor,
        role,
        name: String(name || (role === 'phone' ? 'Phone' : 'Computer')).slice(
          0,
          80
        ),
        proximityToken:
          existing?.proximityToken || randomBytes(16).toString('hex'),
      };
      devices.set(socket.id, device);
      return { proximityToken: device.proximityToken };
    });
    handle('unregister', () => {
      devices.delete(socket.id);
      for (const s of sessions.values())
        if ([s.desktopId, s.phoneId].includes(socket.id))
          finish(s, 'Device unavailable');
      return {};
    });
    handle('devices', () => {
      const actor = identity(socket);
      return {
        devices: [...devices.entries()]
          .filter(
            ([id, d]) =>
              id !== socket.id &&
              d.userId === actor.userId &&
              d.deviceId !== actor.deviceId &&
              d.role === 'phone'
          )
          .map(([id, d]) => ({
            id,
            name: d.name,
            busy: [...sessions.values()].some((s) => s.phoneId === id),
          })),
      };
    });
    handle(
      'request',
      ({ phoneId, proximityToken, roomId }) => {
        const actor = devices.get(socket.id);
        if (actor?.role !== 'desktop')
          throw new Error('Start Hop in from your computer');
        const call =
          typeof roomId === 'string' && conference(socket.id, roomId);
        if (!call)
          throw new Error('Join a conference before using your phone camera');
        if (typeof proximityToken === 'string') {
          phoneId = [...devices.entries()].find(
            ([, d]) =>
              d.userId === actor.userId && d.proximityToken === proximityToken
          )?.[0];
        }
        const phone = devices.get(phoneId);
        if (
          !phone ||
          phone.role !== 'phone' ||
          phone.userId !== actor.userId ||
          phone.deviceId === actor.deviceId
        ) {
          throw new Error('This phone is not available on your account');
        }
        if (
          [...sessions.values()].some(
            (s) => s.desktopId === socket.id || s.phoneId === phoneId
          )
        )
          throw new Error('This device already has a camera connection');
        const session = {
          id: randomUUID(),
          userId: actor.userId,
          desktopId: socket.id,
          phoneId,
          roomId,
          attemptId: getCallAttemptId(call),
          status: 'requested',
          expiresAt: now() + 45000,
        };
        sessions.set(session.id, session);
        emit(phoneId, 'request', {
          sessionId: session.id,
          computerName: actor.name,
          expiresAt: session.expiresAt,
        });
        return { sessionId: session.id, phoneName: phone.name };
      },
      10
    );
    handle('respond', ({ sessionId, accept }) => {
      const s = sessions.get(sessionId);
      if (
        !owns(socket, s) ||
        s.phoneId !== socket.id ||
        s.status !== 'requested'
      )
        throw new Error('Camera request is no longer available');
      if (accept !== true) {
        finish(s, 'Request declined');
        return {};
      }
      s.status = 'connecting';
      s.expiresAt = now() + 30000;
      const payload = { sessionId: s.id, iceServers };
      emit(s.desktopId, 'accepted', payload);
      return payload;
    });
    handle(
      'signal',
      ({ sessionId, description, candidate }) => {
        const s = sessions.get(sessionId);
        if (!owns(socket, s) || s.status === 'requested')
          throw new Error('Camera session is not ready');
        let signal;
        if (description) {
          const expected = socket.id === s.desktopId ? 'offer' : 'answer';
          if (
            description.type !== expected ||
            typeof description.sdp !== 'string' ||
            description.sdp.length > 64000 ||
            !/^m=video /m.test(description.sdp) ||
            /^m=(audio|application) /m.test(description.sdp)
          )
            throw new Error('Only camera video is allowed');
          signal = { description: { type: expected, sdp: description.sdp } };
        } else if (
          candidate &&
          typeof candidate.candidate === 'string' &&
          candidate.candidate.length <= 4096 &&
          (candidate.sdpMid == null ||
            (typeof candidate.sdpMid === 'string' &&
              candidate.sdpMid.length < 64)) &&
          (candidate.sdpMLineIndex == null ||
            (Number.isInteger(candidate.sdpMLineIndex) &&
              candidate.sdpMLineIndex >= 0 &&
              candidate.sdpMLineIndex < 8))
        ) {
          signal = {
            candidate: {
              candidate: candidate.candidate,
              sdpMid: candidate.sdpMid ?? null,
              sdpMLineIndex: candidate.sdpMLineIndex ?? null,
            },
          };
        } else throw new Error('Invalid camera signal');
        emit(socket.id === s.desktopId ? s.phoneId : s.desktopId, 'signal', {
          sessionId,
          ...signal,
        });
        return {};
      },
      240
    );
    handle('live', ({ sessionId }) => {
      const s = sessions.get(sessionId);
      if (
        !owns(socket, s) ||
        socket.id !== s.desktopId ||
        s.status === 'requested'
      )
        throw new Error('Camera session is not ready');
      s.status = 'live';
      s.expiresAt = now() + 6 * 60 * 60 * 1000;
      emit(s.phoneId, 'live', { sessionId });
      return {};
    });
    handle('stop', ({ sessionId }) => {
      const s = sessions.get(sessionId);
      if (s && !owns(socket, s))
        throw new Error('Camera session does not belong to this device');
      if (s) finish(s, 'Camera disconnected');
      return {};
    });
    socket.on('disconnect', () => {
      devices.delete(socket.id);
      for (const s of sessions.values())
        if ([s.desktopId, s.phoneId].includes(socket.id))
          finish(s, 'Device disconnected');
      for (const key of budgets.keys())
        if (key.startsWith(`${socket.id}:`)) budgets.delete(key);
    });
  }
  return {
    register,
    sweep,
    close() {
      clearInterval(timer);
      for (const s of sessions.values()) finish(s, 'Server restarting');
    },
  };
}

module.exports = { createHopIn };

/**
 * Optional Redis layer for Socket.IO horizontal scaling.
 *
 * DESIGN GOAL: never take the app down. If REDIS_URL is unset, the `redis` /
 * `@socket.io/redis-adapter` packages aren't installed, or the connection
 * fails, this module logs a warning and the server keeps running on the
 * default in-memory Socket.IO adapter (single-instance behaviour, identical
 * to before). Redis activates automatically only when everything is present.
 *
 * To enable in production:
 *   1. npm install redis @socket.io/redis-adapter
 *   2. set REDIS_URL=redis://host:6379 in the environment
 *   3. (multi-instance) ensure every node uses the same REDIS_URL
 *
 * Once active, emits done via `io.to('user:'+userId).emit(...)` reach that
 * user's sockets on ALL instances, and rooms fan out across the cluster.
 */

let _pub = null;
let _sub = null;

/**
 * Attach the Redis adapter to the given Socket.IO server, if possible.
 * Resolves to true when Redis was wired up, false when falling back to memory.
 * Never throws.
 *
 * @param {import('socket.io').Server} io
 * @returns {Promise<boolean>}
 */
async function initSocketRedisAdapter(io) {
  const url = process.env.REDIS_URL;
  if (!url) {
    console.log('[Redis] REDIS_URL not set — using in-memory Socket.IO adapter (single instance).');
    return false;
  }

  let createClient;
  let createAdapter;
  try {
    ({ createClient } = require('redis'));
    ({ createAdapter } = require('@socket.io/redis-adapter'));
  } catch (err) {
    console.warn('[Redis] redis / @socket.io/redis-adapter not installed — staying on in-memory adapter. (' + err.message + ')');
    return false;
  }

  try {
    const pub = createClient({ url });
    const sub = pub.duplicate();
    // Prevent an unhandled 'error' event from crashing the process if Redis
    // drops later; the adapter reconnects on its own.
    pub.on('error', (e) => console.warn('[Redis] pub client error:', e.message));
    sub.on('error', (e) => console.warn('[Redis] sub client error:', e.message));

    await pub.connect();
    await sub.connect();

    io.adapter(createAdapter(pub, sub));
    _pub = pub;
    _sub = sub;
    console.log('[Redis] Socket.IO Redis adapter active — multi-instance fan-out enabled.');
    return true;
  } catch (err) {
    console.warn('[Redis] Failed to connect — falling back to in-memory adapter:', err.message);
    return false;
  }
}

/** Best-effort shutdown for graceful exits. */
async function closeRedis() {
  try { if (_pub) await _pub.quit(); } catch (_) {}
  try { if (_sub) await _sub.quit(); } catch (_) {}
  _pub = null;
  _sub = null;
}

module.exports = { initSocketRedisAdapter, closeRedis };

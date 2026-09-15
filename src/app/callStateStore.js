/**
 * Call-state store abstraction — the scale-ready seam for `activeCalls`.
 *
 * WHY THIS EXISTS
 * ---------------
 * The call registry (`roomId -> { callId, answeredAt, callType, ... }`) is the hot
 * path: it is read synchronously on the connect/answer path, BEFORE the phone even
 * rings. Putting it behind a network hop (Redis) naively would add latency to every
 * call. But a future multi-instance deployment needs cross-instance visibility.
 *
 * The resolution: build the SEAM now, not the dependency. `activeCalls` is a
 * `CallStateStore`:
 *   • `InMemoryCallStateStore` (default) — a `Map` subclass. Zero behavior change,
 *     zero latency. This is what runs today and on any single-instance deployment.
 *   • `RedisCallStateStore` (disabled) — a local read-through cache (still a `Map`,
 *     so reads stay synchronous and fast) with write-through mirroring to Redis so
 *     other instances can see the call. Selected only by `CALL_STATE_BACKEND=redis`
 *     AND a reachable Redis; otherwise it degrades to pure in-memory. Never throws.
 *
 * Because both stores ARE `Map`s, every existing `activeCalls.get/set/has/delete/
 * entries/size/clear` call site keeps working unchanged — the abstraction is the
 * object's identity, not a rewritten API.
 *
 * The multi-instance constraint Redis alone does NOT solve: a call's mediasoup media
 * room lives on ONE instance's worker. Cross-instance calling therefore also requires
 * sticky routing by `roomId` (LB affinity) so both peers land on the same instance.
 * The store gives cross-instance *visibility*; stickiness gives cross-instance *media*.
 */

const KEY_PREFIX = 'call:active:';

/**
 * Shared semantic helpers layered on top of the raw Map. Kept additive so existing
 * code that reads `entry.answeredAt` directly is unaffected; new code can prefer
 * these for intent-revealing reads/writes.
 */
class CallStateStoreMixin extends Map {
  /** True if the call for `roomId` exists and has been answered. */
  isAnswered(roomId) {
    const entry = this.get(roomId);
    return !!(entry && entry.answeredAt);
  }

  /** Stamp the call answered (idempotent). Returns the updated entry or null. */
  markAnswered(roomId, at = Date.now()) {
    const entry = this.get(roomId);
    if (!entry) return null;
    if (!entry.answeredAt) {
      entry.answeredAt = at;
      this.set(roomId, entry);
    }
    return entry;
  }
}

/**
 * Default, single-instance store. Synchronous, in-process, identical to the plain
 * `new Map()` it replaces — just with the semantic helpers and a stable type name.
 */
class InMemoryCallStateStore extends CallStateStoreMixin {
  get backend() { return 'memory'; }
}

/**
 * Cross-instance store (PROTOTYPE — disabled by default).
 *
 * Reads are served from the local Map (read-through cache) so the hot path stays
 * synchronous and fast. Writes mirror to Redis with a TTL so expiry is Redis-native
 * (no cross-instance `setTimeout` to GC stale calls). If no Redis client is wired,
 * it behaves EXACTLY like the in-memory store — flipping the flag without a reachable
 * Redis can never break or slow down calls.
 *
 * NOTE: not wired to a live client yet. `attachClient()` + `hydrate()` are the
 * integration points for when multi-instance is actually turned on.
 */
class RedisCallStateStore extends CallStateStoreMixin {
  constructor({ ttlSeconds = 120 } = {}) {
    super();
    this._client = null;          // redis client (injected later via attachClient)
    this._ttlSeconds = ttlSeconds;
  }

  get backend() { return 'redis'; }

  /** Inject a connected redis client. Optional — without it this is pure in-memory. */
  attachClient(client) {
    this._client = client || null;
  }

  /** Load existing call state from Redis into the local cache on boot. Best-effort. */
  async hydrate() {
    if (!this._client) return;
    try {
      const keys = await this._client.keys(`${KEY_PREFIX}*`);
      for (const k of keys) {
        const raw = await this._client.get(k);
        if (!raw) continue;
        try { super.set(k.slice(KEY_PREFIX.length), JSON.parse(raw)); } catch (_) {}
      }
    } catch (e) {
      console.warn('[CallStateStore] hydrate failed — staying on local cache:', e.message);
    }
  }

  set(roomId, value) {
    // Local cache is authoritative for synchronous reads; mirror to Redis async.
    super.set(roomId, value);
    if (this._client) {
      try {
        // Fire-and-forget: a Redis hiccup must never block the call path.
        this._client
          .set(`${KEY_PREFIX}${roomId}`, JSON.stringify(value), { EX: this._ttlSeconds })
          .catch((e) => console.warn('[CallStateStore] mirror set failed:', e.message));
      } catch (_) {}
    }
    return this;
  }

  delete(roomId) {
    const existed = super.delete(roomId);
    if (this._client) {
      try {
        this._client
          .del(`${KEY_PREFIX}${roomId}`)
          .catch((e) => console.warn('[CallStateStore] mirror del failed:', e.message));
      } catch (_) {}
    }
    return existed;
  }
}

/**
 * Build the call-state store selected by `CALL_STATE_BACKEND` (default 'memory').
 * Unknown values fall back to in-memory. The Redis store still degrades to pure
 * in-memory until a client is attached, so this is safe to flip without wiring.
 */
function createCallStateStore({ ttlSeconds } = {}) {
  const backend = (process.env.CALL_STATE_BACKEND || 'memory').toLowerCase();
  if (backend === 'redis') {
    console.log('[CallStateStore] backend=redis (prototype; in-memory until a client is attached).');
    return new RedisCallStateStore({ ttlSeconds });
  }
  return new InMemoryCallStateStore();
}

module.exports = {
  CallStateStoreMixin,
  InMemoryCallStateStore,
  RedisCallStateStore,
  createCallStateStore,
  KEY_PREFIX,
};

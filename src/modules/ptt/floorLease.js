/**
 * PTT floor lease — who is allowed to transmit on a channel, right now.
 *
 * ── Why a lease and not a boolean ────────────────────────────────────────────
 * The failure that matters is not two people talking at once; it is ONE person
 * locking a channel forever. A phone that crashes, loses signal, or is killed by
 * the OS mid-transmission never sends its release. If the floor were a plain
 * "held by X" flag, that channel is dead until someone restarts the server.
 *
 * So the floor is a LEASE with an expiry. The holder must keep renewing it
 * (`renew`, driven by a client heartbeat). Stop renewing for any reason — crash,
 * tunnel, subway, force-quit — and it lapses on its own. Nothing has to detect
 * the failure; the absence of renewal IS the detection.
 *
 * ── Why in-process is correct here (for now) ─────────────────────────────────
 * Production runs a SINGLE pm2 process. Node is single-threaded, so a
 * check-then-set inside one synchronous function body cannot interleave — it is
 * genuinely atomic, with no lock and no network hop. Redis would add a
 * round-trip to a budget we want under ~150 ms and buy nothing today.
 *
 * That changes the moment a second instance exists. The interface here is
 * deliberately the small set of operations Redis can implement verbatim
 * (`SET NX PX` for acquire, a compare-and-delete Lua script for release/renew),
 * so going multi-instance is a swap of this file's internals, not a redesign of
 * its callers. `src/app/callStateStore.js` already models that same
 * in-memory/Redis split for call state.
 *
 * Time source is `Date.now()`. A wall-clock jump could extend or shorten one
 * lease by the jump size; the blast radius is a single transmission, and using a
 * monotonic clock would break the Redis port later, so this is a deliberate trade.
 */
const { randomUUID } = require('crypto');

/** How long a grant survives without a heartbeat. */
const LEASE_TTL_MS = 10_000;
/** Hard ceiling on one continuous transmission, regardless of heartbeats. */
const MAX_TRANSMISSION_MS = 120_000;
/**
 * How often we scan for lapsed leases.
 *
 * This does NOT affect when a lease stops being valid — `get`/`acquire` compare
 * against the clock inline, so the next speaker can take a lapsed floor
 * immediately. It only bounds how long listeners keep seeing a stale
 * "X is speaking" indicator, so it is derived from the TTL rather than fixed:
 * a short TTL in tests or a future config must not wait a full second to notify.
 */
const sweepIntervalFor = ttlMs => Math.max(200, Math.min(1_000, Math.floor(ttlMs / 4)));

class FloorLease {
  constructor({ ttlMs = LEASE_TTL_MS, maxMs = MAX_TRANSMISSION_MS } = {}) {
    /** @type {Map<string, {channelId,userId,username,socketId,priority,transmissionId,acquiredAt,expiresAt}>} */
    this._floors = new Map();
    this._ttlMs = ttlMs;
    this._maxMs = maxMs;
    this._sweepTimer = null;
    /** @type {(release: {floor: object, reason: string}) => void} */
    this._onExpire = () => {};
  }

  /** Register the callback fired when a lease lapses on its own. */
  onExpire(fn) {
    if (typeof fn === 'function') this._onExpire = fn;
  }

  /**
   * Try to take the floor. Returns `{ok:true, floor}` or `{ok:false, reason, holder}`.
   *
   * The expiry check is inlined rather than delegated so that acquire remains a
   * single uninterrupted synchronous path: read, validate, write. Anything
   * awaited in the middle would reopen the race this function exists to close.
   *
   * `priority` (default 0, higher wins) lets an admin/superadmin request cut off
   * a lower-priority current holder instead of being refused. Equal priority is
   * never a preemption — only a strictly higher requester displaces the holder —
   * so two same-tier users contending for the floor behave exactly as before.
   */
  acquire(channelId, { userId, username, socketId, priority = 0 }) {
    const now = Date.now();
    const current = this._floors.get(channelId);
    const expired = current && current.expiresAt <= now ? current : null;
    if (expired) this._floors.delete(channelId);

    // Re-pressing while you already hold this exact floor is idempotent.
    if (
      current && current.expiresAt > now &&
      current.userId === userId && current.socketId === socketId
    ) {
      return { ok: true, floor: current, reacquired: true };
    }

    // One microphone, one radio floor. Listening remains multi-channel, but a
    // single socket may never publish into two logical channels at once.
    for (const floor of this._floors.values()) {
      if (
        floor.channelId !== channelId &&
        floor.socketId === socketId &&
        floor.expiresAt > now
      ) {
        return {
          ok: false,
          reason: 'already_transmitting',
          holder: {
            userId: floor.userId,
            username: floor.username,
            channelId: floor.channelId,
          },
        };
      }
    }

    if (current && current.expiresAt > now) {
      if (priority <= (current.priority || 0)) {
        return {
          ok: false,
          reason: 'floor_busy',
          holder: { userId: current.userId, username: current.username },
        };
      }
      // Strictly higher priority: displace the current holder rather than
      // refuse. The caller is responsible for notifying the displaced holder —
      // this function only reports who they were.
      this._floors.delete(channelId);
      const floor = {
        channelId,
        userId,
        username,
        socketId,
        priority,
        transmissionId: randomUUID(),
        acquiredAt: now,
        expiresAt: now + this._ttlMs,
      };
      this._floors.set(channelId, floor);
      return { ok: true, floor, reacquired: false, preempted: current };
    }

    // Either free, or the previous holder's lease already lapsed and the sweep
    // has not run yet. Taking it here is safe: the sweep only fires the expiry
    // callback for a floor object it still finds in the map.
    const floor = {
      channelId,
      userId,
      username,
      socketId,
      priority,
      transmissionId: randomUUID(),
      acquiredAt: now,
      expiresAt: now + this._ttlMs,
    };
    this._floors.set(channelId, floor);
    return { ok: true, floor, reacquired: false, expired };
  }

  /**
   * Extend the lease. Only the current holder may renew, and only up to the
   * hard cap — otherwise a stuck button (or a malicious client) holds a channel
   * hostage indefinitely just by heartbeating.
   */
  renew(channelId, { userId, socketId, transmissionId }) {
    const now = Date.now();
    const floor = this._floors.get(channelId);
    if (!floor || floor.expiresAt <= now) return { ok: false, reason: 'no_floor' };
    if (
      floor.userId !== userId ||
      floor.socketId !== socketId ||
      floor.transmissionId !== transmissionId
    ) {
      return { ok: false, reason: 'not_holder' };
    }
    if (now - floor.acquiredAt >= this._maxMs) {
      this._floors.delete(channelId);
      return { ok: false, reason: 'max_length', floor };
    }
    floor.expiresAt = now + this._ttlMs;
    return { ok: true, floor };
  }

  /**
   * Give the floor up. `transmissionId` is required for a holder-initiated
   * release so a late release from a PREVIOUS transmission cannot cut off the
   * person who has since taken the floor — the exact class of bug that makes
   * radios cut out for no visible reason.
   */
  release(channelId, { userId, socketId, transmissionId } = {}) {
    const floor = this._floors.get(channelId);
    if (!floor) return { ok: false, reason: 'no_floor' };
    if (floor.userId !== userId || floor.socketId !== socketId) {
      return { ok: false, reason: 'not_holder' };
    }
    if (!transmissionId || floor.transmissionId !== transmissionId) {
      return { ok: false, reason: 'stale_transmission' };
    }
    this._floors.delete(channelId);
    return { ok: true, floor };
  }

  /** Current holder, or null when free. Never returns a lapsed lease. */
  get(channelId) {
    const floor = this._floors.get(channelId);
    if (!floor) return null;
    if (floor.expiresAt <= Date.now()) return null;
    return floor;
  }

  /**
   * Drop every floor held by a socket. Called on disconnect so a hang-up,
   * crash or network drop frees the channel immediately instead of waiting out
   * the TTL — the TTL is the backstop, not the primary path.
   */
  releaseAllForSocket(socketId) {
    const released = [];
    for (const [channelId, floor] of this._floors.entries()) {
      if (floor.socketId === socketId) {
        this._floors.delete(channelId);
        released.push(floor);
      }
    }
    return released;
  }

  /** Begin sweeping lapsed leases. Idempotent. */
  start() {
    if (this._sweepTimer) return;
    this._sweepTimer = setInterval(() => this._sweep(), sweepIntervalFor(this._ttlMs));
    // Never hold the event loop open for this.
    if (typeof this._sweepTimer.unref === 'function') this._sweepTimer.unref();
  }

  stop() {
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    this._sweepTimer = null;
  }

  _sweep() {
    const now = Date.now();
    for (const [channelId, floor] of this._floors.entries()) {
      const lapsed = floor.expiresAt <= now;
      const tooLong = now - floor.acquiredAt >= this._maxMs;
      if (!lapsed && !tooLong) continue;
      this._floors.delete(channelId);
      try {
        this._onExpire({ floor, reason: tooLong ? 'max_length' : 'expired' });
      } catch (err) {
        console.error('[PTT] floor expiry handler failed:', err.message);
      }
    }
  }
}

module.exports = { FloorLease, LEASE_TTL_MS, MAX_TRANSMISSION_MS };

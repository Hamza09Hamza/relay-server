/**
 * Socket.IO Per-Socket Rate Limiting
 *
 * Prevents DoS attacks by enforcing per-socket rate limits on events:
 * - Messages: 60 per minute (1 per second)
 * - Typing: 10 per minute
 * - Calls: 5 per minute
 * - Other events: 30 per minute
 */

class SocketRateLimiter {
  constructor() {
    // Map of socketId -> { eventName -> { timestamps: [], lastCheck } }
    this.rateLimits = new Map();
  }

  /**
   * Check if socket is allowed to emit an event
   * Returns true if within rate limit, false if exceeded
   * @param {string} socketId - Socket ID
   * @param {string} eventName - Event name (send_group_message, typing_start, etc)
   * @returns {boolean} true if allowed, false if rate limited
   */
  isAllowed(socketId, eventName) {
    const now = Date.now();
    const limit = this.getLimit(eventName);

    if (!this.rateLimits.has(socketId)) {
      this.rateLimits.set(socketId, {});
    }

    const socketLimits = this.rateLimits.get(socketId);

    if (!socketLimits[eventName]) {
      socketLimits[eventName] = { timestamps: [] };
    }

    const tracker = socketLimits[eventName];

    // Remove timestamps older than 1 minute
    const oneMinuteAgo = now - 60000;
    tracker.timestamps = tracker.timestamps.filter(ts => ts > oneMinuteAgo);

    // Check if under limit
    if (tracker.timestamps.length >= limit.maxPerMinute) {
      return false; // Rate limited
    }

    // Record this event
    tracker.timestamps.push(now);
    return true; // Allowed
  }

  /**
   * Get rate limit config for an event type
   * @param {string} eventName
   * @returns {Object} { maxPerMinute, description }
   */
  getLimit(eventName) {
    const limits = {
      send_group_message: { maxPerMinute: 60, description: 'Group messages' },
      send_private_message: { maxPerMinute: 60, description: 'Private messages' },
      typing_start: { maxPerMinute: 10, description: 'Typing indicators' },
      typing_end: { maxPerMinute: 10, description: 'Typing stop' },
      call_user: { maxPerMinute: 5, description: 'Call initiations' },
      call_answer: { maxPerMinute: 5, description: 'Call answers' },
      call_reject: { maxPerMinute: 5, description: 'Call rejections' },
      call_end: { maxPerMinute: 5, description: 'Call endings' },
      add_member_to_group: { maxPerMinute: 20, description: 'Add member' },
      invite_to_conference: { maxPerMinute: 10, description: 'Conference invitations' },
      conference_host_action: { maxPerMinute: 30, description: 'Conference host controls' },
      conference_add_note: { maxPerMinute: 30, description: 'Conference notes' },
      conference_reaction: { maxPerMinute: 40, description: 'Conference reactions' },
      kick_member: { maxPerMinute: 20, description: 'Remove member' },
      camera_on: { maxPerMinute: 10, description: 'Camera toggle' },
      camera_off: { maxPerMinute: 10, description: 'Camera toggle' },
      recording_metadata: { maxPerMinute: 10, description: 'Recording events' },
      ptt_join: { maxPerMinute: 120, description: 'PTT logical channel joins' },
      ptt_create_transport: { maxPerMinute: 12, description: 'PTT media transports' },
      ptt_consume: { maxPerMinute: 240, description: 'PTT media consumers' },
      ptt_produce: { maxPerMinute: 120, description: 'PTT transmissions' },
      ptt_floor_request: { maxPerMinute: 60, description: 'PTT floor requests' },
      ptt_floor_heartbeat: { maxPerMinute: 30, description: 'PTT lease heartbeats' },
      // Default for unmapped events
      default: { maxPerMinute: 30, description: 'Default rate limit' },
    };

    return limits[eventName] || limits.default;
  }

  /**
   * Clean up old socket entries to prevent memory leak
   * Call periodically (e.g., every 5 minutes)
   * Removes sockets with no recent events (older than 1 hour)
   */
  cleanup() {
    const oneHourAgo = Date.now() - 3600000;

    for (const [socketId, socketLimits] of this.rateLimits.entries()) {
      let hasRecentActivity = false;

      for (const [eventName, tracker] of Object.entries(socketLimits)) {
        // Remove old timestamps
        tracker.timestamps = tracker.timestamps.filter(ts => ts > oneHourAgo);
        if (tracker.timestamps.length > 0) {
          hasRecentActivity = true;
        }
      }

      // Remove socket entry if no recent activity
      if (!hasRecentActivity) {
        this.rateLimits.delete(socketId);
      }
    }
  }

  /**
   * Remove socket when disconnected
   * @param {string} socketId
   */
  removeSocket(socketId) {
    this.rateLimits.delete(socketId);
  }

  /**
   * Get stats for monitoring
   * @returns {Object} Stats about rate limiting
   */
  getStats() {
    const totalSockets = this.rateLimits.size;
    const limitedSockets = Array.from(this.rateLimits.entries()).filter(
      ([_, limits]) => Object.values(limits).some(t => t.timestamps.length > 20)
    ).length;

    return {
      totalSockets,
      potentiallyLimitedSockets: limitedSockets,
      timestamp: new Date().toISOString(),
    };
  }
}

module.exports = new SocketRateLimiter();

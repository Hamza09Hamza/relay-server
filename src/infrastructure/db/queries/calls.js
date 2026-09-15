const db = require('../index');

// Allowed call statuses — prevents arbitrary values from reaching the DB
const VALID_CALL_STATUSES = ['ringing', 'ongoing', 'completed', 'missed', 'rejected'];

const CallQueries = {
  /**
   * Create a call record when a call starts.
   * @param {{ roomId: string, initiatorId: string, callType: 'audio'|'video', sessionKind?: 'call'|'conference' }} data
   * @returns {Promise<object>}
   */
  async create({ roomId, initiatorId, callType, sessionKind = 'call' }) {
    const { rows } = await db.query(
      `INSERT INTO calls (room_id, initiator_id, call_type, status, session_kind)
       VALUES ($1, $2, $3, 'ringing', $4)
       RETURNING *`,
      [roomId, initiatorId, callType, sessionKind],
    );
    return rows[0];
  },

  /**
   * Find a call by id.
   */
  async findById(id) {
    const { rows } = await db.query('SELECT * FROM calls WHERE id = $1', [id]);
    return rows[0] || null;
  },

  /**
   * Update the status of a call (ringing -> ongoing -> completed, etc).
   */
  async updateStatus(id, status) {
    if (!VALID_CALL_STATUSES.includes(status)) {
      throw new Error(`Invalid call status: ${status}`);
    }
    const extras = [];
    if (['completed', 'missed', 'rejected'].includes(status)) {
      extras.push('ended_at = NOW()');
    }
    if (status === 'ongoing') {
      // Use COALESCE so only the FIRST answer sets started_at;
      // later participants answering won't overwrite it.
      extras.push('started_at = COALESCE(started_at, NOW())');
    }
    const extraSql = extras.length ? ', ' + extras.join(', ') : '';
    const { rows } = await db.query(
      `UPDATE calls SET status = $2 ${extraSql} WHERE id = $1 RETURNING *`,
      [id, status],
    );
    return rows[0] || null;
  },

  /**
   * End a call (sets ended_at and status to completed).
   */
  async end(id) {
    return this.updateStatus(id, 'completed');
  },

  /**
   * Promote a call's type (audio -> video) when video media first appears
   * mid-call. Idempotent and one-directional: a call only ever gains video, it
   * never reverts to audio, so the recording label + history reflect that this
   * call carried video at some point. Pure audio calls are never touched.
   */
  async setCallType(id, callType) {
    if (callType !== 'audio' && callType !== 'video') {
      throw new Error(`Invalid call type: ${callType}`);
    }
    const { rows } = await db.query(
      `UPDATE calls SET call_type = $2
       WHERE id = $1 AND call_type IS DISTINCT FROM $2
       RETURNING *`,
      [id, callType],
    );
    return rows[0] || null;
  },

  /**
   * Add a participant to a call (idempotent – skips if already exists).
   */
  async addParticipant(callId, userId) {
    const { rows } = await db.query(
      `INSERT INTO call_participants (call_id, user_id, answered)
       SELECT $1, $2, FALSE
       WHERE NOT EXISTS (
         SELECT 1 FROM call_participants WHERE call_id = $1 AND user_id = $2
       )
       RETURNING *`,
      [callId, userId],
    );
    return rows[0] || null;
  },

  /**
   * Mark a participant as having answered.
   */
  async answerParticipant(callId, userId) {
    const { rows } = await db.query(
      `UPDATE call_participants
       SET answered = TRUE, joined_at = NOW(), left_at = NULL
       WHERE call_id = $1 AND user_id = $2
       RETURNING *`,
      [callId, userId],
    );
    return rows[0] || null;
  },

  /**
   * Mark a participant as having left.
   */
  async removeParticipant(callId, userId) {
    await db.query(
      `UPDATE call_participants SET left_at = NOW()
       WHERE call_id = $1 AND user_id = $2 AND left_at IS NULL`,
      [callId, userId],
    );
  },

  /**
   * Get participants of a call.
   */
  async getParticipants(callId) {
    const { rows } = await db.query(
      `SELECT cp.*, u.username, u.profile_picture
       FROM call_participants cp
       JOIN users u ON u.id = cp.user_id
       WHERE cp.call_id = $1
       ORDER BY cp.joined_at`,
      [callId],
    );
    return rows;
  },

  /**
   * Call history for a user (paginated).
   */
  async listByUser(userId, { limit = 30, offset = 0 } = {}) {
    const { rows } = await db.query(
      `SELECT c.*, u.username AS initiator_username
       FROM calls c
       JOIN call_participants cp ON cp.call_id = c.id
       JOIN users u ON u.id = c.initiator_id
       WHERE cp.user_id = $1
       ORDER BY c.started_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset],
    );
    return rows;
  },

  /**
   * Call history for a room (paginated).
   */
  async listByRoom(roomId, { limit = 30, offset = 0 } = {}) {
    const { rows } = await db.query(
      `SELECT c.*, u.username AS initiator_username
       FROM calls c
       JOIN users u ON u.id = c.initiator_id
       WHERE c.room_id = $1
       ORDER BY c.started_at DESC
       LIMIT $2 OFFSET $3`,
      [roomId, limit, offset],
    );
    return rows;
  },

  /**
   * Conference history for a user (paginated) — the user-facing "Recent"
   * list, distinct from the admin call/recording listings. The conference's
   * title lives on its (never-deleted, never-listed) ephemeral room row,
   * since `calls` itself has no title column.
   */
  async listConferencesByUser(userId, { limit = 20, offset = 0 } = {}) {
    const { rows } = await db.query(
      `SELECT c.id AS call_id, c.call_type, c.status, c.started_at, c.ended_at,
              r.name AS title,
              (SELECT COUNT(*)::int FROM conference_entries ce
               WHERE ce.call_id = c.id AND ce.entry_type = 'message') AS message_count,
              (SELECT COUNT(*)::int FROM conference_entries ce
               WHERE ce.call_id = c.id AND ce.entry_type = 'note') AS note_count,
              COALESCE(
                (SELECT json_agg(json_build_object('userId', u.id, 'username', u.username))
                 FROM call_participants cp2
                 JOIN users u ON u.id = cp2.user_id
                 WHERE cp2.call_id = c.id AND cp2.answered = TRUE),
                '[]'::json
              ) AS participants
       FROM calls c
       JOIN rooms r ON r.id = c.room_id
       JOIN call_participants cp ON cp.call_id = c.id
       WHERE c.session_kind = 'conference' AND cp.user_id = $1
       ORDER BY c.started_at DESC NULLS LAST
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset],
    );
    return rows;
  },
};

module.exports = CallQueries;

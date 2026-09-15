const db = require('../index');
const enc = require('../../encryption/encryption');
const { KEY_PURPOSES } = enc;

// Allowed participant roles — prevents arbitrary values from reaching the DB
const VALID_ROLES = ['member', 'admin'];

const RoomQueries = {
  /**
   * Create a room.
   * @param {{ type: 'private'|'group', name?: string, createdBy: string, ephemeral?: boolean }} data
   * @returns {Promise<object>}
   */
  async create({ type, name, createdBy, ephemeral = false }) {
    const { rows } = await db.query(
      `INSERT INTO rooms (type, name, created_by, is_ephemeral)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [type, name || null, createdBy, !!ephemeral],
    );
    return rows[0];
  },

  /**
   * Find a room by id.
   */
  async findById(id) {
    const { rows } = await db.query('SELECT * FROM rooms WHERE id = $1', [id]);
    return rows[0] || null;
  },

  /**
   * Update a group's editable info. Only the fields passed are touched;
   * `description: null` clears it.
   */
  async updateInfo(roomId, { name, description } = {}) {
    const sets = [];
    const params = [roomId];
    if (name !== undefined) {
      params.push(name);
      sets.push(`name = $${params.length}`);
    }
    if (description !== undefined) {
      params.push(description);
      sets.push(`description = $${params.length}`);
    }
    if (sets.length === 0) return this.findById(roomId);
    const { rows } = await db.query(
      `UPDATE rooms SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
      params,
    );
    return rows[0] || null;
  },

  /**
   * Find or create a private room between exactly two users.
   * Prevents duplicate private rooms.
   */
  async findPrivate(userIdA, userIdB) {
    const { rows } = await db.query(
      `SELECT r.* FROM rooms r
       JOIN room_participants rp1 ON rp1.room_id = r.id AND rp1.user_id = $1
       JOIN room_participants rp2 ON rp2.room_id = r.id AND rp2.user_id = $2
       WHERE r.type = 'private'
       LIMIT 1`,
      [userIdA, userIdB],
    );
    return rows[0] || null;
  },

  async findOrCreatePrivate(userIdA, userIdB, createdBy) {
    const { rows } = await db.query(
      `SELECT r.* FROM rooms r
       JOIN room_participants rp1 ON rp1.room_id = r.id AND rp1.user_id = $1
       JOIN room_participants rp2 ON rp2.room_id = r.id AND rp2.user_id = $2
       WHERE r.type = 'private'
       LIMIT 1`,
      [userIdA, userIdB],
    );

    if (rows.length > 0) return { room: rows[0], created: false };

    return db.transaction(async (client) => {
      const { rows: roomRows } = await client.query(
        `INSERT INTO rooms (type, created_by) VALUES ('private', $1) RETURNING *`,
        [createdBy],
      );
      const room = roomRows[0];

      await client.query(
        `INSERT INTO room_participants (room_id, user_id, role) VALUES ($1, $2, 'member'), ($1, $3, 'member')`,
        [room.id, userIdA, userIdB],
      );

      return { room, created: true };
    });
  },

  /**
   * Add a participant to a room.
   */
  async addParticipant(roomId, userId, role = 'member') {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid room role: ${role}`);
    }
    const { rows } = await db.query(
      `INSERT INTO room_participants (room_id, user_id, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (room_id, user_id) DO UPDATE SET left_at = NULL
       RETURNING *`,
      [roomId, userId, role],
    );
    return rows[0];
  },

  /**
   * Remove a participant (soft-delete via left_at).
   */
  async removeParticipant(roomId, userId) {
    await db.query(
      `UPDATE room_participants SET left_at = NOW()
       WHERE room_id = $1 AND user_id = $2 AND left_at IS NULL`,
      [roomId, userId],
    );
  },

  /**
   * Update a participant's role (admin / member).
   */
  async updateRole(roomId, userId, role) {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid room role: ${role}`);
    }
    await db.query(
      `UPDATE room_participants SET role = $3
       WHERE room_id = $1 AND user_id = $2 AND left_at IS NULL`,
      [roomId, userId, role],
    );
  },

  /**
   * List active participants of a room.
   */
  async getParticipants(roomId) {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.full_name, u.profile_picture, u.is_online, rp.role, rp.joined_at
       FROM room_participants rp
       JOIN users u ON u.id = rp.user_id
       WHERE rp.room_id = $1 AND rp.left_at IS NULL
       ORDER BY rp.joined_at`,
      [roomId],
    );
    return rows;
  },

  /**
   * List rooms a user belongs to (with latest message preview, unread count and
   * participants), newest-activity first.
   *
   * Pagination (Instagram-style lazy load): pass `limit` for a page size and
   * `before` (an ISO timestamp cursor = the last_message_at of the last row you
   * already have) to fetch the next, older page. Omit both to return ALL rooms
   * (the original behaviour — preserved for any caller that wants the full list).
   *
   * Participants are aggregated inline as JSON so this is a SINGLE query instead
   * of the previous N+1 (one extra getParticipants() round-trip per room).
   */
  async listByUser(userId, { limit = null, before = null } = {}) {
    const { rows } = await db.query(
      `SELECT * FROM (
         SELECT r.*,
              rp.role,
              (SELECT id FROM messages m WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message_id,
              (SELECT content FROM messages m WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message,
              (SELECT created_at FROM messages m WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message_at,
              (SELECT message_type FROM messages m WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message_type,
              (SELECT sender_id FROM messages m WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message_sender_id,
              (SELECT u2.username FROM messages m JOIN users u2 ON u2.id = m.sender_id WHERE m.room_id = r.id AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp) ORDER BY m.created_at DESC LIMIT 1) AS last_message_sender,
              (SELECT COALESCE(
                  json_agg(json_build_object(
                    'id', u.id,
                    'username', u.username,
                    'full_name', u.full_name,
                    'profile_picture', u.profile_picture,
                    'is_online', u.is_online,
                    'role', rp2.role,
                    'joined_at', rp2.joined_at
                  ) ORDER BY rp2.joined_at),
                  '[]'::json)
                 FROM room_participants rp2
                 JOIN users u ON u.id = rp2.user_id
                 WHERE rp2.room_id = r.id AND rp2.left_at IS NULL
              ) AS participants,
              COALESCE(
                (SELECT COUNT(*)::int
                 FROM messages m
                 WHERE m.room_id = r.id
                   AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp)
                   AND m.sender_id != $1
                   AND NOT EXISTS (
                     SELECT 1 FROM message_status ms
                     WHERE ms.message_id = m.id
                       AND ms.user_id = $1
                       AND ms.status = 'read'
                   )
                ), 0
              ) AS unread_count
         FROM rooms r
         JOIN room_participants rp ON rp.room_id = r.id
         WHERE rp.user_id = $1 AND rp.left_at IS NULL
           AND NOT r.is_ephemeral
           AND EXISTS (
             SELECT 1 FROM messages m
             WHERE m.room_id = r.id
               AND m.created_at > COALESCE(rp.cleared_at, '1970-01-01'::timestamp)
           )
       ) sub
       WHERE ($2::timestamp IS NULL OR sub.last_message_at < $2::timestamp)
       ORDER BY sub.last_message_at DESC NULLS LAST
       LIMIT $3`,
      [userId, before, limit],
    );

    // Decrypt last_message preview for each room
    if (enc.isInitialized()) {
      for (const row of rows) {
        if (row.last_message && enc.isEncrypted(row.last_message)) {
          try {
            row.last_message = enc.decrypt(row.last_message, KEY_PURPOSES.MESSAGES, row.last_message_id || undefined);
          } catch (err) {
            console.error('[Decrypt] last_message error for room', row.id, ':', err.message);
          }
        }
      }
    }

    return rows;
  },
};

module.exports = RoomQueries;

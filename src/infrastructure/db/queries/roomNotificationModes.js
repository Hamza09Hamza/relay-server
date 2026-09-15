const db = require('../index');
const { ROOM_NOTIFICATION_MODES } = require('../../../app/mentions');

/**
 * Per user, per room notification mode. 'all' is the default and is stored
 * as the absence of a row, so the table only ever holds exceptions.
 */
const RoomNotificationModes = {
  async set(userId, roomId, mode) {
    if (!ROOM_NOTIFICATION_MODES.includes(mode)) {
      throw new Error(`Invalid notification mode: ${mode}`);
    }
    if (mode === 'all') {
      await db.query(
        'DELETE FROM room_notification_modes WHERE user_id = $1 AND room_id = $2',
        [userId, roomId],
      );
      return;
    }
    await db.query(
      `INSERT INTO room_notification_modes (user_id, room_id, mode, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, room_id)
       DO UPDATE SET mode = EXCLUDED.mode, updated_at = NOW()`,
      [userId, roomId, mode],
    );
  },

  async get(userId, roomId) {
    const { rows } = await db.query(
      'SELECT mode FROM room_notification_modes WHERE user_id = $1 AND room_id = $2',
      [userId, roomId],
    );
    return rows[0]?.mode || 'all';
  },

  /** Modes for many members of one room at once — one query per message fan-out. */
  async getForRoom(roomId, userIds) {
    const modes = new Map();
    if (!Array.isArray(userIds) || userIds.length === 0) return modes;
    const { rows } = await db.query(
      // Compared as text: user ids are UUIDs on some deployments and integers
      // on others (migration 009), and this must work on both.
      `SELECT user_id, mode FROM room_notification_modes
       WHERE room_id = $1 AND user_id::text = ANY($2::text[])`,
      [roomId, userIds.map(String)],
    );
    for (const row of rows) modes.set(String(row.user_id), row.mode);
    return modes;
  },

  /** { roomId: mode } for every room where the user is not on the default. */
  async listForUser(userId) {
    const { rows } = await db.query(
      'SELECT room_id, mode FROM room_notification_modes WHERE user_id = $1',
      [userId],
    );
    return Object.fromEntries(rows.map(row => [String(row.room_id), row.mode]));
  },
};

module.exports = RoomNotificationModes;

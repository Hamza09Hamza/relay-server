const db = require('../index');

const VALID_TYPES = new Set([
  'message', 'note', 'joined', 'left', 'hand_raised', 'hand_lowered',
]);

const ConferenceArchiveQueries = {
  async addEntry({ callId, userId = null, entryType, content = null, metadata = {} }) {
    if (!VALID_TYPES.has(entryType)) throw new Error(`Invalid conference entry type: ${entryType}`);
    const { rows } = await db.query(
      `INSERT INTO conference_entries (call_id, user_id, entry_type, content, metadata)
       SELECT c.id, $2, $3, $4, $5::jsonb
       FROM calls c
       WHERE c.id = $1 AND c.session_kind = 'conference'
       RETURNING *`,
      [callId, userId == null ? null : String(userId), entryType, content, JSON.stringify(metadata || {})],
    );
    return rows[0] || null;
  },

  /**
   * Conversation and notes of a conference that is still running, in the
   * exact wire shape live clients already consume (`receive_group_message` /
   * `conference_note_added`). Sent to every (re)joining device so a late
   * joiner, a reconnect or an app restart mid-meeting starts from the shared
   * record instead of an empty panel. Bounded to the most recent entries.
   */
  async listLiveHistory(callId, { limit = 500 } = {}) {
    const { rows } = await db.query(
      `SELECT * FROM (
         SELECT e.id, e.entry_type, e.content, e.user_id, e.created_at, u.username
         FROM conference_entries e
         LEFT JOIN users u ON u.id::text = e.user_id
         WHERE e.call_id = $1 AND e.entry_type IN ('message', 'note')
         ORDER BY e.created_at DESC, e.id DESC
         LIMIT $2
       ) recent
       ORDER BY created_at, id`,
      [callId, limit],
    );
    const messages = [];
    const notes = [];
    for (const row of rows) {
      const timestamp = new Date(row.created_at).getTime();
      const author = row.username || 'Participant';
      if (row.entry_type === 'message') {
        messages.push({
          id: String(row.id),
          messageId: String(row.id),
          senderId: row.user_id,
          sender: author,
          text: row.content,
          timestamp,
        });
      } else {
        notes.push({
          id: String(row.id),
          authorId: row.user_id,
          author,
          text: row.content,
          timestamp,
        });
      }
    }
    return { messages, notes };
  },

  async getForParticipant(callId, userId) {
    const { rows: calls } = await db.query(
      `SELECT c.id AS call_id, c.call_type, c.status, c.started_at, c.ended_at,
              c.initiator_id, r.name AS title,
              host.username AS organizer_username,
              host.full_name AS organizer_full_name
       FROM calls c
       JOIN rooms r ON r.id = c.room_id
       JOIN users host ON host.id = c.initiator_id
       WHERE c.id = $1
         AND c.session_kind = 'conference'
         AND EXISTS (
           SELECT 1 FROM call_participants access
           WHERE access.call_id = c.id AND access.user_id = $2
         )`,
      [callId, userId],
    );
    if (!calls[0]) return null;

    // Attendance comes from the archive's own join events: call_participants
    // only keeps the latest join, and would show a rejoin as the arrival time.
    const [{ rows: participants }, { rows: entries }] = await Promise.all([
      db.query(
        `SELECT cp.user_id AS "userId", u.username, u.full_name AS "fullName",
                u.profile_picture AS "profilePicture", cp.answered,
                COALESCE(att.first_joined_at, CASE WHEN cp.answered THEN cp.joined_at END) AS "joinedAt",
                CASE WHEN cp.answered THEN cp.left_at END AS "leftAt",
                COALESCE(att.join_count, 0) AS "joinCount",
                (cp.user_id = $2) AS "isOrganizer"
         FROM call_participants cp
         JOIN users u ON u.id = cp.user_id
         LEFT JOIN LATERAL (
           SELECT MIN(e.created_at) AS first_joined_at, COUNT(*)::int AS join_count
           FROM conference_entries e
           WHERE e.call_id = cp.call_id
             AND e.entry_type = 'joined'
             AND e.user_id = cp.user_id::text
         ) att ON TRUE
         WHERE cp.call_id = $1
         ORDER BY "joinedAt" NULLS LAST, u.username`,
        [callId, calls[0].initiator_id],
      ),
      db.query(
        `SELECT e.id, e.entry_type AS type, e.content, e.metadata,
                e.created_at AS "createdAt", e.user_id AS "userId",
                u.username, u.full_name AS "fullName",
                u.profile_picture AS "profilePicture"
         FROM conference_entries e
         LEFT JOIN users u ON u.id::text = e.user_id
         WHERE e.call_id = $1
         ORDER BY e.created_at, e.id`,
        [callId],
      ),
    ]);

    return { conference: calls[0], participants, entries };
  },
};

module.exports = ConferenceArchiveQueries;

const db = require('../index');

/**
 * Scheduled ("planned") conferences + invite lists. See migration 044.
 * A row here is a future intent; once started it flips to status='started' and
 * a real ephemeral-room conference call takes over (session_kind='conference').
 */
const ScheduledConferenceQueries = {
  /** Create a scheduled conference and its invitee rows in one transaction. */
  async create({ title, callType = 'video', scheduledFor, createdBy, inviteeIds = [] }) {
    // De-dupe + never invite the creator (they own it).
    const creatorId = String(createdBy);
    const unique = [...new Set(
      inviteeIds
        .filter((id) => id !== null && id !== undefined && String(id) !== creatorId)
        .map((id) => String(id)),
    )];
    return db.transaction(async (client) => {
      const { rows } = await client.query(
        `INSERT INTO scheduled_conferences (title, call_type, scheduled_for, created_by)
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [title, callType, scheduledFor, createdBy],
      );
      const conf = rows[0];
      for (const uid of unique) {
        await client.query(
          `INSERT INTO scheduled_conference_invitees (conference_id, user_id)
           VALUES ($1, $2) ON CONFLICT (conference_id, user_id) DO NOTHING`,
          [conf.id, uid],
        );
      }
      conf.inviteeIds = unique;
      return conf;
    });
  },

  /** Upcoming conferences the user is part of (creator OR invitee), soonest first. */
  async listUpcomingForUser(userId) {
    const { rows } = await db.query(
      `SELECT sc.*,
              u.username AS creator_username,
              COALESCE(
                (SELECT json_agg(json_build_object('userId', iu.id, 'username', iu.username, 'response', i.response))
                 FROM scheduled_conference_invitees i
                 JOIN users iu ON iu.id = i.user_id
                 WHERE i.conference_id = sc.id),
                '[]'::json
              ) AS invitees
       FROM scheduled_conferences sc
       JOIN users u ON u.id = sc.created_by
       WHERE sc.status = 'scheduled'
         AND sc.scheduled_for > NOW() - INTERVAL '1 hour'
         AND (sc.created_by = $1
              OR EXISTS (SELECT 1 FROM scheduled_conference_invitees i2
                         WHERE i2.conference_id = sc.id AND i2.user_id = $1))
       ORDER BY sc.scheduled_for ASC`,
      [userId],
    );
    return rows;
  },

  async getById(id) {
    const { rows } = await db.query('SELECT * FROM scheduled_conferences WHERE id = $1', [id]);
    return rows[0] || null;
  },

  async getInviteeIds(conferenceId) {
    const { rows } = await db.query(
      'SELECT user_id FROM scheduled_conference_invitees WHERE conference_id = $1',
      [conferenceId],
    );
    return rows.map((r) => r.user_id);
  },

  async setStatus(id, status) {
    await db.query('UPDATE scheduled_conferences SET status = $2 WHERE id = $1', [id, status]);
  },

  async setInviteeResponse(conferenceId, userId, response) {
    await db.query(
      `UPDATE scheduled_conference_invitees SET response = $3
       WHERE conference_id = $1 AND user_id = $2`,
      [conferenceId, userId, response],
    );
  },

  /** Conferences within `withinMinutes` of starting that haven't been reminded yet. */
  async listDueForReminder(withinMinutes = 15) {
    const { rows } = await db.query(
      `SELECT sc.*,
              ARRAY(
                SELECT i.user_id
                FROM scheduled_conference_invitees i
                WHERE i.conference_id = sc.id
                ORDER BY i.id
              ) AS invitee_ids
       FROM scheduled_conferences sc
       WHERE sc.status = 'scheduled'
         AND sc.reminder_sent = FALSE
         AND sc.scheduled_for > NOW()
         AND sc.scheduled_for <= NOW() + ($1 || ' minutes')::interval`,
      [String(withinMinutes)],
    );
    return rows;
  },

  async markReminderSent(id) {
    await db.query('UPDATE scheduled_conferences SET reminder_sent = TRUE WHERE id = $1', [id]);
  },

  /** Conferences whose scheduled_for has arrived but haven't gotten the "starting now" push yet. */
  async listDueForStartNotification() {
    const { rows } = await db.query(
      `SELECT sc.*,
              ARRAY(
                SELECT i.user_id
                FROM scheduled_conference_invitees i
                WHERE i.conference_id = sc.id
                ORDER BY i.id
              ) AS invitee_ids
       FROM scheduled_conferences sc
       WHERE sc.status = 'scheduled'
         AND sc.start_notified = FALSE
         AND sc.scheduled_for <= NOW()
         -- A "starting now" push for something a day overdue isn't useful, and
         -- without a lower bound a conference nobody ever started (or whose
         -- notification loop errored before markStartNotified ran) stays
         -- "due" and gets rescanned on every 60s tick forever. Bounding the
         -- window keeps the scan cost flat regardless of how much of that
         -- backlog has accumulated.
         AND sc.scheduled_for >= NOW() - INTERVAL '24 hours'`,
    );
    return rows;
  },

  async markStartNotified(id) {
    await db.query('UPDATE scheduled_conferences SET start_notified = TRUE WHERE id = $1', [id]);
  },
};

module.exports = ScheduledConferenceQueries;

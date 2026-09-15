const db = require('../index');

/**
 * Durable journal for the in-memory RecordingQueue.
 *
 * Each transcoding job is mirrored here so a process restart can RESUME any job
 * left mid-flight (status 'queued'/'transcoding') from its serialized raw snapshot,
 * or clean it up if the raw artifacts no longer exist. See migration
 * 039_add_recording_jobs.sql and the RecordingQueue in server.js.
 *
 * The hot path stays in-memory; these writes are best-effort and must never block
 * or break recording if the DB is briefly unavailable (callers swallow errors).
 */
const RecordingJobQueries = {
  /**
   * Upsert a job in 'queued' state with its resume snapshot.
   * @param {{ callId: string, dbRoomId?: string|null, payload?: object|null }} data
   */
  async enqueue({ callId, dbRoomId = null, payload = null }) {
    await db.query(
      `INSERT INTO recording_jobs (call_id, db_room_id, status, payload, attempts, created_at, updated_at)
       VALUES ($1, $2, 'queued', $3, 0, NOW(), NOW())
       ON CONFLICT (call_id) DO UPDATE
         SET db_room_id = EXCLUDED.db_room_id,
             status     = 'queued',
             payload    = EXCLUDED.payload,
             error      = NULL,
             updated_at = NOW()`,
      [callId, dbRoomId, payload ? JSON.stringify(payload) : null],
    );
  },

  /** Mark a job as actively transcoding and bump the attempt counter. */
  async markTranscoding(callId) {
    await db.query(
      `UPDATE recording_jobs
         SET status = 'transcoding', attempts = attempts + 1,
             started_at = NOW(), updated_at = NOW()
       WHERE call_id = $1`,
      [callId],
    );
  },

  /** Mark a job done. */
  async markDone(callId) {
    await db.query(
      `UPDATE recording_jobs
         SET status = 'done', done_at = NOW(), updated_at = NOW()
       WHERE call_id = $1`,
      [callId],
    );
  },

  /** Mark a job failed with an error message. */
  async markError(callId, errorMessage) {
    await db.query(
      `UPDATE recording_jobs
         SET status = 'error', error = $2, done_at = NOW(), updated_at = NOW()
       WHERE call_id = $1`,
      [callId, errorMessage ? String(errorMessage).slice(0, 1000) : null],
    );
  },

  /**
   * List jobs that were interrupted by a restart (still queued/transcoding).
   * Oldest first so resume order matches enqueue order.
   */
  async listResumable() {
    const { rows } = await db.query(
      `SELECT call_id, db_room_id, status, payload, attempts
         FROM recording_jobs
        WHERE status IN ('queued', 'transcoding')
        ORDER BY created_at ASC`,
    );
    return rows;
  },

  /** Delete a single job row. */
  async deleteByCallId(callId) {
    await db.query('DELETE FROM recording_jobs WHERE call_id = $1', [callId]);
  },

  /**
   * Sweep terminal rows (done/error) older than the retention window so the
   * table doesn't grow unbounded. Returns the number of rows removed.
   */
  async sweepTerminal(retentionMinutes = 60) {
    const { rowCount } = await db.query(
      `DELETE FROM recording_jobs
        WHERE status IN ('done', 'error')
          AND done_at < NOW() - ($1 || ' minutes')::interval`,
      [String(retentionMinutes)],
    );
    return rowCount;
  },
};

module.exports = RecordingJobQueries;

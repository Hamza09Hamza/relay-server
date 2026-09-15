const db = require('../index');
const fs = require('fs');

const RecordingQueries = {
  /**
   * Create a recording entry after a call recording finishes.
   * @param {{ callId: string, filePath: string, fileSize?: number, duration?: number, format: 'mp3'|'mp4', userId?: string, username?: string, fileHash?: string, speakerTimeline?: Array<{startSec:number,endSec:number}>, videoTimeline?: Array<{startSec:number,endSec:number}>, presenceTimeline?: Array<{startSec:number,endSec:number}>, presenceEvents?: Array<{type:'join'|'leave',atSec:number}> }} data
   * @returns {Promise<object>}
   */
  async create({ callId, filePath, fileSize, duration, format, userId, username, fileHash, speakerTimeline, videoTimeline, presenceTimeline, presenceEvents }) {
    const { rows } = await db.query(
      `INSERT INTO recordings (call_id, file_path, file_size, duration, format, user_id, username, file_hash, speaker_timeline, video_timeline, presence_timeline, presence_events)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb)
       RETURNING *`,
      [
        callId,
        filePath,
        fileSize || null,
        duration || null,
        format,
        userId || null,
        username || null,
        fileHash || null,
        JSON.stringify(Array.isArray(speakerTimeline) ? speakerTimeline : []),
        JSON.stringify(Array.isArray(videoTimeline) ? videoTimeline : []),
        JSON.stringify(Array.isArray(presenceTimeline) ? presenceTimeline : []),
        JSON.stringify(Array.isArray(presenceEvents) ? presenceEvents : []),
      ],
    );
    return rows[0];
  },

  /**
   * Find a recording by id.
   */
  async findById(id) {
    const { rows } = await db.query('SELECT * FROM recordings WHERE id = $1', [id]);
    return rows[0] || null;
  },

  /**
   * Find recordings belonging to a call.
   */
  async findByCallId(callId) {
    const { rows } = await db.query(
      'SELECT * FROM recordings WHERE call_id = $1 ORDER BY created_at DESC',
      [callId],
    );
    return rows;
  },

  /**
   * List recordings accessible by a user (via call participation).
   */
  async listByUser(userId, { limit = 30, offset = 0 } = {}) {
    const { rows } = await db.query(
      `SELECT r.*, c.call_type, c.started_at AS call_started_at
       FROM recordings r
       JOIN calls c ON c.id = r.call_id
       JOIN call_participants cp ON cp.call_id = c.id
       WHERE cp.user_id = $1
       ORDER BY r.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset],
    );
    return rows;
  },

  /**
   * Delete a recording (row + file on disk).
   */
  async remove(id) {
    const recording = await this.findById(id);
    if (!recording) return false;

    await db.query('DELETE FROM recordings WHERE id = $1', [id]);

    try {
      if (recording.file_path && fs.existsSync(recording.file_path)) {
        fs.unlinkSync(recording.file_path);
      }
    } catch (err) {
      console.error('[Recording] Failed to delete file:', err.message);
    }

    return true;
  },
};

module.exports = RecordingQueries;

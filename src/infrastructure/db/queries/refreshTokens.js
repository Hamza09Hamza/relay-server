const db = require('../index');

/**
 * Refresh-token persistence. Only SHA-256 hashes are stored (see auth.service).
 * Rotation: on each refresh the old row is revoked and `replaced_by` points to
 * the new row, so reuse of a rotated token is detectable.
 */
const RefreshTokenQueries = {
  async create({ userId, tokenHash, expiresAt, userAgent = null, deviceId = null }) {
    const { rows } = await db.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, device_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [userId, tokenHash, expiresAt, userAgent, deviceId],
    );
    return rows[0];
  },

  /** Valid = exists, not revoked, not expired. */
  async findValidByHash(tokenHash) {
    const { rows } = await db.query(
      `SELECT * FROM refresh_tokens
       WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
      [tokenHash],
    );
    return rows[0] || null;
  },

  /** Raw lookup (used to detect reuse of an already-revoked token). */
  async findByHash(tokenHash) {
    const { rows } = await db.query(
      `SELECT * FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    return rows[0] || null;
  },

  async revoke(id, replacedBy = null) {
    await db.query(
      `UPDATE refresh_tokens SET revoked_at = NOW(), replaced_by = $2
       WHERE id = $1 AND revoked_at IS NULL`,
      [id, replacedBy],
    );
  },

  async revokeByHash(tokenHash) {
    await db.query(
      `UPDATE refresh_tokens SET revoked_at = NOW()
       WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash],
    );
  },

  /** Revoke every active token for a user (token reuse, password change, ban). */
  async revokeAllForUser(userId) {
    await db.query(
      `UPDATE refresh_tokens SET revoked_at = NOW()
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
  },

  /** Housekeeping: drop expired rows and long-revoked rows. */
  async deleteExpired() {
    const { rowCount } = await db.query(
      `DELETE FROM refresh_tokens
       WHERE expires_at < NOW()
          OR (revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL '30 days')`,
    );
    return rowCount;
  },
};

module.exports = RefreshTokenQueries;

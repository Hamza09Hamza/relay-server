const db = require('../index');

/**
 * Remove sensitive fields from a user object before sending to client.
 * @param {object} user
 * @returns {object} sanitized user
 */
function sanitize(user) {
  if (!user || typeof user !== 'object') return user;
  const {
    password,
    password_reset_token,
    password_reset_status,
    can_message,
    can_call,
    can_conference,
    can_ptt,
    ...safeUser
  } = user;
  delete safeUser.password;
  delete safeUser.passwordResetToken;
  delete safeUser.passwordResetStatus;
  safeUser.capabilities = user.role === 'superadmin'
    ? { messages: true, calls: true, conferences: true, ptt: true }
    : {
        messages: can_message !== false,
        calls: can_call !== false,
        conferences: can_conference !== false,
        ptt: can_ptt !== false,
      };
  return safeUser;
}

// Allowed account statuses — prevents arbitrary values from reaching the DB
const VALID_USER_STATUSES = ['pending', 'active', 'rejected'];

const UserQueries = {
  async setCapabilities(id, capabilities) {
    const { rows } = await db.query(
      `UPDATE users
       SET can_message = $2, can_call = $3, can_conference = $4, can_ptt = $5
       WHERE id = $1
       RETURNING *`,
      [
        id,
        capabilities.messages,
        capabilities.calls,
        capabilities.conferences,
        capabilities.ptt,
      ],
    );
    return rows[0] || null;
  },

  async hasCapability(id, capability) {
    const columns = {
      messages: 'can_message',
      calls: 'can_call',
      conferences: 'can_conference',
      ptt: 'can_ptt',
    };
    const column = columns[capability];
    if (!column) return false;
    const { rows } = await db.query(
      `SELECT role, status, ${column} AS enabled FROM users WHERE id = $1`,
      [id],
    );
    const user = rows[0];
    return !!user && user.status === 'active' &&
      (user.role === 'superadmin' || user.enabled === true);
  },

  /**
   * All four capabilities in one query — for call sites that would otherwise
   * call hasCapability() repeatedly for the same user (e.g. checking several
   * differently-typed notifications in a loop). Null if the account isn't
   * active. Same semantics as hasCapability: a superadmin always has every
   * capability regardless of the stored flags.
   */
  async getActiveCapabilities(id) {
    const { rows } = await db.query(
      `SELECT role, status, can_message, can_call, can_conference, can_ptt
       FROM users WHERE id = $1`,
      [id],
    );
    const user = rows[0];
    if (!user || user.status !== 'active') return null;
    if (user.role === 'superadmin') {
      return { messages: true, calls: true, conferences: true, ptt: true };
    }
    return {
      messages: user.can_message === true,
      calls: user.can_call === true,
      conferences: user.can_conference === true,
      ptt: user.can_ptt === true,
    };
  },

  async filterIdsWithCapability(ids, capability) {
    const columns = {
      messages: 'can_message', calls: 'can_call', conferences: 'can_conference', ptt: 'can_ptt',
    };
    const column = columns[capability];
    const uniqueIds = [...new Set((ids || []).filter(Boolean).map(String))];
    if (!column || uniqueIds.length === 0) return [];
    const { rows } = await db.query(
      `SELECT id::text AS id FROM users
       WHERE id::text = ANY($1::text[]) AND status = 'active'
         AND (role = 'superadmin' OR ${column} = TRUE)`,
      [uniqueIds],
    );
    return rows.map(row => row.id);
  },

  /**
   * Create a new user.
   * @param {{ username: string, email?: string, phoneNumber?: string, password: string, profilePicture?: string }} data
   * @returns {Promise<object>} The created user row.
   */
  async create({ username, fullName, email, phoneNumber, password, profilePicture, role, status }) {
    const { rows } = await db.query(
      `INSERT INTO users (username, full_name, email, phone_number, password, profile_picture, role, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [
        username,
        fullName || username, // fallback: use username as display name
        email || null,
        phoneNumber || null,
        password,
        profilePicture || null,
        role || 'user',
        status || 'pending',
      ],
    );
    return rows[0];
  },

  /**
   * Find a user by primary key.
   */
  async findById(id) {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    return rows[0] || null;
  },

  /**
   * Find a user by username.
   */
  async findByUsername(username) {
    // Excludes soft-deleted accounts: a deleted user must be invisible to
    // both login (can't authenticate as them) and registration (their old
    // username becomes free to reuse) without a separate check in either.
    const { rows } = await db.query('SELECT * FROM users WHERE username = $1 AND NOT deleted', [username]);
    return rows[0] || null;
  },

  /**
   * Find a user by email.
   */
  async findByEmail(email) {
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1 AND NOT deleted', [email]);
    return rows[0] || null;
  },

  /**
   * Set the online status of a user.
   */
  async setOnlineStatus(id, isOnline) {
    const { rows } = await db.query(
      `UPDATE users
       SET is_online  = $2,
           last_seen  = CASE WHEN $2 = FALSE THEN NOW() ELSE last_seen END
       WHERE id = $1
       RETURNING *`,
      [id, isOnline],
    );
    return rows[0] || null;
  },

  /**
   * Update profile fields (username, email, phone, picture).
   *
   * SECURITY: Uses an explicit column map (not regex transform) to
   * convert JS property names to DB column names. Only mapped columns
   * are allowed — everything else is silently ignored.
   */
  async updateProfile(id, fields) {
    // Explicit mapping: accepted JS key → DB column name
    const COLUMN_MAP = {
      username: 'username',
      fullName: 'full_name',
      full_name: 'full_name',
      email: 'email',
      phoneNumber: 'phone_number',
      phone_number: 'phone_number',
      profilePicture: 'profile_picture',
      profile_picture: 'profile_picture',
    };

    const sets = [];
    const values = [];
    let idx = 1;

    for (const [key, value] of Object.entries(fields)) {
      const column = COLUMN_MAP[key];
      if (column) {
        sets.push(`${column} = $${idx}`);
        values.push(value);
        idx++;
      }
    }

    if (sets.length === 0) return this.findById(id);

    values.push(id);
    const { rows } = await db.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id = $${idx} RETURNING *`,
      values,
    );
    return rows[0] || null;
  },

  /**
   * Update password. Also bumps token_version so any access token issued
   * before this change stops passing authMiddleware's version check —
   * a password change must invalidate sessions, not just future refreshes.
   */
  async updatePassword(id, password) {
    await db.query(
      'UPDATE users SET password = $2, token_version = token_version + 1 WHERE id = $1',
      [id, password],
    );
  },

  /**
   * Minimal per-request auth check — deliberately narrow (no password hash,
   * no profile fields) since authMiddleware calls this on every cache miss.
   */
  async findAuthStatus(id) {
    const { rows } = await db.query(
      `SELECT id, deleted, status, token_version,
              EXISTS (
                SELECT 1 FROM user_workspaces
                WHERE user_id = users.id AND status = 'suspended'
              ) AS suspended
       FROM users WHERE id = $1`,
      [id],
    );
    return rows[0] || null;
  },

  /**
   * Set password reset status and optional token.
   */
  async setPasswordResetStatus(id, status, token = null) {
    const { rows } = await db.query(
      'UPDATE users SET password_reset_status = $2, password_reset_token = $3 WHERE id = $1 RETURNING *',
      [id, status, token],
    );
    return rows[0] || null;
  },

  /**
   * Find a user by password reset token.
   */
  async findByResetToken(token) {
    if (!token) return null;
    const { rows } = await db.query(
      'SELECT * FROM users WHERE password_reset_token = $1',
      [token],
    );
    return rows[0] || null;
  },

  /**
   * Clear password reset state.
   */
  async clearPasswordReset(id) {
    await db.query(
      'UPDATE users SET password_reset_status = NULL, password_reset_token = NULL WHERE id = $1',
      [id],
    );
  },

  /**
   * List users with pending password reset requests.
   */
  async listPasswordResetRequests() {
    const { rows } = await db.query(
      "SELECT * FROM users WHERE password_reset_status = 'requested' ORDER BY created_at ASC",
    );
    return rows;
  },

  /**
   * Set account status (pending, active, rejected).
   */
  async setStatus(id, status) {
    if (!VALID_USER_STATUSES.includes(status)) {
      throw new Error(`Invalid user status: ${status}`);
    }
    const { rows } = await db.query(
      'UPDATE users SET status = $2 WHERE id = $1 RETURNING *',
      [id, status],
    );
    return rows[0] || null;
  },

  /**
   * List all users with a given status.
   */
  async listByStatus(status, { limit = 50, offset = 0 } = {}) {
    const { rows } = await db.query(
      `SELECT * FROM users WHERE status = $1
       ORDER BY created_at ASC
       LIMIT $2 OFFSET $3`,
      [status, limit, offset],
    );
    return rows;
  },

  /**
   * List every user (admin view). Supports pagination.
   */
  async listAll({ limit = 50, offset = 0 } = {}) {
    const { rows } = await db.query(
      'SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset],
    );
    return rows;
  },

  /**
   * Update user fields.
   *
   * SECURITY: Only columns in ALLOWED_COLUMNS can be updated.
   * Object keys from the caller are matched against this whitelist
   * BEFORE being interpolated as SQL identifiers, preventing SQL
   * injection via crafted key names like "role = 'admin' --".
   *
   * @param {string} userId
   * @param {Object} updates - Object with fields to update
   */
  async update(userId, updates) {
    // Whitelist of columns that may be updated via this generic method.
    // Add new columns here when needed — never interpolate unvalidated keys.
    const ALLOWED_COLUMNS = [
      'username', 'full_name', 'email', 'phone_number', 'profile_picture',
      'is_online', 'last_seen', 'status',
    ];

    // Map camelCase JS keys → snake_case DB columns for lookup
    const CAMEL_TO_SNAKE = {
      username: 'username',
      fullName: 'full_name',
      full_name: 'full_name',
      email: 'email',
      phoneNumber: 'phone_number',
      phone_number: 'phone_number',
      profilePicture: 'profile_picture',
      profile_picture: 'profile_picture',
      isOnline: 'is_online',
      is_online: 'is_online',
      lastSeen: 'last_seen',
      last_seen: 'last_seen',
      status: 'status',
    };

    const safeSets = [];
    const safeValues = [];

    for (const [key, value] of Object.entries(updates)) {
      const column = CAMEL_TO_SNAKE[key];
      if (column && ALLOWED_COLUMNS.includes(column)) {
        safeSets.push(column);
        safeValues.push(value);
      }
    }

    if (safeSets.length === 0) return null;

    const setClause = safeSets
      .map((col, idx) => `${col} = $${idx + 2}`)
      .join(', ');

    const result = await db.query(
      `UPDATE users SET ${setClause} WHERE id = $1 RETURNING *`,
      [userId, ...safeValues],
    );

    return result.rows[0];
  },
};

UserQueries.sanitize = sanitize;

module.exports = UserQueries;

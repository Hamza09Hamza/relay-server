const db = require('../index');

const UserWorkspaceQueries = {
  /**
   * Global users.role='admin' is a derived state, not an independently-set
   * flag — it means "admin of at least one active workspace". Call this any
   * time a user_workspaces row is removed or demoted outside the dedicated
   * promote/demote-from-workspace routes (which already keep this in sync
   * inline), e.g. after a transfer removes their last admin membership.
   * Never touches superadmin — that's manually assigned, not derived.
   */
  async syncGlobalAdminRole(userId) {
    const { rows: userRows } = await db.query(`SELECT role FROM users WHERE id = $1`, [userId]);
    const current = userRows[0]?.role;
    if (!current || current === 'superadmin') return;
    const { rows: adminRows } = await db.query(
      `SELECT 1 FROM user_workspaces WHERE user_id = $1 AND role = 'admin' AND status = 'active' LIMIT 1`,
      [userId],
    );
    const shouldBeAdmin = adminRows.length > 0;
    const nextRole = shouldBeAdmin ? 'admin' : 'user';
    if (current !== nextRole) {
      await db.query(`UPDATE users SET role = $2 WHERE id = $1`, [userId, nextRole]);
    }
  },

  async getForUser(userId) {
    const { rows } = await db.query(
      `SELECT uw.*, w.name AS workspace_name, w.slug AS workspace_slug, w.color AS workspace_color
       FROM user_workspaces uw
       JOIN workspaces w ON w.id = uw.workspace_id
       WHERE uw.user_id = $1
       ORDER BY w.name ASC`,
      [userId],
    );
    return rows;
  },

  async getPendingForWorkspace(workspaceId) {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, u.phone_number, u.profile_picture,
              u.role, u.status AS user_status, uw.created_at AS requested_at,
              uw.id AS membership_id
       FROM user_workspaces uw
       JOIN users u ON u.id = uw.user_id
       WHERE uw.workspace_id = $1 AND uw.status = 'pending'
       ORDER BY uw.created_at ASC`,
      [workspaceId],
    );
    return rows;
  },

  async getActiveForWorkspace(workspaceId) {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, u.phone_number, u.profile_picture,
              u.role, u.status AS user_status, uw.role AS workspace_role,
              uw.status AS membership_status, uw.accepted_at
       FROM user_workspaces uw
       JOIN users u ON u.id = uw.user_id
       WHERE uw.workspace_id = $1 AND uw.status = 'active'
       ORDER BY u.username ASC`,
      [workspaceId],
    );
    return rows;
  },

  async getAdminsForWorkspace(workspaceId) {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, u.profile_picture, u.role
       FROM user_workspaces uw
       JOIN users u ON u.id = uw.user_id
       WHERE uw.workspace_id = $1 AND uw.role = 'admin' AND uw.status = 'active'`,
      [workspaceId],
    );
    return rows;
  },

  async addRequest(userId, workspaceId) {
    const { rows } = await db.query(
      `INSERT INTO user_workspaces (user_id, workspace_id, role, status)
       VALUES ($1, $2, 'member', 'pending')
       ON CONFLICT (user_id, workspace_id) DO NOTHING
       RETURNING *`,
      [userId, workspaceId],
    );
    return rows[0] || null;
  },

  async accept(userId, workspaceId, acceptedBy) {
    const { rows } = await db.query(
      `UPDATE user_workspaces
       SET status = 'active', accepted_by = $3, accepted_at = NOW()
       WHERE user_id = $1 AND workspace_id = $2 AND status = 'pending'
       RETURNING *`,
      [userId, workspaceId, acceptedBy],
    );
    return rows[0] || null;
  },

  async reject(userId, workspaceId) {
    const { rows } = await db.query(
      `UPDATE user_workspaces SET status = 'rejected'
       WHERE user_id = $1 AND workspace_id = $2 AND status = 'pending'
       RETURNING *`,
      [userId, workspaceId],
    );
    return rows[0] || null;
  },

  async suspend(userId, workspaceId, reason = null) {
    const { rows } = await db.query(
      `UPDATE user_workspaces
       SET status = 'suspended',
           suspension_reason = $3,
           suspended_at = NOW()
       WHERE user_id = $1 AND workspace_id = $2
       RETURNING *`,
      [userId, workspaceId, reason || null],
    );
    return rows[0] || null;
  },

  async getSuspensionReason(userId) {
    const { rows } = await db.query(
      `SELECT suspension_reason, suspended_at
       FROM user_workspaces
       WHERE user_id = $1 AND status = 'suspended'
       ORDER BY suspended_at DESC NULLS LAST
       LIMIT 1`,
      [userId],
    );
    return rows[0] || null;
  },

  async reinstate(userId, workspaceId) {
    const { rows } = await db.query(
      `UPDATE user_workspaces SET status = 'active'
       WHERE user_id = $1 AND workspace_id = $2
       RETURNING *`,
      [userId, workspaceId],
    );
    return rows[0] || null;
  },

  async setRole(userId, workspaceId, role) {
    const { rows } = await db.query(
      `UPDATE user_workspaces SET role = $3
       WHERE user_id = $1 AND workspace_id = $2
       RETURNING *`,
      [userId, workspaceId, role],
    );
    return rows[0] || null;
  },

  async getMembership(userId, workspaceId) {
    const { rows } = await db.query(
      `SELECT * FROM user_workspaces WHERE user_id = $1 AND workspace_id = $2`,
      [userId, workspaceId],
    );
    return rows[0] || null;
  },

  async isAdminOfWorkspace(userId, workspaceId) {
    const { rows } = await db.query(
      `SELECT 1 FROM user_workspaces
       WHERE user_id = $1 AND workspace_id = $2
         AND role = 'admin' AND status = 'active'`,
      [userId, workspaceId],
    );
    return rows.length > 0;
  },

  // Returns all users (active) who share at least 1 workspace with the given user.
  // Superadmins are excluded — they only appear via accepted contact requests.
  async getSharedWorkspaceUsers(userId) {
    const { rows } = await db.query(
      `SELECT DISTINCT u.id, u.username, u.email, u.phone_number,
              u.profile_picture, u.role, u.status
       FROM user_workspaces my_uw
       JOIN user_workspaces other_uw ON other_uw.workspace_id = my_uw.workspace_id
       JOIN users u ON u.id = other_uw.user_id
       WHERE my_uw.user_id = $1
         AND my_uw.status = 'active'
         AND other_uw.status = 'active'
         AND u.id != $1
         AND u.status = 'active'
         AND u.role != 'superadmin'`,
      [userId],
    );
    return rows;
  },

  // Returns all active workspaces the user administers
  async getAdminWorkspacesForUser(userId) {
    const { rows } = await db.query(
      `SELECT w.* FROM user_workspaces uw
       JOIN workspaces w ON w.id = uw.workspace_id
       WHERE uw.user_id = $1 AND uw.role = 'admin' AND uw.status = 'active'
       ORDER BY w.name ASC`,
      [userId],
    );
    return rows;
  },

  // Pending across all workspaces the user administers
  async getPendingForAdmin(adminId) {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, u.phone_number, u.profile_picture,
              u.role, uw.created_at AS requested_at,
              uw.workspace_id, w.name AS workspace_name, w.slug AS workspace_slug,
              w.color AS workspace_color
       FROM user_workspaces my_uw
       JOIN user_workspaces uw ON uw.workspace_id = my_uw.workspace_id
       JOIN users u ON u.id = uw.user_id
       JOIN workspaces w ON w.id = uw.workspace_id
       WHERE my_uw.user_id = $1 AND my_uw.role = 'admin' AND my_uw.status = 'active'
         AND uw.status = 'pending'
         AND u.id != $1
       ORDER BY uw.created_at ASC`,
      [adminId],
    );
    return rows;
  },

  // All users across all workspaces the admin manages.
  // Superadmins excluded — only visible via accepted contact requests.
  async getUsersForAdmin(adminId) {
    const { rows } = await db.query(
      `SELECT DISTINCT u.id, u.username, u.email, u.phone_number,
              u.profile_picture, u.role, u.status
       FROM user_workspaces my_uw
       JOIN user_workspaces uw ON uw.workspace_id = my_uw.workspace_id
       JOIN users u ON u.id = uw.user_id
       WHERE my_uw.user_id = $1 AND my_uw.role = 'admin' AND my_uw.status = 'active'
         AND uw.status = 'active'
         AND u.id != $1
         AND u.role != 'superadmin'
       ORDER BY u.username ASC`,
      [adminId],
    );
    return rows;
  },

  // Get all workspace memberships for a specific user (for admin view)
  async getMembershipsForUser(userId) {
    const { rows } = await db.query(
      `SELECT uw.*, w.name AS workspace_name, w.slug AS workspace_slug, w.color AS workspace_color
       FROM user_workspaces uw
       JOIN workspaces w ON w.id = uw.workspace_id
       WHERE uw.user_id = $1
       ORDER BY w.name ASC`,
      [userId],
    );
    return rows;
  },
};

module.exports = UserWorkspaceQueries;

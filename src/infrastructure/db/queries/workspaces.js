const db = require('../index');

const WorkspaceQueries = {
  async listAll() {
    const { rows } = await db.query(
      'SELECT * FROM workspaces ORDER BY name ASC',
    );
    return rows;
  },

  async findById(id) {
    const { rows } = await db.query('SELECT * FROM workspaces WHERE id = $1', [id]);
    return rows[0] || null;
  },

  async findBySlug(slug) {
    const { rows } = await db.query('SELECT * FROM workspaces WHERE slug = $1', [slug]);
    return rows[0] || null;
  },

  async create({ name, slug, color, createdBy }) {
    const { rows } = await db.query(
      `INSERT INTO workspaces (name, slug, color, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, slug, color || '#4F46E5', createdBy || null],
    );
    return rows[0];
  },

  async update(id, { name, color }) {
    const fields = [];
    const values = [];
    let idx = 1;
    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (color !== undefined) { fields.push(`color = $${idx++}`); values.push(color); }
    if (fields.length === 0) throw new Error('No fields to update');
    values.push(id);
    const { rows } = await db.query(
      `UPDATE workspaces SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values,
    );
    return rows[0] || null;
  },

  async delete(id) {
    await db.query('DELETE FROM workspaces WHERE id = $1', [id]);
  },

  async getMemberCount(id) {
    const { rows } = await db.query(
      `SELECT COUNT(*) AS count FROM user_workspaces
       WHERE workspace_id = $1 AND status = 'active'`,
      [id],
    );
    return parseInt(rows[0].count, 10);
  },

  async getAdminCount(id) {
    const { rows } = await db.query(
      `SELECT COUNT(*) AS count FROM user_workspaces
       WHERE workspace_id = $1 AND role = 'admin' AND status = 'active'`,
      [id],
    );
    return parseInt(rows[0].count, 10);
  },

  async listAllWithStats() {
    const { rows } = await db.query(
      `SELECT f.*,
         COUNT(uf.id) FILTER (WHERE uf.status = 'active' AND u.role != 'superadmin')::INTEGER AS member_count,
         COUNT(uf.id) FILTER (WHERE uf.role = 'admin' AND uf.status = 'active' AND u.role != 'superadmin')::INTEGER AS admin_count,
         COUNT(uf.id) FILTER (WHERE uf.status = 'pending')::INTEGER AS pending_count,
         json_agg(json_build_object(
           'id', u.id,
           'username', u.username,
           'email', u.email,
           'full_name', u.full_name,
           'status', uf.status,
           'role', uf.role
         ) ORDER BY u.username) FILTER (WHERE uf.status = 'active' AND u.role != 'superadmin') AS active_members,
         json_agg(json_build_object(
           'id', u.id,
           'username', u.username,
           'email', u.email,
           'full_name', u.full_name,
           'status', uf.status,
           'role', uf.role
         ) ORDER BY u.username) FILTER (WHERE uf.status = 'pending') AS pending_members
       FROM workspaces f
       LEFT JOIN user_workspaces uf ON uf.workspace_id = f.id
       LEFT JOIN users u ON u.id = uf.user_id
       GROUP BY f.id
       ORDER BY f.name ASC`,
    );
    return rows.map(row => ({
      ...row,
      active_members: row.active_members ? row.active_members.filter(m => m.id !== null) : [],
      pending_members: row.pending_members ? row.pending_members.filter(m => m.id !== null) : [],
    }));
  },
};

module.exports = WorkspaceQueries;

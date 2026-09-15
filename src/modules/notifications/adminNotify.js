/**
 * Admin notification fan-out — realtime socket only.
 *
 * The reference deployment this was adapted from also had an FCM push leg
 * for admins who are offline; that requires push infrastructure (device
 * tokens, a messaging provider) that's out of scope here, so this notifies
 * whichever admins/superadmins are connected right now and leaves it there.
 * Factory because it needs the Socket.IO server created in server.js.
 */
const db = require('../../infrastructure/db');
const { connectedUsers } = require('../../app/state');

function createAdminNotifier({ io }) {
  /**
   * Notify admins of a specific workspace (plus every superadmin) about an
   * event — new pending user, join request, etc.
   */
  async function notifyWorkspaceAdmins(workspaceId, title, body, data = {}) {
    try {
      const { rows: admins } = await db.query(`
        SELECT DISTINCT u.id
        FROM users u
        WHERE u.role = 'superadmin'
           OR (
             u.role = 'admin'
             AND EXISTS (
               SELECT 1 FROM user_workspaces uw
               WHERE uw.user_id = u.id AND uw.workspace_id = $1
                 AND uw.role = 'admin' AND uw.status = 'active'
             )
           )
      `, [workspaceId]);
      const adminIds = new Set(admins.map(a => a.id));
      const socketEvent = data.type === 'user_pending' ? 'user_pending_approval' : 'workspace_request_received';

      for (const [sid, u] of connectedUsers.entries()) {
        if (adminIds.has(u.userId)) {
          io.to(sid).emit(socketEvent, { workspaceId, title, body, ...data });
        }
      }
    } catch (err) {
      console.error('[AdminNotify] notifyWorkspaceAdmins error:', err.message);
    }
  }

  return { notifyWorkspaceAdmins };
}

module.exports = { createAdminNotifier };

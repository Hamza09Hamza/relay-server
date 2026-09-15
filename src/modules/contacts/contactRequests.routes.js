/**
 * Contact Requests — non-superadmins must request to contact superadmins.
 * Factory: needs emitToUser for real-time notification of both parties.
 */
const express = require('express');
const db = require('../../infrastructure/db');
const queries = require('../../infrastructure/db/queries');
const { authMiddleware } = require('../auth/auth.middleware');

module.exports = function contactRequestsRoutes({ emitToUser }) {
  const router = express.Router();

  // Send a contact request to a superadmin
  router.post('/api/contact-requests', authMiddleware, async (req, res) => {
    try {
      const { to_user_id } = req.body;
      if (!to_user_id) return res.status(400).json({ error: 'to_user_id required' });

      const target = await queries.users.findById(to_user_id);
      if (!target) return res.status(404).json({ error: 'User not found' });
      if (target.role !== 'superadmin') {
        return res.status(400).json({ error: 'Contact requests are only for superadmins' });
      }
      if (target.id === req.userId) {
        return res.status(400).json({ error: 'Cannot request yourself' });
      }

      const { rows } = await db.query(
        `INSERT INTO contact_requests (from_user_id, to_user_id, status)
         VALUES ($1, $2, 'pending')
         ON CONFLICT (from_user_id, to_user_id) DO UPDATE SET status = 'pending', responded_at = NULL
         RETURNING *`,
        [req.userId, to_user_id],
      );

      // Notify the superadmin in real-time
      const sender = await queries.users.findById(req.userId);
      emitToUser(to_user_id, 'contact_request_received', {
        request: rows[0],
        from: queries.users.sanitize(sender),
      });

      res.json({ request: rows[0] });
    } catch (err) {
      console.error('[ContactRequest] Send error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Get incoming contact requests (superadmin only)
  router.get('/api/contact-requests/incoming', authMiddleware, async (req, res) => {
    try {
      const user = await queries.users.findById(req.userId);
      if (user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Superadmin only' });
      }
      const { rows } = await db.query(
        `SELECT cr.*, u.username, u.full_name, u.profile_picture, u.role
         FROM contact_requests cr
         JOIN users u ON u.id = cr.from_user_id
         WHERE cr.to_user_id = $1 AND cr.status = 'pending'
         ORDER BY cr.created_at DESC`,
        [req.userId],
      );
      res.json({ requests: rows });
    } catch (err) {
      console.error('[ContactRequest] Incoming error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Accept or reject a contact request
  router.put('/api/contact-requests/:requestId', authMiddleware, async (req, res) => {
    try {
      const { status } = req.body;
      if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'status must be accepted or rejected' });
      }
      const { rows } = await db.query(
        `UPDATE contact_requests
         SET status = $1, responded_at = NOW()
         WHERE id = $2 AND to_user_id = $3
         RETURNING *`,
        [status, req.params.requestId, req.userId],
      );
      if (!rows.length) return res.status(404).json({ error: 'Request not found' });

      // Notify the requester
      emitToUser(rows[0].from_user_id, 'contact_request_updated', {
        request: rows[0],
        status,
      });

      res.json({ request: rows[0] });
    } catch (err) {
      console.error('[ContactRequest] Respond error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};

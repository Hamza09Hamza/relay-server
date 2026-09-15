/**
 * Auth routes — registration, login, and the forgot-password flow.
 *
 * Exported as a factory: server.js injects the shared dependencies that have
 * not yet been extracted into their own modules (db, queries, io, the admin
 * notification helpers, BCRYPT_ROUNDS). As those get modularised the injection
 * site changes, but this file does not.
 */
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { signToken, generateRefreshToken, hashRefreshToken } = require('./auth.service');
const { REFRESH_TOKEN_TTL_DAYS } = require('../../app/config');
const { UUID_RE } = require('../../shared/validation');
const { connectedUsers, tempResetPasswords } = require('../../app/state');
const { invalidateAuthStatusCache } = require('./auth.middleware');

module.exports = function authRoutes({
  db, queries, io, notifyWorkspaceAdmins, BCRYPT_ROUNDS,
}) {
  const router = express.Router();

  const REFRESH_TTL_MS = REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;

  // Persist a new refresh token and return the raw value to hand to the client.
  async function issueRefreshToken(userId, userAgent) {
    const raw = generateRefreshToken();
    await queries.refreshTokens.create({
      userId,
      tokenHash: hashRefreshToken(raw),
      expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
      userAgent: userAgent || null,
    });
    return raw;
  }

  // Record a sign-in attempt (IP + user agent) for security auditing.
  // Fire-and-forget: auditing must never slow down or break a login. Rows
  // are auto-purged after 90 days by a daily cleanup job.
  function recordLoginAttempt(req, { userId = null, username = null, outcome }) {
    const ip = req.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || null;
    const userAgent = req.headers['user-agent'] || null;
    db.query(
      `INSERT INTO login_audit (user_id, username, ip, user_agent, outcome)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        userId,
        username ? String(username).slice(0, 100) : null,
        ip,
        userAgent ? String(userAgent).slice(0, 400) : null,
        outcome,
      ],
    ).catch(err => console.warn('[Auth] login_audit insert failed:', err.message));
  }

  // Rate limiters — protect auth endpoints from brute-force / credential stuffing.
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15-minute window
    max: 10,                    // 10 attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts, please try again later' },
  });

  const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1-hour window
    max: 5,                    // 5 signups per IP per hour
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many registration attempts, please try again later' },
  });

  const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts, please try again later' },
  });

  // Separate, permissive limiter for the polling endpoint (polling every 4s needs room)
  const resetStatusLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
  });

  router.post('/api/auth/register', registerLimiter, async (req, res) => {
    try {
      const { username, full_name, email, password, workspace_ids } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required', field: 'username' });
      }
      if (!full_name || !full_name.trim()) {
        return res.status(400).json({ error: 'Full name is required', field: 'full_name' });
      }

      const existing = await queries.users.findByUsername(username);
      if (existing) {
        return res.status(409).json({ error: 'Username already taken', field: 'username' });
      }

      // workspace_ids is mandatory: the admin "pending" queue is keyed off
      // user_workspaces rows (status='pending' per membership), so a user
      // created with zero memberships would have no pending row anywhere —
      // invisible to the approval queue and permanently stuck at
      // users.status='pending' with no way for an admin to approve them.
      const requestedWorkspaceIds = Array.isArray(workspace_ids)
        ? workspace_ids.filter(id => UUID_RE.test(String(id)))
        : [];
      if (requestedWorkspaceIds.length === 0) {
        return res.status(400).json({ error: 'At least one workspace is required', field: 'workspace_ids' });
      }

      const validWorkspaceIds = [];
      for (const workspaceId of requestedWorkspaceIds) {
        const workspace = await queries.workspaces.findById(workspaceId);
        if (workspace) validWorkspaceIds.push(workspaceId);
      }
      if (validWorkspaceIds.length === 0) {
        return res.status(400).json({ error: 'At least one valid workspace is required', field: 'workspace_ids' });
      }

      const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);
      const user = await queries.users.create({ username, fullName: full_name.trim(), email, password: hashedPassword });
      const token = signToken(user.id, user.token_version);

      for (const workspaceId of validWorkspaceIds) {
        await queries.userWorkspaces.addRequest(user.id, workspaceId);
      }

      // Notify admins of each requested workspace.
      for (const workspaceId of validWorkspaceIds) {
        const workspace = await queries.workspaces.findById(workspaceId);
        notifyWorkspaceAdmins(
          workspaceId,
          '👤 New User Pending',
          `${user.username}${user.email ? ` (${user.email})` : ''} is waiting for approval in ${workspace?.name || 'your workspace'}`,
          { type: 'user_pending', userId: String(user.id), username: user.username },
        ).catch(err => console.warn('[Register] Workspace notify error:', err.message));
      }

      const pendingMsg = `Account created. Your request to join ${validWorkspaceIds.length} workspace(s) is pending admin approval.`;
      // Do NOT return a token — pending users must be approved before they can authenticate
      res.status(201).json({ user: queries.users.sanitize(user), message: pendingMsg });
    } catch (err) {
      console.error('[Auth] Register error:', err.message);
      if (err.code === '23505') {
        const field = err.constraint?.includes('email') ? 'email' : 'username';
        const msg = field === 'email' ? 'Email already in use' : 'Username already taken';
        return res.status(409).json({ error: msg, field });
      }
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
      }

      const user = await queries.users.findByUsername(username);
      if (!user) {
        recordLoginAttempt(req, { username, outcome: 'unknown_user' });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const passwordValid = await bcrypt.compare(password, user.password);
      if (!passwordValid) {
        recordLoginAttempt(req, { userId: user.id, username, outcome: 'bad_password' });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (user.status === 'pending') {
        recordLoginAttempt(req, { userId: user.id, username, outcome: 'pending' });
        return res.status(403).json({ error: 'Account pending admin approval' });
      }
      if (user.status === 'rejected') {
        recordLoginAttempt(req, { userId: user.id, username, outcome: 'rejected' });
        return res.status(403).json({ error: 'Account has been rejected' });
      }

      recordLoginAttempt(req, { userId: user.id, username, outcome: 'success' });
      const token = signToken(user.id, user.token_version);
      // Fail-soft: if the refresh_tokens table isn't there yet, login must
      // still succeed with just the access token.
      let refreshToken = null;
      try {
        refreshToken = await issueRefreshToken(user.id, req.headers['user-agent']);
      } catch (e) {
        console.warn('[Auth] Could not issue refresh token (continuing without):', e.message);
      }
      await queries.users.setOnlineStatus(user.id, true);

      // Clean up any stale reset state on successful login
      if (user.password_reset_status) {
        tempResetPasswords.delete(user.id);
        await queries.users.clearPasswordReset(user.id).catch(() => {});
      }

      // `refreshToken` is additive — older clients that only read `token`
      // keep working unchanged; updated clients use it for silent re-auth.
      res.json({ user: queries.users.sanitize(user), token, ...(refreshToken ? { refreshToken } : {}) });
    } catch (err) {
      console.error('[Auth] Login error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // User requests a password reset (unauthenticated)
  router.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
    try {
      const { username } = req.body;
      if (!username || typeof username !== 'string') {
        return res.status(400).json({ error: 'Username is required' });
      }
      const user = await queries.users.findByUsername(username.trim());
      if (!user) {
        // Don't reveal whether the user exists
        return res.json({ resetToken: crypto.randomBytes(32).toString('hex') });
      }
      // Always generate a fresh token — this invalidates any other device already waiting
      // (old token becomes orphaned and old device will get 'unknown' on next poll)
      const resetToken = crypto.randomBytes(32).toString('hex');
      await queries.users.setPasswordResetStatus(user.id, 'requested', resetToken);
      console.log(`[Auth] Password reset requested by user ${user.username}`);

      // Notify connected admins/superadmins via socket in real time.
      const admins = await db.query(`SELECT id FROM users WHERE role IN ('admin', 'superadmin')`);
      const adminIds = new Set(admins.rows.map(r => r.id));

      for (const [sid, u] of connectedUsers.entries()) {
        if (adminIds.has(u.userId)) {
          io.to(sid).emit('password_reset_requested', {
            userId: user.id,
            username: user.username,
          });
        }
      }

      res.json({ resetToken });
    } catch (err) {
      console.error('[Auth] Forgot password error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // User polls for reset status (unauthenticated)
  router.get('/api/auth/reset-status', resetStatusLimiter, async (req, res) => {
    try {
      const { token } = req.query;
      if (!token || typeof token !== 'string') {
        return res.status(400).json({ error: 'Token is required' });
      }
      const user = await queries.users.findByResetToken(token);
      if (!user) {
        return res.json({ status: 'unknown' });
      }
      const result = { status: user.password_reset_status || 'unknown' };

      // If admin set a password, include it — keep in memory until 30min timeout clears it
      // so repeated polls (e.g. after network hiccup) still return the password
      if (user.password_reset_status === 'admin_set') {
        const tempPw = tempResetPasswords.get(user.id);
        if (tempPw) {
          result.tempPassword = tempPw;
          // Don't delete here — 30 min timeout on the Map entry handles cleanup
        }
        // Don't clear DB status here — cleanup happens when user next logs in
      }

      res.json(result);
    } catch (err) {
      console.error('[Auth] Reset status error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // User sets their own new password (only when admin allowed it)
  router.post('/api/auth/set-new-password', forgotPasswordLimiter, async (req, res) => {
    try {
      const { token, newPassword } = req.body;
      if (!token || typeof token !== 'string') {
        return res.status(400).json({ error: 'Token is required' });
      }
      if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      const user = await queries.users.findByResetToken(token);
      if (!user || user.password_reset_status !== 'allowed') {
        return res.status(403).json({ error: 'Password reset not allowed' });
      }
      const hashedPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
      await queries.users.updatePassword(user.id, hashedPassword);
      await queries.users.clearPasswordReset(user.id);
      // Invalidate any outstanding refresh sessions after a password change.
      await queries.refreshTokens.revokeAllForUser(user.id).catch(() => {});
      invalidateAuthStatusCache(user.id);
      console.log(`[Auth] User ${user.username} set new password via self-reset`);
      res.json({ success: true });
    } catch (err) {
      console.error('[Auth] Set new password error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Silent re-auth: exchange a valid refresh token for a fresh access token.
  // The refresh token is rotated on every call (old one revoked, new one issued).
  // No IP/brute-force limiter that could lock a legitimate user out mid-session;
  // the token itself is a 96-char secret, so guessing is infeasible.
  router.post('/api/auth/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body || {};
      if (!refreshToken || typeof refreshToken !== 'string') {
        return res.status(400).json({ error: 'refreshToken is required' });
      }
      const stored = await queries.refreshTokens.findValidByHash(hashRefreshToken(refreshToken));
      if (!stored) {
        // Unknown / expired / already-rotated. We deliberately do NOT revoke the
        // user's other tokens here — a flaky-network retry of an already-rotated
        // token must not log the user out of their other devices.
        return res.status(401).json({ error: 'Invalid or expired refresh token' });
      }
      const user = await queries.users.findById(stored.user_id);
      if (!user || user.deleted || user.status === 'pending' || user.status === 'rejected') {
        await queries.refreshTokens.revoke(stored.id, null).catch(() => {});
        return res.status(401).json({ error: 'Account not available' });
      }
      // Rotate the refresh token.
      const newRaw = generateRefreshToken();
      const created = await queries.refreshTokens.create({
        userId: user.id,
        tokenHash: hashRefreshToken(newRaw),
        expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
        userAgent: req.headers['user-agent'] || null,
      });
      await queries.refreshTokens.revoke(stored.id, created.id);

      const token = signToken(user.id, user.token_version);
      res.json({ token, refreshToken: newRaw, user: queries.users.sanitize(user) });
    } catch (err) {
      console.error('[Auth] Refresh error:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Logout — best-effort revoke of the presented refresh token.
  router.post('/api/auth/logout', async (req, res) => {
    try {
      const { refreshToken } = req.body || {};
      if (refreshToken && typeof refreshToken === 'string') {
        await queries.refreshTokens.revokeByHash(hashRefreshToken(refreshToken)).catch(() => {});
      }
    } catch (_) { /* best-effort */ }
    res.json({ success: true });
  });

  return router;
};

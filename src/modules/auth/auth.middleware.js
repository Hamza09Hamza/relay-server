/**
 * Auth middleware — JWT verification and admin / superadmin gates.
 *
 * `authMiddleware` sets `req.userId` from a verified Bearer token. Beyond
 * signature/expiry, it also rejects a token whose account has since been
 * deleted/suspended, or whose password has changed since the token was
 * issued (via the `v` / token_version claim) — otherwise, with
 * ACCESS_TOKEN_TTL defaulting to 60 days, either of those would leave a
 * revoked account's token working for up to 60 days. This check is cached
 * briefly (authStatusCache) so it costs one DB lookup per user per TTL
 * window, not one per request; deletion/password-change routes call
 * invalidateAuthStatusCache() to skip the stale window entirely.
 *
 * Tokens signed before this change carry no `v` claim — they are
 * grandfathered in (version check skipped) until replaced by a fresh
 * login/refresh, the same backward-compatible approach already used when
 * ACCESS_TOKEN_TTL's own `exp` claim was introduced.
 *
 * `adminMiddleware` / `superadminMiddleware` additionally gate by role and
 * set `req.adminUser`. Admin-role lookups are cached briefly to avoid a DB
 * round-trip on every request (e.g. HTTP range requests while streaming).
 */
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../../app/config');
const { isValidUserId } = require('../../shared/validation');
const queries = require('../../infrastructure/db/queries');
const { adminRoleCache, authStatusCache } = require('../../app/state');

// Short-lived admin-role cache TTL — 1 minute, with immediate invalidation on
// role changes via invalidateAdminCache().
const ADMIN_CACHE_TTL_MS = 1 * 60 * 1000;

// Kept short: this is the maximum window a deleted/suspended/password-changed
// account's still-unexpired JWT can keep working after the change, on any
// request path that doesn't also call invalidateAuthStatusCache() directly.
const AUTH_STATUS_CACHE_TTL_MS = 30 * 1000;

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed token' });
  }
  let decoded;
  try {
    decoded = jwt.verify(header.split(' ')[1], JWT_SECRET, {
      algorithms: ['HS256'],
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  if (!isValidUserId(decoded.userId)) {
    return res.status(401).json({ error: 'Invalid user ID in token' });
  }

  try {
    const now = Date.now();
    let status = authStatusCache.get(decoded.userId);
    if (!status || now >= status.expiresAt) {
      const user = await queries.users.findAuthStatus(decoded.userId);
      status = user
        ? {
          deleted: user.deleted,
          suspended: user.suspended,
          accountStatus: user.status,
          tokenVersion: user.token_version,
        }
        : { deleted: true, suspended: false, accountStatus: null, tokenVersion: null };
      status.expiresAt = now + AUTH_STATUS_CACHE_TTL_MS;
      authStatusCache.set(decoded.userId, status);
    }
    if (status.deleted || status.suspended || status.accountStatus === 'rejected') {
      return res.status(401).json({ error: 'Account no longer available' });
    }
    if (typeof decoded.v === 'number' && decoded.v !== status.tokenVersion) {
      return res.status(401).json({ error: 'Session no longer valid — please log in again' });
    }
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }

  req.userId = decoded.userId;
  next();
}

/** Drop the cached admin-role for a user (call after any role change). */
function invalidateAdminCache(userId) {
  adminRoleCache.delete(userId);
  console.log(`[Cache] Invalidated admin cache for userId ${userId}`);
}

/**
 * Drop the cached auth status for a user — call right after deleting,
 * suspending, or changing the password of that user so the next request
 * with their old token is rejected immediately instead of within
 * AUTH_STATUS_CACHE_TTL_MS.
 */
function invalidateAuthStatusCache(userId) {
  authStatusCache.delete(userId);
}

async function adminMiddleware(req, res, next) {
  try {
    const userId = req.userId;
    const now = Date.now();
    const cached = adminRoleCache.get(userId);
    if (cached && now < cached.expiresAt) {
      if (!cached.isAdmin) return res.status(403).json({ error: 'Admin access required' });
      req.adminUser = { id: userId, role: cached.role || 'admin' };
      return next();
    }
    const user = await queries.users.findById(userId);
    const isAdmin = !!(user && (user.role === 'admin' || user.role === 'superadmin'));
    adminRoleCache.set(userId, { isAdmin, role: user?.role, expiresAt: now + ADMIN_CACHE_TTL_MS });
    if (!isAdmin) return res.status(403).json({ error: 'Admin access required' });
    req.adminUser = user;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}

async function superadminMiddleware(req, res, next) {
  try {
    const user = await queries.users.findById(req.userId);
    if (!user || user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Superadmin access required' });
    }
    req.adminUser = user;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}

module.exports = {
  authMiddleware,
  adminMiddleware,
  superadminMiddleware,
  invalidateAdminCache,
  invalidateAuthStatusCache,
  ADMIN_CACHE_TTL_MS,
};

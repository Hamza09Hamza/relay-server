/**
 * Auth service — access-token signing and refresh-token helpers.
 *
 * Access token: a JWT carrying { userId }. It now has an expiry
 * (ACCESS_TOKEN_TTL, long by default) — existing permanent tokens issued
 * before this change still verify fine because jsonwebtoken treats a missing
 * `exp` as "never expires", so no deployed client is logged out.
 *
 * Refresh token: an opaque random string. We never store it directly — only
 * its SHA-256 hash goes in the DB, so a database leak can't be replayed.
 * Tokens are rotated on each refresh.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { JWT_SECRET, ACCESS_TOKEN_TTL } = require('../../app/config');

/**
 * Sign an access JWT for the given user id. `tokenVersion` (the user's
 * current users.token_version) is embedded as `v` so authMiddleware can
 * reject this token immediately after a password change, without waiting
 * for ACCESS_TOKEN_TTL to expire it naturally. Omit it only for callers that
 * don't have the user row handy — the token still works, just without the
 * fast-revocation check (falls back to expiry only, today's behavior).
 */
function signToken(userId, tokenVersion) {
  const payload = tokenVersion == null ? { userId } : { userId, v: tokenVersion };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL });
}

/** Generate a new opaque refresh token (the value handed to the client). */
function generateRefreshToken() {
  return crypto.randomBytes(48).toString('hex');
}

/** Hash a refresh token for storage / lookup (never store the raw value). */
function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

module.exports = { signToken, generateRefreshToken, hashRefreshToken };

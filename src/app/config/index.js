/**
 * Application configuration — environment-derived constants.
 *
 * Loaded after dotenv has populated process.env. Fails fast at startup if a
 * required variable is missing, so misconfiguration surfaces immediately
 * rather than as a confusing runtime error later.
 */

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Exiting.');
  process.exit(1);
}

// bcrypt cost factor for password hashing (login, registration, admin resets)
const BCRYPT_ROUNDS = 12;

// Access-token lifetime. Defaults LONG so existing clients (which don't yet
// perform silent refresh) are never logged out. Once a client adopts
// POST /api/auth/refresh, shorten this via the ACCESS_TOKEN_TTL env var
// (e.g. '1h' or '15m') for proper short-lived access tokens.
// Accepts any value `jsonwebtoken` understands ('60d', '1h', '900s', ...).
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || '60d';

// Refresh-token lifetime in days (sliding: rotated and re-dated on each use).
const REFRESH_TOKEN_TTL_DAYS = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS, 10) || 180;

// How long a paired device may go unseen before it's purged from
// user_devices (and, with it, its approval). Matches ACCESS_TOKEN_TTL by
// default — a device we'd purge is one whose access token has likely gone
// stale anyway. Purge is lazy (runs on next listForUser call), not cron-based.
const STALE_DEVICE_TTL_DAYS = parseInt(process.env.STALE_DEVICE_TTL_DAYS, 10) || 60;

module.exports = {
  JWT_SECRET,
  BCRYPT_ROUNDS,
  ACCESS_TOKEN_TTL,
  REFRESH_TOKEN_TTL_DAYS,
  STALE_DEVICE_TTL_DAYS,
};

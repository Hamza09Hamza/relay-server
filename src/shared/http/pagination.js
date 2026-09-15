/**
 * Pagination guards — prevent clients from requesting unbounded scans.
 *
 * `?limit=10000000` would otherwise force the DB (and any in-process
 * decrypt-then-filter loops) to chew through the whole table. parseLimit
 * clamps to a sane ceiling; parseOffset rejects negative offsets that would
 * otherwise make Postgres throw on `OFFSET -n`.
 */

/**
 * @param {*} raw                       - req.query.limit (string|undefined)
 * @param {{def?: number, max?: number}} [opts]
 * @returns {number} clamped limit in [1, max]
 */
function parseLimit(raw, { def = 50, max = 200 } = {}) {
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return def;
  return Math.min(n, max);
}

/**
 * @param {*} raw - req.query.offset (string|undefined)
 * @returns {number} non-negative offset (0 if missing/invalid)
 */
function parseOffset(raw) {
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

module.exports = { parseLimit, parseOffset };

/**
 * Shared input-validation helpers.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INTEGER_USER_ID_RE = /^[1-9]\d*$/;

function isValidUserId(id) {
  if (id === null || id === undefined) return false;
  const value = String(id);
  return INTEGER_USER_ID_RE.test(value) || UUID_RE.test(value);
}

module.exports = { isValidUserId, UUID_RE, INTEGER_USER_ID_RE };

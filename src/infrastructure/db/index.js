const { Pool } = require('pg');

// max: 20 was the actual bottleneck behind a run of "slow query"/"transient
// pool error" log noise that had nothing to do with query cost — a PTT wake
// fans out to every subscriber on a channel near-simultaneously, and that
// alone was enough concurrent DB traffic to exhaust 20 connections, stalling
// unrelated features (chat, admin stats, room lists) for the full 5s
// connectionTimeoutMillis while they waited for one to free up. Confirmed live
// against production Postgres: max_connections was 100 and normal load used
// only ~2-7 of them, so the app was self-limiting to a fifth of what the
// database could actually serve. 50 stays well clear of that ceiling —
// raising past it would turn a 5s wait into an outright refused connection,
// which is worse — while giving bursts room the old cap didn't have.
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  database: process.env.DB_NAME || 'relay',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  max: 50,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

// Connection-level failures the pool can throw when it briefly can't hand out
// or hold onto a connection (e.g. a momentary spike in concurrent demand).
// These are not query errors — retrying is safe because nothing ran yet.
const TRANSIENT_POOL_ERRORS = [
  'Connection terminated due to connection timeout',
  'timeout exceeded when trying to connect',
  'Connection terminated unexpectedly',
];

function isTransientPoolError(err) {
  const message = err?.message || '';
  return TRANSIENT_POOL_ERRORS.some(pattern => message.includes(pattern));
}

/**
 * Execute a single query against the database.
 * @param {string} text - SQL query string
 * @param {Array} params - Query parameters
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(text, params) {
  const start = Date.now();
  let result;
  try {
    result = await pool.query(text, params);
  } catch (err) {
    if (!isTransientPoolError(err)) throw err;
    console.warn('[DB] Transient pool error, retrying once:', err.message);
    await new Promise(resolve => setTimeout(resolve, 250));
    result = await pool.query(text, params);
  }
  const duration = Date.now() - start;

  if (duration > 500) {
    console.warn('[DB] Slow query detected (%dms):', duration, text);
  }

  return result;
}

/**
 * Acquire a client from the pool for transactions.
 * Caller must release the client when done.
 * @returns {Promise<import('pg').PoolClient>}
 */
async function getClient() {
  return pool.connect();
}

/**
 * Execute a callback within a database transaction.
 * Automatically commits on success and rolls back on error.
 * @param {function(import('pg').PoolClient): Promise<*>} callback
 * @returns {Promise<*>}
 */
async function transaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Test the database connection.
 * @returns {Promise<boolean>}
 */
async function testConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    console.log('[DB] Connection verified at', result.rows[0].now);
    return true;
  } catch (err) {
    console.error('[DB] Connection failed:', err.message);
    return false;
  }
}

/**
 * Gracefully close all pool connections.
 */
async function close() {
  await pool.end();
  console.log('[DB] Pool closed');
}

module.exports = {
  pool,
  query,
  getClient,
  transaction,
  testConnection,
  close,
};

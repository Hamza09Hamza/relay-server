/**
 * Database initialisation script.
 *
 * Reads schema.sql and applies it to the configured database.
 * Safe to run multiple times thanks to IF NOT EXISTS guards.
 *
 * Usage:
 *   node src/infrastructure/db/init.js
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '..', '..', '..', '.env') });
const fs = require('fs');
const path = require('path');
const db = require('./index');

async function init() {
  console.log('[DB] Initialising database...');

  const connected = await db.testConnection();
  if (!connected) {
    console.error('[DB] Cannot reach the database. Aborting.');
    process.exit(1);
  }

  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf-8');

  try {
    await db.query(sql);
    console.log('[DB] Schema applied successfully.');
  } catch (err) {
    console.error('[DB] Failed to apply schema:', err.message);
    process.exit(1);
  } finally {
    await db.close();
  }
}

init();

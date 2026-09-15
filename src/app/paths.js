/**
 * Filesystem paths — single source of truth for the server's data directories.
 *
 * ROOT_DIR is the repository root (the directory containing server.js). Do
 * NOT change these without a data migration: uploads, profile pictures, and
 * recordings already live at these paths.
 */
const path = require('path');
const fs = require('fs');

const ROOT_DIR = path.resolve(__dirname, '..', '..');

const UPLOADS_DIR = path.join(ROOT_DIR, 'uploads');
const PROFILE_PICTURES_DIR = path.join(ROOT_DIR, 'profile-pictures');
const RECORDINGS_DIR = path.join(ROOT_DIR, 'recordings');
const LOGS_DIR = path.join(ROOT_DIR, 'logs');

// Ensure data directories exist on boot.
for (const dir of [UPLOADS_DIR, PROFILE_PICTURES_DIR, RECORDINGS_DIR, LOGS_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

module.exports = {
  ROOT_DIR,
  UPLOADS_DIR,
  PROFILE_PICTURES_DIR,
  RECORDINGS_DIR,
  LOGS_DIR,
};

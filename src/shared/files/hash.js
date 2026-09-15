/**
 * File hashing — SHA-256 integrity digests for recordings
 * (generated at save time, verified before playback).
 */
const fs = require('fs');
const crypto = require('crypto');

function hashFile(filePath) {
  const data = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = { hashFile };

/**
 * Shared multer instance for user file uploads (chat files, profile pictures).
 * Disk storage into UPLOADS_DIR with a random unique filename; MIME allowlist
 * lives in src/shared/files/mime.js.
 */
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { UPLOADS_DIR } = require('../../app/paths');
const { ALLOWED_MIME_TYPES } = require('../../shared/files/mime');

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    // The served /uploads/:name route only checks that the caller holds *a*
    // valid JWT, not that they belong to the file's room — so the filename
    // itself is effectively the capability. Date.now()+Math.random() is
    // predictable (timestamp) and non-cryptographic, which weakens that
    // capability; a 128-bit crypto-random name makes it unguessable.
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${crypto.randomBytes(16).toString('hex')}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_MIME_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed: ${file.mimetype}`), false);
    }
  },
});

module.exports = { upload };

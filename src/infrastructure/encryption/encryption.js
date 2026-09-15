'use strict';

const crypto = require('crypto');

// ── Constants ──────────────────────────────────────────────────────────────
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;          // 96 bits — NIST recommended for GCM
const AUTH_TAG_LENGTH = 16;    // 128 bits — full-length tag
const KEY_LENGTH = 32;         // 256 bits
const CURRENT_VERSION = 0x01;  // For future key rotation

// Purpose identifiers for HKDF sub-key derivation
const KEY_PURPOSES = {
  MESSAGES:      'relay:messages:v1',
  FILES:         'relay:files:v1',
  NOTIFICATIONS: 'relay:notifications:v1',
  RECORDINGS:    'relay:recordings:v1',
  FILE_NAMES:    'relay:filenames:v1',
};

// ── Master Key Management ──────────────────────────────────────────────────

let _masterKey = null;

/**
 * Initialize the encryption engine with the master key.
 * Must be called once at server startup.
 *
 * The master key should be a 64-character hex string (32 bytes / 256 bits).
 * Source: ENCRYPTION_MASTER_KEY environment variable.
 *
 * @param {string} hexKey - 64-character hex string
 * @throws {Error} if key is invalid
 */
function init(hexKey) {
  if (!hexKey || typeof hexKey !== 'string') {
    throw new Error(
      '[Encryption] ENCRYPTION_MASTER_KEY environment variable is required.\n' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }

  const cleaned = hexKey.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    throw new Error(
      `[Encryption] ENCRYPTION_MASTER_KEY must be exactly 64 hex characters (32 bytes). Got ${cleaned.length} chars.`
    );
  }

  _masterKey = Buffer.from(cleaned, 'hex');
  console.log('[Encryption] Engine initialized — AES-256-GCM + HKDF-SHA256');
}

/**
 * Generate a new random 256-bit master key.
 * @returns {string} 64-character hex string
 */
function generateMasterKey() {
  return crypto.randomBytes(KEY_LENGTH).toString('hex');
}

/**
 * Check if the encryption engine is initialized.
 * @returns {boolean}
 */
function isInitialized() {
  return _masterKey !== null;
}

// ── HKDF Key Derivation (RFC 5869) ────────────────────────────────────────

/**
 * Derive a purpose-specific 256-bit sub-key from the master key using HKDF.
 *
 * Each purpose (messages, files, etc.) gets a cryptographically independent
 * key. Even if one sub-key is compromised, the others remain safe.
 *
 * @param {string} purpose - One of KEY_PURPOSES values
 * @returns {Buffer} 32-byte derived key
 */
function deriveKey(purpose) {
  if (!_masterKey) {
    throw new Error('[Encryption] Engine not initialized. Call init() first.');
  }

  // HKDF-SHA256: extract-then-expand
  // Salt: fixed per purpose (deterministic derivation)
  const salt = crypto.createHash('sha256').update(purpose).digest();
  const prk = crypto.createHmac('sha256', salt).update(_masterKey).digest();

  // Expand: single iteration is sufficient for 256-bit output
  const info = Buffer.from(purpose, 'utf8');
  const t1 = crypto.createHmac('sha256', prk)
    .update(Buffer.concat([info, Buffer.from([0x01])]))
    .digest();

  return t1; // 32 bytes = 256 bits
}

// Cache derived keys for performance (they're deterministic)
const _keyCache = new Map();

function getCachedKey(purpose) {
  if (!_keyCache.has(purpose)) {
    _keyCache.set(purpose, deriveKey(purpose));
  }
  return _keyCache.get(purpose);
}

// ── AES-256-GCM Encryption / Decryption ───────────────────────────────────

/**
 * Encrypt a string with AES-256-GCM.
 *
 * Returns a base64 string: version[1] || iv[12] || authTag[16] || ciphertext[N]
 *
 * The auth tag provides built-in integrity verification (no separate HMAC).
 * Associated data (AAD) can optionally bind the ciphertext to a context
 * (e.g., message ID) to prevent ciphertext relocation attacks.
 *
 * @param {string} plaintext          - Text to encrypt
 * @param {string} purpose            - One of KEY_PURPOSES
 * @param {string} [associatedData]   - Optional AAD (e.g., record ID)
 * @returns {string} Base64-encoded encrypted blob
 */
function encrypt(plaintext, purpose, associatedData) {
  if (plaintext === null || plaintext === undefined) return null;

  const key = getCachedKey(purpose);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  if (associatedData) {
    cipher.setAAD(Buffer.from(associatedData, 'utf8'));
  }

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  // Pack: version || iv || authTag || ciphertext
  const blob = Buffer.concat([
    Buffer.from([CURRENT_VERSION]),
    iv,
    authTag,
    encrypted,
  ]);

  return blob.toString('base64');
}

/**
 * Decrypt a blob produced by encrypt().
 *
 * @param {string} blob               - Base64 string from encrypt()
 * @param {string} purpose            - Must match the purpose used for encryption
 * @param {string} [associatedData]   - Must match the AAD used for encryption
 * @returns {string} Decrypted plaintext
 * @throws {Error} If auth tag verification fails (tampered data)
 */
function decrypt(blob, purpose, associatedData) {
  if (blob === null || blob === undefined) return null;

  const buf = Buffer.from(blob, 'base64');

  if (buf.length < 1 + IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('[Encryption] Blob too short — corrupted or not encrypted');
  }

  const version = buf[0];
  if (version !== CURRENT_VERSION) {
    throw new Error(`[Encryption] Unknown version: ${version}. Expected: ${CURRENT_VERSION}`);
  }

  const iv = buf.subarray(1, 1 + IV_LENGTH);
  const authTag = buf.subarray(1 + IV_LENGTH, 1 + IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = buf.subarray(1 + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = getCachedKey(purpose);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  decipher.setAuthTag(authTag);

  if (associatedData) {
    decipher.setAAD(Buffer.from(associatedData, 'utf8'));
  }

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch (err) {
    throw new Error(
      `[Encryption] Decryption failed — data may have been tampered with. ${err.message}`
    );
  }
}

/**
 * Encrypt a JSON object (serializes to string first).
 */
function encryptJSON(obj, purpose, associatedData) {
  if (obj === null || obj === undefined) return null;
  return encrypt(JSON.stringify(obj), purpose, associatedData);
}

/**
 * Decrypt a blob back to a JSON object.
 */
function decryptJSON(blob, purpose, associatedData) {
  if (blob === null || blob === undefined) return null;
  const text = decrypt(blob, purpose, associatedData);
  return JSON.parse(text);
}

// ── File Encryption (streaming AES-256-GCM) ──────────────────────────────

/**
 * Encrypt a file on disk in-place (or to a new path).
 *
 * For files, we use AES-256-GCM with the file content as a single chunk.
 * The encrypted file format:
 *   version[1] || iv[12] || authTag[16] || ciphertext[N]
 *
 * @param {string} inputPath  - Path to the plaintext file
 * @param {string} [outputPath] - Path for encrypted file (defaults to inputPath + '.enc')
 * @returns {string} Path to the encrypted file
 */
function encryptFile(inputPath, outputPath) {
  const outPath = outputPath || inputPath + '.enc';
  const plaintext = require('fs').readFileSync(inputPath);

  const key = getCachedKey(KEY_PURPOSES.FILES);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  // Use filename as AAD to bind the ciphertext to this specific file
  const filename = require('path').basename(inputPath);
  cipher.setAAD(Buffer.from(filename, 'utf8'));

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const blob = Buffer.concat([
    Buffer.from([CURRENT_VERSION]),
    iv,
    authTag,
    encrypted,
  ]);

  require('fs').writeFileSync(outPath, blob);
  return outPath;
}

/**
 * Decrypt a file encrypted by encryptFile().
 *
 * @param {string} inputPath  - Path to the encrypted file
 * @param {string} originalFilename - Original filename (used as AAD for verification)
 * @returns {Buffer} Decrypted file contents
 */
function decryptFile(inputPath, originalFilename) {
  const buf = require('fs').readFileSync(inputPath);

  if (buf.length < 1 + IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('[Encryption] Encrypted file too short — corrupted');
  }

  const version = buf[0];
  if (version !== CURRENT_VERSION) {
    throw new Error(`[Encryption] Unknown file version: ${version}`);
  }

  const iv = buf.subarray(1, 1 + IV_LENGTH);
  const authTag = buf.subarray(1 + IV_LENGTH, 1 + IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = buf.subarray(1 + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = getCachedKey(KEY_PURPOSES.FILES);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  decipher.setAuthTag(authTag);
  decipher.setAAD(Buffer.from(originalFilename, 'utf8'));

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error(`[Encryption] File decryption failed: ${err.message}`);
  }
}

// ── Utility: Check if a string looks like an encrypted blob ───────────────

/**
 * Quick check: is this value an encrypted blob (base64, starts with version byte)?
 * Useful during migration to distinguish encrypted vs plaintext data.
 */
function isEncrypted(value) {
  if (!value || typeof value !== 'string') return false;
  try {
    const buf = Buffer.from(value, 'base64');
    return buf.length >= 1 + IV_LENGTH + AUTH_TAG_LENGTH && buf[0] === CURRENT_VERSION;
  } catch {
    return false;
  }
}

// ── Export ─────────────────────────────────────────────────────────────────

module.exports = {
  // Lifecycle
  init,
  isInitialized,
  generateMasterKey,

  // Core encrypt/decrypt
  encrypt,
  decrypt,
  encryptJSON,
  decryptJSON,

  // File encrypt/decrypt
  encryptFile,
  decryptFile,

  // Utility
  isEncrypted,

  // Constants (for use by other modules)
  KEY_PURPOSES,
};

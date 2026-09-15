/**
 * MIME helpers — extension → content-type map used when serving stored files,
 * and the allowlist used by multer's upload fileFilter.
 */
const path = require('path');

const MIME_TYPES = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mp3': 'audio/mpeg',
  '.m4a': 'audio/m4a',
  '.aac': 'audio/aac',
  '.ogg': 'audio/ogg',
  '.wav': 'audio/wav',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain',
  // Office documents
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  // Data / config
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.yaml': 'text/yaml',
  '.yml': 'text/yaml',
  // Code files
  '.js': 'text/javascript',
  '.ts': 'text/typescript',
  '.jsx': 'text/javascript',
  '.tsx': 'text/typescript',
  '.py': 'text/x-python',
  '.java': 'text/x-java-source',
  '.c': 'text/x-c',
  '.cpp': 'text/x-c',
  '.h': 'text/x-c',
  '.cs': 'text/plain',
  '.go': 'text/plain',
  '.rs': 'text/plain',
  '.rb': 'text/plain',
  '.php': 'text/plain',
  '.swift': 'text/plain',
  '.kt': 'text/plain',
  '.sh': 'text/x-shellscript',
  '.sql': 'text/plain',
  // Web
  '.html': 'text/html',
  '.css': 'text/css',
  '.md': 'text/markdown',
  // Archives
  '.zip': 'application/zip',
  '.rar': 'application/x-rar-compressed',
  '.7z': 'application/x-7z-compressed',
  '.tar': 'application/x-tar',
  '.gz': 'application/gzip',
};

function getContentTypeByName(fileName) {
  const ext = path.extname(fileName || '').toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

// Allowed MIME types for file uploads
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif',
  'video/mp4', 'video/webm', 'video/quicktime', 'video/3gpp', 'video/x-matroska',
  'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/mp4', 'audio/aac', 'audio/m4a', 'audio/x-m4a', 'audio/3gpp',
  'application/pdf',
  // Office documents
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  // Text / data / config
  'text/plain',
  'text/csv',
  'text/html',
  'text/css',
  'text/markdown',
  'text/yaml',
  'text/xml',
  'text/javascript',
  'text/typescript',
  'text/x-python',
  'text/x-java-source',
  'text/x-c',
  'text/x-shellscript',
  'application/json',
  'application/xml',
  'application/javascript',
  'application/x-yaml',
  // Archives
  'application/zip',
  'application/x-zip-compressed',
  'application/x-rar-compressed',
  'application/x-7z-compressed',
  'application/x-tar',
  'application/gzip',
  // Fallback — allow generic binary for unknown code/config files
  'application/octet-stream',
]);

module.exports = { MIME_TYPES, getContentTypeByName, ALLOWED_MIME_TYPES };

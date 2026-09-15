/**
 * HTTP Range support for in-memory buffers (decrypted files).
 * Media players rely on 206 partial responses for seeking.
 */

function parseSingleByteRange(rangeHeader, totalSize) {
  if (!Number.isSafeInteger(totalSize) || totalSize <= 0) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(String(rangeHeader || '').trim());
  if (!match || (!match[1] && !match[2])) return null;

  if (!match[1]) {
    const suffixLength = Number(match[2]);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return null;
    return {
      start: Math.max(0, totalSize - suffixLength),
      end: totalSize - 1,
    };
  }

  const start = Number(match[1]);
  const requestedEnd = match[2] ? Number(match[2]) : totalSize - 1;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(requestedEnd) ||
      start < 0 || start >= totalSize || requestedEnd < start) {
    return null;
  }
  return { start, end: Math.min(requestedEnd, totalSize - 1) };
}

function sendBufferWithRange(req, res, buffer, contentType) {
  const totalSize = buffer.length;
  const range = req.headers.range;

  if (range) {
    const parsed = parseSingleByteRange(range, totalSize);
    if (!parsed) {
      res.setHeader('Content-Range', `bytes */${totalSize}`);
      return res.status(416).end();
    }
    const { start, end } = parsed;

    const chunk = buffer.subarray(start, end + 1);
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${totalSize}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': chunk.length,
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
    });
    return res.end(chunk);
  }

  res.writeHead(200, {
    'Content-Length': totalSize,
    'Content-Type': contentType,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
  });
  return res.end(buffer);
}

module.exports = { parseSingleByteRange, sendBufferWithRange };

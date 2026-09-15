const db = require('../index');
const enc = require('../../encryption/encryption');
const { KEY_PURPOSES } = enc;

/**
 * Escape ILIKE special characters so user input is treated as literal text.
 * Without this, a search for '%' would match every row (wildcard injection).
 */
function escapeILike(str) {
  return str.replace(/([%_\\])/g, '\\$1');
}

// Allowed statuses for message read-receipts
const VALID_MESSAGE_STATUSES = ['sent', 'delivered', 'read'];

// ── Encryption helpers ────────────────────────────────────────────────────
// Transparently encrypt before DB write and decrypt after DB read.
// If the encryption engine is not initialized, pass through plaintext
// (graceful degradation for dev/testing).

function encryptContent(content, msgId) {
  if (!content || !enc.isInitialized()) return content;
  return enc.encrypt(content, KEY_PURPOSES.MESSAGES, msgId || undefined);
}

function encryptFileUrl(fileUrl, msgId) {
  if (!fileUrl || !enc.isInitialized()) return fileUrl;
  return enc.encrypt(fileUrl, KEY_PURPOSES.FILE_NAMES, msgId || undefined);
}

function decryptRow(row) {
  if (!row || !enc.isInitialized()) return row;
  try {
    if (row.content && enc.isEncrypted(row.content)) {
      row.content = enc.decrypt(row.content, KEY_PURPOSES.MESSAGES, row.id || undefined);
    }
  } catch (err) {
    console.error('[Decrypt] content error for msg', row.id, ':', err.message);
    // Return the raw encrypted blob — don't crash
  }
  try {
    if (row.file_url && enc.isEncrypted(row.file_url)) {
      row.file_url = enc.decrypt(row.file_url, KEY_PURPOSES.FILE_NAMES, row.id || undefined);
    }
  } catch (err) {
    console.error('[Decrypt] file_url error for msg', row.id, ':', err.message);
  }
  return row;
}

function decryptRows(rows) {
  if (!rows || !enc.isInitialized()) return rows;
  return rows.map(decryptRow);
}

const MessageQueries = {
  /**
   * Insert a message.
   * @param {{ roomId: string, senderId: string, content?: string, messageType?: string, fileUrl?: string }} data
   * @returns {Promise<object>}
   */
  async create({ roomId, senderId, content, messageType = 'text', fileUrl, replyToId, mentions, mentionsEveryone }) {
    // First insert to get the ID, then encrypt with ID as AAD, then update.
    // This binds the ciphertext to the specific message row (prevents relocation).
    const baseParams = [roomId, senderId, content || null, messageType, fileUrl || null, replyToId || null];
    // Only a message that actually mentions someone touches the mention columns,
    // so an ordinary message never depends on them.
    const hasMentions = (Array.isArray(mentions) && mentions.length > 0) || !!mentionsEveryone;
    const { rows } = hasMentions
      ? await db.query(
        `INSERT INTO messages (room_id, sender_id, content, message_type, file_url, reply_to_id, mentions, mentions_everyone)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
         RETURNING *`,
        [...baseParams, JSON.stringify(Array.isArray(mentions) ? mentions : []), !!mentionsEveryone],
      )
      : await db.query(
        `INSERT INTO messages (room_id, sender_id, content, message_type, file_url, reply_to_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        baseParams,
      );

    const msg = rows[0];

    // Encrypt content and file_url using the message ID as AAD
    if (enc.isInitialized() && (content || fileUrl)) {
      const encContent = encryptContent(content, msg.id);
      const encFileUrl = encryptFileUrl(fileUrl, msg.id);
      await db.query(
        `UPDATE messages SET content = $1, file_url = $2 WHERE id = $3`,
        [encContent, encFileUrl, msg.id],
      );
      // Return the decrypted values to the caller (they expect plaintext)
      msg.content = content || null;
      msg.file_url = fileUrl || null;
    }

    return msg;
  },

  /**
   * Find a message by id.
   */
  async findById(id) {
    const { rows } = await db.query('SELECT * FROM messages WHERE id = $1', [id]);
    return decryptRow(rows[0]) || null;
  },

  /**
   * Paginated message history for a room.
   * @param {string} roomId
   * @param {{ limit?: number, before?: string }} options
   * @returns {Promise<object[]>}
   */
  async listByRoom(roomId, { limit = 50, before, after, userId } = {}) {
    const params = [roomId];
    let whereExtra = '';

    // If userId provided, filter messages after the user cleared the chat
    if (userId) {
      whereExtra = `AND m.created_at > COALESCE(
        (SELECT cleared_at FROM room_participants WHERE room_id = $1 AND user_id = $${params.length + 1}),
        '1970-01-01'::timestamp
      )`;
      params.push(userId);
    }

    if (before) {
      whereExtra += ' AND m.created_at < $' + (params.length + 1);
      params.push(before);
    }

    if (after) {
      whereExtra += ' AND m.created_at > $' + (params.length + 1);
      params.push(after);
    }

    params.push(limit);

    const { rows } = await db.query(
      `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
              COALESCE(
                (SELECT CASE
                   WHEN COUNT(*) = 0 THEN 'sent'
                   WHEN MIN(CASE ms.status WHEN 'read' THEN 2 WHEN 'delivered' THEN 1 ELSE 0 END) >= 2 THEN 'read'
                   WHEN MIN(CASE ms.status WHEN 'read' THEN 2 WHEN 'delivered' THEN 1 ELSE 0 END) >= 1 THEN 'delivered'
                   ELSE 'sent'
                 END
                 FROM message_status ms WHERE ms.message_id = m.id),
                'sent'
              ) AS delivery_status,
              COALESCE(
                (SELECT json_agg(
                   json_build_object(
                     'userId', mr.user_id,
                     'emoji', mr.emoji,
                     'username', COALESCE(mru.full_name, mru.username),
                     'createdAt', mr.created_at
                   ) ORDER BY mr.created_at)
                 FROM message_reactions mr
                 JOIN users mru ON mru.id = mr.user_id
                 WHERE mr.message_id = m.id),
                '[]'
              ) AS reactions,
              rm.content      AS reply_to_content_raw,
              rm.file_url     AS reply_to_file_url_raw,
              rm.message_type AS reply_to_type,
              ru.username     AS reply_to_sender
       FROM messages m
       LEFT JOIN users u ON u.id = m.sender_id
       LEFT JOIN messages rm ON rm.id = m.reply_to_id
       LEFT JOIN users ru ON ru.id = rm.sender_id
       WHERE m.room_id = $1 ${whereExtra}
       ORDER BY m.created_at DESC
       LIMIT $${params.length}`,
      params,
    );
    // Decrypt both message and its quoted parent
    const decrypted = decryptRows(rows);
    for (const row of decrypted) {
      if (row.reply_to_content_raw) {
        try {
          row.reply_to_content = enc.isInitialized() && enc.isEncrypted(row.reply_to_content_raw)
            ? enc.decrypt(row.reply_to_content_raw, KEY_PURPOSES.MESSAGES, row.reply_to_id || undefined)
            : row.reply_to_content_raw;
        } catch { row.reply_to_content = null; }
      }
      delete row.reply_to_content_raw;
      delete row.reply_to_file_url_raw;
    }
    return decrypted;
  },

  /**
   * Get only new messages since a given timestamp (for incremental sync / caching).
   * Returns messages in ascending (oldest-first) order.
   * If userId provided, filters messages after the user cleared the chat.
   */
  async listNewSince(roomId, sinceTimestamp, userId) {
    const params = [roomId, sinceTimestamp];
    let whereExtra = '';

    if (userId) {
      whereExtra = `AND m.created_at > COALESCE(
        (SELECT cleared_at FROM room_participants WHERE room_id = $1 AND user_id = $${params.length + 1}),
        '1970-01-01'::timestamp
      )`;
      params.push(userId);
    }

    const { rows } = await db.query(
      `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
              COALESCE(
                (SELECT CASE
                   WHEN COUNT(*) = 0 THEN 'sent'
                   WHEN MIN(CASE ms.status WHEN 'read' THEN 2 WHEN 'delivered' THEN 1 ELSE 0 END) >= 2 THEN 'read'
                   WHEN MIN(CASE ms.status WHEN 'read' THEN 2 WHEN 'delivered' THEN 1 ELSE 0 END) >= 1 THEN 'delivered'
                   ELSE 'sent'
                 END
                 FROM message_status ms WHERE ms.message_id = m.id),
                'sent'
              ) AS delivery_status,
              COALESCE(
                (SELECT json_agg(
                   json_build_object(
                     'userId', mr.user_id,
                     'emoji', mr.emoji,
                     'username', COALESCE(mru.full_name, mru.username),
                     'createdAt', mr.created_at
                   ) ORDER BY mr.created_at)
                 FROM message_reactions mr
                 JOIN users mru ON mru.id = mr.user_id
                 WHERE mr.message_id = m.id),
                '[]'
              ) AS reactions,
              rm.content      AS reply_to_content_raw,
              rm.message_type AS reply_to_type,
              ru.username     AS reply_to_sender
       FROM messages m
       LEFT JOIN users u ON u.id = m.sender_id
       LEFT JOIN messages rm ON rm.id = m.reply_to_id
       LEFT JOIN users ru ON ru.id = rm.sender_id
       WHERE m.room_id = $1 AND (
         m.created_at > $2 OR
         m.edited_at > $2 OR
         EXISTS (SELECT 1 FROM message_reactions mr WHERE mr.message_id = m.id AND mr.created_at > $2) OR
         EXISTS (SELECT 1 FROM message_status ms WHERE ms.message_id = m.id AND ms.updated_at > $2)
       ) ${whereExtra}
       ORDER BY m.created_at ASC`,
      params,
    );
    const decrypted = decryptRows(rows);
    for (const row of decrypted) {
      if (row.reply_to_content_raw) {
        try {
          row.reply_to_content = enc.isInitialized() && enc.isEncrypted(row.reply_to_content_raw)
            ? enc.decrypt(row.reply_to_content_raw, KEY_PURPOSES.MESSAGES, row.reply_to_id || undefined)
            : row.reply_to_content_raw;
        } catch { row.reply_to_content = null; }
      }
      delete row.reply_to_content_raw;
    }
    return decrypted;
  },

  /**
   * Edit a message (only content, sets edited_at).
   */
  async update(id, content) {
    // Encrypt the new content with the message ID as AAD
    const encContent = encryptContent(content, id);
    const { rows } = await db.query(
      `UPDATE messages SET content = $2, edited_at = NOW()
       WHERE id = $1 RETURNING *`,
      [id, encContent],
    );
    const row = rows[0] || null;
    if (row) row.content = content; // Return plaintext to caller
    return row;
  },

  /**
   * Delete a message.
   */
  async remove(id) {
    await db.query('DELETE FROM messages WHERE id = $1', [id]);
  },

  // ---------- Read receipts ----------

  /**
   * Upsert a message status entry.
   */
  async setStatus(messageId, userId, status) {
    if (!VALID_MESSAGE_STATUSES.includes(status)) {
      throw new Error(`Invalid message status: ${status}`);
    }
    const { rows } = await db.query(
      `INSERT INTO message_status (message_id, user_id, status, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (message_id, user_id)
       DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
       RETURNING *`,
      [messageId, userId, status],
    );
    return rows[0];
  },

  /**
   * Mark all messages in a room as delivered/read for a user.
   */
  async markRoomAs(roomId, userId, status) {
    if (!VALID_MESSAGE_STATUSES.includes(status)) {
      throw new Error(`Invalid message status: ${status}`);
    }
    await db.query(
      `INSERT INTO message_status (message_id, user_id, status, updated_at)
       SELECT m.id, $2, $3, NOW()
       FROM messages m
       WHERE m.room_id = $1 AND m.sender_id != $2
       ON CONFLICT (message_id, user_id)
       DO UPDATE SET status = EXCLUDED.status, updated_at = NOW()
         WHERE message_status.status != $3`,
      [roomId, userId, status],
    );
  },

  /**
   * Get read receipt info for a single message.
   */
  async getStatus(messageId) {
    const { rows } = await db.query(
      `SELECT ms.*, u.username
       FROM message_status ms
       JOIN users u ON u.id = ms.user_id
       WHERE ms.message_id = $1`,
      [messageId],
    );
    return rows;
  },

  /**
   * Search messages within a specific room.
   * When encryption is active, fetches candidates and filters after decryption.
   */
  async searchInRoom(roomId, query, { limit = 50 } = {}) {
    if (enc.isInitialized()) {
      // Encrypted content can't be searched via SQL ILIKE.
      // Fetch recent messages for this room, decrypt, then filter.
      const { rows } = await db.query(
        `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture
         FROM messages m
         LEFT JOIN users u ON u.id = m.sender_id
         WHERE m.room_id = $1
           AND m.message_type = 'text'
         ORDER BY m.created_at DESC
         LIMIT $2`,
        [roomId, limit * 10], // Fetch more to compensate for filtering
      );
      const decrypted = decryptRows(rows);
      const lowerQ = query.toLowerCase();
      return decrypted
        .filter(r => r.content && r.content.toLowerCase().includes(lowerQ))
        .slice(0, limit);
    }

    const { rows } = await db.query(
      `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture
       FROM messages m
       LEFT JOIN users u ON u.id = m.sender_id
       WHERE m.room_id = $1
         AND m.message_type = 'text'
         AND m.content ILIKE '%' || $2 || '%'
       ORDER BY m.created_at DESC
       LIMIT $3`,
      [roomId, escapeILike(query), limit],
    );
    return rows;
  },

  /**
   * Global search across all rooms — returns messages with room info.
   * When encrypted, fetches candidates, decrypts, and filters.
   */
  async searchGlobal(query, { limit = 50 } = {}) {
    if (enc.isInitialized()) {
      const { rows } = await db.query(
        `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
                r.type AS room_type, r.name AS room_name,
                COALESCE(
                  r.name,
                  (SELECT string_agg(u2.username, ', ')
                   FROM room_participants rp2
                   JOIN users u2 ON u2.id = rp2.user_id
                   WHERE rp2.room_id = r.id AND rp2.left_at IS NULL)
                ) AS room_display_name
         FROM messages m
         LEFT JOIN users u ON u.id = m.sender_id
         LEFT JOIN rooms r ON r.id = m.room_id
         WHERE m.message_type = 'text'
         ORDER BY m.created_at DESC
         LIMIT $1`,
        [limit * 10],
      );
      const decrypted = decryptRows(rows);
      const lowerQ = query.toLowerCase();
      return decrypted
        .filter(r => r.content && r.content.toLowerCase().includes(lowerQ))
        .slice(0, limit);
    }

    const { rows } = await db.query(
      `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
              r.type AS room_type, r.name AS room_name,
              COALESCE(
                r.name,
                (SELECT string_agg(u2.username, ', ')
                 FROM room_participants rp2
                 JOIN users u2 ON u2.id = rp2.user_id
                 WHERE rp2.room_id = r.id AND rp2.left_at IS NULL)
              ) AS room_display_name
       FROM messages m
       LEFT JOIN users u ON u.id = m.sender_id
       LEFT JOIN rooms r ON r.id = m.room_id
       WHERE m.message_type = 'text'
         AND m.content ILIKE '%' || $1 || '%'
       ORDER BY m.created_at DESC
       LIMIT $2`,
      [escapeILike(query), limit],
    );
    return rows;
  },

  /**
   * Search messages across rooms a specific user belongs to.
   * When encrypted, fetches candidates, decrypts, and filters.
   */
  async searchByUser(userId, query, { limit = 50 } = {}) {
    if (enc.isInitialized()) {
      const { rows } = await db.query(
        `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
                r.type AS room_type, r.name AS room_name,
                COALESCE(
                  r.name,
                  (SELECT string_agg(u2.username, ', ')
                   FROM room_participants rp2
                   JOIN users u2 ON u2.id = rp2.user_id
                   WHERE rp2.room_id = r.id AND rp2.left_at IS NULL)
                ) AS room_display_name
         FROM messages m
         LEFT JOIN users u ON u.id = m.sender_id
         LEFT JOIN rooms r ON r.id = m.room_id
         JOIN room_participants rp ON rp.room_id = m.room_id AND rp.user_id = $1 AND rp.left_at IS NULL
         WHERE m.message_type = 'text'
         ORDER BY m.created_at DESC
         LIMIT $2`,
        [userId, limit * 10],
      );
      const decrypted = decryptRows(rows);
      const lowerQ = query.toLowerCase();
      return decrypted
        .filter(r => r.content && r.content.toLowerCase().includes(lowerQ))
        .slice(0, limit);
    }

    const { rows } = await db.query(
      `SELECT m.*, u.username AS sender_username, u.profile_picture AS sender_picture,
              r.type AS room_type, r.name AS room_name,
              COALESCE(
                r.name,
                (SELECT string_agg(u2.username, ', ')
                 FROM room_participants rp2
                 JOIN users u2 ON u2.id = rp2.user_id
                 WHERE rp2.room_id = r.id AND rp2.left_at IS NULL)
              ) AS room_display_name
       FROM messages m
       LEFT JOIN users u ON u.id = m.sender_id
       LEFT JOIN rooms r ON r.id = m.room_id
       JOIN room_participants rp ON rp.room_id = m.room_id AND rp.user_id = $1 AND rp.left_at IS NULL
       WHERE m.message_type = 'text'
         AND m.content ILIKE '%' || $2 || '%'
       ORDER BY m.created_at DESC
       LIMIT $3`,
      [userId, escapeILike(query), limit],
    );
    return rows;
  },
};

module.exports = MessageQueries;

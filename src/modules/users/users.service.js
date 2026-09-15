/**
 * User-domain checks shared by HTTP routes and socket handlers.
 */
const db = require('../../infrastructure/db');

async function isUserSuspended(userId) {
  try {
    const { rowCount } = await db.query(
      `SELECT 1 FROM user_workspaces WHERE user_id = $1 AND status = 'suspended' LIMIT 1`,
      [userId],
    );
    return rowCount > 0;
  } catch {
    return false;
  }
}

/**
 * Check if two users share at least one active workspace membership.
 */
async function doUsersShareWorkspace(userIdA, userIdB) {
  try {
    const { rowCount } = await db.query(
      `SELECT 1 FROM user_workspaces uw1
       JOIN user_workspaces uw2 ON uw1.workspace_id = uw2.workspace_id
       WHERE uw1.user_id = $1 AND uw2.user_id = $2
         AND uw1.status = 'active' AND uw2.status = 'active'
       LIMIT 1`,
      [userIdA, userIdB],
    );
    return rowCount > 0;
  } catch {
    return false;
  }
}

/**
 * Whether two active accounts have an established communication relationship.
 *
 * The relationship is server-owned and can come from an active shared
 * workspace, a durable introduction made by a persistent group, an accepted
 * contact request, or an existing private conversation. Superadmins may
 * initiate contact globally; other users still need one of those
 * relationships when contacting a superadmin.
 */
async function canUsersCommunicate(actorId, targetId) {
  try {
    return await canUsersCommunicateOrThrow(actorId, targetId);
  } catch (error) {
    console.error('[Users] Communication permission check failed:', error.message);
    // Authorization failures must fail closed. A database outage must not turn
    // into a temporary cross-workspace bypass.
    return false;
  }
}

/**
 * Same check, but lets a DB error propagate instead of swallowing it. Keep the
 * throwing form internal so authorization callers consistently use the
 * fail-closed public wrapper above.
 */
async function canUsersCommunicateOrThrow(actorId, targetId) {
  if (!actorId || !targetId || String(actorId) === String(targetId)) return false;
  const { rows } = await db.query(
    `SELECT actor.role AS actor_role,
            target.role AS target_role,
            actor.status AS actor_status,
            target.status AS target_status,
            EXISTS (
              SELECT 1
              FROM user_workspaces mine
              JOIN user_workspaces theirs ON theirs.workspace_id = mine.workspace_id
              WHERE mine.user_id = $1 AND theirs.user_id = $2
                AND mine.status = 'active' AND theirs.status = 'active'
            ) AS shares_workspace,
            EXISTS (
              SELECT 1 FROM user_communication_links link
              WHERE (link.user_id_a = $1 AND link.user_id_b = $2)
                 OR (link.user_id_a = $2 AND link.user_id_b = $1)
            ) AS introduced_by_group,
            EXISTS (
              SELECT 1 FROM contact_requests request
              WHERE ((request.from_user_id = $1 AND request.to_user_id = $2)
                  OR (request.from_user_id = $2 AND request.to_user_id = $1))
                AND request.status = 'accepted'
            ) AS accepted_contact,
            EXISTS (
              SELECT 1
              FROM rooms room
              JOIN room_participants mine
                ON mine.room_id = room.id AND mine.user_id = $1
              JOIN room_participants theirs
                ON theirs.room_id = room.id AND theirs.user_id = $2
              WHERE room.type = 'private'
            ) AS existing_private_room
     FROM users actor
     JOIN users target ON target.id = $2
     WHERE actor.id = $1`,
    [actorId, targetId],
  );
  const relation = rows[0];
  if (!relation || relation.actor_status !== 'active' || relation.target_status !== 'active') {
    return false;
  }
  if (relation.actor_role === 'superadmin') return true;
  return Boolean(
    relation.shares_workspace ||
    relation.introduced_by_group ||
    relation.accepted_contact ||
    relation.existing_private_room
  );
}

/** Persist introductions among everyone currently in a real, non-ephemeral group. */
async function recordGroupIntroductions(roomId) {
  const { rowCount } = await db.query(
    `INSERT INTO user_communication_links (user_id_a, user_id_b, source_group_id)
     SELECT left_member.user_id, right_member.user_id, room.id
     FROM rooms room
     JOIN room_participants left_member
       ON left_member.room_id = room.id AND left_member.left_at IS NULL
     JOIN room_participants right_member
       ON right_member.room_id = room.id AND right_member.left_at IS NULL
      AND left_member.user_id::text < right_member.user_id::text
     WHERE room.id = $1
       AND room.type = 'group'
       AND COALESCE(room.is_ephemeral, FALSE) = FALSE
     ON CONFLICT (user_id_a, user_id_b) DO NOTHING`,
    [roomId],
  );
  return rowCount || 0;
}

module.exports = {
  isUserSuspended,
  doUsersShareWorkspace,
  canUsersCommunicate,
  recordGroupIntroductions,
};

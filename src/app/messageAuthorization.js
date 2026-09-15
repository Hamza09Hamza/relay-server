'use strict';

function sameId(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) return false;
  return String(left) === String(right);
}

/**
 * Return the one server-authoritative recipient for a two-person private room.
 * A requested recipient is accepted only when it matches that participant.
 */
function resolvePrivateRecipient(members, senderId, requestedRecipientId) {
  if (!Array.isArray(members) || !members.some(member => sameId(member.id, senderId))) {
    return { ok: false, error: 'Not a member of this room' };
  }

  const recipients = members.filter(member => !sameId(member.id, senderId));
  if (recipients.length !== 1) {
    return { ok: false, error: 'Invalid private room membership' };
  }

  const recipientId = recipients[0].id;
  if (requestedRecipientId != null && !sameId(requestedRecipientId, recipientId)) {
    return { ok: false, error: 'Recipient does not belong to this room' };
  }

  return { ok: true, recipientId };
}

function isAuthorizedMessageRecipient(members, userId, senderId) {
  return Array.isArray(members) &&
    !sameId(userId, senderId) &&
    members.some(member => sameId(member.id, userId));
}

module.exports = { resolvePrivateRecipient, isAuthorizedMessageRecipient };

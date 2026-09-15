/**
 * Mentions and per-room notification modes — pure helpers shared by the
 * socket handlers.
 */

const MAX_MENTIONS = 50;

/** 'all' is the default and is never stored; see room_notification_modes. */
const ROOM_NOTIFICATION_MODES = ['all', 'mentions', 'none'];

/**
 * The @everyone token in every language the app ships. Clients insert the
 * canonical `@everyone` from the mention picker and only *display* it in the
 * reader's language; these cover someone typing it out by hand in theirs.
 */
const EVERYONE_TOKENS = ['everyone', 'tous', 'الجميع'];

// Whitespace (or start) before the @, and a word boundary after the token —
// written out explicitly because \b does not understand Arabic.
const EVERYONE_RE = new RegExp(
  `(^|\\s)@(${EVERYONE_TOKENS.join('|')})(?=$|[\\s.,!?;:)\\]])`,
  'iu',
);

function detectsEveryone(text) {
  return typeof text === 'string' && EVERYONE_RE.test(text);
}

/**
 * Turn a client-supplied mention list into one the server will stand behind.
 *
 * A mention is kept only if it names a current member of the room, is not the
 * sender, and the message text really contains `@<that member's name>`. The
 * displayed name is always taken from the member record, never from the
 * client: otherwise a sender could render "@Admin" in the text while silently
 * pinging someone else.
 */
function normalizeMentions(raw, participants, senderId, text) {
  if (!Array.isArray(raw) || !Array.isArray(participants) || typeof text !== 'string') {
    return [];
  }
  const members = new Map(participants.map(p => [String(p.id), p]));
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    const id = String((item && typeof item === 'object' ? item.id : item) ?? '');
    if (!id || seen.has(id) || id === String(senderId)) continue;
    const member = members.get(id);
    if (!member) continue;
    const name = [member.full_name, member.username]
      .filter(candidate => typeof candidate === 'string' && candidate.trim())
      .map(candidate => candidate.trim())
      .find(candidate => text.includes(`@${candidate}`));
    if (!name) continue;
    seen.add(id);
    out.push({ id, name });
    if (out.length >= MAX_MENTIONS) break;
  }
  return out;
}

/** Should a member with this room mode be notified about this message? */
function shouldNotifyForMode(mode, isMentioned) {
  if (mode === 'none') return false;
  if (mode === 'mentions') return !!isMentioned;
  return true;
}

module.exports = {
  MAX_MENTIONS,
  ROOM_NOTIFICATION_MODES,
  EVERYONE_TOKENS,
  detectsEveryone,
  normalizeMentions,
  shouldNotifyForMode,
};

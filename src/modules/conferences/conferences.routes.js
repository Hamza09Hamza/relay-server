/**
 * Conferences — user-facing endpoints for the Conferences tab (both frontends):
 *   • recent    — the user's own conference history (from `calls`)
 *   • scheduled — plan a conference for later + invite people (live socket
 *                 event for online users, plus a reminder ~15 min before via
 *                 the job in server.js)
 *   • upcoming  — everything the user is invited to / owns that hasn't started
 *
 * Distinct from the admin call/recording listings — this is scoped to the
 * authenticated user.
 *
 * Factory (needs emitToUser): a live 'conference_invite'/'conference_reminder'
 * socket event to the invitee's `user:<id>` room is how they learn about an
 * invite/reminder in real time; there's no push channel for offline delivery
 * in this build, so an invite only reaches invitees who are online (or open
 * the app before it starts, via the /upcoming listing).
 */
const express = require('express');
const queries = require('../../infrastructure/db/queries');
const { authMiddleware } = require('../auth/auth.middleware');
const { parseLimit, parseOffset } = require('../../shared/http/pagination');

function fmtWhen(iso) {
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return '';
  }
}

function sameUserId(left, right) {
  if (left === null || left === undefined || right === null || right === undefined) return false;
  return String(left) === String(right);
}

module.exports = function conferencesRoutes({ emitToUser }) {
  const router = express.Router();

  const requireConferenceCapability = async (req, res, next) => {
    try {
      if (!(await queries.users.hasCapability(req.userId, 'conferences'))) {
        return res.status(403).json({ error: 'Conferences are not enabled for this account' });
      }
      next();
    } catch (err) {
      res.status(500).json({ error: 'Internal server error' });
    }
  };

// ── Recent history ─────────────────────────────────────────────
router.get('/api/conferences/recent', authMiddleware, requireConferenceCapability, async (req, res) => {
  try {
    const limit = parseLimit(req.query.limit, { def: 20, max: 100 });
    const offset = parseOffset(req.query.offset);
    const conferences = await queries.calls.listConferencesByUser(req.userId, { limit, offset });
    res.json({ conferences });
  } catch (err) {
    console.error('[Conferences] Recent list error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Upcoming (scheduled) the user owns or is invited to ────────
router.get('/api/conferences/upcoming', authMiddleware, requireConferenceCapability, async (req, res) => {
  try {
    const conferences = await queries.scheduledConferences.listUpcomingForUser(req.userId);
    res.json({ conferences });
  } catch (err) {
    console.error('[Conferences] Upcoming list error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Plan a conference for later + notify invitees ──────────────
router.post('/api/conferences/scheduled', authMiddleware, requireConferenceCapability, async (req, res) => {
  try {
    const { title, callType, scheduledFor, inviteeIds } = req.body || {};
    const when = new Date(scheduledFor);
    if (!scheduledFor || Number.isNaN(when.getTime())) {
      return res.status(400).json({ error: 'A valid scheduledFor date is required' });
    }
    if (when.getTime() < Date.now() - 60_000) {
      return res.status(400).json({ error: 'Cannot schedule a conference in the past' });
    }
    const allowedInviteeIds = await queries.users.filterIdsWithCapability(
      Array.isArray(inviteeIds) ? inviteeIds : [], 'conferences',
    );
    const conf = await queries.scheduledConferences.create({
      title: (title || 'Conference').trim().slice(0, 120),
      callType: callType === 'audio' ? 'audio' : 'video',
      scheduledFor: when.toISOString(),
      createdBy: req.userId,
      inviteeIds: allowedInviteeIds,
    });

    // Notify each invitee with a live socket event — the only delivery
    // channel here, so only invitees who are online (or check /upcoming
    // later) learn about it.
    const creator = await queries.users.findById(req.userId).catch(() => null);
    const creatorName = creator?.full_name || creator?.username || 'Someone';
    const invitePayload = {
      conferenceId: conf.id, title: conf.title, scheduledFor: conf.scheduled_for,
      callType: conf.call_type, from: creatorName,
    };
    for (const uid of conf.inviteeIds) {
      try { emitToUser(uid, 'conference_invite', invitePayload); } catch (_) {}
    }

    res.status(201).json({ conference: conf });
  } catch (err) {
    console.error('[Conferences] Schedule error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Prepare/commit a scheduled conference start (creator only) ──
// New clients prepare first, create the real room/call, then commit so a media
// setup failure never makes the meeting disappear. Legacy callers omit commit
// and retain the original one-shot behavior.
router.post('/api/conferences/scheduled/:id/start', authMiddleware, requireConferenceCapability, async (req, res) => {
  try {
    // New clients use this as a two-phase operation: prepare validates and
    // returns the authoritative invite list without hiding the schedule; commit
    // runs only after the real SFU conference has started successfully. Omitted
    // `commit` keeps the legacy one-shot behavior for older clients.
    const commit = req.body?.commit !== false;
    const conf = await queries.scheduledConferences.getById(req.params.id);
    if (!conf) return res.status(404).json({ error: 'Conference not found' });
    if (!sameUserId(conf.created_by, req.userId)) {
      return res.status(403).json({ error: 'Only the organizer can start this conference' });
    }
    if (conf.status !== 'scheduled' && !(commit && conf.status === 'started')) {
      return res.status(409).json({ error: `Conference is already ${conf.status}` });
    }
    const inviteeIds = await queries.scheduledConferences.getInviteeIds(conf.id);
    if (commit && conf.status === 'scheduled') {
      await queries.scheduledConferences.setStatus(conf.id, 'started');
    }
    res.json({
      ok: true,
      prepared: !commit,
      inviteeIds,
      title: conf.title,
      callType: conf.call_type,
    });
  } catch (err) {
    console.error('[Conferences] Start error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Cancel a scheduled conference (creator only) ───────────────
router.post('/api/conferences/scheduled/:id/cancel', authMiddleware, async (req, res) => {
  try {
    const conf = await queries.scheduledConferences.getById(req.params.id);
    if (!conf) return res.status(404).json({ error: 'Conference not found' });
    if (!sameUserId(conf.created_by, req.userId)) {
      return res.status(403).json({ error: 'Only the organizer can cancel this conference' });
    }
    await queries.scheduledConferences.setStatus(conf.id, 'cancelled');
    res.json({ ok: true });
  } catch (err) {
    console.error('[Conferences] Cancel error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Invitee responds (accept / decline) ────────────────────────
router.post('/api/conferences/scheduled/:id/respond', authMiddleware, async (req, res) => {
  try {
    const response = req.body?.response === 'accepted' ? 'accepted'
      : req.body?.response === 'declined' ? 'declined' : null;
    if (!response) return res.status(400).json({ error: 'response must be accepted or declined' });
    await queries.scheduledConferences.setInviteeResponse(req.params.id, req.userId, response);
    res.json({ ok: true });
  } catch (err) {
    console.error('[Conferences] Respond error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Keep this dynamic route after every named / scheduled route so "upcoming"
// can never be interpreted as a call id.
router.get('/api/conferences/:callId', authMiddleware, requireConferenceCapability, async (req, res) => {
  try {
    const archive = await queries.conferenceArchives.getForParticipant(req.params.callId, req.userId);
    if (!archive) return res.status(404).json({ error: 'Conference not found' });
    res.json(archive);
  } catch (err) {
    console.error('[Conferences] Archive error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  return router;
};

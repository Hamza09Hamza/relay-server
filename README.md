# relay-server

A real-time communication backend: 1:1 and group chat, push-to-talk (PTT) radio
channels, 1:1 calls, and multi-party conferencing — all over Socket.IO signalling
and a [mediasoup](https://mediasoup.org/) WebRTC SFU, backed by PostgreSQL.

This is a standalone extraction of a larger production system, trimmed to its
core communication engine. Push notifications, per-device admin management, and
admin analytics dashboards are intentionally out of scope — this project focuses
on the real-time media and messaging core.

## Features

- **Chat**: 1:1 and group messaging, replies, reactions, pinning, read receipts,
  mentions (including `@everyone`), per-room notification modes, typing
  indicators, incremental sync for offline catch-up.
- **Calls**: 1:1 audio/video calling with ringing, busy detection, reconnect
  grace windows (a dropped connection doesn't instantly end the call), and
  server-authoritative call state.
- **Conferencing**: multi-party group calls with live invites, host controls
  (mute/remove participant/end for all), raised hands, emoji reactions, shared
  notes, and screen sharing.
- **Push-to-talk**: workspace-scoped radio channels with server-enforced
  half-duplex floor control (one speaker at a time), multi-channel listening,
  and automatic per-transmission recording.
- **Recording**: automatic call recording once 2+ participants are producing
  media, with a server-side pipeline that extracts per-participant segments and
  composes a single grid-video + mixed-audio file per call.
- **Workspaces**: multi-tenant isolation — users only discover, message, and
  call people who share a workspace (or an explicit contact link).

## Architecture

```
server.js               Express + Socket.IO bootstrap, chat/call/conference
                         socket handlers, recording post-processing queue
mediaServer.js           mediasoup engine: rooms, peers, transports,
                         producers/consumers, RTP capture for recording
recordingSegmentExtractor.js   Per-participant segment extraction (FFmpeg)
recordingCompositor.js         Grid-video + mixed-audio composite per call
recordingTimeline.js           Pure segment-derivation math
socketRateLimiter.js           Per-socket, per-event-type rate limiting

src/
  app/          Shared in-memory state, call-attempt bookkeeping, config
  infrastructure/  Postgres access + schema, Redis (optional multi-instance
                   Socket.IO fan-out), encryption for data at rest
  modules/
    auth/        Registration, login, JWT issuance/refresh
    users/       Profile + capability management, workspace membership
    contacts/    Contact request flow
    conferences/ Scheduled conferences, live invites
    recordings/  Playback/streaming endpoints
    ptt/         Push-to-talk channels, floor control, recording
    uploads/     File uploads with at-rest encryption
    hop-in/      Ephemeral device-to-device camera handoff
    notifications/  Socket-only admin notifications (no push provider)
```

### Notable design decisions

- **Server-authoritative everything.** Call state, PTT floor ownership, and
  conference membership are decided server-side; clients render what the
  server tells them, never the reverse.
- **Reconnect grace.** A dropped socket doesn't immediately end a call or
  drop a PTT listener — a short grace window absorbs network blips (elevator,
  tunnel, wifi↔cellular handover) before treating the participant as gone.
- **Two-phase recording.** Phase 1 (raw RTP capture teardown) runs
  synchronously so a redial can't collide with an in-flight capture. Phase 2
  (segment extraction + composite) runs in a bounded-concurrency background
  queue with crash recovery — an interrupted transcode resumes from a
  journaled snapshot on the next boot.
- **No push provider.** Delivery to an offline client is best-effort over the
  live socket; anything missed is picked up via incremental sync on
  reconnect rather than through a third-party push service.

## Setup

Requires Node.js 18+, PostgreSQL, and `ffmpeg` on `PATH` (for recording).

```bash
npm install
cp .env.example .env   # fill in JWT_SECRET and your DB credentials
npm run db:init         # applies src/infrastructure/db/schema.sql
npm start
```

See `.env.example` for every configuration option (CORS origins, Redis for
multi-instance deployments, recording/transcoding tuning, verbose logging).

## Development

```bash
npm run dev   # nodemon, restarts on file changes
```

The server listens on `PORT` (default `3000`) and binds to `0.0.0.0` in
development or `127.0.0.1` behind a reverse proxy otherwise (override with
`HOST`).

## Testing

```bash
npm test
```

Unit tests (`node --test`, no external dependencies) cover the pure-logic
modules: PTT floor-lease acquisition/renewal/preemption, server-authoritative
recording-segment derivation, mentions/notification-mode rules, per-socket
rate limiting, and call/message authorization helpers. They don't touch the
database or mediasoup — those paths are exercised by running the server
directly against a real Postgres instance.

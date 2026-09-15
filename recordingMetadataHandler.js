/**
 * Recording Metadata Handler
 *
 * Receives camera state metadata from frontend
 * Stores in DB and orchestrates segment extraction
 */

const db = require('./src/infrastructure/db');

/**
 * Store camera metadata and create segments
 * Called when user leaves a call
 */
async function handleRecordingMetadata(callId, userId, metadata, options = {}) {
    try {
        console.log(`[RecordingMetadata] Received for call ${callId}, user ${userId}`);
        console.log('[RecordingMetadata] Events:', JSON.stringify(metadata.events, null, 2));

        const incomingEvents = Array.isArray(metadata?.events) ? metadata.events : [];
        const sessionBaseOffsetMs = Number(options?.sessionBaseOffsetMs || 0);

        const incomingExtentMs = getTimelineExtentMs(incomingEvents);
        const incomingMinMs = getTimelineMinMs(incomingEvents);
        // Rebase when the incoming timestamps start near 0 (i.e. the frontend
        // restarted its local timer on rejoin) rather than starting near the
        // session offset (which would mean they are already absolute).
        // The old heuristic (extent < offset * 0.6) failed when the rejoin
        // session lasted longer than 60% of the pre-rejoin wait.
        const shouldRebaseBySession =
            Number.isFinite(sessionBaseOffsetMs) &&
            sessionBaseOffsetMs > 0 &&
            incomingExtentMs > 0 &&
            incomingMinMs < Math.min(sessionBaseOffsetMs * 0.5, 5000);

        const normalizedIncomingEvents = shouldRebaseBySession
            ? rebaseEvents(incomingEvents, sessionBaseOffsetMs)
            : incomingEvents;

        if (shouldRebaseBySession) {
            console.log(
                `[RecordingMetadata] Rebasing incoming metadata by +${sessionBaseOffsetMs}ms for call ${callId}, user ${userId}`
            );
        }

        // Read existing metadata first so rejoin submissions with shorter
        // local timelines do not overwrite a longer timeline already stored.
        const existingResult = await db.query(
            `
            SELECT events
            FROM recording_metadata
            WHERE call_id = $1 AND user_id = $2
            LIMIT 1
            `,
            [callId, userId]
        );

        const existingEvents = existingResult.rows[0]?.events || null;
        const selectedEvents = pickPreferredEvents(existingEvents, normalizedIncomingEvents);

        if (existingEvents && selectedEvents !== normalizedIncomingEvents) {
            console.log(
                `[RecordingMetadata] Keeping existing longer metadata for call ${callId}, user ${userId}`
            );
        }

        // Store metadata in DB
        const result = await db.query(
            `
            INSERT INTO recording_metadata (call_id, user_id, events)
            VALUES ($1, $2, $3)
            ON CONFLICT (call_id, user_id)
            DO UPDATE SET events = $3, updated_at = NOW()
            RETURNING id
            `,
            [callId, userId, JSON.stringify(selectedEvents)]
        );

        const metadataId = result.rows[0].id;
        console.log(`[RecordingMetadata] Stored metadata ID: ${metadataId}`);

        // NOTE: recording_segments rows are NO LONGER derived here from client
        // camera events. The segment timeline is now SERVER-AUTHORITATIVE:
        // recordingSegmentExtractor.deriveServerSegments builds camera-on windows
        // from the SFU's observed RTP (per-producer start/end + pauseEvents) and
        // is the sole writer of recording_segments. The events stored above are
        // kept only as non-authoritative labels for debugging/admin display, so
        // a late/laggy/clock-drifted client report can no longer corrupt cuts.
        console.log(
            `[RecordingMetadata] Stored ${Array.isArray(selectedEvents) ? selectedEvents.length : 0} event label(s) ` +
            `for call ${callId}, user ${userId} (segments are server-derived)`
        );
        return {
            success: true,
            metadataId,
        };

    } catch (error) {
        console.error('[RecordingMetadata] Error:', error);
        throw error;
    }
}

function getTimelineExtentMs(events) {
    if (!Array.isArray(events) || events.length === 0) return 0;
    let maxTs = 0;
    for (const ev of events) {
        const ts = Number(ev?.timestampMs);
        if (Number.isFinite(ts) && ts > maxTs) {
            maxTs = ts;
        }
    }
    return maxTs;
}

function getTimelineMinMs(events) {
    if (!Array.isArray(events) || events.length === 0) return Infinity;
    let minTs = Infinity;
    for (const ev of events) {
        const ts = Number(ev?.timestampMs);
        if (Number.isFinite(ts) && ts >= 0 && ts < minTs) {
            minTs = ts;
        }
    }
    return minTs;
}

function rebaseEvents(events, offsetMs) {
    return (Array.isArray(events) ? events : []).map((ev) => {
        const ts = Number(ev?.timestampMs);
        const nextTs = Number.isFinite(ts) ? Math.max(0, Math.round(ts + offsetMs)) : 0;
        return {
            ...ev,
            timestampMs: nextTs,
        };
    });
}

function mergeSegments(segments) {
    const cleaned = (Array.isArray(segments) ? segments : [])
        .map((s) => ({
            startMs: Number(s?.startMs),
            endMs: Number(s?.endMs),
        }))
        .filter((s) => Number.isFinite(s.startMs) && Number.isFinite(s.endMs) && s.endMs > s.startMs)
        .sort((a, b) => a.startMs - b.startMs);

    const merged = [];
    for (const seg of cleaned) {
        const last = merged[merged.length - 1];
        if (last && seg.startMs <= last.endMs + 150) {
            last.endMs = Math.max(last.endMs, seg.endMs);
        } else {
            merged.push({ ...seg });
        }
    }

    return merged;
}

function pickPreferredEvents(existingEvents, incomingEvents) {
    if (!Array.isArray(existingEvents) || existingEvents.length === 0) {
        return Array.isArray(incomingEvents) ? incomingEvents : [];
    }
    if (!Array.isArray(incomingEvents) || incomingEvents.length === 0) {
        return existingEvents;
    }

    const existingExtent = getTimelineExtentMs(existingEvents);
    const incomingExtent = getTimelineExtentMs(incomingEvents);

    if (incomingExtent > existingExtent) return incomingEvents;
    if (incomingExtent < existingExtent) return existingEvents;

    // Same extent: prefer the one with more extracted camera segments.
    const existingSegCount = extractCameraSegments(existingEvents).length;
    const incomingSegCount = extractCameraSegments(incomingEvents).length;
    return incomingSegCount >= existingSegCount ? incomingEvents : existingEvents;
}

/**
 * Extract camera on/off segments from metadata events
 * Returns array of {startMs, endMs} for each camera-active period
 */
function extractCameraSegments(events) {
    const segments = [];
    let currentStart = null;

    for (const event of events) {
        if (event.type === 'camera_opened') {
            // If we already have an open segment, close it first (duplicate camera_opened)
            if (currentStart !== null) {
                segments.push({ startMs: currentStart, endMs: event.timestampMs });
            }
            currentStart = event.timestampMs;
        } else if (event.type === 'camera_closed' && currentStart !== null) {
            segments.push({
                startMs: currentStart,
                endMs: event.timestampMs
            });
            currentStart = null;
        } else if (event.type === 'call_ended' && currentStart !== null) {
            // Call ended while camera still on
            segments.push({
                startMs: currentStart,
                endMs: event.timestampMs
            });
            currentStart = null;
        }
    }

    return segments;
}

/**
 * Get segments for a user in a call
 */
async function getRecordingMetadata(callId, userId) {
    try {
        const result = await db.query(
            `
            SELECT
                id,
                events,
                created_at
            FROM recording_metadata
            WHERE call_id = $1 AND user_id = $2
            `,
            [callId, userId]
        );

        if (result.rows.length === 0) {
            return null;
        }

        const metadata = result.rows[0];

        // Also fetch segments
        const segmentsResult = await db.query(
            `
            SELECT
                id,
                segment_index,
                start_ms,
                end_ms,
                file_path,
                file_size,
                duration_ms
            FROM recording_segments
            WHERE call_id = $1 AND user_id = $2
            ORDER BY segment_index ASC
            `,
            [callId, userId]
        );

        return {
            ...metadata,
            segments: segmentsResult.rows || []
        };

    } catch (error) {
        console.error('[RecordingMetadata] Error fetching:', error);
        throw error;
    }
}

/**
 * Get all segments for a call (all users)
 */
async function getCallRecordingMetadata(callId) {
    try {
        const result = await db.query(
            `
            SELECT
                rm.user_id,
                rm.events,
                rm.created_at,
                json_agg(json_build_object(
                    'id', rs.id,
                    'segment_index', rs.segment_index,
                    'start_ms', rs.start_ms,
                    'end_ms', rs.end_ms,
                    'file_path', rs.file_path,
                    'file_size', rs.file_size,
                    'duration_ms', rs.duration_ms
                ) ORDER BY rs.segment_index) as segments
            FROM recording_metadata rm
            LEFT JOIN recording_segments rs ON rm.call_id = rs.call_id AND rm.user_id = rs.user_id
            WHERE rm.call_id = $1
            GROUP BY rm.user_id, rm.events, rm.created_at
            `,
            [callId]
        );

        return result.rows;

    } catch (error) {
        console.error('[RecordingMetadata] Error fetching call metadata:', error);
        throw error;
    }
}

module.exports = {
    handleRecordingMetadata,
    extractCameraSegments,
    getRecordingMetadata,
    getCallRecordingMetadata
};

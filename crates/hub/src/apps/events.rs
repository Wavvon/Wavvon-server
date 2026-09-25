//! Hub event fan-out: writes audit log rows and pushes `hub_event` envelopes
//! to subscribed app WS sessions.
//!
//! Call `publish_hub_event` from any server-side broadcast point (ws.rs,
//! messages.rs, channels.rs, moderation.rs) after the underlying action
//! has been committed to the DB.

use std::sync::Arc;

use uuid::Uuid;

use crate::state::AppState;

/// Publish a hub event.
///
/// - Writes a row to `hub_audit_log`.
/// - Queries `app_subscriptions` for every app interested in `event_type` (and
///   optionally `channel_id`).
/// - For each subscribed app with an active WS session, checks that it can
///   read the channel the event happened in.
/// - Pushes a `hub_event` JSON envelope over the app's WS sender.
///
/// Errors are logged and swallowed — event delivery is best-effort.
pub async fn publish_hub_event(
    state: &Arc<AppState>,
    event_type: &str,
    actor_pubkey: Option<&str>,
    target_pubkey: Option<&str>,
    channel_id: Option<&str>,
    payload: serde_json::Value,
) {
    let seq = match next_seq(state).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("publish_hub_event: failed to get seq: {e}");
            return;
        }
    };

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let payload_json = payload.to_string();

    if let Err(e) = sqlx::query(
        "INSERT INTO hub_audit_log(id, seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(&id)
    .bind(seq)
    .bind(event_type)
    .bind(now)
    .bind(actor_pubkey)
    .bind(target_pubkey)
    .bind(channel_id)
    .bind(&payload_json)
    .execute(&state.db)
    .await
    {
        tracing::warn!("publish_hub_event: failed to write audit log: {e}");
        return;
    }

    // Fan out to outgoing webhooks. This codebase has no broadcast channel
    // for hub events (see module doc above), so we call directly rather than
    // subscribing to one. Delivery tasks are spawned internally and never
    // block this function.
    crate::outgoing_webhooks::worker::dispatch_event(
        state, event_type, channel_id, seq, now, &payload,
    )
    .await;

    // Fetch the hub_url once.
    let hub_url = crate::apps::dispatch::hub_url_public(state).await;

    // Query every app subscribed to this event_type, hub-wide or for this channel.
    // A subscription row with channel_id = '' means hub-wide (no channel filter).
    #[derive(sqlx::FromRow)]
    struct SubRow {
        app_pubkey: String,
    }

    let subs: Vec<SubRow> = sqlx::query_as::<_, SubRow>(
        "SELECT DISTINCT app_pubkey FROM app_subscriptions
         WHERE event_type = $1
           AND (channel_id = '' OR channel_id = $2)",
    )
    .bind(event_type)
    .bind(channel_id.unwrap_or(""))
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if subs.is_empty() {
        return;
    }

    let sessions = state.app_sessions.read().await;

    for sub in &subs {
        // One pubkey may hold several concurrent WS sessions; skip if none
        // are active.
        let Some(per_app) = sessions.get(&sub.app_pubkey) else {
            continue;
        };
        if per_app.is_empty() {
            continue;
        }

        // Containment is the subscriber's own read access to the channel
        // the event happened in — the same answer `GET /messages` gives
        // them. The two mechanisms this replaces (a per-pubkey channel scope
        // list, and a capability that delivered message events with the
        // content stripped) were both the permission model rewritten by
        // hand for one kind of caller.
        if let Some(ch_id) = channel_id {
            let allowed =
                crate::permissions::channel_permissions(&state.db, &sub.app_pubkey, ch_id)
                    .await
                    .map(|perms| perms.has(crate::permissions::MESSAGES_READ))
                    .unwrap_or(false);

            if !allowed {
                continue;
            }
        }

        let envelope_payload = payload.clone();

        let envelope = serde_json::json!({
            "type": "hub_event",
            "seq": seq,
            "event": event_type,
            "hub_url": hub_url,
            "at": now,
            "payload": envelope_payload,
        });

        let json = envelope.to_string();
        // Deliver to every active session for this pubkey. Non-blocking
        // send; a full channel drops the event for that session only.
        for tx in per_app.values() {
            let _ = tx.try_send(json.clone());
        }
    }
}

/// Replay audit log rows for an app starting from `since_seq + 1`, filtered
/// to the app's subscriptions.
///
/// Returns `(rows_sent, earliest_seq_in_window, earliest_at_in_window)`.
/// If `since_seq` is outside the 72-hour window, returns the earliest
/// available row information so the caller can send `replay_unavailable`.
pub async fn replay_events_for_app(
    state: &Arc<AppState>,
    app_pubkey: &str,
    since_seq: i64,
    tx: &tokio::sync::mpsc::Sender<String>,
) -> ReplayResult {
    let now = crate::auth::handlers::unix_timestamp();
    let window_start = now - 72 * 3600;

    // Find the earliest seq still in the window.
    let earliest: Option<(i64, i64)> =
        sqlx::query_as("SELECT seq, at FROM hub_audit_log WHERE at >= $1 ORDER BY seq ASC LIMIT 1")
            .bind(window_start)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

    let (earliest_seq, earliest_at) = match earliest {
        Some((s, a)) => (s, a),
        None => {
            // Nothing in the window at all — nothing to replay.
            return ReplayResult::Complete { replayed: 0 };
        }
    };

    // If since_seq is before the window, signal unavailable.
    if since_seq < earliest_seq - 1 {
        return ReplayResult::Unavailable {
            earliest_seq,
            earliest_at,
        };
    }

    // Collect the app's subscribed event types.
    let sub_events: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT event_type FROM app_subscriptions WHERE app_pubkey = $1",
    )
    .bind(app_pubkey)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if sub_events.is_empty() {
        return ReplayResult::Complete { replayed: 0 };
    }

    // Fetch rows in order from since_seq+1.
    #[derive(sqlx::FromRow)]
    struct AuditRow {
        seq: i64,
        event_type: String,
        at: i64,
        actor_pubkey: Option<String>,
        target_pubkey: Option<String>,
        channel_id: Option<String>,
        payload_json: String,
    }

    // We batch rows in memory — for large gaps this could be large but the
    // 72h window is a hard limit so total rows is bounded.
    let rows: Vec<AuditRow> = sqlx::query_as::<_, AuditRow>(
        "SELECT seq, event_type, at, actor_pubkey, target_pubkey, channel_id, payload_json
         FROM hub_audit_log
         WHERE seq > $1 AND at >= $2
         ORDER BY seq ASC",
    )
    .bind(since_seq)
    .bind(window_start)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let hub_url = crate::apps::dispatch::hub_url_public(state).await;
    let mut replayed = 0usize;
    let batch_size = 100usize;
    let mut batch_count = 0usize;

    for row in &rows {
        // Filter by subscription.
        if !sub_events.iter().any(|e| e == &row.event_type) {
            continue;
        }

        // Same read check as the live path: a replay must not hand back
        // what the live stream would have withheld.
        if let Some(ref ch_id) = row.channel_id {
            let allowed = crate::permissions::channel_permissions(&state.db, app_pubkey, ch_id)
                .await
                .map(|perms| perms.has(crate::permissions::MESSAGES_READ))
                .unwrap_or(false);

            if !allowed {
                continue;
            }
        }

        let envelope_payload: serde_json::Value =
            serde_json::from_str(&row.payload_json).unwrap_or(serde_json::Value::Null);

        let envelope = serde_json::json!({
            "type": "hub_event",
            "seq": row.seq,
            "event": row.event_type,
            "hub_url": hub_url,
            "at": row.at,
            "actor_pubkey": row.actor_pubkey,
            "target_pubkey": row.target_pubkey,
            "channel_id": row.channel_id,
            "payload": envelope_payload,
            "replayed": true,
        });

        if tx.send(envelope.to_string()).await.is_err() {
            // App disconnected mid-replay.
            break;
        }

        replayed += 1;
        batch_count += 1;

        // Yield every `batch_size` messages so we don't starve the tokio
        // runtime on a large replay.
        if batch_count >= batch_size {
            batch_count = 0;
            tokio::task::yield_now().await;
        }
    }

    ReplayResult::Complete { replayed }
}

pub enum ReplayResult {
    Complete { replayed: usize },
    Unavailable { earliest_seq: i64, earliest_at: i64 },
}

/// Return the current live seq (from hub_audit_seq).
pub async fn current_seq(state: &AppState) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT seq FROM hub_audit_seq WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
}

/// Atomically increment the sequence counter and return the new value.
async fn next_seq(state: &AppState) -> Result<i64, sqlx::Error> {
    sqlx::query("UPDATE hub_audit_seq SET seq = seq + 1 WHERE id = 1")
        .execute(&state.db)
        .await?;
    sqlx::query_scalar::<_, i64>("SELECT seq FROM hub_audit_seq WHERE id = 1")
        .fetch_one(&state.db)
        .await
}

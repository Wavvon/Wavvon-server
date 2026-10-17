//! Group membership changes that other hubs can trust (Wavvon-server#119).
//!
//! A remote hub's roster for a group is the member list it saw on first
//! delivery. Adds and leaves used to stay on the hub they happened on, so a
//! remote roster went stale, and a remote hub that trusted the list each DM
//! carried instead let anyone who knew a conversation id write into it. A
//! change now travels as something the actor signed, and a remote hub applies
//! it only from someone its own roster already holds.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use wavvon_identity::SubkeyCert;

use crate::auth::middleware::{AuthUser, PeerHub};
use crate::state::{AppState, DmEvent};

use super::keys::{bind_cert_master, verify_tiered_signature};
use super::messages::{delivery_urls, resolve_master_binding};
use super::models::{ensure_user_stub, load_members};

/// How far ahead of this hub's clock a change may be dated. The ledger keeps
/// the newest change per member, so a change from the far future would freeze
/// that member's membership against every later one.
const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// The actor's signature over a change, as a client sends it with an add or a
/// leave.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedMemberChange {
    pub issued_at: u64,
    pub signature: String,
    #[serde(default)]
    pub signer_cert: Option<SubkeyCert>,
}

/// A change as it travels between hubs: self-contained, so the receiver needs
/// nothing from the sender but its peer session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedMemberChange {
    pub conversation_id: String,
    pub actor: String,
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
    pub issued_at: u64,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_cert: Option<SubkeyCert>,
}

impl FederatedMemberChange {
    fn signing_bytes(&self) -> Vec<u8> {
        wavvon_identity::dm_member_change_signing_bytes(
            &self.conversation_id,
            &self.actor,
            &self.added,
            &self.removed,
            self.issued_at,
        )
    }
}

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
}

fn too_far_ahead(issued_at: u64) -> bool {
    issued_at as i64 > crate::auth::handlers::unix_timestamp() + MAX_CLOCK_SKEW_SECS
}

/// Verify a change a local member signed, before it is applied here.
pub(super) fn verify_local(
    user: &AuthUser,
    change: &FederatedMemberChange,
) -> Result<(), (StatusCode, String)> {
    if too_far_ahead(change.issued_at) {
        return Err((
            StatusCode::BAD_REQUEST,
            "member change issued_at is in the future".to_string(),
        ));
    }
    let cert_master = verify_tiered_signature(
        &change.signing_bytes(),
        &change.signature,
        change.signer_cert.as_ref(),
        &user.public_key,
        "member change",
    )?;
    bind_cert_master(cert_master, user)
}

/// Record that `member`'s membership was settled at `issued_at`. Returns false
/// when a change at least as new is already recorded, which the caller reads
/// as "leave the roster alone".
async fn advance_ledger(
    state: &AppState,
    conversation_id: &str,
    member: &str,
    issued_at: i64,
) -> Result<bool, (StatusCode, String)> {
    let advanced = sqlx::query(
        "INSERT INTO conversation_member_changes (conversation_id, public_key, issued_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (conversation_id, public_key) DO UPDATE SET issued_at = excluded.issued_at
         WHERE conversation_member_changes.issued_at < excluded.issued_at",
    )
    .bind(conversation_id)
    .bind(member)
    .bind(issued_at)
    .execute(&state.db)
    .await
    .map_err(db_err)?
    .rows_affected();
    Ok(advanced == 1)
}

/// Mark a local change in the ledger, signed or not, so a replayed older one
/// arriving from elsewhere cannot undo it.
pub(super) async fn record_local(
    state: &AppState,
    conversation_id: &str,
    members: &[String],
    issued_at: i64,
) -> Result<(), (StatusCode, String)> {
    for m in members {
        advance_ledger(state, conversation_id, m, issued_at).await?;
    }
    Ok(())
}

/// Queue a signed change for the hub of every member but the actor, as the
/// roster stands once the change is applied here.
pub(super) async fn fan_out(
    state: &AppState,
    change: &FederatedMemberChange,
) -> Result<(), (StatusCode, String)> {
    let mut urls = std::collections::BTreeSet::new();
    for m in load_members(state, &change.conversation_id).await? {
        if m.public_key != change.actor {
            urls.extend(delivery_urls(state, &m).await?);
        }
    }
    let payload = serde_json::to_string(change)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?;
    let now = crate::auth::handlers::unix_timestamp();
    for url in urls {
        sqlx::query(
            "INSERT INTO dm_member_change_outbox (recipient_hub_url, payload, next_attempt_at)
             VALUES ($1, $2, $3)",
        )
        .bind(&url)
        .bind(&payload)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
    }
    Ok(())
}

/// POST /federation/dm-member-change
pub async fn receive_member_change(
    State(state): State<Arc<AppState>>,
    _peer: PeerHub,
    Json(change): Json<FederatedMemberChange>,
) -> Result<StatusCode, (StatusCode, String)> {
    let conv_type: Option<String> =
        sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = $1")
            .bind(&change.conversation_id)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    // A hub that has never seen the conversation has no roster to correct: its
    // first DM there arrives carrying the members as they are by then.
    let Some(conv_type) = conv_type else {
        return Ok(StatusCode::OK);
    };
    if conv_type != "group" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only a group has members to change".to_string(),
        ));
    }
    if change.added.is_empty() && change.removed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty member change".to_string()));
    }
    // Leaving is the only removal there is: nobody removes anybody else.
    if change.removed.iter().any(|m| m != &change.actor) {
        return Err((
            StatusCode::FORBIDDEN,
            "A member can only remove themselves".to_string(),
        ));
    }
    if too_far_ahead(change.issued_at) {
        return Err((
            StatusCode::BAD_REQUEST,
            "member change issued_at is in the future".to_string(),
        ));
    }

    let cert_master = verify_tiered_signature(
        &change.signing_bytes(),
        &change.signature,
        change.signer_cert.as_ref(),
        &change.actor,
        "member change",
    )
    .map_err(|(_, msg)| (StatusCode::UNAUTHORIZED, msg))?;
    if let Some(master) = cert_master {
        let bound = master == change.actor
            || resolve_master_binding(&state, &change.actor, &master, None).await?;
        if !bound {
            return Err((
                StatusCode::UNAUTHORIZED,
                "signer_cert master is not bound to the actor".to_string(),
            ));
        }
    }

    let in_roster: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND public_key = $2)",
    )
    .bind(&change.conversation_id)
    .bind(&change.actor)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    if !in_roster {
        return Err((
            StatusCode::FORBIDDEN,
            "The actor is not a member of this conversation".to_string(),
        ));
    }

    let issued_at = change.issued_at as i64;
    let mut added = Vec::new();
    for m in &change.added {
        if !advance_ledger(&state, &change.conversation_id, m, issued_at).await? {
            continue;
        }
        ensure_user_stub(&state.db, m, issued_at).await?;
        sqlx::query(
            "INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url)
             VALUES ($1, $2, $3, NULL)
             ON CONFLICT (conversation_id, public_key) DO NOTHING",
        )
        .bind(&change.conversation_id)
        .bind(m)
        .bind(issued_at)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
        added.push(m.clone());
    }
    let mut removed = Vec::new();
    for m in &change.removed {
        if !advance_ledger(&state, &change.conversation_id, m, issued_at).await? {
            continue;
        }
        sqlx::query(
            "DELETE FROM conversation_members WHERE conversation_id = $1 AND public_key = $2",
        )
        .bind(&change.conversation_id)
        .bind(m)
        .execute(&state.db)
        .await
        .map_err(db_err)?;
        removed.push(m.clone());
    }

    if !added.is_empty() || !removed.is_empty() {
        let _ = state.dm_tx.send(DmEvent::MemberChanged {
            conversation_id: change.conversation_id,
            actor: change.actor,
            added,
            removed,
        });
    }
    Ok(StatusCode::OK)
}

/// Deliver one queued change. An `Err` leaves it in the outbox for a retry.
pub async fn deliver_member_change(
    state: &AppState,
    hub_url: &str,
    payload: &str,
) -> Result<(), String> {
    let token = crate::federation::peer_token(state, hub_url)
        .await
        .ok_or_else(|| "authenticate: failed".to_string())?;
    let resp = state
        .federation_client
        .post_member_change(hub_url, &token, payload)
        .await
        .map_err(|e| format!("deliver: {e}"))?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        crate::federation::forget_peer_token(state, hub_url).await;
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("remote hub returned {status}: {body}"));
    }
    Ok(())
}

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wavvon_identity::{recovery_attestation_signing_bytes, recovery_request_signing_bytes};

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response models
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetContactsRequest {
    /// Ordered list of contact pubkeys. Replaces the existing list entirely.
    pub contacts: Vec<String>,
    /// How many attestations are required before the request reaches admins.
    pub threshold: u32,
}

#[derive(Serialize)]
pub struct ContactEntry {
    pub pubkey: String,
    pub added_at: i64,
}

#[derive(Serialize)]
pub struct ContactsResponse {
    pub owner_pubkey: String,
    pub contacts: Vec<ContactEntry>,
    pub threshold: u32,
}

#[derive(Deserialize)]
pub struct RotateKeyRequest {
    pub old_pubkey: String,
    pub new_pubkey: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Ed25519 signature by `new_pubkey` over
    /// `recovery_request_signing_bytes(hub_pubkey, old_pubkey, new_pubkey)`
    /// (hex). Proves the requester holds the key they're rotating to
    /// (recovery-attestation.md §4 "New-key proof: required").
    pub new_key_signature: String,
    /// No longer accepted — attestations are gathered one at a time via
    /// `POST /recovery/rotation-request/:id/attest` after this request is
    /// open. Present only so a legacy/misbehaving client gets a clear
    /// rejection instead of having its attestations silently dropped.
    #[serde(default)]
    pub attestations: Vec<AttestationInput>,
}

#[derive(Deserialize)]
pub struct AttestationInput {
    #[allow(dead_code)]
    pub attester: String,
    #[allow(dead_code)]
    pub signature: String,
}

#[derive(Deserialize)]
pub struct AttestRequest {
    pub attester: String,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RotationRequestResponse {
    pub id: String,
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub status: String,
    pub created_at: i64,
    pub attestation_count: i64,
    pub nonce: String,
}

#[derive(Serialize)]
pub struct RotationRequestBundle {
    pub id: String,
    pub hub_pubkey: String,
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub nonce: String,
    pub status: String,
    pub attestation_count: i64,
    pub threshold: i64,
}

#[derive(Serialize)]
pub struct PendingRequestAdmin {
    pub id: String,
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub reason: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub attestation_count: i64,
}

#[derive(Deserialize)]
pub struct AdminDecideRequest {
    /// "approve" or "deny"
    pub decision: String,
}

// ---------------------------------------------------------------------------
// Owner-side: manage recovery contacts
// ---------------------------------------------------------------------------

/// PUT /recovery/contacts — replace the contact list + threshold for this hub.
pub async fn put_contacts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SetContactsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if req.contacts.len() > 5 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Maximum 5 recovery contacts".to_string(),
        ));
    }
    if req.threshold == 0 || req.threshold as usize > req.contacts.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "threshold must be between 1 and the number of contacts".to_string(),
        ));
    }
    // Contacts must be distinct from the owner.
    if req.contacts.iter().any(|c| c == &user.public_key) {
        return Err((
            StatusCode::BAD_REQUEST,
            "You cannot be your own recovery contact".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    // Upsert the settings row.
    sqlx::query(
        "INSERT INTO recovery_settings (owner_pubkey, threshold, created_at)
         VALUES ($1, $2, $3)
         ON CONFLICT(owner_pubkey) DO UPDATE SET threshold = excluded.threshold",
    )
    .bind(&user.public_key)
    .bind(req.threshold as i64)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Replace the contact list atomically: delete old, insert new.
    sqlx::query("DELETE FROM recovery_contacts WHERE owner_pubkey = $1")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for contact in &req.contacts {
        sqlx::query(
            "INSERT INTO recovery_contacts (owner_pubkey, contact_pubkey, created_at)
             VALUES ($1, $2, $3) ON CONFLICT (owner_pubkey, contact_pubkey) DO NOTHING",
        )
        .bind(&user.public_key)
        .bind(contact)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

/// GET /recovery/contacts — read back the caller's current contact list.
pub async fn get_contacts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<ContactsResponse>, (StatusCode, String)> {
    let threshold: Option<i64> =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    #[derive(sqlx::FromRow)]
    struct ContactRow {
        contact_pubkey: String,
        created_at: i64,
    }

    let contact_rows = sqlx::query_as::<_, ContactRow>(
        "SELECT contact_pubkey, created_at FROM recovery_contacts WHERE owner_pubkey = $1 ORDER BY created_at",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let contacts = contact_rows
        .into_iter()
        .map(|r| ContactEntry {
            pubkey: r.contact_pubkey,
            added_at: r.created_at,
        })
        .collect();

    Ok(Json(ContactsResponse {
        owner_pubkey: user.public_key,
        contacts,
        threshold: threshold.unwrap_or(0) as u32,
    }))
}

/// DELETE /recovery/contacts/:pubkey — remove one contact.
pub async fn delete_contact(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM recovery_contacts WHERE owner_pubkey = $1 AND contact_pubkey = $2")
        .bind(&user.public_key)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Key rotation request
// ---------------------------------------------------------------------------

/// POST /recovery/rotate-key — the new key opens a rotation request.
///
/// Requires `new_key_signature`: proof the requester holds `new_pubkey`
/// (recovery-attestation.md §4). Attestations are no longer gathered inline
/// — the request opens `pending` with zero attestations; contacts vouch one
/// at a time via `POST /recovery/rotation-request/:id/attest`.
pub async fn post_rotate_key(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<(StatusCode, Json<RotationRequestResponse>), (StatusCode, String)> {
    if !req.attestations.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Inline attestations are no longer accepted; open the request with zero \
             attestations, then have each contact call POST \
             /recovery/rotation-request/:id/attest"
                .to_string(),
        ));
    }

    // Validate that old_pubkey has contacts configured on this hub.
    let threshold: Option<i64> =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = $1")
            .bind(&req.old_pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    threshold.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "The old pubkey has no recovery contacts configured on this hub".to_string(),
        )
    })?;

    // new_pubkey must be distinct from old_pubkey.
    if req.new_pubkey == req.old_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "new_pubkey must differ from old_pubkey".to_string(),
        ));
    }

    // New-key proof: new_pubkey must sign the request bundle, proving the
    // requester holds that key.
    let hub_pubkey = state.hub_identity.public_key_hex();
    let proof_bytes = recovery_request_signing_bytes(&hub_pubkey, &req.old_pubkey, &req.new_pubkey);
    let proof_sig = hex::decode(&req.new_key_signature).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid new_key_signature hex".to_string(),
        )
    })?;
    wavvon_identity::verify_signature(&req.new_pubkey, &proof_bytes, &proof_sig).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "new_key_signature does not verify against new_pubkey".to_string(),
        )
    })?;

    let request_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO key_rotation_requests
            (id, old_pubkey, new_pubkey, reason, status, created_at, nonce)
         VALUES ($1, $2, $3, $4, 'pending', $5, $6)",
    )
    .bind(&request_id)
    .bind(&req.old_pubkey)
    .bind(&req.new_pubkey)
    .bind(&req.reason)
    .bind(now)
    .bind(&nonce)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(RotationRequestResponse {
            id: request_id,
            old_pubkey: req.old_pubkey,
            new_pubkey: req.new_pubkey,
            status: "pending".to_string(),
            created_at: now,
            attestation_count: 0,
            nonce,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Contact-side: fetch a request bundle to sign, then attest
// ---------------------------------------------------------------------------

/// GET /recovery/rotation-request/:id — the bundle a recovery contact needs
/// to sign, plus progress. No session required: a contact learns the
/// request id out-of-band (recovery-attestation.md §2) and may not hold an
/// account on this hub at all.
pub async fn get_rotation_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<RotationRequestBundle>, (StatusCode, String)> {
    let row = fetch_rotation_request(&state, &id).await?;

    let threshold: i64 =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = $1")
            .bind(&row.old_pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .unwrap_or(0);

    Ok(Json(RotationRequestBundle {
        id: row.id,
        hub_pubkey: state.hub_identity.public_key_hex(),
        old_pubkey: row.old_pubkey,
        new_pubkey: row.new_pubkey,
        nonce: row.nonce.unwrap_or_default(),
        status: row.status,
        attestation_count: row.attestation_count,
        threshold,
    }))
}

/// POST /recovery/rotation-request/:id/attest — a recovery contact vouches
/// for an open rotation request.
///
/// Verifies the Ed25519 signature over the canonical bundle bytes, confirms
/// the attester is a designated contact for `old_pubkey` and isn't the old
/// or new key itself, upserts (deduped per contact), and flips
/// `pending -> ready_for_review` once the count reaches threshold.
pub async fn post_attest(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AttestRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = fetch_rotation_request(&state, &id).await?;

    if row.status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Request is '{}', no longer accepting attestations",
                row.status
            ),
        ));
    }

    if req.attester == row.old_pubkey || req.attester == row.new_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            "attester must not be the old or new key".to_string(),
        ));
    }

    let is_contact: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM recovery_contacts WHERE owner_pubkey = $1 AND contact_pubkey = $2",
    )
    .bind(&row.old_pubkey)
    .bind(&req.attester)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        > 0;

    if !is_contact {
        return Err((
            StatusCode::FORBIDDEN,
            "attester is not a designated recovery contact for this owner".to_string(),
        ));
    }

    let nonce = row.nonce.clone().unwrap_or_default();
    let bundle = recovery_attestation_signing_bytes(
        &state.hub_identity.public_key_hex(),
        &row.old_pubkey,
        &row.new_pubkey,
        &nonce,
    );
    let sig = hex::decode(&req.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    wavvon_identity::verify_signature(&req.attester, &bundle, &sig).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "signature does not verify against attester's bundle".to_string(),
        )
    })?;

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO rotation_attestations
            (id, request_id, attester_pubkey, signature, attested_at)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (request_id, attester_pubkey) DO NOTHING",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&id)
    .bind(&req.attester)
    .bind(&req.signature)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let threshold: i64 =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = $1")
            .bind(&row.old_pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .unwrap_or(0);

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM rotation_attestations WHERE request_id = $1")
            .bind(&id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if count >= threshold {
        sqlx::query(
            "UPDATE key_rotation_requests SET status = 'ready_for_review' WHERE id = $1 AND status = 'pending'",
        )
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Owner-side: list own rotation requests
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct MyRotationRequest {
    pub id: String,
    pub new_pubkey: String,
    pub status: String,
    pub created_at: i64,
    pub attestation_count: i64,
    pub threshold: i64,
}

/// GET /recovery/requests — list the authenticated user's own rotation requests.
pub async fn get_my_requests(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<MyRotationRequest>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, RotationRow>(
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at, r.nonce,
                COUNT(a.id) AS attestation_count
         FROM key_rotation_requests r
         LEFT JOIN rotation_attestations a ON a.request_id = r.id
         WHERE r.old_pubkey = $1
         GROUP BY r.id
         ORDER BY r.created_at DESC",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let threshold: i64 =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .unwrap_or(0);

    let out = rows
        .into_iter()
        .map(|r| MyRotationRequest {
            id: r.id,
            new_pubkey: r.new_pubkey,
            status: r.status,
            created_at: r.created_at,
            attestation_count: r.attestation_count,
            threshold,
        })
        .collect();

    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// Admin: review pending rotation requests
// ---------------------------------------------------------------------------

/// GET /admin/recovery/pending — list rotation requests waiting for admin action.
pub async fn admin_list_pending(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<PendingRequestAdmin>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let rows = sqlx::query_as::<_, RotationRow>(
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at, r.nonce,
                COUNT(a.id) AS attestation_count
         FROM key_rotation_requests r
         LEFT JOIN rotation_attestations a ON a.request_id = r.id
         WHERE r.status = 'ready_for_review' OR r.status = 'pending'
         GROUP BY r.id
         ORDER BY r.created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out = rows
        .into_iter()
        .map(|r| PendingRequestAdmin {
            id: r.id,
            old_pubkey: r.old_pubkey,
            new_pubkey: r.new_pubkey,
            reason: r.reason,
            status: r.status,
            created_at: r.created_at,
            attestation_count: r.attestation_count,
        })
        .collect();

    Ok(Json(out))
}

/// POST /admin/recovery/:id/approve — admin approves a rotation request.
///
/// Updates users.public_key-based rows to replace old_pubkey with new_pubkey.
/// The old row's sessions are deleted; the user must re-authenticate with the new key.
pub async fn admin_approve(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let row = fetch_rotation_request(&state, &id).await?;
    if row.status != "ready_for_review" && row.status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            "Request is not in an approvable state".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    // Insert new user row if it doesn't exist yet (new key may not have authed before).
    sqlx::query(
        "INSERT INTO users (public_key, display_name, first_seen_at, last_seen_at)
         VALUES ($1, NULL, $2, $3) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(&row.new_pubkey)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Transfer NON-OWNER roles from old key to new key. The owner role never
    // rides along a recovery transfer (identity-recovery.md: owner needs the
    // separate successor path) — otherwise K colluding contacts plus a fooled
    // admin could mint a second owner.
    sqlx::query(
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
         SELECT $1, role_id, $2
         FROM user_roles
         WHERE user_public_key = $3 AND role_id != 'builtin-owner'
         ON CONFLICT (user_public_key, role_id) DO NOTHING",
    )
    .bind(&row.new_pubkey)
    .bind(now)
    .bind(&row.old_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // A transfer, not a copy: the lost/compromised old key keeps nothing but
    // owner (which only the successor path moves).
    sqlx::query(
        "DELETE FROM user_roles
         WHERE user_public_key = $1 AND role_id != 'builtin-owner'",
    )
    .bind(&row.old_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Revoke all sessions for the old key.
    sqlx::query("DELETE FROM sessions WHERE public_key = $1")
        .bind(&row.old_pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Mark request as approved.
    sqlx::query(
        "UPDATE key_rotation_requests
         SET status = 'approved', decided_at = $1, decided_by = $2
         WHERE id = $3",
    )
    .bind(now)
    .bind(&user.public_key)
    .bind(&id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

/// POST /admin/recovery/:id/deny — admin denies a rotation request.
pub async fn admin_deny(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    let row = fetch_rotation_request(&state, &id).await?;
    if row.status != "ready_for_review" && row.status != "pending" {
        return Err((
            StatusCode::CONFLICT,
            "Request is not in a deniable state".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "UPDATE key_rotation_requests
         SET status = 'rejected', decided_at = $1, decided_by = $2
         WHERE id = $3",
    )
    .bind(now)
    .bind(&user.public_key)
    .bind(&id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fetch_rotation_request(
    state: &AppState,
    id: &str,
) -> Result<RotationRow, (StatusCode, String)> {
    sqlx::query_as::<_, RotationRow>(
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at, r.nonce,
                COUNT(a.id) AS attestation_count
         FROM key_rotation_requests r
         LEFT JOIN rotation_attestations a ON a.request_id = r.id
         WHERE r.id = $1
         GROUP BY r.id",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Rotation request not found".to_string(),
        )
    })
}

#[derive(sqlx::FromRow)]
struct RotationRow {
    id: String,
    old_pubkey: String,
    new_pubkey: String,
    reason: Option<String>,
    nonce: Option<String>,
    status: String,
    created_at: i64,
    attestation_count: i64,
}

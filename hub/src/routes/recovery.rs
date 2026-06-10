use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    pub attestations: Vec<AttestationInput>,
}

#[derive(Deserialize)]
pub struct AttestationInput {
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
         VALUES (?, ?, ?)
         ON CONFLICT(owner_pubkey) DO UPDATE SET threshold = excluded.threshold",
    )
    .bind(&user.public_key)
    .bind(req.threshold as i64)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Replace the contact list atomically: delete old, insert new.
    sqlx::query("DELETE FROM recovery_contacts WHERE owner_pubkey = ?")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for contact in &req.contacts {
        sqlx::query(
            "INSERT INTO recovery_contacts (owner_pubkey, contact_pubkey, created_at)
             VALUES (?, ?, ?) ON CONFLICT (owner_pubkey, contact_pubkey) DO NOTHING",
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
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = ?")
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
        "SELECT contact_pubkey, created_at FROM recovery_contacts WHERE owner_pubkey = ? ORDER BY created_at",
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
    sqlx::query("DELETE FROM recovery_contacts WHERE owner_pubkey = ? AND contact_pubkey = ?")
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

/// POST /recovery/rotate-key — new key opens a rotation request with
/// pre-gathered attestations included inline.
///
/// The request is accepted immediately if at least one attestation is valid.
/// Status 'pending' means fewer attestations than threshold; once attestation
/// count >= threshold the row flips to 'ready_for_review'.
pub async fn post_rotate_key(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<(StatusCode, Json<RotationRequestResponse>), (StatusCode, String)> {
    // Validate that old_pubkey has contacts configured on this hub.
    let threshold: Option<i64> =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = ?")
            .bind(&req.old_pubkey)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let threshold = threshold.ok_or_else(|| {
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

    let request_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    // Insert the request row.
    sqlx::query(
        "INSERT INTO key_rotation_requests
            (id, old_pubkey, new_pubkey, reason, status, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?)",
    )
    .bind(&request_id)
    .bind(&req.old_pubkey)
    .bind(&req.new_pubkey)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Store valid attestations.
    let mut valid_count: i64 = 0;
    for att in &req.attestations {
        // Self-attestation guard: attester must not be old or new key.
        if att.attester == req.old_pubkey || att.attester == req.new_pubkey {
            continue;
        }
        // Attester must be in the contact set for old_pubkey.
        let is_contact: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM recovery_contacts
             WHERE owner_pubkey = ? AND contact_pubkey = ?",
        )
        .bind(&req.old_pubkey)
        .bind(&att.attester)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            > 0;

        if !is_contact {
            continue;
        }

        sqlx::query(
            "INSERT INTO rotation_attestations
                (id, request_id, attester_pubkey, signature, attested_at)
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (request_id, attester_pubkey) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&request_id)
        .bind(&att.attester)
        .bind(&att.signature)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        valid_count += 1;
    }

    // Flip to ready_for_review if threshold reached.
    let status = if valid_count >= threshold {
        sqlx::query("UPDATE key_rotation_requests SET status = 'ready_for_review' WHERE id = ?")
            .bind(&request_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        "ready_for_review".to_string()
    } else {
        "pending".to_string()
    };

    Ok((
        StatusCode::CREATED,
        Json(RotationRequestResponse {
            id: request_id,
            old_pubkey: req.old_pubkey,
            new_pubkey: req.new_pubkey,
            status,
            created_at: now,
            attestation_count: valid_count,
        }),
    ))
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
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at,
                COUNT(a.id) AS attestation_count
         FROM key_rotation_requests r
         LEFT JOIN rotation_attestations a ON a.request_id = r.id
         WHERE r.old_pubkey = ?
         GROUP BY r.id
         ORDER BY r.created_at DESC",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let threshold: i64 =
        sqlx::query_scalar("SELECT threshold FROM recovery_settings WHERE owner_pubkey = ?")
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
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at,
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
         VALUES (?, NULL, ?, ?) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(&row.new_pubkey)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Transfer roles from old key to new key.
    sqlx::query(
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
         SELECT ?, role_id, ?
         FROM user_roles WHERE user_public_key = ?
         ON CONFLICT (user_public_key, role_id) DO NOTHING",
    )
    .bind(&row.new_pubkey)
    .bind(now)
    .bind(&row.old_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Revoke all sessions for the old key.
    sqlx::query("DELETE FROM sessions WHERE public_key = ?")
        .bind(&row.old_pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Mark request as approved.
    sqlx::query(
        "UPDATE key_rotation_requests
         SET status = 'approved', decided_at = ?, decided_by = ?
         WHERE id = ?",
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
         SET status = 'rejected', decided_at = ?, decided_by = ?
         WHERE id = ?",
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
        "SELECT r.id, r.old_pubkey, r.new_pubkey, r.reason, r.status, r.created_at,
                COUNT(a.id) AS attestation_count
         FROM key_rotation_requests r
         LEFT JOIN rotation_attestations a ON a.request_id = r.id
         WHERE r.id = ?
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
    status: String,
    created_at: i64,
    attestation_count: i64,
}

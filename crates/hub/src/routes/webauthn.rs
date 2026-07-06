use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::auth::middleware::AuthUser;
use crate::state::{AppState, AuthChallenge, RegChallenge};

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn gen_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn pubkey_to_uuid(pubkey: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, pubkey.as_bytes())
}

fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::new_with_prefix(input).finalize();
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegBeginRequest {
    pub user_pubkey: String,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegBeginResponse {
    pub session_id: String,
    pub options: serde_json::Value,
}

/// POST /auth/webauthn/begin — start passkey registration.
pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegBeginRequest>,
) -> Result<Json<RegBeginResponse>, (StatusCode, String)> {
    let display = body
        .display_name
        .unwrap_or_else(|| body.user_pubkey[..8.min(body.user_pubkey.len())].to_string());

    // Exclude credentials the user already has so re-registration on the same
    // authenticator is blocked (prevents duplicate rows).
    let existing: Vec<String> =
        sqlx::query_scalar("SELECT credential_id FROM webauthn_credentials WHERE user_pubkey = $1")
            .bind(&body.user_pubkey)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let exclude: Option<Vec<webauthn_rs::prelude::CredentialID>> = if existing.is_empty() {
        None
    } else {
        let ids = existing
            .iter()
            .filter_map(|id| hex::decode(id).ok())
            .map(webauthn_rs::prelude::CredentialID::from)
            .collect::<Vec<_>>();
        if ids.is_empty() {
            None
        } else {
            Some(ids)
        }
    };

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(
            pubkey_to_uuid(&body.user_pubkey),
            &body.user_pubkey,
            &display,
            exclude,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WebAuthn error: {e}"),
            )
        })?;

    let session_id = gen_token();
    state.webauthn_reg_challenges.write().await.insert(
        session_id.clone(),
        RegChallenge {
            user_pubkey: body.user_pubkey,
            state: reg_state,
        },
    );

    let options = serde_json::to_value(&ccr)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RegBeginResponse {
        session_id,
        options,
    }))
}

#[derive(Deserialize)]
pub struct RegFinishRequest {
    pub session_id: String,
    pub credential: RegisterPublicKeyCredential,
    pub friendly_name: Option<String>,
}

#[derive(Serialize)]
pub struct SessionTokenResponse {
    pub session_token: String,
}

/// POST /auth/webauthn/finish — complete passkey registration; issue session token.
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegFinishRequest>,
) -> Result<Json<SessionTokenResponse>, (StatusCode, String)> {
    let challenge = state
        .webauthn_reg_challenges
        .write()
        .await
        .remove(&body.session_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Unknown or expired session".to_string(),
        ))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&body.credential, &challenge.state)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Registration failed: {e}")))?;

    let credential_id = hex::encode(passkey.cred_id().as_ref());
    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = now_secs();
    sqlx::query(
        "INSERT INTO webauthn_credentials
             (credential_id, user_pubkey, passkey_json, friendly_name, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (credential_id) DO NOTHING",
    )
    .bind(&credential_id)
    .bind(&challenge.user_pubkey)
    .bind(&passkey_json)
    .bind(&body.friendly_name)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let session_token = issue_session_token(&state, &challenge.user_pubkey).await?;
    Ok(Json(SessionTokenResponse { session_token }))
}

// ---------------------------------------------------------------------------
// Assertion (login)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AssertBeginRequest {
    pub user_pubkey: String,
}

#[derive(Serialize)]
pub struct AssertBeginResponse {
    pub session_id: String,
    pub options: serde_json::Value,
}

/// POST /auth/webauthn/assert/begin — start passkey authentication.
pub async fn assert_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AssertBeginRequest>,
) -> Result<Json<AssertBeginResponse>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT passkey_json FROM webauthn_credentials WHERE user_pubkey = $1",
    )
    .bind(&body.user_pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if rows.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            "No passkeys for this user".to_string(),
        ));
    }

    let passkeys: Vec<webauthn_rs::prelude::Passkey> = rows
        .iter()
        .filter_map(|(j,)| serde_json::from_str(j).ok())
        .collect();

    if passkeys.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to deserialise stored passkeys".to_string(),
        ));
    }

    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WebAuthn error: {e}"),
            )
        })?;

    let session_id = gen_token();
    state.webauthn_auth_challenges.write().await.insert(
        session_id.clone(),
        AuthChallenge {
            user_pubkey: body.user_pubkey,
            state: auth_state,
            passkeys,
        },
    );

    let options = serde_json::to_value(&rcr)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AssertBeginResponse {
        session_id,
        options,
    }))
}

#[derive(Deserialize)]
pub struct AssertFinishRequest {
    pub session_id: String,
    pub credential: PublicKeyCredential,
}

/// POST /auth/webauthn/assert/finish — complete assertion; issue session token.
pub async fn assert_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AssertFinishRequest>,
) -> Result<Json<SessionTokenResponse>, (StatusCode, String)> {
    let mut challenge = state
        .webauthn_auth_challenges
        .write()
        .await
        .remove(&body.session_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Unknown or expired session".to_string(),
        ))?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&body.credential, &challenge.state)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("Authentication failed: {e}"),
            )
        })?;

    // Update sign_count for the credential that was used.
    let now = now_secs();
    for sk in &mut challenge.passkeys {
        if sk.cred_id() == auth_result.cred_id() {
            sk.update_credential(&auth_result);
            let updated_json = serde_json::to_string(sk).unwrap_or_default();
            let cred_id = hex::encode(sk.cred_id().as_ref());
            let _ = sqlx::query(
                "UPDATE webauthn_credentials \
                 SET passkey_json = $1, last_used_at = $2 \
                 WHERE credential_id = $3",
            )
            .bind(&updated_json)
            .bind(now)
            .bind(&cred_id)
            .execute(&state.db)
            .await;
            break;
        }
    }

    let session_token = issue_session_token(&state, &challenge.user_pubkey).await?;
    Ok(Json(SessionTokenResponse { session_token }))
}

// ---------------------------------------------------------------------------
// Device tokens
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeviceTokenCreateRequest {
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceTokenCreateResponse {
    pub id: String,
    pub token: String,
    pub expires_at: i64,
}

/// POST /auth/device-token/create — mint a long-lived device token (authenticated).
pub async fn device_token_create(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<DeviceTokenCreateRequest>,
) -> Result<Json<DeviceTokenCreateResponse>, (StatusCode, String)> {
    let id = Uuid::new_v4().to_string();
    let raw_token = gen_token();
    let token_hash = sha256_hex(&raw_token);
    let now = now_secs();
    let expires_at = now + state.device_token_ttl_secs;

    sqlx::query(
        "INSERT INTO device_tokens (id, token_hash, user_pubkey, device_name, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&token_hash)
    .bind(&user.public_key)
    .bind(&body.device_name)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(DeviceTokenCreateResponse {
        id,
        token: raw_token,
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct DeviceTokenRedeemRequest {
    pub token: String,
}

/// POST /auth/device-token/redeem — exchange device token for session token.
/// Rotates the device token on each use so the original token is invalidated.
pub async fn device_token_redeem(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeviceTokenRedeemRequest>,
) -> Result<Json<SessionTokenResponse>, (StatusCode, String)> {
    let token_hash = sha256_hex(&body.token);
    let now = now_secs();

    let row = sqlx::query_as::<_, (String, String, i64, bool)>(
        "SELECT id, user_pubkey, expires_at, revoked FROM device_tokens WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid device token".to_string()))?;

    let (id, user_pubkey, expires_at, revoked) = row;
    if revoked || now > expires_at {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Device token expired or revoked".to_string(),
        ));
    }

    // Rotate: issue new token, invalidate old.
    let new_raw = gen_token();
    let new_hash = sha256_hex(&new_raw);
    let new_expires = now + state.device_token_ttl_secs;

    sqlx::query(
        "UPDATE device_tokens \
         SET token_hash = $1, expires_at = $2, last_used_at = $3 \
         WHERE id = $4",
    )
    .bind(&new_hash)
    .bind(new_expires)
    .bind(now)
    .bind(&id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let session_token = issue_session_token(&state, &user_pubkey).await?;
    Ok(Json(SessionTokenResponse { session_token }))
}

// ---------------------------------------------------------------------------
// Credential management (/me/credentials)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct CredentialInfo {
    pub id: String,
    pub friendly_name: Option<String>,
    pub aaguid: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// GET /me/credentials — list this user's passkeys.
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<CredentialInfo>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, i64, Option<i64>)>(
        "SELECT credential_id, friendly_name, aaguid, created_at, last_used_at
         FROM webauthn_credentials
         WHERE user_pubkey = $1
         ORDER BY created_at",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out = rows
        .into_iter()
        .map(
            |(id, friendly_name, aaguid, created_at, last_used_at)| CredentialInfo {
                id,
                friendly_name,
                aaguid,
                created_at,
                last_used_at,
            },
        )
        .collect();

    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct RenameCredentialRequest {
    pub friendly_name: String,
}

/// PATCH /me/credentials/:id — rename a passkey.
pub async fn rename_credential(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<RenameCredentialRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let affected = sqlx::query(
        "UPDATE webauthn_credentials
         SET friendly_name = $1
         WHERE credential_id = $2 AND user_pubkey = $3",
    )
    .bind(&body.friendly_name)
    .bind(&id)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .rows_affected();

    if affected == 0 {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    } else {
        Ok(StatusCode::OK)
    }
}

/// DELETE /me/credentials/:id — remove a passkey.
pub async fn delete_credential(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM webauthn_credentials WHERE credential_id = $1 AND user_pubkey = $2")
        .bind(&id)
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Device management (/me/devices)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub device_name: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
}

/// GET /me/devices — list trusted devices.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<DeviceInfo>>, (StatusCode, String)> {
    let now = now_secs();
    let rows = sqlx::query_as::<_, (String, Option<String>, i64, i64, Option<i64>)>(
        "SELECT id, device_name, created_at, expires_at, last_used_at
         FROM device_tokens
         WHERE user_pubkey = $1 AND revoked = FALSE AND expires_at > $2
         ORDER BY created_at DESC",
    )
    .bind(&user.public_key)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let out = rows
        .into_iter()
        .map(
            |(id, device_name, created_at, expires_at, last_used_at)| DeviceInfo {
                id,
                device_name,
                created_at,
                expires_at,
                last_used_at,
            },
        )
        .collect();

    Ok(Json(out))
}

/// DELETE /me/devices/:id — revoke a trusted device token.
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let affected =
        sqlx::query("UPDATE device_tokens SET revoked = TRUE WHERE id = $1 AND user_pubkey = $2")
            .bind(&id)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .rows_affected();

    if affected == 0 {
        Err((StatusCode::NOT_FOUND, "Device token not found".to_string()))
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

async fn issue_session_token(
    state: &AppState,
    public_key: &str,
) -> Result<String, (StatusCode, String)> {
    // Ensure a users row exists so the FK on sessions is satisfied.
    // Passkey-registered users may not have gone through /auth/verify.
    let now = now_secs();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at)
         VALUES ($1, $2)
         ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let token = gen_token();
    sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at) \
         VALUES ($1, $2, $3, NULL)",
    )
    .bind(&token)
    .bind(public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(token)
}

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MANAGE_CHANNELS};
use crate::routes::invite_models::{CreateInviteRequest, InviteResponse};
use crate::state::AppState;

/// Short expiry forced onto invites that grant an admin-holding role (or
/// `builtin-owner`) when the creator didn't already ask for something
/// shorter. A role-granting invite is a takeover token — it shouldn't sit
/// around unused indefinitely (task #34).
const ADMIN_GRANT_DEFAULT_EXPIRY_SECS: i64 = 24 * 3600;

/// True if holding `role_id` alone grants the `admin` permission.
/// `builtin-owner` is seeded with an explicit `admin` row (see
/// `db::migrations::run`), so no separate special-case is needed here.
///
/// `pub(crate)` so `routes::hub::update_hub` can reuse it to reject an
/// admin-holding role as `default_invite_role_id` (hub-level invite role
/// policy).
pub(crate) async fn role_grants_admin(
    db: &sqlx::PgPool,
    role_id: &str,
) -> Result<bool, (StatusCode, String)> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id = $1 AND permission = 'admin')",
    )
    .bind(role_id)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    let now = crate::auth::handlers::unix_timestamp();
    let mut max_uses = req.max_uses;
    let mut expires_at = req.expires_in_seconds.map(|s| now + s);

    if let Some(role_id) = req.grant_role_id.as_deref() {
        // Can't mint an invite that grants a role at or above your own —
        // same rule used for direct role assignment (routes/roles.rs).
        let role_priority: i64 = sqlx::query_scalar("SELECT priority FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .ok_or((
                StatusCode::BAD_REQUEST,
                "grant_role_id does not reference an existing role".to_string(),
            ))?;

        if role_priority >= perms.max_priority {
            return Err((
                StatusCode::FORBIDDEN,
                "Cannot create an invite that grants a role at or above your own priority"
                    .to_string(),
            ));
        }

        // An admin-holding role is a takeover token: cap it to a single use
        // and a short expiry, unless the creator already asked for
        // something even shorter/more restrictive.
        if role_grants_admin(&state.db, role_id).await? {
            max_uses = Some(max_uses.map_or(1, |m| m.min(1)));
            let forced_expiry = now + ADMIN_GRANT_DEFAULT_EXPIRY_SECS;
            expires_at = Some(match expires_at {
                Some(existing) if existing < forced_expiry => existing,
                _ => forced_expiry,
            });
        }
    }

    let code = generate_invite_code();

    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at, grant_role_id) VALUES ($1, $2, $3, 0, $4, $5, $6)",
    )
    .bind(&code)
    .bind(&user.public_key)
    .bind(max_uses)
    .bind(expires_at)
    .bind(now)
    .bind(&req.grant_role_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            code,
            created_by: user.public_key,
            max_uses,
            uses: 0,
            expires_at,
            created_at: now,
            grant_role_id: req.grant_role_id,
        }),
    ))
}

pub async fn list_invites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<InviteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    let rows = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at, grant_role_id FROM invites ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| InviteResponse {
                code: r.code,
                created_by: r.created_by,
                max_uses: r.max_uses,
                uses: r.uses,
                expires_at: r.expires_at,
                created_at: r.created_at,
                grant_role_id: r.grant_role_id,
            })
            .collect(),
    ))
}

pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(code): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MANAGE_CHANNELS)?;

    sqlx::query("DELETE FROM invites WHERE code = $1")
        .bind(&code)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Called during auth to validate and consume an invite code.
/// Returns `Ok((created_by, grant_role_id))` if the code is valid —
/// `created_by` is the invite's minter (needed by `apply_invite_role_grant`'s
/// redemption-time priority re-check) and `grant_role_id` is the role (if
/// any) the caller should additionally assign to the joining user (task
/// #34) — or `Err` if the code is invalid, expired, or exhausted.
///
/// Uses a single atomic UPDATE with the guard conditions so that
/// concurrent registrations cannot over-consume a limited invite.
pub async fn validate_and_use_invite(
    db: &sqlx::PgPool,
    code: &str,
) -> Result<(String, Option<String>), (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    // First verify the code exists and hasn't expired (expiry is checked here
    // because SQLite doesn't have a clean way to distinguish "not found" from
    // "max_uses exceeded" without a separate read).
    let invite = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at, grant_role_id FROM invites WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::FORBIDDEN, "Invalid invite code".to_string()))?;

    if let Some(expires_at) = invite.expires_at {
        if now > expires_at {
            return Err((StatusCode::FORBIDDEN, "Invite code has expired".to_string()));
        }
    }

    // Atomic conditional increment: only increments when uses < max_uses (or max_uses is NULL).
    // rows_affected == 0 means the race was lost and the invite is now exhausted.
    let result = sqlx::query(
        "UPDATE invites SET uses = uses + 1
         WHERE code = $1 AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(code)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::FORBIDDEN,
            "Invite code has been used up".to_string(),
        ));
    }

    Ok((invite.created_by, invite.grant_role_id))
}

/// Applies an invite's `grant_role_id` (if any) — or, absent an explicit
/// grant, the hub-level `default_invite_role_id` setting (invite role
/// policies, hub-level default) — to a newly admitted user. Shared by both
/// invite-redemption paths — new-registration via `/auth/verify` and
/// existing-session via `/join/:code` — so the grant logic (and its guards)
/// lives in exactly one place (task #34 follow-on).
///
/// `grant_role_id: None` means the invite itself didn't request a role; this
/// function then looks up `default_invite_role_id` in `hub_settings` and
/// falls back to that instead. An explicit invite grant always wins over the
/// default — the default is never consulted when `grant_role_id` is `Some`.
///
/// Explicit-grant guard: re-validates the priority guard at redemption time.
/// `create_invite` already rejects minting an invite that grants a role at or
/// above the creator's priority, but the creator's own priority (or the
/// role's priority) can change between mint and redemption, and a stale
/// invite otherwise stays live at a would-be-blocked-if-minted-today grant.
/// On a guard failure this withholds the bonus role rather than failing the
/// caller's request — the join/registration has already succeeded by this
/// point. The first-boot owner invite's `created_by = 'system'` sentinel is
/// exempt, matching `maybe_mint_first_boot_owner_invite`'s documented
/// exception (no real user holds a priority to compare against yet).
///
/// Default-role guard: no inviter priority is meaningful here (a hub-level
/// setting has no "creator"), so instead this defends against the role
/// having been deleted, or having gained the `admin` permission, since the
/// setting was configured — either silently skips the default rather than
/// failing the redemption.
pub async fn apply_invite_role_grant(
    db: &sqlx::PgPool,
    invite_created_by: &str,
    grant_role_id: Option<&str>,
    user_public_key: &str,
    now: i64,
) -> Result<(), (StatusCode, String)> {
    let role_id: String = match grant_role_id {
        Some(role_id) => {
            if invite_created_by != "system" {
                let role_priority: Option<i64> =
                    sqlx::query_scalar("SELECT priority FROM roles WHERE id = $1")
                        .bind(role_id)
                        .fetch_optional(db)
                        .await
                        .map_err(|e| {
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
                        })?;

                let role_priority = match role_priority {
                    Some(p) => p,
                    None => return Ok(()), // the role was deleted since the invite was minted
                };

                let creator_perms = permissions::user_permissions(db, invite_created_by).await?;
                if role_priority >= creator_perms.max_priority {
                    // The creator no longer outranks this role (demoted, or
                    // the role's own priority changed since the invite was
                    // minted) — withhold the grant instead of failing the
                    // redemption.
                    return Ok(());
                }
            }
            role_id.to_string()
        }
        None => {
            let default_role_id: Option<String> = sqlx::query_scalar(
                "SELECT value FROM hub_settings WHERE key = 'default_invite_role_id'",
            )
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .filter(|v: &String| !v.is_empty());

            let Some(default_role_id) = default_role_id else {
                return Ok(()); // no default configured — nothing to grant
            };

            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1)")
                    .bind(&default_role_id)
                    .fetch_one(db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if !exists {
                return Ok(()); // the default role was deleted since it was configured
            }
            if role_grants_admin(db, &default_role_id).await? {
                // Defense in depth: the role gained `admin` since it was set
                // as the default — refuse to silently hand out admin.
                return Ok(());
            }

            default_role_id
        }
    };

    sqlx::query(
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_public_key, role_id) DO NOTHING",
    )
    .bind(user_public_key)
    .bind(&role_id)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(())
}

/// Mints (or reuses) the single owner-granting invite for a brand-new hub
/// that has no users yet (task #31/#34). Fresh hubs default to
/// `invite_only=true`, which would otherwise leave no way for anyone —
/// including the intended owner — to ever register: creating an invite
/// requires `manage_channels`, which requires already having a role, which
/// requires already having registered. This bypasses that deadlock by
/// minting the invite directly at the DB layer (not through
/// `create_invite`'s permission/priority-guarded HTTP path), which is also
/// why granting `builtin-owner` is allowed here and nowhere else.
///
/// Idempotent: the minted code is remembered in
/// `hub_settings['first_boot_owner_invite_code']` and reused as long as it
/// hasn't been exhausted or expired; a stale one is replaced with a fresh
/// mint. Returns `None` once the hub has any real user (the `'system'`
/// sentinel bootstrap inserts for template channels doesn't count — see
/// `auth::handlers::verify`'s `existing_users` query for the same
/// exclusion) — at that point ownership has already been claimed (or
/// seeded via `WAVVON_OWNER_PUBKEY`) and nothing is left to mint for.
pub async fn maybe_mint_first_boot_owner_invite(
    db: &sqlx::PgPool,
) -> Result<Option<String>, (StatusCode, String)> {
    let user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key <> 'system'")
            .fetch_one(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if user_count > 0 {
        return Ok(None);
    }

    let now = crate::auth::handlers::unix_timestamp();

    let existing_code: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'first_boot_owner_invite_code'",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .filter(|v: &String| !v.is_empty());

    if let Some(code) = existing_code {
        let still_valid: Option<(Option<i64>, Option<i64>, i64)> =
            sqlx::query_as("SELECT expires_at, max_uses, uses FROM invites WHERE code = $1")
                .bind(&code)
                .fetch_optional(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if let Some((expires_at, max_uses, uses)) = still_valid {
            let not_expired = expires_at.map(|exp| now <= exp).unwrap_or(true);
            let not_exhausted = max_uses.map(|m| uses < m).unwrap_or(true);
            if not_expired && not_exhausted {
                return Ok(Some(code));
            }
        }
    }

    let code = generate_invite_code();
    let expires_at = now + ADMIN_GRANT_DEFAULT_EXPIRY_SECS;
    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at, grant_role_id)
         VALUES ($1, 'system', 1, 0, $2, $3, 'builtin-owner')",
    )
    .bind(&code)
    .bind(expires_at)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES ('first_boot_owner_invite_code', $1)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(&code)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Some(code))
}

/// GET /join/:code — public; returns hub info so a visitor can preview before joining.
pub async fn get_join_info(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let invite = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at, grant_role_id FROM invites WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Invite not found".to_string()))?;

    // Note: grant_role_id is intentionally never surfaced here — a public
    // preview must not leak that an invite grants an elevated role.
    let member_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let hub_name =
        sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_name'")
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| state.hub_name.clone());

    Ok(Json(serde_json::json!({
        "hub_name": hub_name,
        "member_count": member_count,
        "code": invite.code,
    })))
}

/// POST /join/:code — requires a valid session token.
/// Validates the invite, increments use_count, and auto-approves the user
/// (bypasses the require_approval gate even when the hub has it enabled).
/// The same role grant applied on the `/auth/verify` registration path is
/// applied here too, via the shared `apply_invite_role_grant` helper (same
/// priority-guard re-check) — whether the invite carries an explicit
/// `grant_role_id` (task #34) or falls back to the hub-level
/// `default_invite_role_id` (invite role policies).
pub async fn join_with_invite(
    State(state): State<Arc<AppState>>,
    user: crate::auth::middleware::AuthUser,
    Path(code): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let now = crate::auth::handlers::unix_timestamp();

    let invite = sqlx::query_as::<_, InviteRow>(
        "SELECT code, created_by, max_uses, uses, expires_at, created_at, grant_role_id FROM invites WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Invite not found".to_string()))?;

    // Note: this endpoint is the "existing session, auto-approve" join path,
    // distinct from new-registration invites handled in auth::handlers::verify.
    if let Some(expires_at) = invite.expires_at {
        if now > expires_at {
            return Err((StatusCode::GONE, "Invite has expired".to_string()));
        }
    }
    if let Some(max_uses) = invite.max_uses {
        if invite.uses >= max_uses {
            return Err((StatusCode::GONE, "Invite has been fully used".to_string()));
        }
    }

    // Increment use count
    sqlx::query("UPDATE invites SET uses = uses + 1 WHERE code = $1")
        .bind(&code)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Auto-approve: set approval_status = 'approved' for this user
    sqlx::query("UPDATE users SET approval_status = 'approved' WHERE public_key = $1")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Always call the shared helper, even when the invite carries no
    // explicit `grant_role_id` — it falls back to `default_invite_role_id`
    // (hub-level invite role policy) in that case, and is itself a no-op
    // when neither an explicit grant nor a default is in play.
    apply_invite_role_grant(
        &state.db,
        &invite.created_by,
        invite.grant_role_id.as_deref(),
        &user.public_key,
        now,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Check if the hub requires invites
pub async fn is_invite_only(db: &sqlx::PgPool) -> Result<bool, (StatusCode, String)> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'invite_only'")
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(value.as_deref() == Some("true"))
}

fn generate_invite_code() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(sqlx::FromRow)]
struct InviteRow {
    code: String,
    created_by: String,
    max_uses: Option<i64>,
    uses: i64,
    expires_at: Option<i64>,
    created_at: i64,
    grant_role_id: Option<String>,
}

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ALLIANCES_MANAGE};
use crate::routes::alliance_models::*;
use crate::state::AppState;

use super::models::{AllianceRow, MemberRow};

pub async fn create_alliance(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateAllianceRequest>,
) -> Result<(StatusCode, Json<AllianceResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ALLIANCES_MANAGE)?;

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query("INSERT INTO alliances (id, name, created_by, created_at) VALUES ($1, $2, $3, $4)")
        .bind(&id)
        .bind(&req.name)
        .bind(&user.public_key)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add this hub as the first member. Use the live name from hub_settings
    // (an admin may have renamed since startup) rather than state.hub_name.
    let hub_name = crate::routes::hub::current_hub_name(&state).await;
    sqlx::query(
        "INSERT INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(state.hub_identity.public_key_hex())
    .bind(&hub_name)
    .bind("self")
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Created alliance '{}'", req.name);

    Ok((
        StatusCode::CREATED,
        Json(AllianceResponse {
            id,
            name: req.name,
            created_by: user.public_key,
            created_at: now,
        }),
    ))
}

pub async fn list_alliances(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<AllianceResponse>>, (StatusCode, String)> {
    // A peer hub is told about the alliances it shares with this one and no
    // others: a hub in many alliances shares different channels into each, and
    // the id is what every other alliance route is addressed by.
    let peer = super::models::caller_is_peer(&state, &user.public_key).await?;
    let rows = sqlx::query_as::<_, AllianceRow>(
        "SELECT DISTINCT a.id, a.name, a.created_by, a.created_at
         FROM alliances a
         INNER JOIN alliance_members am ON a.id = am.alliance_id
         WHERE am.hub_public_key = $1
           AND ($2::text IS NULL OR EXISTS(
                 SELECT 1 FROM alliance_members peer_am
                 WHERE peer_am.alliance_id = a.id AND peer_am.hub_public_key = $2))
         ORDER BY a.created_at",
    )
    .bind(state.hub_identity.public_key_hex())
    .bind(if peer {
        Some(user.public_key.clone())
    } else {
        None
    })
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AllianceResponse {
                id: r.id,
                name: r.name,
                created_by: r.created_by,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn get_alliance(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<Json<AllianceDetailResponse>, (StatusCode, String)> {
    super::models::require_alliance_visibility(&state, &user.public_key, &alliance_id).await?;

    // And this hub has to be in it. The row can outlive membership for a
    // moment — a departure announced to us by a peer, a mirror not yet
    // cleaned — and answering from it would describe an alliance this hub is
    // not part of.
    let ours: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2)",
    )
    .bind(&alliance_id)
    .bind(state.hub_identity.public_key_hex())
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if !ours {
        return Err((StatusCode::NOT_FOUND, "Alliance not found".to_string()));
    }

    let alliance = sqlx::query_as::<_, AllianceRow>(
        "SELECT id, name, created_by, created_at FROM alliances WHERE id = $1",
    )
    .bind(&alliance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Alliance not found".to_string()))?;

    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT hub_public_key, hub_name, hub_url, joined_at FROM alliance_members WHERE alliance_id = $1",
    )
    .bind(&alliance_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(AllianceDetailResponse {
        id: alliance.id,
        name: alliance.name,
        created_by: alliance.created_by,
        created_at: alliance.created_at,
        members: members
            .into_iter()
            .map(|m| AllianceMemberInfo {
                hub_public_key: m.hub_public_key,
                hub_name: m.hub_name,
                hub_url: m.hub_url,
                joined_at: m.joined_at,
            })
            .collect(),
    }))
}

pub async fn leave_alliance(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(alliance_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ALLIANCES_MANAGE)?;

    let hub_key = state.hub_identity.public_key_hex();

    // Tell the partners first: afterwards the rows that name them are gone.
    super::membership::announce_departure(&state, &alliance_id).await;

    // Remove shared channels
    sqlx::query(
        "DELETE FROM alliance_shared_channels WHERE alliance_id = $1 AND channel_id IN (SELECT id FROM channels)",
    )
    .bind(&alliance_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Remove membership
    sqlx::query("DELETE FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2")
        .bind(&alliance_id)
        .bind(&hub_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // And drop the rest of the mirror. What is left of an alliance this hub
    // is no longer in is other hubs' membership rows, which serve nothing:
    // they name peers this hub has no business calling about it, and they kept
    // `GET /alliances/{id}` answering for an alliance it had walked out of.
    // Counting members and only cleaning up at zero left exactly that residue
    // on every departure but the last.
    sqlx::query("DELETE FROM alliance_members WHERE alliance_id = $1")
        .bind(&alliance_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM alliance_shared_channels WHERE alliance_id = $1")
        .bind(&alliance_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM alliances WHERE id = $1")
        .bind(&alliance_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

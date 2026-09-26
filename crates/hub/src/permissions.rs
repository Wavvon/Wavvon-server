use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use sqlx::PgPool;

/// Where a permission may be granted.
///
/// The channel column is a subset by design (permissions.md §3): an entry is
/// `HubAndChannel` only when the thing it governs lives in a channel. There is
/// no channel-scoped hub administration — "manage the hub, but only in
/// #general" is not a sentence.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Hub-wide only. A channel overwrite naming it is refused.
    Hub,
    /// Hub-wide, and as a channel overwrite through the ancestor cascade.
    HubAndChannel,
}

impl Scope {
    pub fn allows_channel(self) -> bool {
        matches!(self, Scope::HubAndChannel)
    }
}

/// One catalogue entry: the id clients render and the hub checks, and where it
/// may be granted.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Permission {
    pub id: &'static str,
    pub scope: Scope,
}

/// Declares the catalogue once: each entry becomes a `pub const` carrying the
/// id, plus a row in [`CATALOGUE`] carrying its scope.
///
/// The list used to be written out a second time by hand, which meant a
/// permission added without touching it was accepted by every route and
/// validated by none. One list now, and the scope travels with the id so the
/// overwrite validator and the catalogue endpoint cannot disagree about which
/// permissions have a channel dimension — that decision used to live in a
/// TypeScript comment (permissions.md §1.5).
macro_rules! permission_catalogue {
    ($( $(#[$meta:meta])* $name:ident => $value:literal, $scope:ident ),* $(,)?) => {
        $( $(#[$meta])* pub const $name: &str = $value; )*

        /// Every permission the server recognizes, with its scope.
        pub const CATALOGUE: &[Permission] = &[
            $(Permission { id: $value, scope: Scope::$scope }),*
        ];

        /// Ids only, for the checks that just need membership.
        pub const ALL_PERMISSIONS: &[&str] = &[$($value),*];
    };
}

permission_catalogue! {
    // ── Messages ────────────────────────────────────────────────────────
    /// Reading a channel, and the visibility filter behind every list and the
    /// WS auto-subscribe. The auto-subscribe asks for this one **only** —
    /// widening it to match the channel list is a data leak (§3, Voice).
    MESSAGES_READ => "messages.read", HubAndChannel,
    MESSAGES_SEND => "messages.send", HubAndChannel,
    MESSAGES_MANAGE => "messages.manage", HubAndChannel,

    // ── Forum ───────────────────────────────────────────────────────────
    FORUM_POSTS_CREATE => "forum.posts.create", HubAndChannel,
    FORUM_POSTS_MANAGE => "forum.posts.manage", HubAndChannel,

    // ── Channels ────────────────────────────────────────────────────────
    /// Create, rename, move, delete, re-parent — plus voice zones and talk
    /// power, both of which are channel configuration rather than an activity.
    CHANNELS_MANAGE => "channels.manage", HubAndChannel,
    CHANNELS_APPEARANCE => "channels.appearance", HubAndChannel,
    CHANNELS_PERMISSIONS => "channels.permissions", HubAndChannel,

    // ── Voice ───────────────────────────────────────────────────────────
    /// Entering voice on a channel, and screen share. Independent of
    /// `messages.read` in both directions: a channel everyone reads where only
    /// one role may join, and a lobby anyone may talk in with no readable
    /// text. Neither was expressible before it.
    VOICE_JOIN => "voice.join", HubAndChannel,
    VOICE_SOUNDBOARD_USE => "voice.soundboard.use", HubAndChannel,
    VOICE_SOUNDBOARD_MANAGE => "voice.soundboard.manage", Hub,
    /// Resolved against the **destination** channel, not the source.
    VOICE_MOVE_MEMBERS => "voice.move_members", HubAndChannel,

    // ── Moderation ──────────────────────────────────────────────────────
    MODERATION_KICK => "moderation.kick", Hub,
    MODERATION_MUTE => "moderation.mute", HubAndChannel,
    MODERATION_TIMEOUT => "moderation.timeout", Hub,
    /// Split from the permanent ban by irreversibility: an hour is a cooling
    /// period, forever is a decision.
    MODERATION_BAN_TEMPORARY => "moderation.ban.temporary", HubAndChannel,
    MODERATION_BAN_PERMANENT => "moderation.ban.permanent", HubAndChannel,
    MODERATION_REPORTS_READ => "moderation.reports.read", Hub,
    MODERATION_REPORTS_REVIEW => "moderation.reports.review", Hub,
    MODERATION_SETTINGS => "moderation.settings", Hub,

    // ── Federated ban lists ─────────────────────────────────────────────
    BANLIST_READ => "banlist.read", Hub,
    /// Split out on its own: adding a source imports a stranger's bans, so the
    /// subject is not this hub's members and the authority is not this hub.
    BANLIST_SOURCES_MANAGE => "banlist.sources.manage", Hub,
    BANLIST_OVERRIDES => "banlist.overrides", Hub,
    BANLIST_SETTINGS => "banlist.settings", Hub,

    // ── Roles and members ───────────────────────────────────────────────
    /// The most dangerous permission on the hub once the wildcard is gone, and
    /// the reason the escalation ceiling in `require_can_grant` is a
    /// precondition rather than hardening.
    ROLES_MANAGE => "roles.manage", Hub,
    MEMBERS_READ => "members.read", Hub,

    // ── Hub ─────────────────────────────────────────────────────────────
    HUB_SETTINGS => "hub.settings", Hub,
    HUB_APPEARANCE => "hub.appearance", Hub,
    HUB_ADMISSION => "hub.admission", Hub,
    /// Nothing about an invite is a channel; it asked for `manage_channels`
    /// only by accident (permissions.md §3, Hub).
    INVITES_MANAGE => "invites.manage", Hub,

    // ── Events ──────────────────────────────────────────────────────────
    EVENTS_CREATE => "events.create", HubAndChannel,
    EVENTS_MANAGE => "events.manage", HubAndChannel,

    // ── Trust ───────────────────────────────────────────────────────────
    CERTS_ISSUE => "certs.issue", Hub,
    /// Separate from issuing: a revocation invalidates trust that already left
    /// the hub.
    CERTS_REVOKE => "certs.revoke", Hub,
    CERTS_SETTINGS => "certs.settings", Hub,
    BADGES_MANAGE => "badges.manage", Hub,

    // ── Federation and presence ─────────────────────────────────────────
    /// Hub-scoped alliance acts only. Inviting another hub, sharing a channel
    /// and the per-share policies live on the `alliance_managers` grant list,
    /// because they belong to one relationship rather than to the hub.
    ALLIANCES_MANAGE => "alliances.manage", Hub,
    ALLIANCES_PEERS => "alliances.peers", Hub,
    /// Makes the hub publicly discoverable, and nothing un-indexes it.
    DIRECTORY_PUBLISH => "directory.publish", Hub,

    // ── Integrations ────────────────────────────────────────────────────
    WEBHOOKS_INCOMING_MANAGE => "webhooks.incoming.manage", Hub,
    WEBHOOKS_OUTGOING_MANAGE => "webhooks.outgoing.manage", Hub,
    /// Registering an app: a profile, slash commands, event subscriptions,
    /// and the message shapes an app authors (embeds, game launch cards).
    /// Not a kind of account — a client is a client — but the hub still has
    /// to know which members speak for a program, because an embed nobody
    /// vouched for is a forgery with a nice border.
    APPS_REGISTER => "apps.register", Hub,
    AUDIT_READ => "audit.read", Hub,

    // ── Surveys ─────────────────────────────────────────────────────────
    SURVEYS_MANAGE => "surveys.manage", Hub,
    /// Split from defining the survey: the responses are personal data, and
    /// running one is a different job from reading who said what.
    SURVEYS_RESPONSES_READ => "surveys.responses.read", Hub,
}

/// The role ownership *is*: `is_owner` is membership of it and nothing else.
///
/// Seeded by the migrations, granted by the first-boot owner invite and by
/// ownership transfer, and refused deletion or emptying by `roles.rs` — which
/// is why §1.1 could move "can do everything" onto it without inventing a new
/// place for ownership to live.
pub const BUILTIN_OWNER_ROLE_ID: &str = "builtin-owner";

/// The scope of `id`, or `None` if the server does not know it.
pub fn scope_of(id: &str) -> Option<Scope> {
    CATALOGUE.iter().find(|p| p.id == id).map(|p| p.scope)
}

/// Rejects any permission string the server does not recognize.
///
/// Every route that persists a caller-supplied permission goes through here:
/// role create/update (`routes/roles.rs`) and channel overwrites
/// (`routes/channel_permissions.rs`). Without it an arbitrary string lands in
/// `role_permissions` or `channel_permission_overwrites` and sits there
/// forever, granting nothing and matching no check — a typo that looks like a
/// permission in the roles UI.
///
/// Call it before writing anything: `update_role` applies name and priority in
/// separate statements, so validating late would leave a half-applied update
/// behind a 400.
pub fn validate_permissions<'a>(
    permissions: impl IntoIterator<Item = &'a str>,
) -> Result<(), (StatusCode, String)> {
    for p in permissions {
        if !ALL_PERMISSIONS.contains(&p) {
            return Err((StatusCode::BAD_REQUEST, format!("unknown permission: {p}")));
        }
    }
    Ok(())
}

/// As [`validate_permissions`], plus the scope: a hub-only permission set as a
/// channel overwrite is refused rather than stored.
///
/// The catalogue advertises each id's scope and the overwrite UI filters on it,
/// but a client is not a guard. Without this the hub would accept a row saying
/// "manage roles, but only in #general" — which grants nothing, matches no
/// check, and looks in the UI exactly like a grant that worked. That is the
/// same shape as the unvalidated strings §0 describes, one level up.
pub fn validate_channel_overwrite<'a>(
    permissions: impl IntoIterator<Item = &'a str>,
) -> Result<(), (StatusCode, String)> {
    for p in permissions {
        match scope_of(p) {
            None => return Err((StatusCode::BAD_REQUEST, format!("unknown permission: {p}"))),
            Some(s) if !s.allows_channel() => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("{p} is hub-wide only and cannot be a channel overwrite"),
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub created_at: i64,
}

pub struct UserPermissions {
    pub roles: Vec<RoleRow>,
    pub effective: HashSet<String>,
    pub max_priority: i64,
    /// "Can do everything regardless", as a property of the caller rather than
    /// a row in `role_permissions` (permissions.md §1.1). Computed from
    /// membership of `builtin-owner`, which is already where ownership lives:
    /// transfer manipulates that role, recovery protects it, and `roles.rs`
    /// refuses to delete or empty it.
    pub is_owner: bool,
}

impl UserPermissions {
    pub fn has(&self, permission: &str) -> bool {
        self.is_owner || self.effective.contains(permission)
    }

    /// For the two acts the catalogue deliberately has no entry for
    /// (permissions.md §2): approving an identity recovery, and ownership
    /// transfer. Both hand one person control of another person's account, and
    /// there is no delegation of that worth the failure mode — so they are not
    /// a permission anyone can be given, they are the owner or nothing.
    pub fn require_owner(&self, act: &str) -> Result<(), (StatusCode, String)> {
        if self.is_owner {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("Only the hub owner may {act}"),
            ))
        }
    }

    pub fn require(&self, permission: &str) -> Result<(), (StatusCode, String)> {
        if self.has(permission) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("Missing permission: {permission}"),
            ))
        }
    }

    /// The first permission in `requested` this caller does not hold, if any —
    /// the escalation ceiling of permissions.md §1.6, which says a caller may
    /// only hand out permissions they hold themselves.
    ///
    /// Callers format their own 403, because the scope belongs in the message:
    /// the channel-overwrite path says "on this channel" and the hub-wide path
    /// does not.
    ///
    /// `has()` short-circuits on `admin`, so an admin or owner clears every
    /// entry for free. That is the exemption §1.6 describes as `is_owner`,
    /// arriving for free while `admin` still exists — when the wildcard is
    /// deleted this must start consulting owner-as-property instead, or the
    /// owner will be unable to grant anything they were not separately given.
    pub fn first_not_held<'a>(
        &self,
        requested: impl IntoIterator<Item = &'a str>,
    ) -> Option<&'a str> {
        requested.into_iter().find(|p| !self.has(p))
    }

    /// [`first_not_held`](Self::first_not_held) as a 403, for the hub-wide
    /// callers that all want the same message.
    ///
    /// Without this, `manage_roles` is a wildcard. Every guard on these paths
    /// bounds *rank*, and the escalation does not need rank: a role beneath
    /// your own priority can carry permissions above it, and handing it to
    /// yourself is one more call.
    ///
    /// The check is on write, not a standing invariant — revoking someone's
    /// permission does not strip roles they already minted carrying it
    /// (permissions.md §1.6), so demoting a delegate is two steps.
    pub fn require_can_grant<'a>(
        &self,
        requested: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), (StatusCode, String)> {
        match self.first_not_held(requested) {
            Some(p) => Err((
                StatusCode::FORBIDDEN,
                format!("Cannot grant permission '{p}' you do not hold"),
            )),
            None => Ok(()),
        }
    }
}

pub async fn user_permissions(
    db: &PgPool,
    public_key: &str,
) -> Result<UserPermissions, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.priority, r.created_at
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = $1",
    )
    .bind(public_key)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    let effective = fetch_permissions(db, &role_ids).await?;
    let max_priority = roles.iter().map(|r| r.priority).max().unwrap_or(0);
    // Ownership is the built-in role, not a permission row (§1.1).
    let is_owner = roles.iter().any(|r| r.id == BUILTIN_OWNER_ROLE_ID);

    Ok(UserPermissions {
        roles,
        effective,
        max_priority,
        is_owner,
    })
}

async fn fetch_permissions(
    db: &PgPool,
    role_ids: &[&str],
) -> Result<HashSet<String>, (StatusCode, String)> {
    if role_ids.is_empty() {
        return Ok(HashSet::new());
    }

    // Build a query with placeholders for each role_id
    let placeholders: Vec<String> = role_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("${}", i + 1))
        .collect();
    let query = format!(
        "SELECT DISTINCT permission FROM role_permissions WHERE role_id IN ({})",
        placeholders.join(",")
    );

    let mut q = sqlx::query_scalar::<_, String>(&query);
    for id in role_ids {
        q = q.bind(id);
    }

    let permissions: Vec<String> = q
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(permissions.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Channel permission overwrites (Nested Channels §3)
// ---------------------------------------------------------------------------
//
// An overwrite targets a role on a channel and sets, per permission, one of
// allow / deny / inherit (absence of a row = inherit). Effective permission
// on a channel = hub-wide baseline, then fold in the ancestor chain
// root -> target, applying each level's rows for the roles the user holds.
// Within one level, allow wins over deny; deeper levels win over shallower
// ones; `admin` is never removed by a deny. See docs/docs/nested-channels-ux.md §3.

#[derive(sqlx::FromRow, Clone)]
pub struct OverwriteRow {
    pub channel_id: String,
    pub role_id: String,
    pub permission: String,
    /// TRUE = allow, FALSE = deny.
    pub allow: bool,
}

/// Walks `channels.parent_id` from `channel_id` up to the root and returns
/// the chain in root -> target order (target included last). If
/// `channel_id` doesn't exist, returns the single-element chain
/// `[channel_id]` — no overwrite rows will match a nonexistent channel, so
/// the fold is a no-op.
pub async fn ancestor_chain(
    db: &PgPool,
    channel_id: &str,
) -> Result<Vec<String>, (StatusCode, String)> {
    let mut chain = vec![channel_id.to_string()];
    let mut current = channel_id.to_string();
    // Safety cap mirrors the existing depth-walk convention in routes/channels.rs.
    for _ in 0..64 {
        let parent: Option<String> =
            sqlx::query_scalar("SELECT parent_id FROM channels WHERE id = $1")
                .bind(&current)
                .fetch_optional(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                .flatten();
        match parent {
            None => break,
            Some(p) => {
                chain.push(p.clone());
                current = p;
            }
        }
    }
    chain.reverse();
    Ok(chain)
}

/// Same as `ancestor_chain`, but walks an already-loaded `id -> parent_id`
/// map instead of issuing a query per hop. Used to batch-filter a channel
/// list without one ancestor-chain round trip per channel (§3.5).
pub fn ancestor_chain_from_map(
    parent_of: &HashMap<String, Option<String>>,
    channel_id: &str,
) -> Vec<String> {
    let mut chain = vec![channel_id.to_string()];
    let mut current = channel_id.to_string();
    for _ in 0..64 {
        match parent_of.get(&current).cloned().flatten() {
            None => break,
            Some(p) => {
                chain.push(p.clone());
                current = p;
            }
        }
    }
    chain.reverse();
    chain
}

/// Batch-loads overwrite rows for a set of channels restricted to a set of
/// roles, in one query.
pub async fn fetch_overwrites(
    db: &PgPool,
    channel_ids: &[String],
    role_ids: &[String],
) -> Result<Vec<OverwriteRow>, (StatusCode, String)> {
    if channel_ids.is_empty() || role_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, OverwriteRow>(
        "SELECT channel_id, role_id, permission, allow
         FROM channel_permission_overwrites
         WHERE channel_id = ANY($1) AND role_id = ANY($2)",
    )
    .bind(channel_ids)
    .bind(role_ids)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

/// Folds `rows` into `baseline` in `chain` order (root -> target), applying
/// the §3.2 rules:
/// - within one channel level, allow wins over deny for the same permission
///   (across whichever roles hold a row at that level);
/// - a deeper (later-in-`chain`) level's decision overrides a shallower one;
/// - `admin` is never removed by a deny.
pub fn fold_overwrites(
    baseline: &HashSet<String>,
    chain: &[String],
    rows: &[OverwriteRow],
) -> HashSet<String> {
    let mut effective = baseline.clone();
    for channel_id in chain {
        let mut allow: HashSet<&str> = HashSet::new();
        let mut deny: HashSet<&str> = HashSet::new();
        for row in rows.iter().filter(|r| &r.channel_id == channel_id) {
            if row.allow {
                allow.insert(row.permission.as_str());
            } else {
                deny.insert(row.permission.as_str());
            }
        }
        for perm in &deny {
            if allow.contains(perm) {
                continue; // allow wins within the same level
            }
            // Owner immunity used to need a special case here, because it
            // was a row in the set being folded. It is a property now, read
            // above the fold in `has()`, so a deny is just a deny.
            effective.remove(*perm);
        }
        for perm in &allow {
            effective.insert((*perm).to_string());
        }
    }
    effective
}

/// Channel-aware resolver: hub-wide baseline permissions, adjusted by the
/// channel's ancestor-chain overwrite cascade for the roles the caller
/// holds. `has` / `require` on the returned `UserPermissions` are unchanged
/// -- call sites switch by one argument, not by shape.
pub async fn channel_permissions(
    db: &PgPool,
    public_key: &str,
    channel_id: &str,
) -> Result<UserPermissions, (StatusCode, String)> {
    let baseline = user_permissions(db, public_key).await?;
    if baseline.roles.is_empty() {
        // Overwrites are role-scoped; a user with no roles can't match any.
        return Ok(baseline);
    }

    let chain = ancestor_chain(db, channel_id).await?;
    let role_ids: Vec<String> = baseline.roles.iter().map(|r| r.id.clone()).collect();
    let rows = fetch_overwrites(db, &chain, &role_ids).await?;
    let effective = fold_overwrites(&baseline.effective, &chain, &rows);

    Ok(UserPermissions {
        roles: baseline.roles,
        effective,
        max_priority: baseline.max_priority,
        // A channel overwrite cannot revoke ownership.
        is_owner: baseline.is_owner,
    })
}

/// Returns the set of channel ids (of every channel currently in the
/// `channels` table, categories included) for which `public_key`'s
/// effective permissions include `permission`, after folding in the
/// ancestor-chain cascade. Used to batch-filter a channel list or a
/// WS auto-subscribe set in two queries total (§3.5) rather than one
/// ancestor-chain round trip per channel.
pub async fn channels_with_permission(
    db: &PgPool,
    public_key: &str,
    permission: &str,
) -> Result<HashSet<String>, (StatusCode, String)> {
    let baseline = user_permissions(db, public_key).await?;

    let all: Vec<(String, Option<String>)> = sqlx::query_as("SELECT id, parent_id FROM channels")
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // The owner holds everything everywhere and no deny reaches them, so the
    // per-channel fold cannot change the answer.
    if baseline.is_owner {
        return Ok(all.into_iter().map(|(id, _)| id).collect());
    }

    if baseline.roles.is_empty() {
        return Ok(all
            .into_iter()
            .filter(|_| baseline.effective.contains(permission))
            .map(|(id, _)| id)
            .collect());
    }

    let parent_of: HashMap<String, Option<String>> = all.iter().cloned().collect();
    let all_ids: Vec<String> = all.into_iter().map(|(id, _)| id).collect();
    let role_ids: Vec<String> = baseline.roles.iter().map(|r| r.id.clone()).collect();
    let overwrite_rows = fetch_overwrites(db, &all_ids, &role_ids).await?;

    Ok(all_ids
        .into_iter()
        .filter(|id| {
            let chain = ancestor_chain_from_map(&parent_of, id);
            let effective = fold_overwrites(&baseline.effective, &chain, &overwrite_rows);
            effective.contains(permission)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_has_no_duplicates() {
        let mut seen = HashSet::new();
        for p in CATALOGUE {
            assert!(
                seen.insert(p.id),
                "duplicate permission in catalogue: {}",
                p.id
            );
        }
    }

    #[test]
    fn ids_and_scopes_come_from_one_list() {
        // The macro guarantees it structurally; this fails loudly if the two
        // ever stop being generated together, which is the drift that produced
        // four disagreeing copies before (permissions.md §0).
        assert_eq!(CATALOGUE.len(), ALL_PERMISSIONS.len());
        for p in CATALOGUE {
            assert!(
                ALL_PERMISSIONS.contains(&p.id),
                "{} missing from the id list",
                p.id
            );
        }
    }

    #[test]
    fn every_id_is_dotted_and_lowercase() {
        // One spelling, so a client's literal either matches or the permission
        // was never in the catalogue at all.
        for p in CATALOGUE {
            assert!(p.id.contains('.'), "{} is not dotted", p.id);
            assert!(
                p.id.split('.').all(|seg| !seg.is_empty()
                    && seg.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
                "{} must be lowercase dotted segments",
                p.id,
            );
        }
    }

    #[test]
    fn hub_administration_is_never_channel_scoped() {
        // The channel column is a subset by design (§3). "Manage the hub, but
        // only in #general" is not a sentence, and an overwrite that pretended
        // otherwise would grant nothing while looking like it granted
        // something.
        for id in [
            "roles.manage",
            "hub.settings",
            "hub.admission",
            "invites.manage",
            "banlist.settings",
            "certs.issue",
            "directory.publish",
            "surveys.responses.read",
            "apps.register",
        ] {
            assert_eq!(
                scope_of(id),
                Some(Scope::Hub),
                "{id} must not be grantable per channel",
            );
        }
    }

    #[test]
    fn what_lives_in_a_channel_is_channel_scoped() {
        for id in [
            "messages.read",
            "messages.send",
            "voice.join",
            "channels.manage",
            "events.create",
            "moderation.mute",
        ] {
            assert_eq!(
                scope_of(id),
                Some(Scope::HubAndChannel),
                "{id} should carry C"
            );
        }
    }

    #[test]
    fn the_deleted_wildcard_is_not_in_the_catalogue() {
        // `admin` is owner-as-property now (§1.1). If it ever comes back as a
        // string, every named permission below it becomes optional again.
        assert_eq!(scope_of("admin"), None);
        assert!(validate_permissions(["admin"]).is_err());
        // And the four strings §4 deletes for gating nothing.
        for dead in [
            "manage_bots",
            "use_video",
            "manage_games",
            "start_game",
            "bots.admit",
        ] {
            assert_eq!(scope_of(dead), None, "{dead} should be gone");
        }
    }

    #[test]
    fn a_hub_only_permission_cannot_be_a_channel_overwrite() {
        // The scope the catalogue advertises has to be the scope the hub
        // enforces, or they are two lists again.
        assert!(validate_channel_overwrite([MESSAGES_READ, VOICE_JOIN]).is_ok());
        let err = validate_channel_overwrite([ROLES_MANAGE]).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("hub-wide only"), "message was: {}", err.1);
        // Still refuses an unknown id, same as the plain validator.
        assert!(validate_channel_overwrite(["read_messages"]).is_err());
    }

    /// Every catalogue entry is consulted by something.
    ///
    /// A permission nothing reads is a checkbox that grants nothing — the
    /// exact defect §0 catalogues four of, and the one this rebuild exists to
    /// end. It came back twice during the rebuild itself, both times because a
    /// bulk rename flattened a mapping that was one-to-two:
    /// `manage_channels` became `channels.manage` everywhere, including on
    /// the invite routes where the catalogue says `invites.manage`; and
    /// `manage_roles` became `roles.manage` everywhere, including on the
    /// channel-overwrite routes where it should be `channels.permissions`.
    ///
    /// Scanning the source at test time rather than trusting review, because
    /// review is what missed it.
    #[test]
    fn no_permission_is_a_checkbox_that_grants_nothing() {
        use std::path::Path;

        // Entries with no reader *yet*, each with the reason it is early.
        // Empty is the healthy state; a name here is a promise, not a parking
        // space.
        const NOT_WIRED_YET: &[(&str, &str)] = &[];

        fn read_all(dir: &Path, out: &mut String) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    read_all(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && path.file_name().is_some_and(|f| f != "permissions.rs")
                {
                    out.push_str(&std::fs::read_to_string(&path).expect("read"));
                    out.push('\n');
                }
            }
        }

        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut blob = String::new();
        read_all(&src_dir, &mut blob);

        let mut orphans = Vec::new();
        for p in CATALOGUE {
            if NOT_WIRED_YET.iter().any(|(id, _)| *id == p.id) {
                continue;
            }
            // Either the constant or the literal id — a few checks are written
            // as strings for want of an import.
            let quoted = format!("\"{}\"", p.id);
            if !blob.contains(&quoted) && !blob.contains(&const_name(p.id)) {
                orphans.push(p.id);
            }
        }

        assert!(
            orphans.is_empty(),
            "these permissions are in the catalogue and read by nothing: {orphans:?}. \
             Either wire them where the catalogue says they belong, or add them to \
             NOT_WIRED_YET with the reason.",
        );
    }

    /// `messages.read` -> `MESSAGES_READ`, the macro's own convention.
    fn const_name(id: &str) -> String {
        id.to_uppercase().replace('.', "_")
    }

    #[test]
    fn known_permissions_are_accepted() {
        assert!(validate_permissions([ROLES_MANAGE, MESSAGES_SEND]).is_ok());
        assert!(validate_permissions([]).is_ok());
    }

    #[test]
    fn unknown_permission_is_rejected_with_400() {
        let err = validate_permissions([ROLES_MANAGE, "roles.manege"]).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("roles.manege"), "message was: {}", err.1);
    }

    #[test]
    fn an_old_id_is_not_quietly_accepted() {
        // The catalogue is rebuilt, not mapped: there is no dual-reading
        // period (§6), so yesterday's spelling has to fail rather than half
        // work.
        for old in [
            "read_messages",
            "manage_roles",
            "ban_members",
            "manage_voice",
        ] {
            assert!(
                validate_permissions([old]).is_err(),
                "{old} should be unknown now"
            );
        }
    }

    #[test]
    fn permission_strings_are_not_confused_by_case_or_whitespace() {
        // Postgres stores whatever we bind and `has()` compares exactly, so a
        // string that only looks right grants nothing. Reject it at the door.
        for bad in [
            "Messages.Read",
            "messages.read ",
            " messages.read",
            "MESSAGES.READ",
        ] {
            assert!(
                validate_permissions([bad]).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    fn perms(is_owner: bool, held: &[&str]) -> UserPermissions {
        UserPermissions {
            roles: Vec::new(),
            effective: held.iter().map(|s| (*s).to_string()).collect(),
            max_priority: 0,
            is_owner,
        }
    }

    #[test]
    fn the_owner_holds_everything_without_holding_anything() {
        let owner = perms(true, &[]);
        for p in CATALOGUE {
            assert!(owner.has(p.id), "the owner should pass {}", p.id);
        }
        assert!(owner.require_owner("transfer ownership").is_ok());
    }

    #[test]
    fn a_member_holds_only_what_it_was_given() {
        let member = perms(false, &[MESSAGES_READ]);
        assert!(member.has(MESSAGES_READ));
        assert!(!member.has(ROLES_MANAGE));
        assert!(member.require_owner("approve a recovery").is_err());
    }

    #[test]
    fn the_ceiling_stops_a_delegate_and_not_the_owner() {
        // §1.6: the guard has to read owner-as-property in the same change
        // that deletes the wildcard, or the owner silently loses the ability
        // to grant anything `builtin-owner` was not separately given.
        let delegate = perms(false, &[ROLES_MANAGE]);
        assert_eq!(
            delegate.first_not_held([ROLES_MANAGE, MODERATION_BAN_PERMANENT]),
            Some(MODERATION_BAN_PERMANENT),
        );
        assert!(delegate
            .require_can_grant([MODERATION_BAN_PERMANENT])
            .is_err());

        let owner = perms(true, &[]);
        assert_eq!(owner.first_not_held([MODERATION_BAN_PERMANENT]), None);
        assert!(owner.require_can_grant([MODERATION_BAN_PERMANENT]).is_ok());
    }
}

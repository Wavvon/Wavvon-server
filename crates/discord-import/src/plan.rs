//! Pure manifest -> ordered apply steps, plus a ref -> hub-id resolver used
//! while executing those steps (docs/docs/discord-import.md §5). No network
//! I/O; `hub_client` drives the actual HTTP calls.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::manifest::{ChannelEntry, ChannelKind, Manifest};

/// The hub's builtin-everyone role id (never created, only referenced).
pub const BUILTIN_EVERYONE_ROLE_ID: &str = "builtin-everyone";

#[derive(Debug, Clone, PartialEq)]
pub enum PlanError {
    DuplicateRoleRef(String),
    DuplicateChannelRef(String),
    /// A channel's `parent` ref doesn't match any channel in the manifest.
    UnclaimedParent {
        channel_ref: String,
        parent_ref: String,
    },
    /// An overwrite's `role` ref doesn't match any role in the manifest.
    UnknownOverwriteRole {
        channel_ref: String,
        role_ref: String,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::DuplicateRoleRef(r) => write!(f, "duplicate role ref: {r}"),
            PlanError::DuplicateChannelRef(r) => write!(f, "duplicate channel ref: {r}"),
            PlanError::UnclaimedParent {
                channel_ref,
                parent_ref,
            } => write!(
                f,
                "channel '{channel_ref}' has parent ref '{parent_ref}' which is not in the manifest"
            ),
            PlanError::UnknownOverwriteRole {
                channel_ref,
                role_ref,
            } => write!(
                f,
                "channel '{channel_ref}' has an overwrite for role ref '{role_ref}' which is not in the manifest"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

#[derive(Debug, Clone, PartialEq)]
pub struct RoleStep {
    pub ref_id: String,
    pub name: String,
    pub priority: i64,
    pub display_separately: bool,
    pub color: Option<String>,
    pub permissions: Vec<String>,
}

/// The three channel shapes the hub's `POST /channels` route accepts
/// (`is_category` flag, or `channel_type` "text"/"forum").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubChannelKind {
    Category,
    Text,
    Forum,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChannelStep {
    pub ref_id: String,
    pub name: String,
    pub kind: HubChannelKind,
    pub parent_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OverwriteStep {
    pub channel_ref: String,
    pub role_ref: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    /// In manifest order, `@everyone` excluded.
    pub role_steps: Vec<RoleStep>,
    /// The manifest ref that represents Discord's `@everyone`, if any --
    /// resolves to `BUILTIN_EVERYONE_ROLE_ID` rather than being created.
    pub everyone_role_ref: Option<String>,
    /// Parents always precede their children; order within a depth level
    /// preserves manifest array order.
    pub channel_steps: Vec<ChannelStep>,
    /// In channel-then-array order, following `channel_steps`.
    pub overwrite_steps: Vec<OverwriteStep>,
}

fn hub_channel_kind(kind: ChannelKind) -> HubChannelKind {
    match kind {
        ChannelKind::Category => HubChannelKind::Category,
        ChannelKind::Text | ChannelKind::Voice | ChannelKind::Announcement => HubChannelKind::Text,
        ChannelKind::Forum => HubChannelKind::Forum,
    }
}

/// Depth of `channel_ref` in the parent chain (0 = top-level). Assumes
/// `by_ref` has already been validated acyclic-enough by the caller (every
/// `parent` ref resolves to a real entry); the 64-hop cap is a defensive
/// backstop, matching the convention in `hub/src/permissions.rs`.
fn depth_of(channel_ref: &str, by_ref: &HashMap<&str, &ChannelEntry>) -> usize {
    let mut depth = 0usize;
    let mut current = channel_ref;
    for _ in 0..64 {
        match by_ref.get(current).and_then(|c| c.parent.as_deref()) {
            Some(parent) => {
                depth += 1;
                current = parent;
            }
            None => break,
        }
    }
    depth
}

/// Builds the ordered apply plan from a validated manifest. Structural
/// problems (duplicate refs, dangling parent/role refs) are reported as
/// `PlanError` rather than silently dropped or fail-forwarded -- these are
/// manifest bugs, not per-item apply failures.
pub fn build_plan(manifest: &Manifest) -> Result<Plan, PlanError> {
    let mut role_steps = Vec::new();
    let mut everyone_role_ref = None;
    let mut seen_role_refs = HashSet::new();

    for r in &manifest.roles {
        if !seen_role_refs.insert(r.r#ref.as_str()) {
            return Err(PlanError::DuplicateRoleRef(r.r#ref.clone()));
        }
        if r.is_everyone {
            everyone_role_ref = Some(r.r#ref.clone());
            continue;
        }
        role_steps.push(RoleStep {
            ref_id: r.r#ref.clone(),
            name: r.name.clone(),
            priority: r.priority,
            display_separately: r.display_separately,
            color: r.color.clone(),
            permissions: r.permissions.clone(),
        });
    }

    let known_role_refs: HashSet<&str> = manifest.roles.iter().map(|r| r.r#ref.as_str()).collect();

    let mut by_ref: HashMap<&str, &ChannelEntry> = HashMap::new();
    for c in &manifest.channels {
        if by_ref.insert(c.r#ref.as_str(), c).is_some() {
            return Err(PlanError::DuplicateChannelRef(c.r#ref.clone()));
        }
    }
    for c in &manifest.channels {
        if let Some(parent_ref) = &c.parent {
            if !by_ref.contains_key(parent_ref.as_str()) {
                return Err(PlanError::UnclaimedParent {
                    channel_ref: c.r#ref.clone(),
                    parent_ref: parent_ref.clone(),
                });
            }
        }
    }

    let mut indexed: Vec<(usize, usize, &ChannelEntry)> = manifest
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| (depth_of(&c.r#ref, &by_ref), i, c))
        .collect();
    // Stable-by-index within a depth level preserves manifest array order.
    indexed.sort_by_key(|(depth, index, _)| (*depth, *index));

    let mut channel_steps = Vec::with_capacity(indexed.len());
    let mut overwrite_steps = Vec::new();
    for (_, _, c) in indexed {
        channel_steps.push(ChannelStep {
            ref_id: c.r#ref.clone(),
            name: c.name.clone(),
            kind: hub_channel_kind(c.kind),
            parent_ref: c.parent.clone(),
        });
        for ow in &c.overwrites {
            if !known_role_refs.contains(ow.role.as_str()) {
                return Err(PlanError::UnknownOverwriteRole {
                    channel_ref: c.r#ref.clone(),
                    role_ref: ow.role.clone(),
                });
            }
            overwrite_steps.push(OverwriteStep {
                channel_ref: c.r#ref.clone(),
                role_ref: ow.role.clone(),
                allow: ow.allow.clone(),
                deny: ow.deny.clone(),
            });
        }
    }

    Ok(Plan {
        role_steps,
        everyone_role_ref,
        channel_steps,
        overwrite_steps,
    })
}

/// Resolves manifest `ref`s to hub-assigned ids as `apply` creates roles
/// and channels. Kept separate from the executor so ref -> placeholder
/// resolution is unit-testable without any HTTP.
#[derive(Debug, Default)]
pub struct RefResolver {
    map: HashMap<String, String>,
}

impl RefResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds the resolver so the manifest's `@everyone` ref resolves to the
    /// hub's builtin-everyone role without ever being created.
    pub fn seed_everyone(&mut self, everyone_ref: &str) {
        self.map.insert(
            everyone_ref.to_string(),
            BUILTIN_EVERYONE_ROLE_ID.to_string(),
        );
    }

    /// Records that `manifest_ref` was created as `hub_id`.
    pub fn insert(&mut self, manifest_ref: &str, hub_id: &str) {
        self.map
            .insert(manifest_ref.to_string(), hub_id.to_string());
    }

    pub fn resolve(&self, manifest_ref: &str) -> Option<&str> {
        self.map.get(manifest_ref).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Overwrite, RoleEntry, Source};

    fn role(r: &str, is_everyone: bool) -> RoleEntry {
        RoleEntry {
            r#ref: r.to_string(),
            name: r.to_string(),
            priority: 10,
            display_separately: false,
            color: None,
            permissions: vec![],
            unmapped: vec![],
            is_everyone,
        }
    }

    fn channel(r: &str, kind: ChannelKind, parent: Option<&str>) -> ChannelEntry {
        ChannelEntry {
            r#ref: r.to_string(),
            name: r.to_string(),
            kind,
            parent: parent.map(str::to_string),
            overwrites: vec![],
        }
    }

    fn base_manifest() -> Manifest {
        Manifest {
            version: 1,
            source: Source {
                kind: "discord".to_string(),
                guild_id: "g".to_string(),
                guild_name: "g".to_string(),
                exported_at: 0,
            },
            roles: vec![],
            channels: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn everyone_role_is_mapped_not_created() {
        let mut m = base_manifest();
        m.roles = vec![role("everyone", true), role("r1", false)];
        let plan = build_plan(&m).expect("plan builds");
        assert_eq!(plan.role_steps.len(), 1);
        assert_eq!(plan.role_steps[0].ref_id, "r1");
        assert_eq!(plan.everyone_role_ref.as_deref(), Some("everyone"));
    }

    #[test]
    fn parent_always_precedes_child() {
        let mut m = base_manifest();
        // Deliberately out of order: child appears before its category.
        m.channels = vec![
            channel("child", ChannelKind::Text, Some("cat")),
            channel("cat", ChannelKind::Category, None),
            channel("grandchild-sibling", ChannelKind::Text, Some("cat")),
        ];
        let plan = build_plan(&m).expect("plan builds");
        let idx = |r: &str| {
            plan.channel_steps
                .iter()
                .position(|c| c.ref_id == r)
                .unwrap()
        };
        assert!(idx("cat") < idx("child"));
        assert!(idx("cat") < idx("grandchild-sibling"));
        // Siblings keep manifest array order.
        assert!(idx("child") < idx("grandchild-sibling"));
    }

    #[test]
    fn unclaimed_parent_is_reported() {
        let mut m = base_manifest();
        m.channels = vec![channel("orphan", ChannelKind::Text, Some("missing-cat"))];
        let err = build_plan(&m).unwrap_err();
        assert_eq!(
            err,
            PlanError::UnclaimedParent {
                channel_ref: "orphan".to_string(),
                parent_ref: "missing-cat".to_string(),
            }
        );
    }

    #[test]
    fn unknown_overwrite_role_is_reported() {
        let mut m = base_manifest();
        m.channels = vec![ChannelEntry {
            r#ref: "c1".to_string(),
            name: "c1".to_string(),
            kind: ChannelKind::Text,
            parent: None,
            overwrites: vec![Overwrite {
                role: "ghost".to_string(),
                allow: vec![],
                deny: vec![],
            }],
        }];
        let err = build_plan(&m).unwrap_err();
        assert_eq!(
            err,
            PlanError::UnknownOverwriteRole {
                channel_ref: "c1".to_string(),
                role_ref: "ghost".to_string(),
            }
        );
    }

    #[test]
    fn channel_kinds_map_to_hub_shapes() {
        let mut m = base_manifest();
        m.channels = vec![
            channel("cat", ChannelKind::Category, None),
            channel("txt", ChannelKind::Text, None),
            channel("voice", ChannelKind::Voice, None),
            channel("ann", ChannelKind::Announcement, None),
            channel("forum", ChannelKind::Forum, None),
        ];
        let plan = build_plan(&m).unwrap();
        let kind_of = |r: &str| {
            plan.channel_steps
                .iter()
                .find(|c| c.ref_id == r)
                .unwrap()
                .kind
        };
        assert_eq!(kind_of("cat"), HubChannelKind::Category);
        assert_eq!(kind_of("txt"), HubChannelKind::Text);
        assert_eq!(kind_of("voice"), HubChannelKind::Text);
        assert_eq!(kind_of("ann"), HubChannelKind::Text);
        assert_eq!(kind_of("forum"), HubChannelKind::Forum);
    }

    #[test]
    fn ref_resolver_resolves_everyone_and_created_ids() {
        let mut resolver = RefResolver::new();
        resolver.seed_everyone("everyone");
        resolver.insert("r1", "hub-role-id-1");
        resolver.insert("c1", "hub-channel-id-1");

        assert_eq!(resolver.resolve("everyone"), Some(BUILTIN_EVERYONE_ROLE_ID));
        assert_eq!(resolver.resolve("r1"), Some("hub-role-id-1"));
        assert_eq!(resolver.resolve("c1"), Some("hub-channel-id-1"));
        assert_eq!(resolver.resolve("nonexistent"), None);
    }

    #[test]
    fn duplicate_role_ref_is_reported() {
        let mut m = base_manifest();
        m.roles = vec![role("r1", false), role("r1", false)];
        let err = build_plan(&m).unwrap_err();
        assert_eq!(err, PlanError::DuplicateRoleRef("r1".to_string()));
    }

    #[test]
    fn duplicate_channel_ref_is_reported() {
        let mut m = base_manifest();
        m.channels = vec![
            channel("c1", ChannelKind::Text, None),
            channel("c1", ChannelKind::Text, None),
        ];
        let err = build_plan(&m).unwrap_err();
        assert_eq!(err, PlanError::DuplicateChannelRef("c1".to_string()));
    }
}

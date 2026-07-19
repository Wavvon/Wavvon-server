use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Bot metadata sent by the bot operator at auth / accept-invite time.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotMeta {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<BotCommandDef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotCommandDef {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<i64>,
}

// ---------------------------------------------------------------------------
// Directory / profile types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotProfile {
    pub pubkey: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    pub capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// Event subscription
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotSubscription {
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Slash-command invocation envelope (hub → bot webhook)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthorInfo {
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashInvocation {
    #[serde(rename = "type")]
    pub kind: String, // always "slash_command"
    pub hub_url: String,
    pub channel_id: String,
    pub message_id_hint: String,
    pub author: AuthorInfo,
    pub command: String,
    pub args_raw: String,
    pub args_tokens: Vec<String>,
}

// ---------------------------------------------------------------------------
// Component interaction envelope (hub → bot webhook)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentInteraction {
    #[serde(rename = "type")]
    pub kind: String, // always "component_interaction"
    pub hub_url: String,
    pub channel_id: String,
    pub message_id: String,
    pub custom_id: String,
    pub values: Vec<String>,
    pub user: AuthorInfo,
}

// ---------------------------------------------------------------------------
// Bot response types (bot → hub, synchronous)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotReaction {
    pub message_id: String,
    pub emoji: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbedField {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbedFooter {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Embed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<EmbedField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SelectOption {
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotComponent {
    #[serde(rename = "type")]
    pub kind: String, // "button" or "select"
    pub custom_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_values: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOption>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentRow {
    #[serde(rename = "type")]
    pub kind: String, // always "row"
    pub components: Vec<BotComponent>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotReply {
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeds: Option<Vec<Embed>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<BotReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reactions: Option<Vec<BotReaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
    /// Game-modal launch card (bot-capability-layer.md §2, §6 Phase 1 item
    /// 3): a "Play" CTA attached to `reply`'s message. Baseline UI -- no
    /// capability grant needed to render the card itself; opening the
    /// webview it points at is what `can_use_interactive_ui` gates
    /// (`bot_app_join`, routes/ws/handlers/mini_app.rs). Ignored if `reply`
    /// is absent -- there is no message for the card to attach to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game: Option<GameLaunchCard>,
}

/// A bot-authored "Play" launch card (bot-capability-layer.md §2).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GameLaunchCard {
    pub entry_url: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Component response types (bot → hub, on component interaction)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<ComponentRow>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EphemeralReply {
    pub body: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComponentResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<ComponentUpdate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_reply: Option<EphemeralReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defer: Option<bool>,
}

// ---------------------------------------------------------------------------
// Hub event push (hub → bot WebSocket)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HubEvent {
    #[serde(rename = "type")]
    pub kind: String, // always "hub_event"
    pub event: String,
    pub hub_url: String,
    pub at: i64,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replayed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Lifecycle messages (hub → bot WebSocket)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BotRemovedMsg {
    #[serde(rename = "type")]
    pub kind: String, // always "bot_removed"
    pub reason: String,
    pub hub_url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenExpiringSoon {
    #[serde(rename = "type")]
    pub kind: String, // always "token_expiring_soon"
    pub expires_at: i64,
}

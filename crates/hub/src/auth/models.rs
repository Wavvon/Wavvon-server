use serde::{Deserialize, Serialize};
use wavvon_identity::SubkeyCert;

use crate::routes::certs::Certification;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

/// Structured proof-of-work submitted alongside auth/verify.
/// `nonce` is the decimal string representation of the u64 nonce that was
/// searched; `level` is the number of leading zero bits the client claims.
#[derive(Deserialize, Serialize, Clone)]
pub struct PowProof {
    pub level: u8,
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub public_key: String,
    pub challenge: String,
    pub signature: String,
    pub invite_code: Option<String>,
    pub security_nonce: Option<u64>,
    pub security_level: Option<u32>,
    /// Structured PoW proof for the `min_pow_level` gate.  When the hub has
    /// `min_pow_level > 0`, this field is required and must satisfy the
    /// minimum.  Clients that pre-compute PoW store the nonce + level in
    /// their identity file and submit them here at auth time.
    #[serde(default)]
    pub pow_proof: Option<PowProof>,
    /// Multi-device: when present, `public_key` is the device's
    /// subkey and the cert links it to a master. The hub uses the
    /// master to find the canonical user row across devices.
    #[serde(default)]
    pub subkey_cert: Option<SubkeyCert>,
    /// Admission challenge token (required when challenge_mode != 'off').
    #[serde(default)]
    pub challenge_token: Option<String>,
    /// Hub self-declaration. When true the caller is a peer hub authenticating
    /// for federation delivery.  The hub is auto-registered in the `peers`
    /// table and does NOT receive human role assignments.  The token is tagged
    /// so that `PeerHub` can distinguish it from regular user sessions.
    #[serde(default)]
    pub is_hub: Option<bool>,
    /// Hub certifications presented at auth time. Evaluated when
    /// cert_mode != 'none' (Task #21).
    #[serde(default)]
    pub certifications: Option<Vec<Certification>>,
    /// Voice in alliance channels (alliances.md): an origin hub's signed
    /// assertion that the caller is its member and the named channel is shared
    /// with an alliance this hub is in. Admits a **visitor** — an
    /// `alliance_voice`-scoped session with no `users` row — and is ignored
    /// entirely for anyone who is already a member here, who has a better
    /// session available.
    #[serde(default)]
    pub alliance_voice_grant: Option<crate::routes::alliances::AllianceVoiceGrant>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse {
    pub token: String,
    /// "lobby" when lobby is enabled and the user's pow_level is below min_security_level,
    /// otherwise "member".
    #[serde(default)]
    pub scope: String,
    /// The canonical user identity this session acts as. For a legacy
    /// single-key auth this equals the auth pubkey, but for a paired device
    /// (auth via subkey cert) it is the shared master/legacy pubkey the hub
    /// attributes the device's actions to. Clients use it to self-identify.
    #[serde(default)]
    pub canonical_pubkey: String,
}

/// Optional challenge token presented during auth/verify when challenge_mode != 'off'.
#[derive(Deserialize, Default)]
pub struct ChallengeTokenField {
    #[serde(default)]
    pub challenge_token: Option<String>,
}

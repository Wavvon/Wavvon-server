use anyhow::Result;
use serde::Deserialize;
use voxply_identity::Identity;

#[derive(Deserialize)]
struct ChallengeResponse {
    challenge: String,
}
#[derive(Deserialize)]
struct VerifyResponse {
    token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let hub_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    let path = Identity::default_path()?;
    let (identity, _) = Identity::load_or_create(&path)?;
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&serde_json::json!({ "public_key": pub_key }))
        .send()
        .await?
        .json()
        .await?;

    let challenge_bytes = hex::decode(&challenge.challenge)?;
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&serde_json::json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await?
        .json()
        .await?;

    let token = &verify.token;
    println!("Authenticated as {}...", &pub_key[..16]);

    client
        .patch(format!("{hub_url}/me"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "display_name": "Admin" }))
        .send()
        .await?;
    println!("Set display name: Admin");

    for name in ["general", "random", "gaming"] {
        let resp = client
            .post(format!("{hub_url}/channels"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await?;
        if resp.status().is_success() {
            println!("Created channel: #{name}");
        } else {
            println!("Channel #{name} already exists");
        }
    }

    let resp = client
        .get(format!("{hub_url}/channels"))
        .bearer_auth(token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        eprintln!("GET /channels failed ({status}): {body}");
        return Ok(());
    }
    let channels: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse channels: {e}. Body: {body}"))?;

    if let Some(general) = channels.iter().find(|c| c["name"] == "general") {
        let ch_id = general["id"].as_str().unwrap();
        for msg in [
            "Welcome to Voxply!",
            "This is the general channel.",
            "Say hi!",
        ] {
            client
                .post(format!("{hub_url}/channels/{ch_id}/messages"))
                .bearer_auth(token)
                .json(&serde_json::json!({ "content": msg }))
                .send()
                .await?;
            println!("Sent: {msg}");
        }
    }

    println!("Done! Hub is seeded.");
    Ok(())
}

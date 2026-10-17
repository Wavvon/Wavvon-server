use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// Alliance member discovery (alliance-member-discovery.md). The owning hub
// answers from its own users table, to an allied peer hub, only for members
// who opted in AND under an alliance whose manager allowed it.

async fn authenticate_as_hub(server: &axum_test::TestServer, hub: &Identity) -> String {
    let pub_key = hub.public_key_hex();
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let verify: serde_json::Value = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(hub.sign(&bytes).to_bytes()),
            "is_hub": true,
        }))
        .await
        .json();
    verify["token"].as_str().unwrap().to_string()
}

/// A member with a display name, who may be findable and reachable.
async fn member(
    h: &common::TestHarness,
    name: &str,
    findable: bool,
    designated: bool,
) -> (Identity, String) {
    let id = Identity::generate();
    let token = common::authenticate(h, &id).await;
    h.patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "display_name": name, "findable_by_allies": findable }))
        .await
        .assert_status_success();
    if designated {
        let master = format!("master-{name}");
        sqlx::query("UPDATE users SET master_pubkey = $1 WHERE public_key = $2")
            .bind(&master)
            .bind(id.public_key_hex())
            .execute(&h.state().db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO home_hub_designations
             (master_pubkey, hubs_json, issued_at, sequence, signature, updated_at)
             VALUES ($1, '[]', 0, 1, 'sig', 0)",
        )
        .bind(&master)
        .execute(&h.state().db)
        .await
        .unwrap();
    }
    (id, token)
}

/// An alliance, plus an allied peer hub already seated in it.
async fn alliance_with_ally(
    h: &common::TestHarness,
    owner: &str,
    people_visible: bool,
) -> (String, String) {
    let alliance: serde_json::Value = h
        .post("/alliances")
        .authorization_bearer(owner)
        .json(&json!({ "name": "Sewing" }))
        .await
        .json();
    let id = alliance["id"].as_str().unwrap().to_string();
    if people_visible {
        h.put(&format!("/alliances/{id}/people-visibility"))
            .authorization_bearer(owner)
            .json(&json!({ "visible": true }))
            .await
            .assert_status(axum::http::StatusCode::NO_CONTENT);
    }
    let ally = Identity::generate();
    let token = authenticate_as_hub(h, &ally).await;
    sqlx::query(
        "INSERT INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at)
         VALUES ($1, $2, 'ally', 'http://ally.invalid', 0)",
    )
    .bind(&id)
    .bind(ally.public_key_hex())
    .execute(&h.state().db)
    .await
    .unwrap();
    (id, token)
}

#[tokio::test]
async fn an_ally_sees_only_opted_in_reachable_members() {
    let (h, owner) = common::setup_with_owner().await;
    let (alice, _) = member(&h, "Alice", true, true).await;
    member(&h, "Bob", false, true).await; // did not opt in
    member(&h, "Carol", true, false).await; // opted in, no designation: unreachable
    let (alliance, ally) = alliance_with_ally(&h, &owner, true).await;

    let resp = h
        .get(&format!("/alliances/{alliance}/people"))
        .authorization_bearer(&ally)
        .await;
    resp.assert_status_ok();
    let people: serde_json::Value = resp.json();
    assert_eq!(people.as_array().unwrap().len(), 1, "got {people}");
    assert_eq!(people[0]["public_key"], alice.public_key_hex());
    assert_eq!(people[0]["master_pubkey"], "master-Alice");
    assert_eq!(people[0]["display_name"], "Alice");
    // Nothing beyond the four fields leaves the hub.
    assert_eq!(people[0].as_object().unwrap().len(), 4);

    // Keyset paging: the cursor is the last entry.
    let after: serde_json::Value = h
        .get(&format!(
            "/alliances/{alliance}/people?limit=1&cursor={}",
            alice.public_key_hex()
        ))
        .authorization_bearer(&ally)
        .await
        .json();
    assert!(after.as_array().unwrap().is_empty());

    let named: serde_json::Value = h
        .get(&format!("/alliances/{alliance}/people?q=zzz"))
        .authorization_bearer(&ally)
        .await
        .json();
    assert!(named.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_member_who_opts_out_disappears_at_once() {
    let (h, owner) = common::setup_with_owner().await;
    let (_, alice_token) = member(&h, "Alice", true, true).await;
    let (alliance, ally) = alliance_with_ally(&h, &owner, true).await;

    h.patch("/me")
        .authorization_bearer(&alice_token)
        .json(&json!({ "findable_by_allies": false }))
        .await
        .assert_status_success();

    let people: serde_json::Value = h
        .get(&format!("/alliances/{alliance}/people"))
        .authorization_bearer(&ally)
        .await
        .json();
    assert!(people.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn people_are_withheld_until_the_alliance_allows_it() {
    let (h, owner) = common::setup_with_owner().await;
    member(&h, "Alice", true, true).await;
    let (alliance, ally) = alliance_with_ally(&h, &owner, false).await;

    h.get(&format!("/alliances/{alliance}/people"))
        .authorization_bearer(&ally)
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn a_hub_outside_the_alliance_is_refused() {
    let (h, owner) = common::setup_with_owner().await;
    member(&h, "Alice", true, true).await;
    let (alliance, _) = alliance_with_ally(&h, &owner, true).await;

    let stranger = authenticate_as_hub(&h, &Identity::generate()).await;
    h.get(&format!("/alliances/{alliance}/people"))
        .authorization_bearer(&stranger)
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn a_peer_cannot_use_this_hub_to_reach_a_third() {
    let (h, owner) = common::setup_with_owner().await;
    let (alliance, ally) = alliance_with_ally(&h, &owner, true).await;
    let third = Identity::generate().public_key_hex();
    sqlx::query(
        "INSERT INTO alliance_members (alliance_id, hub_public_key, hub_name, hub_url, joined_at)
         VALUES ($1, $2, 'third', 'http://third.invalid', 0)",
    )
    .bind(&alliance)
    .bind(&third)
    .execute(&h.state().db)
    .await
    .unwrap();

    h.get(&format!("/alliances/{alliance}/people?hub={third}"))
        .authorization_bearer(&ally)
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn only_a_manager_flips_the_alliance_switch_and_a_peer_never_does() {
    let (h, owner) = common::setup_with_owner().await;
    let (_, plain) = member(&h, "Alice", false, false).await;
    let (alliance, ally) = alliance_with_ally(&h, &owner, false).await;

    let body = json!({ "visible": true });
    h.put(&format!("/alliances/{alliance}/people-visibility"))
        .authorization_bearer(&plain)
        .json(&body)
        .await
        .assert_status_forbidden();
    h.put(&format!("/alliances/{alliance}/people-visibility"))
        .authorization_bearer(&ally)
        .json(&body)
        .await
        .assert_status_forbidden();

    let detail: serde_json::Value = h
        .get(&format!("/alliances/{alliance}"))
        .authorization_bearer(&owner)
        .await
        .json();
    assert_eq!(detail["people_visible"], false);
}

#[tokio::test]
async fn the_member_switch_defaults_off_and_round_trips() {
    let (h, _) = common::setup_with_owner().await;
    let (_, token) = member(&h, "Dave", false, false).await;
    let me: serde_json::Value = h.get("/me").authorization_bearer(&token).await.json();
    assert_eq!(me["findable_by_allies"], false);
    let me: serde_json::Value = h
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "findable_by_allies": true }))
        .await
        .json();
    assert_eq!(me["findable_by_allies"], true);
}

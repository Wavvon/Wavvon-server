//! The join application (join-forms.md): a form a joiner fills while
//! pending, read by a moderator who approves or rejects it.

use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

fn application() -> Value {
    json!({
        "id": "app-1",
        "enabled": true,
        "questions": [
            { "id": "how", "prompt": "How did you find us?", "kind": "text",
              "required": true, "display_order": 1, "max_len": 200 },
            { "id": "adult", "prompt": "I am 18 or older", "kind": "consent",
              "required": true, "display_order": 2 },
            { "id": "games", "prompt": "What do you play?", "kind": "multi",
              "required": false, "display_order": 3, "max_choices": 2,
              "choices": [
                  { "id": "g1", "label": "Shooters", "display_order": 1 },
                  { "id": "g2", "label": "Strategy", "display_order": 2 },
                  { "id": "g3", "label": "Racing", "display_order": 3 },
              ] },
        ]
    })
}

fn answers(adult: bool) -> Value {
    json!({
        "survey_id": "app-1",
        "answers": [
            { "question_id": "how", "text_answer": "A friend" },
            { "question_id": "adult", "checked": adult },
            { "question_id": "games", "choice_ids": ["g1", "g2"] },
        ]
    })
}

#[tokio::test]
async fn an_applicant_waits_with_their_answers_until_a_moderator_decides() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .put("/admin/application")
        .authorization_bearer(&owner_token)
        .json(&application())
        .await
        .assert_status_ok();

    // Readable before joining, with no session at all.
    let form: Value = server.get("/application").await.json();
    assert_eq!(form["id"], "app-1");
    assert_eq!(form["questions"][1]["kind"], "consent");

    // An enabled application seats every newcomer pending.
    let joiner = Identity::generate();
    let token = common::authenticate(&server, &joiner).await;
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // An unchecked consent is refused by the hub, naming the question.
    let resp = server
        .post("/application")
        .authorization_bearer(&token)
        .json(&answers(false))
        .await;
    resp.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(resp.text(), "consent_refused:adult");

    server
        .post("/application")
        .authorization_bearer(&token)
        .json(&answers(true))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let status: Value = server
        .get("/application/status")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(status["state"], "submitted");

    let queue: Vec<Value> = server
        .get("/hub/pending")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let entry = queue
        .iter()
        .find(|p| p["public_key"] == joiner.public_key_hex())
        .expect("the applicant is in the queue");
    assert_eq!(entry["has_application"], true);

    let response: Value = server
        .get(&format!(
            "/admin/application/responses/{}",
            joiner.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let by_q = |q: &str| {
        response["answers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["question_id"] == q)
            .unwrap()
            .clone()
    };
    assert_eq!(by_q("how")["text_answer"], "A friend");
    assert_eq!(by_q("adult")["checked"], true);
    assert_eq!(by_q("games")["choice_label"], "Shooters, Strategy");

    server
        .post(&format!("/hub/pending/{}/approve", joiner.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_rejected_applicant_reads_why_and_leaves_the_queue() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    server
        .put("/admin/application")
        .authorization_bearer(&owner_token)
        .json(&application())
        .await
        .assert_status_ok();

    let joiner = Identity::generate();
    let token = common::authenticate(&server, &joiner).await;
    server
        .post("/application")
        .authorization_bearer(&token)
        .json(&answers(true))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .post(&format!("/hub/pending/{}/reject", joiner.public_key_hex()))
        .authorization_bearer(&owner_token)
        .json(&json!({ "reason": "Adults-only community" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let status: Value = server
        .get("/application/status")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(status["state"], "rejected");
    assert_eq!(status["reason"], "Adults-only community");
    assert!(status["retry_after"].as_i64().is_some());

    let queue: Vec<Value> = server
        .get("/hub/pending")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(queue
        .iter()
        .all(|p| p["public_key"] != joiner.public_key_hex()));

    // Applying again before the cooldown is refused.
    server
        .post("/application")
        .authorization_bearer(&token)
        .json(&answers(true))
        .await
        .assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn an_application_cannot_grant_roles_and_its_answers_need_admission() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let mut form = application();
    form["questions"][2]["choices"][0]["role_ids"] = json!(["builtin-everyone"]);
    server
        .put("/admin/application")
        .authorization_bearer(&owner_token)
        .json(&form)
        .await
        .assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);

    // An ordinary member cannot read anyone's application.
    server
        .put("/admin/application")
        .authorization_bearer(&owner_token)
        .json(&application())
        .await
        .assert_status_ok();
    let joiner = Identity::generate();
    common::authenticate(&server, &joiner).await;
    server
        .post(&format!("/hub/pending/{}/approve", joiner.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();
    let member_token = common::authenticate(&server, &joiner).await;
    server
        .get(&format!(
            "/admin/application/responses/{}",
            owner.public_key_hex()
        ))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

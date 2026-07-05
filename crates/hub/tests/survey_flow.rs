use serde_json::{json, Value};
use wavvon_hub::routes::me::MeResponse;
use wavvon_hub::routes::role_models::RoleResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

fn sample_survey(survey_id: &str, enabled: bool) -> Value {
    json!({
        "id": survey_id,
        "enabled": enabled,
        "questions": [
            {
                "id": "q1",
                "prompt": "How did you find us?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "Search engine", "display_order": 1, "role_ids": [] },
                    { "id": "c2", "label": "Friend", "display_order": 2, "role_ids": [] },
                ]
            },
            {
                "id": "q2",
                "prompt": "Anything else?",
                "kind": "text",
                "required": false,
                "display_order": 2,
            }
        ]
    })
}

#[tokio::test]
async fn survey_current_returns_null_when_no_survey() {
    let server = common::setup().await;
    let user = Identity::generate();
    let token = common::authenticate(&server, &user).await;

    let resp = server
        .get("/survey/current")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body.is_null());
}

#[tokio::test]
async fn admin_can_create_and_retrieve_survey() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-001";
    let survey = sample_survey(survey_id, true);

    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await;
    resp.assert_status_ok();

    // GET /survey/current should now return the survey
    let resp = server
        .get("/survey/current")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], survey_id);
    let questions = body["questions"].as_array().unwrap();
    assert_eq!(questions.len(), 2);

    // Role mappings should NOT appear in /survey/current (public view)
    let first_q = &questions[0];
    let first_choice = &first_q["choices"][0];
    assert!(
        first_choice.get("role_ids").is_none(),
        "role_ids should be absent from public survey view"
    );
}

#[tokio::test]
async fn admin_get_survey_includes_role_ids() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-admin-001";
    let survey = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Choose your role",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "Developer", "display_order": 1, "role_ids": ["builtin-everyone"] },
                ]
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await
        .assert_status_ok();

    // Admin GET should include role_ids
    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(!body.is_null());
    let choices = &body["questions"][0]["choices"];
    let role_ids = choices[0]["role_ids"].as_array().unwrap();
    assert_eq!(role_ids.len(), 1);
    assert_eq!(role_ids[0], "builtin-everyone");
}

#[tokio::test]
async fn survey_submit_happy_path_choice_only() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-submit-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [
                { "question_id": "q1", "choice_id": "c1" }
            ]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // No text answers ? should be approved
    assert_eq!(body["next_state"], "approved");
    let applied: &Vec<Value> = body["applied_roles"].as_array().unwrap();
    assert!(applied.is_empty()); // c1 has no role_ids in sample_survey
}

#[tokio::test]
async fn survey_submit_text_answer_sets_pending() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-text-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [
                { "question_id": "q1", "choice_id": "c1" },
                { "question_id": "q2", "text_answer": "I found you via a forum post" }
            ]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // Has text answer ? should be pending
    assert_eq!(body["next_state"], "pending");
}

#[tokio::test]
async fn survey_submit_required_question_missing_returns_error() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-req-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    // q1 is required but not answered
    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": []
        }))
        .await;
    // Should be 422 Unprocessable Entity
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn survey_cannot_be_submitted_twice() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-dedup-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let answers = json!({
        "survey_id": survey_id,
        "answers": [{ "question_id": "q1", "choice_id": "c1" }]
    });

    server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&answers)
        .await
        .assert_status_ok();

    // Second attempt should fail
    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&answers)
        .await;
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn admin_can_list_survey_responses() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let survey_id = "survey-resp-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [{ "question_id": "q1", "choice_id": "c1" }]
        }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/survey/responses")
        .authorization_bearer(&owner_token)
        .add_query_param("status", "all")
        .await;
    resp.assert_status_ok();
    let responses: Value = resp.json();
    let arr = responses.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pubkey"], user.public_key_hex());
}

#[tokio::test]
async fn non_admin_cannot_access_admin_survey_routes() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let _owner_token = common::authenticate(&server, &owner).await;
    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    // PUT /admin/survey requires admin
    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&user_token)
        .json(&sample_survey("x", true))
        .await;
    resp.assert_status_forbidden();

    // GET /admin/survey requires admin
    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&user_token)
        .await;
    resp.assert_status_forbidden();

    // GET /admin/survey/responses requires admin
    let resp = server
        .get("/admin/survey/responses")
        .authorization_bearer(&user_token)
        .await;
    resp.assert_status_forbidden();
}

// ---------------------------------------------------------------------------
// Role mapping — CRUD, completion auto-assign, admin-permission rejection,
// free-text-does-not-auto-assign (docs/docs/lobby-bot-survey.md Feature 3).
// ---------------------------------------------------------------------------

async fn create_role(
    server: &axum_test::TestServer,
    token: &str,
    name: &str,
    permissions: &[&str],
) -> RoleResponse {
    server
        .post("/roles")
        .authorization_bearer(token)
        .json(&json!({
            "name": name,
            "permissions": permissions,
            "priority": 10,
        }))
        .await
        .json()
}

#[tokio::test]
async fn survey_role_mapping_crud() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let role = create_role(&server, &owner_token, "Gamer", &["send_messages"]).await;

    let survey_id = "survey-mapping-crud";
    let survey = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": [role.id] },
                ]
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let role_ids = body["questions"][0]["choices"][0]["role_ids"]
        .as_array()
        .unwrap();
    assert_eq!(role_ids.len(), 1);
    assert_eq!(role_ids[0], role.id);

    // Update: remove the mapping.
    let updated = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": [] },
                ]
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&updated)
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let role_ids = body["questions"][0]["choices"][0]["role_ids"]
        .as_array()
        .unwrap();
    assert!(role_ids.is_empty(), "mapping should have been removed");
}

#[tokio::test]
async fn survey_completion_auto_assigns_mapped_role() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let role = create_role(&server, &owner_token, "PC Player", &["send_messages"]).await;

    let survey_id = "survey-auto-assign";
    let survey = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": [role.id] },
                ]
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [{ "question_id": "q1", "choice_id": "c1" }]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["next_state"], "approved");
    let applied: Vec<String> = serde_json::from_value(body["applied_roles"].clone()).unwrap();
    assert!(applied.contains(&role.id));

    // Confirm the role actually landed on the user, not just in the response.
    let me: MeResponse = server
        .get("/me")
        .authorization_bearer(&user_token)
        .await
        .json();
    assert!(me.roles.iter().any(|r| r.id == role.id));
}

#[tokio::test]
async fn survey_mapping_to_admin_permission_role_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let admin_role = create_role(&server, &owner_token, "Shadow Admin", &["admin"]).await;

    let survey = json!({
        "id": "survey-admin-mapping",
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": [admin_role.id] },
                ]
            }
        ]
    });

    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await;
    assert!(!resp.status_code().is_success());

    // Also reject a mapping to a role id that doesn't exist at all.
    let bogus = json!({
        "id": "survey-bogus-mapping",
        "enabled": false,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": ["does-not-exist"] },
                ]
            }
        ]
    });
    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&bogus)
        .await;
    assert!(!resp.status_code().is_success());

    // builtin-owner (which carries admin) is rejected the same way.
    let owner_mapping = json!({
        "id": "survey-owner-mapping",
        "enabled": false,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": ["builtin-owner"] },
                ]
            }
        ]
    });
    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&owner_mapping)
        .await;
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn survey_free_text_path_does_not_auto_assign_roles() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let role = create_role(&server, &owner_token, "PC Player", &["send_messages"]).await;

    let survey_id = "survey-mixed-text";
    let survey = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Platform?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "PC", "display_order": 1, "role_ids": [role.id] },
                ]
            },
            {
                "id": "q2",
                "prompt": "Anything else?",
                "kind": "text",
                "required": false,
                "display_order": 2,
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    // Answers a multiple-choice question (mapped to a role) *and* a
    // free-text question. Per the doc's Feature 3 decisions, free-text
    // always routes to manual review, so no role is auto-assigned even
    // though the choice answer alone would have earned one.
    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [
                { "question_id": "q1", "choice_id": "c1" },
                { "question_id": "q2", "text_answer": "I'm a vendor" }
            ]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["next_state"], "pending");
    let applied: &Vec<Value> = body["applied_roles"].as_array().unwrap();
    assert!(
        applied.is_empty(),
        "roles must not auto-assign when a free-text question was answered"
    );

    let me: MeResponse = server
        .get("/me")
        .authorization_bearer(&user_token)
        .await
        .json();
    assert!(
        !me.roles.iter().any(|r| r.id == role.id),
        "mapped role must not land on the user when the submission includes free text"
    );
}

//! Integration tests for `wavvon-hub setup` (task #32): the non-interactive
//! file-generation path. Runs against a real temp directory but touches no
//! database and no network — the wizard itself never does either.
use std::path::Path;

use wavvon_hub::setup::{generate_files, validate, DeploymentMode, SetupInputs};

fn public_inputs(out_dir: &str) -> SetupInputs {
    SetupInputs {
        name: Some("Test Community".to_string()),
        template: Some("gaming".to_string()),
        mode: Some("public".to_string()),
        domain: Some("hub.example.com".to_string()),
        out_dir: Some(out_dir.to_string()),
        start: false,
        non_interactive: true,
    }
}

fn lan_inputs(out_dir: &str) -> SetupInputs {
    SetupInputs {
        name: Some("LAN Hub".to_string()),
        template: Some("minimal".to_string()),
        mode: Some("lan".to_string()),
        domain: None,
        out_dir: Some(out_dir.to_string()),
        start: false,
        non_interactive: true,
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("could not read {path:?}: {e}"))
}

// ── Happy path: public-domain mode ───────────────────────────────────────────

#[test]
fn public_mode_generates_compose_and_env() {
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("wavvon-hub");

    let cfg = validate(public_inputs(out_dir.to_str().unwrap())).unwrap();
    let generated = generate_files(&cfg).unwrap();

    assert!(generated.compose_path.exists());
    assert!(generated.env_path.exists());

    let compose = read(&generated.compose_path);
    let env = read(&generated.env_path);

    // Sidecar present, DB not exposed on a host port.
    assert!(compose.contains("postgres:16-alpine"));
    assert!(compose.contains("condition: service_healthy"));
    assert!(!compose.contains("5432:5432"));

    // Chosen preset wired through.
    assert!(env.contains("WAVVON_TEMPLATE=gaming"));

    // Public-mode specifics.
    assert!(env.contains("WAVVON_PUBLIC_URL=https://hub.example.com"));
    assert!(env.contains("WAVVON_TRUSTED_PROXY=true"));
    assert!(!env.contains("WAVVON_LAN_MODE"));
    assert!(compose.contains("127.0.0.1:3000:3000"));

    // Generated DB password: present, non-empty, and wired into the
    // connection string and the sidecar's env-substituted password.
    assert!(!generated.db_password.is_empty());
    assert!(env.contains(&format!("WAVVON_DB_PASSWORD={}", generated.db_password)));
    assert!(env.contains(&format!(
        "postgres://wavvon:{}@db:5432/wavvon",
        generated.db_password
    )));
    assert!(compose.contains("${WAVVON_DB_PASSWORD}"));
}

// ── Happy path: LAN mode ─────────────────────────────────────────────────────

#[test]
fn lan_mode_generates_compose_and_env() {
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("wavvon-hub");

    let cfg = validate(lan_inputs(out_dir.to_str().unwrap())).unwrap();
    let generated = generate_files(&cfg).unwrap();

    let compose = read(&generated.compose_path);
    let env = read(&generated.env_path);

    assert!(compose.contains("postgres:16-alpine"));
    assert!(env.contains("WAVVON_TEMPLATE=minimal"));
    assert!(env.contains("WAVVON_LAN_MODE=true"));
    assert!(!env.contains("WAVVON_PUBLIC_URL"));
    // LAN mode publishes the HTTP port on every interface, not loopback-only.
    assert!(compose.contains("\"3000:3000\""));
    assert!(matches!(cfg.mode, DeploymentMode::Lan));
}

// ── Two runs never reuse a password ─────────────────────────────────────────

#[test]
fn two_runs_generate_different_passwords() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let cfg1 = validate(public_inputs(tmp1.path().to_str().unwrap())).unwrap();
    let cfg2 = validate(public_inputs(tmp2.path().to_str().unwrap())).unwrap();

    let gen1 = generate_files(&cfg1).unwrap();
    let gen2 = generate_files(&cfg2).unwrap();

    assert_ne!(
        gen1.db_password, gen2.db_password,
        "each run must generate a fresh database password"
    );
}

// ── Output directory is created if missing ──────────────────────────────────

#[test]
fn creates_output_directory_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("nested").join("wavvon-hub");
    assert!(!out_dir.exists());

    let cfg = validate(public_inputs(out_dir.to_str().unwrap())).unwrap();
    generate_files(&cfg).unwrap();

    assert!(out_dir.is_dir());
}

// ── Rejection: bad preset name never reaches file generation ────────────────

#[test]
fn bad_preset_name_is_rejected_before_writing_anything() {
    let tmp = tempfile::tempdir().unwrap();
    let mut inputs = public_inputs(tmp.path().to_str().unwrap());
    inputs.template = Some("not-a-real-preset".to_string());

    let err = validate(inputs).unwrap_err();
    assert!(err.contains("not-a-real-preset"));
    assert!(
        std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
        "nothing should be written when validation fails"
    );
}

// ── Rejection: public mode without a domain ─────────────────────────────────

#[test]
fn public_mode_without_domain_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let mut inputs = public_inputs(tmp.path().to_str().unwrap());
    inputs.domain = None;

    let err = validate(inputs).unwrap_err();
    assert!(err.contains("domain"));
}

// ── Rejection: LAN mode with a domain ────────────────────────────────────────

#[test]
fn lan_mode_with_domain_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let mut inputs = lan_inputs(tmp.path().to_str().unwrap());
    inputs.domain = Some("shouldnt-be-here.example.com".to_string());

    let err = validate(inputs).unwrap_err();
    assert!(err.contains("lan"));
}

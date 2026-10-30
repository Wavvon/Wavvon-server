#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use wavvon_identity::Identity;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn identity_is_saved_owner_only_and_an_old_file_is_narrowed_on_load() {
    let dir = std::env::temp_dir().join(format!("wavvon-secret-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub_identity.json");

    Identity::generate().save(&path).unwrap();
    assert_eq!(mode(&path), 0o600);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    Identity::load(&path).unwrap();
    assert_eq!(mode(&path), 0o600);

    std::fs::remove_dir_all(&dir).unwrap();
}

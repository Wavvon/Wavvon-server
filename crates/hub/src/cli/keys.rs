use std::path::Path;

use anyhow::Context;
use wavvon_identity::Identity;

/// For a hub already restarted under a new key while its old identity file
/// was kept (Wavvon-server#342): the old key signs the same handover payload
/// `rotate-key` writes, naming the *current* key, so clients that knew the
/// old key follow. The live identity is left alone.
pub fn endorse_current_key(old_path: &Path, current_path: &Path, out: &Path) -> anyhow::Result<()> {
    let old = Identity::load(old_path)
        .with_context(|| format!("Could not read an identity from {}", old_path.display()))?;
    let current =
        Identity::load(current_path).context("Failed to load the current hub identity")?;
    let (old_pubkey_hex, new_pubkey_hex) = (old.public_key_hex(), current.public_key_hex());
    anyhow::ensure!(
        old_pubkey_hex != new_pubkey_hex,
        "The old file holds the current key: nothing to endorse"
    );
    let effective_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload_str = format!("{old_pubkey_hex}:{new_pubkey_hex}:{effective_at}");
    let sig = old.sign(payload_str.as_bytes());
    let rotation = serde_json::json!({
        "old_pubkey": old_pubkey_hex,
        "new_pubkey": new_pubkey_hex,
        "effective_at": effective_at,
        "signature": hex::encode(sig.to_bytes()),
    });
    std::fs::write(out, serde_json::to_string_pretty(&rotation)?)?;
    Ok(())
}

/// Generate a new hub keypair, sign a rotation payload with the old key,
/// write it to `hub_rotation.json`, and replace `hub_identity.json` with
/// the new key. The operator must restart the hub afterwards.
pub fn rotate_hub_key(current_path: &Path) -> anyhow::Result<()> {
    let old_identity =
        Identity::load(current_path).context("Failed to load current hub identity")?;

    let new_identity = Identity::generate();

    let old_pubkey_hex = old_identity.public_key_hex();
    let new_pubkey_hex = new_identity.public_key_hex();

    let effective_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Canonical signing bytes: "<old>:<new>:<effective_at>"
    let payload_str = format!("{old_pubkey_hex}:{new_pubkey_hex}:{effective_at}");
    let sig = old_identity.sign(payload_str.as_bytes());

    let rotation = serde_json::json!({
        "old_pubkey": old_pubkey_hex,
        "new_pubkey": new_pubkey_hex,
        "effective_at": effective_at,
        "signature": hex::encode(sig.to_bytes()),
    });

    std::fs::write(
        "hub_rotation.json",
        serde_json::to_string_pretty(&rotation)?,
    )?;

    // Replace the live identity file with the new key.
    new_identity.save(current_path)?;

    Ok(())
}

/// `wavvon-hub rotate-key [--endorse-from <old hub_identity.json>]`.
pub fn rotate_key_cmd() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--endorse-from") {
        let old = args
            .get(i + 1)
            .context("--endorse-from needs the path of the old hub_identity.json")?;
        endorse_current_key(
            Path::new(old),
            Path::new("hub_identity.json"),
            Path::new("hub_rotation.json"),
        )?;
        println!("hub_rotation.json now says the old key handed over to the current one.");
        println!("Restart the hub: clients that knew the old key will follow it here.");
        println!(
            "This does not restore membership: if the database was lost, members \
                 still need an invite. It only keeps the hub in their list as the same hub."
        );
        return Ok(());
    }
    rotate_hub_key(Path::new("hub_identity.json"))?;
    println!("Key rotation complete. hub_identity.json now contains the new key.");
    println!("hub_rotation.json contains the signed rotation payload.");
    println!("Restart the hub for the change to take effect.");
    Ok(())
}

#[cfg(test)]
mod endorse_tests {
    use super::*;

    #[test]
    fn an_old_key_endorses_the_current_one_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("wavvon-endorse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (old_path, cur_path, out) = (
            dir.join("old.json"),
            dir.join("hub_identity.json"),
            dir.join("hub_rotation.json"),
        );
        let old = Identity::generate();
        let current = Identity::generate();
        old.save(&old_path).unwrap();
        current.save(&cur_path).unwrap();

        endorse_current_key(&old_path, &cur_path, &out).unwrap();
        let r: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(r["old_pubkey"], old.public_key_hex());
        assert_eq!(r["new_pubkey"], current.public_key_hex());
        let payload = format!(
            "{}:{}:{}",
            r["old_pubkey"].as_str().unwrap(),
            r["new_pubkey"].as_str().unwrap(),
            r["effective_at"]
        );
        wavvon_identity::verify_signature(
            &old.public_key_hex(),
            payload.as_bytes(),
            &hex::decode(r["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        // The live identity is untouched.
        assert_eq!(
            Identity::load(&cur_path).unwrap().public_key_hex(),
            current.public_key_hex()
        );

        // Refused: the same key twice, and a file that is not an identity.
        assert!(endorse_current_key(&cur_path, &cur_path, &out).is_err());
        std::fs::write(&old_path, "not json").unwrap();
        assert!(endorse_current_key(&old_path, &cur_path, &out).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

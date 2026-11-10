use anyhow::Context;
/// The release signing key. Its private half lives only in the `release`
/// environment of the Wavvon-server repository; the release workflow signs
/// every binary with it, and `update` installs nothing it did not sign.
const RELEASE_PUBKEY_HEX: &str = "e5b1b654ba7b7bfbe91d49dce46b691f76a4c481ffb7f3d808fe8924bcb87663";

/// Whether `sig` is the release key's signature over this asset. The name is
/// signed with the bytes, so a signed binary for one platform cannot be
/// passed off as another's.
fn verify_release_asset(asset_name: &str, bytes: &[u8], sig: &[u8]) -> anyhow::Result<()> {
    let mut message = Vec::with_capacity(bytes.len() + 64);
    message.extend_from_slice(b"wavvon/release-asset/v1\0");
    message.extend_from_slice(asset_name.as_bytes());
    message.push(0);
    message.extend_from_slice(bytes);
    wavvon_identity::verify_signature(RELEASE_PUBKEY_HEX, &message, sig)
}

fn self_update_asset_name() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("wavvon-hub-linux-x86_64")
    } else {
        None
    }
}

pub async fn run_self_update(check_only: bool) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("wavvon-hub/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let release: serde_json::Value = client
        .get("https://api.github.com/repos/Wavvon/Wavvon-server/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("Failed to reach GitHub API")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("Failed to parse GitHub API response")?;

    let tag = release["tag_name"].as_str().unwrap_or("");
    let latest = tag.trim_start_matches('v');
    let current = env!("CARGO_PKG_VERSION");

    if latest.is_empty() {
        anyhow::bail!(
            "GitHub API returned no tag_name — is the repo public and are releases published?"
        );
    }

    if latest == current {
        println!("Already up to date (v{current}).");
        return Ok(());
    }

    println!("Update available: v{current} → v{latest}");

    if check_only {
        println!("Run 'wavvon-hub update' (without --check) to install.");
        return Ok(());
    }

    let asset_name =
        self_update_asset_name().context("Self-update is only supported on Linux x86_64")?;

    let assets = release["assets"]
        .as_array()
        .context("GitHub API response has no assets array")?;

    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(asset_name))
        .with_context(|| format!("No asset '{asset_name}' in release {tag}"))?;

    let download_url = asset["browser_download_url"]
        .as_str()
        .context("Asset has no browser_download_url")?;

    println!("Downloading {download_url} ...");

    let response = client
        .get(download_url)
        .send()
        .await
        .context("Download request failed")?
        .error_for_status()
        .context("Download returned an error status")?;

    let bytes = response
        .bytes()
        .await
        .context("Failed to read download body")?;
    println!("Downloaded {} bytes.", bytes.len());

    let sig_name = format!("{asset_name}.sig");
    let sig_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(sig_name.as_str()))
        .and_then(|a| a["browser_download_url"].as_str())
        .with_context(|| {
            format!("Release {tag} carries no signature ({sig_name}); refusing to install it")
        })?;
    let sig = client
        .get(sig_url)
        .send()
        .await
        .context("Signature download failed")?
        .error_for_status()
        .context("Signature download returned an error status")?
        .bytes()
        .await
        .context("Failed to read the signature")?;
    verify_release_asset(asset_name, &bytes, &sig).context(
        "The downloaded binary is not signed by the Wavvon release key; nothing was installed",
    )?;
    println!("Signature verified.");

    let current_exe =
        std::env::current_exe().context("Cannot determine current executable path")?;

    let tmp = current_exe.with_file_name(".wavvon-hub-update.tmp");
    std::fs::write(&tmp, &bytes).with_context(|| format!("Cannot write temp file {tmp:?}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Cannot set permissions on {tmp:?}"))?;
    }

    std::fs::rename(&tmp, &current_exe)
        .with_context(|| format!("Cannot replace {current_exe:?} with the new binary"))?;

    println!("Update applied (v{latest}). Restart the server to activate the new version.");

    Ok(())
}

/// `wavvon-hub update [--check]`.
pub async fn update_cmd() -> anyhow::Result<()> {
    let check_only = std::env::args().any(|a| a == "--check");
    run_self_update(check_only).await?;
    Ok(())
}

#[cfg(test)]
mod release_signature_tests {
    use super::verify_release_asset;

    // Made with the release key by the same `openssl pkeyutl -sign -rawin`
    // call the release workflow runs, over the tag, "test-asset", NUL, "hello".
    const FIXTURE_SIG: &str = "07640425038ffee7360138d41ab510bec6251e706151e818bb10100be2ccda77582107a8a8736caf3b876461f07ff7d1c37f73dc1cb62b79c364659f8fe01d05";

    #[test]
    fn a_release_signature_verifies_only_for_its_asset_and_bytes() {
        let sig = hex::decode(FIXTURE_SIG).unwrap();
        verify_release_asset("test-asset", b"hello", &sig).unwrap();
        assert!(verify_release_asset("test-asset", b"hellO", &sig).is_err());
        assert!(verify_release_asset("other-asset", b"hello", &sig).is_err());
        assert!(verify_release_asset("test-asset", b"hello", &sig[..63]).is_err());
    }
}

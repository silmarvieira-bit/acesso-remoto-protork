// Custom auto-update channel for the Protork build.
//
// The stock RustDesk updater (src/updater.rs) only ever checks
// github.com/rustdesk/rustdesk releases, which is not where Protork builds are
// published. This module checks our own self-hosted update server instead and
// installs the new MSI silently once it has been verified.
//
// Server-side contract (see the release admin's `publish.mjs` / `server.mjs`,
// not part of this repository):
//   GET {PROTORK_UPDATE_SERVER}/updates/latest-<arch>.signed
//     -> bytes = combined Ed25519 signature (64 bytes) || JSON payload
//        payload = {"product","arch","sequence","expires","size","sha256"}
//   GET {PROTORK_UPDATE_SERVER}/updates/protork-<sequence>-<arch>.msi
//     -> the raw MSI package described by the manifest above
//
// Build-time configuration (baked in via `option_env!`, same pattern as
// PROTORK_ID_SERVER / PROTORK_SERVER_KEY in src/server.rs):
//   PROTORK_UPDATE_SERVER      base URL, e.g. "http://192.168.1.95:8788" (no trailing slash)
//   PROTORK_UPDATE_PUBLIC_KEY  base64 raw 32-byte Ed25519 public key (`publish.mjs public-key`)
//   PROTORK_UPDATE_SEQUENCE    this build's own release sequence number; must match the
//                              SEQUENCE this exact build is published under via `publish.mjs publish`
//
// A build missing PROTORK_UPDATE_SERVER (e.g. a plain debug build) silently
// skips the check rather than failing.

use hbb_common::{bail, log, sodiumoxide::crypto::sign, ResultType};
use serde_derive::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Manifest {
    product: String,
    arch: String,
    sequence: u64,
    expires: u64,
    size: u64,
    sha256: String,
}

fn server_base() -> Option<&'static str> {
    option_env!("PROTORK_UPDATE_SERVER")
}

fn public_key() -> ResultType<sign::PublicKey> {
    let Some(encoded) = option_env!("PROTORK_UPDATE_PUBLIC_KEY") else {
        bail!("PROTORK_UPDATE_PUBLIC_KEY is not set in this build");
    };
    let raw = crate::decode64(encoded)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| hbb_common::anyhow::anyhow!("PROTORK_UPDATE_PUBLIC_KEY must be 32 bytes"))?;
    Ok(sign::PublicKey(raw))
}

fn current_sequence() -> u64 {
    option_env!("PROTORK_UPDATE_SEQUENCE")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Checks the Protork update server for a newer signed release and installs
/// it silently via `msiexec` when one is found. No-op when this build was not
/// configured with an update server.
pub fn check_update() -> ResultType<()> {
    let Some(base) = server_base() else {
        return Ok(());
    };
    let pk = public_key()?;
    let Some(arch) = crate::platform::windows::release_arch_suffix() else {
        bail!("Unsupported architecture for Protork update");
    };

    let manifest_url = format!("{}/updates/latest-{}.signed", base, arch);
    let client = crate::hbbs_http::create_http_client_with_url(&manifest_url);
    let resp = client.get(&manifest_url).send()?;
    if !resp.status().is_success() {
        bail!("Failed to fetch update manifest: {}", resp.status());
    }
    let signed = resp.bytes()?.to_vec();
    let Ok(payload) = sign::verify(&signed, &pk) else {
        bail!("Update manifest signature verification failed");
    };
    let manifest: Manifest = serde_json::from_slice(&payload)?;

    if manifest.product != crate::get_app_name() {
        bail!(
            "Update manifest is for a different product: {}",
            manifest.product
        );
    }
    if manifest.arch != arch {
        bail!("Update manifest architecture mismatch: {}", manifest.arch);
    }
    if manifest.expires <= now_secs() {
        bail!("Update manifest has expired");
    }
    if manifest.sequence <= current_sequence() {
        log::debug!(
            "Protork update: already on sequence {} (server has {})",
            current_sequence(),
            manifest.sequence
        );
        return Ok(());
    }
    if manifest.size == 0 || manifest.size > 512 * 1024 * 1024 {
        bail!("Update manifest reports an invalid package size");
    }
    if !crate::updater::has_no_active_conns() {
        // Retried on the next scheduled check, same as the stock updater.
        bail!("Skipping update while a session is active");
    }

    let package_url = format!(
        "{}/updates/protork-{}-{}.msi",
        base, manifest.sequence, arch
    );
    let client = crate::hbbs_http::create_http_client_with_url(&package_url);
    let resp = client.get(&package_url).send()?;
    if !resp.status().is_success() {
        bail!("Failed to download update package: {}", resp.status());
    }
    let bytes = resp.bytes()?.to_vec();
    if bytes.len() as u64 != manifest.size {
        bail!("Downloaded package size does not match the manifest");
    }
    use hbb_common::sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != manifest.sha256 {
        bail!("Downloaded package hash does not match the manifest");
    }

    let temp_path =
        std::env::temp_dir().join(format!("protork-update-{}.msi", manifest.sequence));
    std::fs::write(&temp_path, &bytes)?;
    // Re-check right before install: the download can take a while.
    if !crate::updater::has_no_active_conns() {
        std::fs::remove_file(&temp_path).ok();
        bail!("Skipping install: a session started during download");
    }

    log::info!(
        "Protork update: installing sequence {} ({} bytes)",
        manifest.sequence,
        manifest.size
    );
    let result = crate::platform::update_me_msi(&temp_path.to_string_lossy(), true);
    if result.is_err() {
        std::fs::remove_file(&temp_path).ok();
    }
    result
}

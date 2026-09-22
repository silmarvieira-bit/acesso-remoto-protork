//! Signed, self-hosted MSI updates. Configuration is pinned at build time.
use hbb_common::{bail, log, ResultType};
use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
use hbb_common::sodiumoxide::crypto::sign;
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::{Read, Write}, time::{Duration, SystemTime, UNIX_EPOCH}};
use std::os::windows::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt};

const MAX_MSI: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST: u64 = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    product: String,
    arch: String,
    sequence: u64,
    expires: u64,
    size: u64,
    sha256: String,
}

fn decode_manifest(signed: &[u8], key: &str, now: u64, current: u64, arch: &str) -> ResultType<Manifest> {
    let raw_key = STANDARD.decode(key)?;
    let pk = match sign::PublicKey::from_slice(&raw_key) {
        Some(pk) => pk,
        None => bail!("Invalid Protork update public key"),
    };
    let payload = match sign::verify(signed, &pk) {
        Ok(payload) => payload,
        Err(_) => bail!("Invalid Protork update signature"),
    };
    let m: Manifest = serde_json::from_slice(&payload)?;
    if m.product != "Acesso Remoto Protork" || m.arch != arch {
        bail!("Wrong update product or architecture");
    }
    if m.sequence < current || m.expires <= now || m.size == 0 || m.size > MAX_MSI {
        bail!("Update is old, expired or has invalid size");
    }
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Invalid update hash");
    }
    Ok(m)
}

pub(super) fn check_update() -> ResultType<()> {
    let base = option_env!("PROTORK_UPDATE_URL").unwrap_or("");
    let key = option_env!("PROTORK_UPDATE_PUBLIC_KEY").unwrap_or("");
    if base.is_empty() || key.is_empty() {
        log::info!("Protork automatic updates are not provisioned");
        return Ok(());
    }
    if !crate::platform::is_root() || !crate::platform::is_msi_installed()? {
        bail!("Protork updater requires an installed MSI and privileged server process");
    }
    if !crate::updater::has_no_active_conns() {
        return Ok(());
    }
    let current: u64 = option_env!("PROTORK_UPDATE_SEQUENCE").unwrap_or("0").parse()?;
    if current == 0 {
        bail!("Protork build has no update sequence");
    }
    let arch = match crate::platform::windows::release_arch_suffix() {
        Some(arch) => arch,
        None => bail!("Unsupported update architecture"),
    };
    let base_url = url::Url::parse(base)?;
    // HTTP is restricted to the known LAN server; signatures authenticate both
    // manifest metadata and MSI hash. Public hosts require HTTPS.
    if !(base_url.scheme() == "https"
        || (base_url.scheme() == "http" && base_url.host_str() == Some("192.168.1.95")))
        || !base_url.username().is_empty() || base_url.password().is_some()
        || base_url.query().is_some() || base_url.fragment().is_some()
        || !base.ends_with('/')
    {
        bail!("Invalid Protork update endpoint");
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::none()).build()?;
    let response = client.get(base_url.join(&format!("latest-{arch}.signed"))?).send()?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(());
    }
    let mut signed = Vec::new();
    response.error_for_status()?.take(MAX_MANIFEST + 1).read_to_end(&mut signed)?;
    if signed.len() as u64 > MAX_MANIFEST { bail!("Oversized update manifest"); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let m = decode_manifest(&signed, key, now, current, arch)?;
    if m.sequence == current { return Ok(()); }

    // Staging is under Program Files, not a shared writable temporary folder.
    let exe = std::env::current_exe()?;
    let parent = match exe.parent() { Some(p) => p, None => bail!("Missing install directory") };
    let program_files = std::path::PathBuf::from(std::env::var("ProgramFiles")?);
    if !parent.starts_with(&program_files) { bail!("Install must be under Program Files"); }
    let stage = parent.join("protork-updates");
    std::fs::create_dir_all(&stage)?;
    for ancestor in stage.ancestors() {
        if std::fs::symlink_metadata(ancestor)?.file_attributes() & 0x400 != 0 {
            bail!("Reparse point in update staging path");
        }
    }
    let icacls = std::path::PathBuf::from(std::env::var("SystemRoot")?).join("System32/icacls.exe");
    let status = std::process::Command::new(icacls).arg(&stage)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
        .creation_flags(0x08000000).status()?;
    if !status.success() { bail!("Cannot protect update staging directory"); }
    let _lock = OpenOptions::new().read(true).write(true).create(true)
        .share_mode(0).open(stage.join("update.lock"))?;
    let filename = format!("protork-{}-{}.msi", m.sequence, m.arch);
    let path = stage.join(&filename);
    // Retry interrupted downloads only inside the protected staging directory.
    if path.exists() && std::fs::symlink_metadata(&path)?.file_attributes() & 0x400 != 0 {
        bail!("Reparse point in update package path");
    }
    let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(true)
        .share_mode(1).open(&path)?;
    let mut body = client.get(base_url.join(&filename)?).send()?.error_for_status()?.take(m.size + 1);
    let mut hasher = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = body.read(&mut buf)?;
        if n == 0 { break; }
        count += n as u64;
        if count > m.size { bail!("Update exceeds signed size"); }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    file.sync_all()?;
    if count != m.size || format!("{:x}", hasher.finalize()) != m.sha256.to_lowercase() {
        bail!("Update checksum mismatch");
    }
    if !crate::updater::has_no_active_conns() { return Ok(()); }
    // MSI opens the database read-only. Release our write handle first, then
    // retain a read-only non-delete-sharing handle through the install handoff.
    drop(file);
    let _verified_package = OpenOptions::new().read(true).share_mode(1).open(&path)?;
    log::info!("Installing signed Protork update sequence {}", m.sequence);
    crate::platform::update_me_msi(&path.to_string_lossy(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_and_release_constraints() {
        let (pk, sk) = sign::gen_keypair();
        let key = STANDARD.encode(pk.0);
        let payload = serde_json::json!({"product":"Acesso Remoto Protork", "arch":"x86_64",
            "sequence":2,"expires":100,"size":20,"sha256":"a".repeat(64)}).to_string();
        let mut signed = sign::sign(payload.as_bytes(), &sk);
        assert!(decode_manifest(&signed, &key, 50, 1, "x86_64").is_ok());
        assert!(decode_manifest(&signed, &key, 100, 1, "x86_64").is_err());
        assert!(decode_manifest(&signed, &key, 50, 2, "x86_64").is_ok());
        assert!(decode_manifest(&signed, &key, 50, 3, "x86_64").is_err());
        assert!(decode_manifest(&signed, &key, 50, 1, "aarch64").is_err());
        signed[0] ^= 1;
        assert!(decode_manifest(&signed, &key, 50, 1, "x86_64").is_err());
    }
}

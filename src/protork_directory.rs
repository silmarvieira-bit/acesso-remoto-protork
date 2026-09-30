//! LAN directory: authenticated bootstrap, expiring DHCP records and pinned
//! device handshake. The directory never grants remote-session permission.
use hbb_common::{bail, config::Config, log, ResultType};
use hbb_common::base64::{engine::general_purpose::STANDARD, Engine as _};
use hbb_common::sodiumoxide::crypto::sign;
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, io::Read, net::Ipv4Addr, sync::{Mutex, Once},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const ENDPOINT: &str = "https://192.168.1.95:8789";
const TRUST: &str = "http://192.168.1.95:8788/updates/directory-trust.signed";
const PORT: u16 = 21120;
static CACHE: Mutex<Vec<Peer>> = Mutex::new(Vec::new());

pub fn enabled() -> bool { option_env!("PROTORK_ID_SERVER") == Some("192.168.1.95") }

pub fn private_ip(ip: &str) -> bool {
    match ip.parse::<Ipv4Addr>() {
        Ok(ip) => ip.is_private(),
        Err(_) => false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    product: String,
    version: u32,
    endpoint: String,
    certificate: String,
    expires: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Peer {
    device: String,
    ip: String,
    public_key: String,
    peer_id: String,
    username: String,
    hostname: String,
    platform: String,
    expires: u64,
    port: u16,
}

fn now() -> ResultType<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }

fn read_body(response: reqwest::blocking::Response, max: u64) -> ResultType<Vec<u8>> {
    let mut body = Vec::new();
    response.error_for_status()?.take(max + 1).read_to_end(&mut body)?;
    if body.len() as u64 > max { bail!("Directory response too large"); }
    Ok(body)
}

fn decode_trust(signed: &[u8], key: &str, now: u64) -> ResultType<Trust> {
    let key = STANDARD.decode(key)?;
    let Some(pk) = sign::PublicKey::from_slice(&key) else { bail!("Invalid directory trust key"); };
    let payload = sign::verify(signed, &pk).map_err(|_| hbb_common::anyhow::anyhow!("Invalid directory trust signature"))?;
    let trust: Trust = serde_json::from_slice(&payload)?;
    if trust.product != "Protork Directory Trust" || trust.version != 1 ||
        trust.endpoint != ENDPOINT || trust.expires <= now || trust.certificate.len() > 8192 {
        bail!("Invalid or expired directory trust");
    }
    Ok(trust)
}

fn client() -> ResultType<reqwest::blocking::Client> {
    let bootstrap = reqwest::blocking::Client::builder().no_proxy()
        .timeout(Duration::from_secs(8)).redirect(reqwest::redirect::Policy::none()).build()?;
    let signed = read_body(bootstrap.get(TRUST).send()?, 16384)?;
    let trust = decode_trust(&signed, option_env!("PROTORK_UPDATE_PUBLIC_KEY").unwrap_or(""), now()?)?;
    Ok(reqwest::blocking::Client::builder().use_rustls_tls().no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(trust.certificate.as_bytes())?)
        .timeout(Duration::from_secs(8)).redirect(reqwest::redirect::Policy::none()).build()?)
}

fn valid_peer(peer: &Peer) -> ResultType<()> {
    let pk = STANDARD.decode(&peer.public_key)?;
    if pk.len() != 32 || format!("{:x}", Sha256::digest(&pk)) != peer.device ||
        !private_ip(&peer.ip) || peer.port != PORT || peer.expires <= now()? * 1000 ||
        peer.expires > (now()? + 120) * 1000 || peer.hostname.len() > 512 || peer.username.len() > 512 ||
        peer.peer_id.len() < 6 || peer.peer_id.len() > 16 || !peer.peer_id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Invalid directory peer");
    }
    Ok(())
}

fn heartbeat(client: &reqwest::blocking::Client) -> ResultType<()> {
    #[derive(Deserialize)] struct Challenge { nonce: String }
    let c: Challenge = serde_json::from_slice(&read_body(client.get(format!("{ENDPOINT}/v1/challenge")).send()?, 1024)?)?;
    if c.nonce.len() != 64 || !c.nonce.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("Invalid directory challenge"); }
    let (sk, pk) = Config::get_key_pair();
    let Some(sk) = sign::SecretKey::from_slice(&sk) else { bail!("Device key unavailable"); };
    let payload = serde_json::json!({"version":1,"nonce":c.nonce,"publicKey":STANDARD.encode(pk),
        "peerId":Config::get_id(),"username":crate::platform::get_active_username(),
        "hostname":crate::whoami_hostname()}).to_string();
    let signature = sign::sign_detached(payload.as_bytes(), &sk);
    let envelope = serde_json::json!({"payload":STANDARD.encode(payload.as_bytes()),"signature":STANDARD.encode(signature.to_bytes())});
    read_body(client.post(format!("{ENDPOINT}/v1/heartbeat")).json(&envelope).send()?, 1024)?;
    Ok(())
}

pub fn start_registration() {
    static ONCE: Once = Once::new();
    if !enabled() { return; }
    ONCE.call_once(|| { std::thread::spawn(|| {
        let mut session = None;
        let mut renewed = Instant::now();
        loop {
            let result = (|| -> ResultType<()> {
                if Config::get_option("stop-service") == "Y" { return Ok(()); }
                if session.is_none() || renewed.elapsed() > Duration::from_secs(3600) {
                    session = Some(client()?); renewed = Instant::now();
                }
                if let Some(ref session) = session { heartbeat(session)?; }
                Ok(())
            })();
            if let Err(error) = result { log::warn!("Protork directory registration: {error}"); session = None; }
            std::thread::park_timeout(Duration::from_secs(25));
        }
    }); });
}

pub fn peers() -> Vec<HashMap<&'static str, String>> {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| { std::thread::spawn(|| {
        loop {
            let result = (|| -> ResultType<Vec<Peer>> {
                #[derive(Deserialize)] struct List { peers: Vec<Peer> }
                let client = client()?;
                let list: List = serde_json::from_slice(&read_body(client.get(format!("{ENDPOINT}/v1/peers")).send()?, 8 * 1024 * 1024)?)?;
                if list.peers.len() > 10000 { bail!("Directory peer limit exceeded"); }
                for p in &list.peers { valid_peer(p)?; }
                Ok(list.peers)
            })();
            match result {
                Ok(peers) => *CACHE.lock().unwrap() = peers,
                Err(error) => { CACHE.lock().unwrap().clear(); log::warn!("Protork directory list: {error}"); }
            }
            #[cfg(feature = "flutter")]
            crate::flutter_ffi::main_load_lan_peers();
            std::thread::park_timeout(Duration::from_secs(20));
        }
    }); });
    let own = Config::get_id();
    CACHE.lock().unwrap().iter().filter(|p| p.peer_id != own && valid_peer(p).is_ok()).map(|p| HashMap::from([
        ("id", format!("lan-{}", p.device)), ("ip", p.ip.clone()),
        ("username", p.username.clone()), ("hostname", p.hostname.clone()),
        ("platform", p.platform.clone()), ("directory_online", "Y".to_owned()),
    ])).collect()
}

pub fn is_own_id(id: &str) -> bool {
    enabled() && id == format!("lan-{:x}", Sha256::digest(Config::get_key_pair().1))
}

fn resolve(id: &str) -> ResultType<Peer> {
    if private_ip(id) {
        #[derive(Deserialize)] struct List { peers: Vec<Peer> }
        let client = client()?;
        let list: List = serde_json::from_slice(&read_body(client.get(format!("{ENDPOINT}/v1/peers")).send()?, 8 * 1024 * 1024)?)?;
        if list.peers.len() > 10000 { bail!("Directory peer limit exceeded"); }
        let mut matches = list.peers.into_iter().filter(|p| p.ip == id);
        let Some(peer) = matches.next() else { bail!("Computer not registered in the directory; connect by Windows user name after registration"); };
        if matches.next().is_some() { bail!("Ambiguous IP address; select the Windows user name"); }
        valid_peer(&peer)?;
        return Ok(peer);
    }
    let Some(device) = id.strip_prefix("lan-") else { bail!("Invalid directory identity"); };
    if device.len() != 64 || !device.bytes().all(|b| b.is_ascii_hexdigit()) { bail!("Invalid directory identity"); }
    let client = client()?;
    let peer: Peer = serde_json::from_slice(&read_body(client.get(format!("{ENDPOINT}/v1/peers/{device}")).send()?, 4096)?)?;
    valid_peer(&peer)?;
    if peer.device != device { bail!("Directory identity mismatch"); }
    Ok(peer)
}

pub async fn connect(id: String, key: &str, token: &str,
    conn_type: hbb_common::rendezvous_proto::ConnType, switch_code: &str,
    force_relay: bool) -> ResultType<(hbb_common::Stream, Vec<u8>, bool)> {
    use hbb_common::{message_proto::{Message, message, PublicKey}, protobuf::Message as _,
        socket_client::connect_tcp_local, timeout, config::{CONNECT_TIMEOUT, READ_TIMEOUT}};
    // Resolve again for every connection/reconnection, never use a cached lease.
    let peer = hbb_common::tokio::task::spawn_blocking(move || resolve(&id)).await??;
    let pk = STANDARD.decode(&peer.public_key)?;
    let Some(sign_pk) = sign::PublicKey::from_slice(&pk) else { bail!("Invalid device key"); };
    let direct = if force_relay { None } else {
        match connect_tcp_local(format!("{}:{}", peer.ip, peer.port), None, CONNECT_TIMEOUT.min(3000)).await {
            Ok(conn) => Some(conn),
            Err(error) => { log::info!("Private-network direct connection unavailable, trying relay: {error}"); None }
        }
    };
    let is_direct = direct.is_some();
    let mut conn = match direct {
        Some(conn) => conn,
        None => crate::client::Client::request_relay(&peer.peer_id,
            "192.168.1.95:21117".to_owned(), "192.168.1.95:21116", true,
            key, token, conn_type, switch_code).await?,
    };
    // Both transports MUST prove the fresh directory device key before credentials.
    // A failed identity handshake is terminal, never a reason to downgrade security.
    let Some(bytes) = timeout(READ_TIMEOUT, conn.next()).await? else { bail!("Peer disconnected"); };
    let msg = Message::parse_from_bytes(&bytes?)?;
    let Some(message::Union::SignedId(si)) = msg.union else { bail!("Secure LAN handshake required"); };
    let (id, their_pk) = crate::decode_id_pk(&si.id, &sign_pk)?;
    if id != peer.peer_id { bail!("DHCP device identity changed"); }
    let (asymmetric_value, symmetric_value, key) = crate::create_symmetric_key_msg(their_pk);
    let mut msg = Message::new();
    msg.set_public_key(PublicKey { asymmetric_value, symmetric_value, ..Default::default() });
    timeout(CONNECT_TIMEOUT, conn.send(&msg)).await??;
    conn.set_key(key);
    Ok((conn, pk, is_direct))
}

pub fn start_listener(server: crate::server::ServerPtr) {
    if !enabled() { return; }
    if crate::platform::is_root() {
        std::thread::spawn(|| {
            if let Err(error) = configure_firewall() { log::error!("Protork LAN firewall: {error}"); }
        });
    }
    hbb_common::tokio::spawn(async move {
        loop {
            match hbb_common::tcp::listen_any(PORT).await {
                Ok(listener) => {
                    start_registration();
                    loop {
                        match listener.accept().await {
                            Ok((stream, addr)) => {
                                let ip = match addr.ip() {
                                    std::net::IpAddr::V4(ip) => Some(ip),
                                    std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
                                };
                                if !ip.map(|ip| ip.is_private()).unwrap_or(false) || Config::get_option("stop-service") == "Y" { continue; }
                                let local = match stream.local_addr() { Ok(a) => a, Err(e) => { log::warn!("LAN address: {e}"); continue; } };
                                let server = server.clone();
                                hbb_common::tokio::spawn(async move {
                                    if let Err(error) = crate::server::create_tcp_connection(server,
                                        hbb_common::Stream::from(stream, local), addr, true, crate::server::ConnectionMeta::default()).await {
                                        log::warn!("Secure LAN connection: {error}");
                                    }
                                });
                            }
                            Err(error) => { log::warn!("Secure LAN accept: {error}"); break; }
                        }
                    }
                }
                Err(error) => log::warn!("Secure LAN listener: {error}"),
            }
            hbb_common::tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

fn configure_firewall() -> ResultType<()> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe()?;
    let program_files = std::path::PathBuf::from(std::env::var("ProgramFiles")?);
    if !exe.starts_with(program_files) { return Ok(()); }
    let powershell = std::path::PathBuf::from(std::env::var("SystemRoot")?)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    // Path goes through the child environment, never interpolated into code.
    let script = "$ErrorActionPreference='Stop'; $p=@{Name='Protork-Secure-LAN-21120'; Enabled='True'; Direction='Inbound'; Action='Allow'; Profile='Any'; Protocol='TCP'; LocalPort=21120; RemoteAddress=@('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'); Program=$env:PROTORK_LAN_PROGRAM}; if(Get-NetFirewallRule -Name $p.Name -ErrorAction SilentlyContinue){Set-NetFirewallRule @p}else{New-NetFirewallRule @p -DisplayName 'Protork Secure LAN' | Out-Null}";
    let status = std::process::Command::new(powershell).env("PROTORK_LAN_PROGRAM", exe)
        .args(["-NoProfile", "-NonInteractive", "-Command", script]).creation_flags(0x08000000).status()?;
    if !status.success() { bail!("Could not configure private-network port 21120"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_ranges_only() {
        for ip in ["10.0.0.1", "172.16.0.1", "172.31.255.1", "192.168.66.113"] { assert!(private_ip(ip)); }
        for ip in ["8.8.8.8", "127.0.0.1", "172.32.0.1", "100.64.1.1", "::1"] { assert!(!private_ip(ip)); }
    }
    #[test]
    fn signed_trust_rejects_tampering_expiry_and_wrong_endpoint() {
        let (pk, sk) = sign::gen_keypair();
        let key = STANDARD.encode(pk.0);
        let payload = serde_json::json!({"product":"Protork Directory Trust","version":1,
            "endpoint":ENDPOINT,"certificate":"test","expires":100}).to_string();
        let mut signed = sign::sign(payload.as_bytes(), &sk);
        assert!(decode_trust(&signed, &key, 50).is_ok());
        assert!(decode_trust(&signed, &key, 100).is_err());
        signed[0] ^= 1;
        assert!(decode_trust(&signed, &key, 50).is_err());
        let payload = payload.replace(ENDPOINT, "https://example.com");
        assert!(decode_trust(&sign::sign(payload.as_bytes(), &sk), &key, 50).is_err());
    }
}

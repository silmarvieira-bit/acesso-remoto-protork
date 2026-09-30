import https from 'node:https';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function privateIPv4(address) {
  const ip = address?.replace(/^::ffff:/, '') || '';
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(ip)) return null;
  const p = ip.split('.').map(Number);
  if (p.some(n => n > 255)) return null;
  return p[0] === 10 || p[0] === 172 && p[1] >= 16 && p[1] <= 31 ||
    p[0] === 192 && p[1] === 168 ? ip : null;
}

const publicPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const ttl = 90_000;
const limit = 10_000;
function decode64(value, length) {
  if (typeof value !== 'string') throw Error('Invalid encoding');
  const b = Buffer.from(value, 'base64');
  if (b.toString('base64') !== value || (length && b.length !== length)) throw Error('Invalid encoding');
  return b;
}
function label(value) {
  return typeof value === 'string' && value.length <= 128 && !/[\x00-\x1f\x7f]/.test(value);
}

// A directory is not an authorization service. Windows usernames are labels,
// self-reported by enrolled LAN devices; remote password/approval stays required.
export class Directory {
  constructor(now = Date.now) {
    this.now = now;
    this.peers = new Map();
    this.challenges = new Map();
  }
  prune() {
    const now = this.now();
    for (const [key, item] of this.peers) if (item.expires <= now) this.peers.delete(key);
    for (const [key, item] of this.challenges) if (item.expires <= now) this.challenges.delete(key);
  }
  challenge(ip) {
    this.prune();
    if (!privateIPv4(ip) || this.challenges.size >= limit) throw Error('Unavailable');
    const nonce = randomBytes(32).toString('hex');
    this.challenges.set(nonce, { ip, expires: this.now() + 30_000 });
    return nonce;
  }
  register(ip, envelope) {
    this.prune();
    if (!privateIPv4(ip)) throw Error('Invalid address');
    const payload = decode64(envelope.payload);
    if (payload.length > 2048) throw Error('Oversized registration');
    const item = JSON.parse(payload);
    const publicKey = decode64(item.publicKey, 32);
    const signature = decode64(envelope.signature, 64);
    if (!verify(null, payload, createPublicKey({ key: Buffer.concat([publicPrefix, publicKey]), type: 'spki', format: 'der' }), signature)) throw Error('Invalid signature');
    const challenge = this.challenges.get(item.nonce);
    if (!challenge || challenge.ip !== ip || challenge.expires <= this.now()) throw Error('Expired challenge');
    if (item.version !== 1 || !label(item.username) || !label(item.hostname) || !item.hostname ||
        typeof item.peerId !== 'string' || !/^\d{6,16}$/.test(item.peerId)) throw Error('Invalid registration');
    this.challenges.delete(item.nonce);
    const device = createHash('sha256').update(publicKey).digest('hex');
    if (!this.peers.has(device) && this.peers.size >= limit) throw Error('Directory full');
    // A new lease replaces the previous occupant. An old device record must not
    // be offered at an address now reported by a different device.
    // Several authenticated devices may share a NAT gateway. Identity, not IP,
    // owns a record. Old DHCP leases expire; clients pin the device handshake.
    this.peers.set(device, { device, ip, publicKey: item.publicKey, peerId: item.peerId,
      username: item.username, hostname: item.hostname, platform: 'Windows',
      expires: this.now() + ttl, port: 21120 });
    return device;
  }
  list() { this.prune(); return [...this.peers.values()].sort((a, b) => a.device.localeCompare(b.device)); }
  get(device) { this.prune(); return this.peers.get(device); }
}

export function createHandler(directory = new Directory()) {
  const rates = new Map();
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const send = (code, value = {}) => { res.writeHead(code); res.end(JSON.stringify(value)); };
    const ip = privateIPv4(req.socket.remoteAddress);
    if (!ip || req.headers.origin || req.headers['sec-fetch-site']) return send(403);
    const now = Date.now();
    for (const [key, rate] of rates) if (rate.until <= now) rates.delete(key);
    if (!rates.has(ip)) {
      if (rates.size >= limit) return send(503);
      rates.set(ip, { until: now + 10_000, count: 0 });
    }
    if (++rates.get(ip).count > 40) return send(429);
    try {
      if (req.method === 'GET' && req.url === '/health') return send(200, { status: 'Protork Directory OK', version: 1 });
      if (req.method === 'GET' && req.url === '/v1/challenge') return send(200, { nonce: directory.challenge(ip) });
      if (req.method === 'GET' && req.url === '/v1/peers') return send(200, { peers: directory.list() });
      const match = /^\/v1\/peers\/([a-f0-9]{64})$/.exec(req.url || '');
      if (req.method === 'GET' && match) {
        const peer = directory.get(match[1]);
        return peer ? send(200, peer) : send(404);
      }
      if (req.method !== 'POST' || req.url !== '/v1/heartbeat') return send(404);
      if (req.headers['content-type'] !== 'application/json') return send(415);
      if (Number(req.headers['content-length']) > 4096) return send(413);
      const chunks = []; let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 4096) { send(413); req.destroy(); return; }
        chunks.push(chunk);
      }
      const device = directory.register(ip, JSON.parse(Buffer.concat(chunks)));
      send(200, { device, ttlSeconds: ttl / 1000 });
    } catch { if (!res.headersSent) send(400); else res.destroy(); }
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
    const server = https.createServer({ pfx: await readFile(config.pfx), passphrase: config.passphrase,
      minVersion: 'TLSv1.2' }, createHandler());
    server.requestTimeout = 10_000; server.headersTimeout = 5_000;
    server.keepAliveTimeout = 3_000; server.maxHeadersCount = 24;
    server.setTimeout(10_000, socket => socket.destroy());
    server.on('error', error => { console.error(error.message); process.exitCode = 1; });
    server.listen(8789, '192.168.1.95', () => console.log('Protork directory listening on 192.168.1.95:8789'));
    process.on('SIGTERM', () => server.close());
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

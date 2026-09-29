import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Directory, privateIPv4, createHandler } from './directory.mjs';
import { Readable } from 'node:stream';

function device() {
  const keys = generateKeyPairSync('ed25519');
  return { ...keys, raw: keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') };
}
function registration(d, k, ip, changes = {}) {
  const payload = Buffer.from(JSON.stringify({ version: 1, publicKey: k.raw, peerId: '123456789',
    username: 'Maria', hostname: 'FINANCEIRO', nonce: d.challenge(ip), ...changes }));
  return { payload: payload.toString('base64'), signature: sign(null, payload, k.privateKey).toString('base64') };
}
test('all RFC1918 subnets, never public/loopback/CGNAT or malformed addresses', () => {
  for (const ip of ['10.0.0.1', '172.16.1.1', '172.31.255.254', '192.168.66.113', '::ffff:192.168.1.2']) assert.ok(privateIPv4(ip));
  for (const ip of ['172.15.0.1', '172.32.0.1', '100.64.0.1', '127.0.0.1', '8.8.8.8', '::1', '10.999.0.1', '010.0.0.1']) assert.equal(privateIPv4(ip), null);
});
test('username and DHCP address update on same stable device', () => {
  const d = new Directory(); const k = device();
  const id = d.register('192.168.66.113', registration(d, k, '192.168.66.113'));
  assert.equal(d.register('10.10.2.4', registration(d, k, '10.10.2.4', { username: 'Joao' })), id);
  assert.equal(d.list().length, 1); assert.equal(d.get(id).ip, '10.10.2.4'); assert.equal(d.get(id).username, 'Joao');
});
test('expired peers disappear; IP reassignment evicts old device', () => {
  let now = 1000; const d = new Directory(() => now); const a = device(); const b = device();
  const old = d.register('10.0.0.2', registration(d, a, '10.0.0.2'));
  d.register('10.0.0.2', registration(d, b, '10.0.0.2'));
  assert.equal(d.get(old), undefined); assert.equal(d.list().length, 1);
  now += 90000; assert.equal(d.list().length, 0);
});
test('forgery, replay, source-IP swap and expired nonce are rejected', () => {
  let now = 1000; const d = new Directory(() => now); const k = device();
  const body = registration(d, k, '10.0.0.2');
  assert.throws(() => d.register('10.0.0.3', body));
  assert.throws(() => d.register('10.0.0.2', { ...body, signature: Buffer.alloc(64).toString('base64') }));
  d.register('10.0.0.2', body); assert.throws(() => d.register('10.0.0.2', body));
  const expired = registration(d, k, '10.0.0.2'); now += 30000;
  assert.throws(() => d.register('10.0.0.2', expired));
});
test('invalid identity/oversized/control-character labels rejected', () => {
  const d = new Directory(); const k = device();
  for (const changes of [{ username: 'a'.repeat(129) }, { hostname: '' }, { username: 'a\nb' }, { peerId: '../secret' }, { version: 2 }]) {
    assert.throws(() => d.register('10.0.0.2', registration(d, k, '10.0.0.2', changes)));
  }
});
async function request(handler, method, url, headers = {}, address = '192.168.1.2', body = '') {
  const req = Readable.from([Buffer.from(body)]);
  Object.assign(req, { method, url, headers, socket: { remoteAddress: address } });
  const res = { setHeader() {}, writeHead(code) { this.code = code; }, end(data) { this.data = JSON.parse(data || '{}'); }, destroy() {} };
  await handler(req, res); return res;
}
test('HTTP denies browser, public source, unknown path, huge upload and throttles', async () => {
  const h = createHandler();
  assert.equal((await request(h, 'GET', '/health')).code, 200);
  assert.equal((await request(h, 'GET', '/v1/peers', {}, '8.8.8.8')).code, 403);
  assert.equal((await request(h, 'GET', '/v1/peers', { origin: 'https://example.com' })).code, 403);
  assert.equal((await request(h, 'GET', '/private.pem')).code, 404);
  assert.equal((await request(h, 'POST', '/v1/heartbeat', { 'content-type': 'application/json', 'content-length': '99999' })).code, 413);
  for (let n = 0; n < 40; n++) await request(h, 'GET', '/health');
  assert.equal((await request(h, 'GET', '/health')).code, 429);
});
test('HTTP challenge/register/list/resolve roundtrip', async () => {
  const d = new Directory(); const h = createHandler(d); const k = device();
  const envelope = registration(d, k, '192.168.1.2');
  const registered = await request(h, 'POST', '/v1/heartbeat', { 'content-type': 'application/json' }, '192.168.1.2', JSON.stringify(envelope));
  assert.equal(registered.code, 200);
  const peer = await request(h, 'GET', '/v1/peers/' + registered.data.device);
  assert.equal(peer.data.ip, '192.168.1.2'); assert.equal(peer.data.username, 'Maria');
  assert.equal((await request(h, 'GET', '/v1/peers')).data.peers.length, 1);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { rootCertificates } from 'node:tls';
import { signedTrust, patchUpdateServer } from './provision.mjs';
test('public trust is signed with product, endpoint and expiry; wrong signing key refused', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  const cert = rootCertificates[0];
  const signed = signedTrust(cert, privateKey, 0, key);
  assert.ok(verify(null, signed.subarray(64), publicKey, signed.subarray(0, 64)));
  const trust = JSON.parse(signed.subarray(64));
  assert.equal(trust.product, 'Protork Directory Trust');
  assert.equal(trust.endpoint, 'https://192.168.1.95:8789');
  assert.ok(trust.expires > 0);
  assert.throws(() => signedTrust(cert, privateKey, 0));
  assert.throws(() => signedTrust(cert, privateKey, Number.MAX_SAFE_INTEGER, key));
});
test('update server modification is narrow, repeatable and fails on unknown source', async () => {
  const source = String.raw`const match = /^\/updates\/(latest-(?:x86_64|aarch64)\.signed|protork-[1-9][0-9]*-(?:x86_64|aarch64)\.msi)$/.exec(req.url || '');`;
  const patched = patchUpdateServer(source);
  assert.notEqual(patched, source);
  assert.equal(patchUpdateServer(patched), patched);
  assert.equal(patched.replace('directory-trust\\.signed|', ''), source);
  assert.throws(() => patchUpdateServer('different server'));
});

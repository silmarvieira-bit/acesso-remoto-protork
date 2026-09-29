import { readFile, writeFile, copyFile, rename } from 'node:fs/promises';
import { createPublicKey, sign, X509Certificate } from 'node:crypto';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import https from 'node:https';

const expectedKey = 'V/vA2KilP/HMDFVVru3mzQU5sXoi5A+u4NdzmX2+Ewc=';
export function signedTrust(certificate, privateKey, now = Date.now(), trustedPublicKey = expectedKey) {
  const key = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (key.subarray(-32).toString('base64') !== trustedPublicKey) throw Error('Chave de atualizacao diferente. Nada publicado.');
  const cert = new X509Certificate(certificate);
  const expires = Math.floor(Date.parse(cert.validTo) / 1000);
  if (expires <= now / 1000 + 86400) throw Error('Certificado expirado ou perto do vencimento.');
  const payload = Buffer.from(JSON.stringify({ product: 'Protork Directory Trust', version: 1,
    endpoint: 'https://192.168.1.95:8789', certificate: cert.toString(), expires }));
  return Buffer.concat([sign(null, payload, privateKey), payload]);
}
export function patchUpdateServer(source) {
  if (source.includes('directory-trust\\.signed|latest-')) return source;
  const marker = '(latest-(?:x86_64|aarch64)\\.signed|';
  if (source.split(marker).length !== 2) throw Error('Servidor de atualizacao diferente do esperado; arquivo preservado.');
  return source.replace(marker, '(directory-trust\\.signed|latest-(?:x86_64|aarch64)\\.signed|');
}
async function health(root) {
  const ca = new X509Certificate(await readFile(join(root, 'root.cer'))).toString();
  await new Promise((done, reject) => {
    const req = https.get('https://192.168.1.95:8789/health', { ca, timeout: 4000 }, res => {
      let body = ''; res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { if (res.statusCode !== 200 || JSON.parse(body).status !== 'Protork Directory OK') throw Error('Resposta inesperada'); done(); }
        catch (error) { reject(error); }
      });
    });
    req.on('timeout', () => req.destroy(Error('Tempo esgotado'))); req.on('error', reject);
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [command, root] = process.argv.slice(2);
    if (command === 'health') { await health(root); console.log('TLS verificado. Diretorio ativo.'); }
    else if (command === 'prepare') {
      const updateRoot = 'C:\\ProgramData\\ProtorkUpdates';
      const serverFile = join(updateRoot, 'server.mjs');
      const source = await readFile(serverFile, 'utf8');
      const patched = patchUpdateServer(source);
      const signed = signedTrust(await readFile(join(root, 'root.cer')),
        await readFile('C:\\ProgramData\\ProtorkUpdateSigning\\private.pem'));
      // Backup once per content change; do not replace the existing update feed.
      if (patched !== source) {
        await copyFile(serverFile, join(root, `update-server-backup-${Date.now()}.mjs`));
        await writeFile(serverFile, patched);
      }
      const target = join(updateRoot, 'public', 'directory-trust.signed');
      await writeFile(target + '.tmp', signed); await rename(target + '.tmp', target);
      console.log('Certificado publico assinado. MSI e manifestos existentes preservados.');
    } else throw Error('Comando invalido');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

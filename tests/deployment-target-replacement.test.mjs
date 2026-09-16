import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const OLD_HOST = 'galor-tweak-runner-01';
const NEW_HOST = 'galor-tweak-runner-02';
const OLD_DROPLET = '597343619';
const NEW_DROPLET = '601160120';

const productionPaths = [
  'README.md',
  'docs/operations/cloudflare-private-ingress.md',
  'docs/operations/digitalocean.md',
  'lib/engineering-connection.ts',
  'scripts/install-cloudflare-tunnel.sh',
  'scripts/install-digitalocean.sh',
  'scripts/lil-tweak-rollback.py',
];

test('production deployment target is the reviewed replacement droplet', async () => {
  const texts = await Promise.all(productionPaths.map((path) => readFile(path, 'utf8')));
  const joined = texts.join('\n');
  assert.doesNotMatch(joined, new RegExp(OLD_HOST, 'g'));
  assert.doesNotMatch(joined, new RegExp(OLD_DROPLET, 'g'));
  assert.match(joined, new RegExp(NEW_HOST, 'g'));
  assert.match(joined, new RegExp(NEW_DROPLET, 'g'));
});

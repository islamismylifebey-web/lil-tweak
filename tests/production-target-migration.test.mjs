import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const TARGET_HOST = 'galor-tweak-runner-02';
const TARGET_DROPLET = '601149985';
const OLD_HOST = 'galor-tweak-runner-01';
const OLD_DROPLET = '597343619';

const hostBoundFiles = [
  'scripts/install-digitalocean.sh',
  'scripts/install-cloudflare-tunnel.sh',
  'scripts/lil-tweak-rollback.py',
  'lib/engineering-connection.ts',
  'README.md',
  'docs/operations/digitalocean.md',
  'docs/operations/cloudflare-private-ingress.md',
];

test('production deployment is bound to the approved fresh runner-02 target', async () => {
  for (const path of hostBoundFiles) {
    const text = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.match(text, new RegExp(TARGET_HOST), `${path} must name the new production host`);
    assert.doesNotMatch(text, new RegExp(OLD_HOST), `${path} must not retain the old production host`);
  }
  for (const path of ['README.md', 'docs/operations/digitalocean.md']) {
    const text = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.match(text, new RegExp(TARGET_DROPLET), `${path} must name the new droplet`);
    assert.doesNotMatch(text, new RegExp(OLD_DROPLET), `${path} must not retain the old droplet`);
  }
});

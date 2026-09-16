import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

const GO_VERSION = '1.27.1';
const GO_SHA256 = '63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445';
const PODMAN_VERSION = '6.1.2';
const PODMAN_SHA256 = '6785e4dc11dad67000308749fed0f981698792309830a6b870bd5a97b3527182';
const GOSU_COMMIT = '6456aaa0f3c854d199d0f037f068eb97515b7513';
const GOSU_SOURCE_SHA256 = '33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b';

test('core uses only the checksum-pinned Podman remote client', async () => {
  const core = await readFile(new URL('../deploy/Containerfile.core', import.meta.url), 'utf8');

  assert.match(core, new RegExp(`PODMAN_REMOTE_VERSION=${PODMAN_VERSION.replaceAll('.', '\\.')}`));
  assert.match(core, new RegExp(`PODMAN_REMOTE_SHA256=${PODMAN_SHA256}`));
  assert.match(core, /podman-remote-static-linux_amd64\.tar\.gz/);
  assert.match(core, /sha256sum --check/);
  assert.doesNotMatch(core, /apt-get install[^\n]*\bpodman\b/);
});

test('runner replaces vulnerable distro Go and bundled tool packages with reviewed pins', async () => {
  const runner = await readFile(new URL('../deploy/Containerfile.runner', import.meta.url), 'utf8');

  assert.match(runner, new RegExp(`GO_VERSION=${GO_VERSION.replaceAll('.', '\\.')}`));
  assert.match(runner, new RegExp(`GO_SHA256=${GO_SHA256}`));
  assert.match(runner, /go1\.27\.1\.linux-amd64\.tar\.gz/);
  assert.match(runner, /sha256sum --check/);
  assert.doesNotMatch(runner, /\bgolang-go\b/);
  assert.match(runner, /npm@11\.19\.1/);
  assert.match(runner, /wheel==0\.46\.2/);
  assert.match(runner, /python3-wheel/);
  assert.match(runner, /apt-get purge[^\n]*python3-wheel/);
});

test('runner removes Debian wheel before installing the reviewed pip wheel', async () => {
  const runner = await readFile(new URL('../deploy/Containerfile.runner', import.meta.url), 'utf8');
  const purge = runner.indexOf('apt-get purge --yes python3-wheel');
  const install = runner.indexOf('python3 -m pip install --break-system-packages --no-cache-dir wheel==0.46.2');

  assert.ok(purge >= 0, 'Debian python3-wheel purge must exist');
  assert.ok(install >= 0, 'reviewed wheel install must exist');
  assert.ok(purge < install, 'Debian wheel must be removed before pip installs wheel 0.46.2');
});

test('PostgreSQL is a patched child image with rebuilt gosu instead of a byte-for-byte mirror', async () => {
  const postgres = await readFile(new URL('../deploy/Containerfile.postgres', import.meta.url), 'utf8');
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-server-images.yml', import.meta.url), 'utf8'));
  const step = workflow.jobs.publish.steps.find(item => item.id === 'postgres');

  assert.match(postgres, /ARG POSTGRES_PARENT_IMAGE/);
  assert.match(postgres, /apt-get update\s*\\\n\s*&& apt-get upgrade --yes/);
  assert.match(postgres, new RegExp(`GO_VERSION=${GO_VERSION.replaceAll('.', '\\.')}`));
  assert.match(postgres, new RegExp(`GO_SHA256=${GO_SHA256}`));
  assert.match(postgres, new RegExp(`GOSU_COMMIT=${GOSU_COMMIT}`));
  assert.match(postgres, new RegExp(`GOSU_SOURCE_SHA256=${GOSU_SOURCE_SHA256}`));
  assert.match(postgres, /CGO_ENABLED=0/);

  assert.ok(step);
  assert.match(step.run, /docker buildx build/);
  assert.match(step.run, /Containerfile\.postgres/);
  assert.match(step.run, /POSTGRES_PARENT_IMAGE=\$POSTGRES_PARENT_IMAGE/);
  assert.doesNotMatch(step.run, /imagetools create/);
});

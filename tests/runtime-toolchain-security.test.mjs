import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

const workflowUrl = new URL('../.github/workflows/manual-server-images.yml', import.meta.url);
const coreUrl = new URL('../deploy/Containerfile.core', import.meta.url);
const runnerUrl = new URL('../deploy/Containerfile.runner', import.meta.url);
const postgresUrl = new URL('../deploy/Containerfile.postgres', import.meta.url);
const releaseScriptUrl = new URL('../scripts/lil-tweak-private-release.py', import.meta.url);

test('private images pin current isolated toolchains', async () => {
  const workflow = yaml.load(await readFile(workflowUrl, 'utf8'));
  const env = workflow.jobs.publish.env;
  assert.equal(env.PYTHON_BASE_IMAGE, 'docker.io/library/python@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79');
  assert.equal(env.NODE_TOOLCHAIN_IMAGE, 'docker.io/library/node@sha256:a21d059ea0c6c8a82fe2f35e66d0dc1b285e4db5b799e20317b6c8acab2488c6');
  assert.equal(env.GO_TOOLCHAIN_IMAGE, 'docker.io/library/golang@sha256:ba4c8df3f74321b0d5c44911ccb694c8156340b684eed1fae09a9bd9f7a82b4d');
  assert.equal(env.POSTGRES_PARENT_IMAGE, 'docker.io/library/postgres@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee');
  assert.equal(String(env.NPM_VERSION), '12.0.2');
  assert.equal(String(env.WHEEL_VERSION), '0.48.0');
  assert.equal(String(env.PYTEST_VERSION), '9.1.1');
});

test('core ships only the checksum-pinned Podman remote client', async () => {
  const core = await readFile(coreUrl, 'utf8');
  assert.doesNotMatch(core, /apt-get install[^\n]*\bpodman\b/);
  assert.match(core, /podman-remote-static-linux_amd64\.tar\.gz/);
  assert.match(core, /6785e4dc11dad67000308749fed0f981698792309830a6b870bd5a97b3527182/);
  assert.match(core, /\/usr\/local\/bin\/podman/);
});

test('runner copies current Node and Go toolchains onto the reviewed Python base', async () => {
  const runner = await readFile(runnerUrl, 'utf8');
  assert.match(runner, /FROM \$\{NODE_TOOLCHAIN_IMAGE\} AS node-toolchain/);
  assert.match(runner, /FROM \$\{GO_TOOLCHAIN_IMAGE\} AS go-toolchain/);
  assert.match(runner, /FROM \$\{PYTHON_BASE_IMAGE\}/);
  assert.doesNotMatch(runner, /\bgolang-go\b/);
  assert.doesNotMatch(runner, /\bpython3-pip\b/);
  assert.doesNotMatch(runner, /\bpython3-pytest\b/);
  assert.match(runner, /npm@\$\{NPM_VERSION\}/);
  assert.match(runner, /wheel==\$\{WHEEL_VERSION\}/);
  assert.match(runner, /pytest==\$\{PYTEST_VERSION\}/);
  assert.match(runner, /COPY --from=go-toolchain \/usr\/local\/go \/usr\/local\/go/);
});

test('PostgreSQL is rebuilt as a patched child with gosu on the current Go toolchain', async () => {
  const workflow = yaml.load(await readFile(workflowUrl, 'utf8'));
  const postgres = await readFile(postgresUrl, 'utf8');
  const publish = workflow.jobs.publish;
  const step = publish.steps.find(item => item.name === 'Publish the hardened PostgreSQL linux/amd64 child manifest');
  assert.ok(step);
  assert.match(step.run, /Containerfile\.postgres/);
  assert.match(step.run, /POSTGRES_PARENT_IMAGE/);
  assert.match(step.run, /GO_TOOLCHAIN_IMAGE/);
  assert.match(postgres, /FROM \$\{GO_TOOLCHAIN_IMAGE\} AS gosu-builder/);
  assert.match(postgres, /go install github\.com\/tianon\/gosu@v1\.19/);
  assert.match(postgres, /FROM \$\{POSTGRES_PARENT_IMAGE\}/);
  assert.match(postgres, /apk upgrade --no-cache/);
  assert.match(postgres, /COPY --from=gosu-builder \/out\/gosu \/usr\/local\/bin\/gosu/);
});

test('release receipts describe the actual child images and all three scans', async () => {
  const script = await readFile(releaseScriptUrl, 'utf8');
  assert.doesNotMatch(script, /postgres_image\.rsplit\("@", 1\)\[1\] != POSTGRES_PARENT_IMAGE/);
  assert.match(script, /"postgres\.sbom\.json"/);
  assert.match(script, /"postgres\.grype\.json"/);
  assert.match(script, /"node_toolchain"/);
  assert.match(script, /"go_toolchain"/);
  assert.match(script, /"postgres": POSTGRES_PARENT_IMAGE/);
});

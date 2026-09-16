import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

test('manual package diagnostic is main-only, bounded and read-only', async () => {
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-package-diagnostic.yml', import.meta.url), 'utf8'));
  assert.deepEqual(workflow.on, { workflow_dispatch: null });
  assert.deepEqual(workflow.permissions, { packages: 'read' });
  const job = workflow.jobs.diagnostic;
  assert.equal(job['timeout-minutes'], 3);
  assert.equal(job.steps.length, 1);
  assert.equal(job.steps[0].uses, undefined);
  assert.match(job.if, /refs\/heads\/main/);
  assert.match(job.if, /islamismylifebey-web\/lil-tweak/);
  assert.equal(job.steps[0].env.REGISTRY_TOKEN, '${{ github.token }}');
  const body = job.steps[0].run;
  assert.match(body, /method="GET"/);
  assert.match(body, /read\(8193\)/);
  assert.match(body, /replace\(token, "\[REDACTED\]"\)/);
  assert.doesNotMatch(body, /docker|push|subprocess|write_text|write_bytes/);
});

test('manual release verification uses the same private temporary-root contract as CI', async () => {
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-server-images.yml', import.meta.url), 'utf8'));
  const verify = workflow.jobs.verify;
  const preparation = verify.steps.findIndex(step => step.name === 'Create runner-owned temporary root');
  const verification = verify.steps.findIndex(step => step.name === 'Verify the complete source tree');
  assert.ok(preparation >= 0 && preparation < verification);
  assert.match(verify.steps[preparation].run, /install -d -m 0700 "\$RUNNER_TEMP\/lil-tweak-ci"/);
  for (const key of ['TMPDIR', 'TMP', 'TEMP']) {
    assert.equal(verify.steps[verification].env[key], '${{ runner.temp }}/lil-tweak-ci');
  }
  assert.deepEqual(verify.permissions, { contents: 'read' });
  assert.deepEqual(workflow.jobs.publish.needs, 'verify');
});

test('manual image release probes named packages without a user-namespace listing', async () => {
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-server-images.yml', import.meta.url), 'utf8'));
  const publish = workflow.jobs.publish;
  const preflight = publish.steps.find(step => step.name === 'Check package state before publication').run;
  const postflight = publish.steps.find(step => step.name === 'Require private packages linked to this exact repository').run;

  assert.doesNotMatch(preflight, /\/user\/packages/);
  assert.doesNotMatch(preflight, /\/users\/\$REGISTRY_OWNER\/packages\?/);
  assert.match(preflight, /for package in "\$CORE_PACKAGE" "\$RUNNER_PACKAGE" "\$POSTGRES_PACKAGE"/);
  assert.match(preflight, /\/users\/\$REGISTRY_OWNER\/packages\/container\/\$package/);
  assert.match(preflight, /case "\$status" in/);
  assert.match(preflight, /200\)/);
  assert.match(preflight, /404\)/);
  assert.match(preflight, /package-metadata/);

  assert.doesNotMatch(postflight, /\/user\/packages/);
  assert.match(postflight, /\/users\/\$REGISTRY_OWNER\/packages\/container\/\$package/);
  assert.match(postflight, /"\$status" != 200/);
});

test('private release pins the reviewed patched runtime bases by linux amd64 digest', async () => {
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-server-images.yml', import.meta.url), 'utf8'));
  const env = workflow.jobs.publish.env;
  assert.equal(
    env.PYTHON_BASE_IMAGE,
    'docker.io/library/python@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79',
  );
  assert.equal(
    env.RUNNER_BASE_IMAGE,
    'docker.io/library/node@sha256:a05717adfe7289e2a0fa36a694dc430a510adab6467c7036e51551198935abef',
  );
  assert.equal(
    env.POSTGRES_PARENT_IMAGE,
    'docker.io/library/postgres@sha256:d13db94ae661d517c5ed57c509a578d5ea64aae639871ba25294f4f42d83de28',
  );

  const core = await readFile(new URL('../deploy/Containerfile.core', import.meta.url), 'utf8');
  const runner = await readFile(new URL('../deploy/Containerfile.runner', import.meta.url), 'utf8');
  assert.match(core, /apt-get update\s*\\\n\s*&& apt-get upgrade --yes/);
  assert.match(runner, /apt-get update\s*\\\n\s*&& apt-get upgrade --yes/);
});

test('private release blocks fixable high and critical vulnerabilities after preserving full scan evidence', async () => {
  const workflow = yaml.load(await readFile(new URL('../.github/workflows/manual-server-images.yml', import.meta.url), 'utf8'));
  const publish = workflow.jobs.publish;
  const evidence = publish.steps.find(step => step.name === 'Generate final-digest SBOM and Grype evidence');
  const gate = publish.steps.find(step => step.name === 'Reject fixable high or critical vulnerabilities');

  assert.ok(evidence);
  assert.equal(evidence.env.POSTGRES_IMAGE, '${{ steps.postgres.outputs.reference }}');
  assert.match(evidence.run, /core\.sbom\.json/);
  assert.match(evidence.run, /runner\.sbom\.json/);
  assert.match(evidence.run, /postgres\.sbom\.json/);
  assert.match(evidence.run, /core\.grype\.json/);
  assert.match(evidence.run, /runner\.grype\.json/);
  assert.match(evidence.run, /postgres\.grype\.json/);
  assert.ok(gate);
  assert.match(gate.run, /for role in core runner postgres/);
  assert.match(gate.run, /--only-fixed/);
  assert.match(gate.run, /--fail-on high/);
  assert.match(gate.run, /\$role\.grype\.fixable\.txt/);
});

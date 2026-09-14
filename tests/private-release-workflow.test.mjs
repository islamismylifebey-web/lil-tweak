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

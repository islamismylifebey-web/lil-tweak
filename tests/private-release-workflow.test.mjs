import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

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

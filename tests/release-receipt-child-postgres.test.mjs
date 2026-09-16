import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const PYTHON_BASE_DIGEST = '2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79';
const RUNNER_BASE_DIGEST = 'a05717adfe7289e2a0fa36a694dc430a510adab6467c7036e51551198935abef';
const POSTGRES_PARENT_DIGEST = 'd13db94ae661d517c5ed57c509a578d5ea64aae639871ba25294f4f42d83de28';

test('release receipts describe the patched PostgreSQL child and all six final-image scans', async () => {
  const helper = await readFile(new URL('../scripts/lil-tweak-private-release.py', import.meta.url), 'utf8');

  assert.match(helper, new RegExp(PYTHON_BASE_DIGEST));
  assert.match(helper, new RegExp(RUNNER_BASE_DIGEST));
  assert.match(helper, new RegExp(POSTGRES_PARENT_DIGEST));
  assert.doesNotMatch(helper, /postgres_image\.rsplit\("@", 1\)\[1\] != POSTGRES_PARENT_IMAGE\.rsplit\("@", 1\)\[1\]/);
  assert.match(helper, /postgres_image\.rsplit\("@", 1\)\[1\] == POSTGRES_PARENT_IMAGE\.rsplit\("@", 1\)\[1\]/);
  assert.match(helper, /for reference in \(PYTHON_BASE_IMAGE, RUNNER_BASE_IMAGE, POSTGRES_PARENT_IMAGE\)/);

  for (const name of [
    'core.sbom.json',
    'runner.sbom.json',
    'postgres.sbom.json',
    'core.grype.json',
    'runner.grype.json',
    'postgres.grype.json',
  ]) {
    assert.match(helper, new RegExp(`"${name.replace('.', '\\.')}"`));
  }
});

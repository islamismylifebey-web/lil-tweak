import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

function source(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

test("configuration and operations docs keep only the retired Hub tombstone", async () => {
  const [readme, deployEnvironment, coreEnvironment, runbook] = await Promise.all([
    source("README.md"),
    source("deploy/core.env.example"),
    source("core/.env.example"),
    source("docs/operations/digitalocean.md"),
  ]);

  for (const [path, document] of [
    ["README.md", readme],
    ["deploy/core.env.example", deployEnvironment],
    ["core/.env.example", coreEnvironment],
    ["docs/operations/digitalocean.md", runbook],
  ]) {
    assert.doesNotMatch(
      document,
      /optional[\s\S]{0,160}GALOR|GALOR[\s\S]{0,160}optional|read-only HTTP dependency|future enablement|galor-readonly\.internal/i,
      path,
    );
  }

  assert.match(readme, /GALOR Hub is abandoned and is not a Lil Tweak dependency/);
  assert.match(readme, /directly owns the signed Core-to-Podman runner path/);
  assert.match(runbook, /GALOR Hub is abandoned and is not a Lil Tweak dependency/);
  assert.match(runbook, /directly owns the signed Core-to-Podman runner path/);
  assert.match(deployEnvironment, /Retired boundary:.*LIL_TWEAK_GALOR_READONLY_URL.*rejected/i);
  assert.match(coreEnvironment, /Retired boundary:.*LIL_TWEAK_GALOR_READONLY_URL.*rejected/i);
  assert.doesNotMatch(deployEnvironment, /^\s*#\s*LIL_TWEAK_GALOR_READONLY_URL=/m);
  assert.doesNotMatch(coreEnvironment, /^\s*#\s*LIL_TWEAK_GALOR_READONLY_URL=/m);
});

test("browser connection contract has no Hub status surface", async () => {
  const client = await source("app/engineering-client.ts");

  assert.doesNotMatch(client, /\bgalorHub\b|^\s*galor:\s*\{/m);
  assert.match(client, /owner:\s*"lil-tweak"/);
  assert.match(client, /route:\s*"direct_core_to_podman"/);
  assert.match(client, /intermediary:\s*"none"/);
  assert.match(client, /connection:\s*"not_reported"/);
  assert.match(client, /qualification:\s*"not_reported"/);
});

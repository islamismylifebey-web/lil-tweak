import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

const requiredFiles = [
  "deploy/Containerfile.core",
  "deploy/Containerfile.runner",
  "deploy/healthcheck.py",
  "core/lil_tweak/runtime_probe.py",
  "deploy/quadlet/lil-tweak-core.container",
  "deploy/quadlet/lil-tweak-postgres.container",
  "deploy/quadlet/lil-tweak.network",
  "deploy/quadlet/lil-tweak-data.volume",
  "deploy/quadlet/lil-tweak-postgres-data.volume",
  "deploy/lil-tweak-core.service.d/hardening.conf",
  "deploy/lil-tweak-postgres.service.d/hardening.conf",
  "scripts/install-digitalocean.sh",
  "scripts/install-cloudflare-tunnel.sh",
  "scripts/install-lil-tweak-release.sh",
  "scripts/lil-tweak-secret-snapshot.py",
  "scripts/lil-tweak-host-identity.py",
  "deploy/cloudflared/validate_credentials.py",
  "deploy/cloudflared/verify_binary.py",
  "scripts/verify-deployment.sh",
  "docs/operations/digitalocean.md",
  "docs/operations/cloudflare-d1.md",
  "deploy/cloudflare/wrangler.d1.example.jsonc",
  "deploy/cloudflare/d1-schema-probe.sql",
];

test("ships the complete isolated DigitalOcean deployment surface", () => {
  for (const path of requiredFiles) {
    assert.doesNotThrow(() => read(path), `missing ${path}`);
  }
});

test("core and PostgreSQL Quadlets are private, separate, and immutable", () => {
  const core = read("deploy/quadlet/lil-tweak-core.container");
  const postgres = read("deploy/quadlet/lil-tweak-postgres.container");

  assert.match(core, /^Image=@@LIL_TWEAK_CORE_IMAGE@@$/m);
  assert.match(postgres, /^Image=@@LIL_TWEAK_POSTGRES_IMAGE@@$/m);
  assert.match(core, /^Pull=never$/m);
  assert.match(postgres, /^Pull=never$/m);
  assert.match(core, /^Network=lil-tweak\.network$/m);
  assert.match(postgres, /^Network=lil-tweak\.network$/m);
  assert.match(core, /^PublishPort=127\.0\.0\.1:8017:8080$/m);
  assert.doesNotMatch(postgres, /PublishPort=/);
  assert.match(core, /^Volume=lil-tweak-data\.volume:\/var\/lib\/lil-tweak:U,Z$/m);
  assert.match(
    core,
    /^Tmpfs=\/var\/lib\/lil-tweak\/work:rw,exec,nosuid,nodev,size=1g,nr_inodes=204800,mode=0700,uid=10001,gid=10001$/m,
  );
  assert.doesNotMatch(core, /^Volume=.*:\/var\/lib\/lil-tweak\/work(?::|$)/m);
  assert.match(postgres, /^Volume=lil-tweak-postgres-data\.volume:\/var\/lib\/postgresql\/data:Z$/m);
  assert.match(core, /^ReadOnly=true$/m);
  assert.match(core, /^NoNewPrivileges=true$/m);
  assert.match(core, /^DropCapability=all$/m);
  assert.match(core, /^Memory=1536m$/m);
  assert.match(core, /^Label=com\.galor\.lil-tweak\.max-concurrent-jobs=1$/m);
  assert.match(postgres, /^Memory=512m$/m);
  assert.match(core, /^HealthCmd=\/usr\/local\/bin\/python \/app\/deploy\/healthcheck\.py$/m);
  assert.doesNotMatch(`${core}\n${postgres}`, /galor[-_. ]?(network|volume|database|user)/i);
});

test("runtime and service hardening enforce a single owner-only worker", () => {
  const core = read("deploy/quadlet/lil-tweak-core.container");
  const hardening = read("deploy/lil-tweak-core.service.d/hardening.conf");

  for (const setting of [
    "LIL_TWEAK_MAX_CONCURRENT_JOBS=1",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "RestrictSUIDSGID=true",
    "LockPersonality=true",
    "MemorySwapMax=0",
    "UMask=0077",
  ]) {
    assert.ok(`${core}\n${hardening}`.includes(setting), `missing ${setting}`);
  }
});

test("ships a reproducible non-root multi-language sandbox image", () => {
  const runner = read("deploy/Containerfile.runner");
  assert.match(runner, /^ARG RUNNER_BASE_IMAGE$/m);
  assert.match(runner, /^FROM \$\{RUNNER_BASE_IMAGE\}$/m);
  assert.match(runner, /python3-pytest/);
  assert.match(runner, /golang-go/);
  assert.match(runner, /cargo/);
  assert.match(runner, /default-jdk-headless/);
  assert.match(runner, /\bpatch\b/);
  assert.match(runner, /! command -v git/);
  assert.doesNotMatch(runner, /^\s*git\s*\\?$/m);
  assert.match(runner, /^USER 65532:65532$/m);
  assert.match(runner, /^WORKDIR \/workspace$/m);
  assert.doesNotMatch(runner, /curl\s+[^\n]*\|\s*(?:ba)?sh/);
});

test("installer is fresh-host bound and rejects mutable images", () => {
  const installer = read("scripts/install-digitalocean.sh");
  const secretSnapshot = read("scripts/lil-tweak-secret-snapshot.py");
  const hostIdentity = read("scripts/lil-tweak-host-identity.py");
  const coreEnvironmentExample = read("core/.env.example");

  assert.match(installer, /SERVICE_USER="lil-tweak"/);
  assert.match(installer, /@sha256:\[0-9a-f\]\{64\}/);
  assert.match(installer, /loginctl enable-linger/);
  assert.match(hostIdentity, /etc\/subuid/);
  assert.match(hostIdentity, /SUBORDINATE_COUNT = 65_536/);
  assert.match(installer, /systemctl start "user@\$\{service_uid\}\.service"/);
  assert.match(installer, /install -D/);
  assert.match(installer, /systemctl --user daemon-reload/);
  assert.match(installer, /migrations\/001_initial\.sql/);
  assert.match(installer, /migrations\/002_fencing\.sql/);
  assert.match(installer, /SECRET_SNAPSHOT_HELPER/);
  assert.match(installer, /unset secrets_source LIL_TWEAK_SECRETS_SOURCE/);
  assert.match(secretSnapshot, /LIL_TWEAK_WORK_ROOT_INODES/);
  assert.match(secretSnapshot, /"204800"/);
  assert.doesNotMatch(coreEnvironmentExample, /^LIL_TWEAK_GALOR_READONLY_URL=/m);
  assert.match(installer, /secret create lil-tweak-postgres-admin-password -/);
  assert.match(installer, /podman pull --authfile "\$\{runtime_auth_file\}" "\$\{image\}"/);
  assert.match(installer, /podman image inspect/);
  assert.match(installer, /pulled image digest mismatch/);
  assert.match(installer, /schema_exists=/);
  assert.match(installer, /\$\{schema_version\}" == "1"/);
  assert.match(installer, /\$\{schema_version\}" == "2"/);
  assert.match(installer, /\$\{schema_version\}" == "3"/);
  assert.match(installer, /apply_migration "\$\{MIGRATION_002_SOURCE\}"/);
  assert.match(installer, /apply_migration "\$\{MIGRATION_003_SOURCE\}"/);
  assert.doesNotMatch(installer, /CASE WHEN to_regclass/);
  assert.doesNotMatch(installer, /systemctl --user enable --now lil-tweak-(?:core|postgres)\.service/);
  assert.doesNotMatch(installer, /\beval\b/);
  assert.doesNotMatch(installer, /curl\s+[^\n]*\|\s*(?:ba)?sh/);
  assert.doesNotMatch(installer, /"\$\{SERVICE_HOME\}\/work"/);
  assert.doesNotMatch(read("deploy/lil-tweak-core.service.d/hardening.conf"), /ReadWritePaths=-\/var\/lib\/lil-tweak\/work/);
});

test("first-release runbook binds a fresh receipt to the reviewed runtime manifest", () => {
  const wrapper = read("scripts/install-lil-tweak-release.sh");
  const installer = read("scripts/install-digitalocean.sh");
  const runbook = read("docs/operations/digitalocean.md");

  const fresh = wrapper.indexOf('"${ROLLBACK_HELPER}" verify-fresh-install');
  const core = wrapper.indexOf('"${CORE_INSTALLER}" --install-under-wrapper "$$"');
  const tunnel = wrapper.indexOf('"${TUNNEL_INSTALLER}" --install-under-wrapper "$$"');
  const completed = wrapper.indexOf('"${ROLLBACK_HELPER}" mark-completed');
  assert.ok(fresh >= 0 && fresh < core && core < tunnel && tunnel < completed);

  const provenance = installer.indexOf('"${RELEASE_HELPER}" verify-runtime-install');
  const mutation = installer.indexOf("mutation_started=1");
  assert.ok(provenance >= 0 && provenance < mutation);

  for (const phrase of [
    "This first production installation is deliberately fresh-host only.",
    "A completed receipt cannot be reused for another installation.",
    "LIL_TWEAK_SOURCE_MANIFEST",
    "LIL_TWEAK_RUNTIME_MANIFEST",
    "LIL_TWEAK_RUNTIME_MANIFEST_SHA256",
  ]) {
    assert.ok(runbook.includes(phrase), `missing first-release contract: ${phrase}`);
  }
  assert.doesNotMatch(runbook, /The installer is idempotent for the same inputs\./);
});

test("scripts support offline checks without contacting the droplet", () => {
  for (const script of [
    "scripts/install-lil-tweak-release.sh",
    "scripts/install-digitalocean.sh",
    "scripts/install-cloudflare-tunnel.sh",
    "scripts/verify-deployment.sh",
  ]) {
    const syntax = spawnSync("bash", ["-n", script], { encoding: "utf8" });
    assert.equal(syntax.status, 0, syntax.stderr);
    const check = spawnSync("bash", [script, "--check"], { encoding: "utf8" });
    assert.equal(check.status, 0, `${script}: ${check.stderr || check.stdout}`);
    assert.match(check.stdout, /check: ok/i);
  }
  for (const script of [
    "scripts/lil-tweak-secret-snapshot.py",
    "scripts/lil-tweak-host-identity.py",
  ]) {
    const helperCheck = spawnSync("python3", [script, "--check"], { encoding: "utf8" });
    assert.equal(helperCheck.status, 0, helperCheck.stderr || helperCheck.stdout);
    assert.match(helperCheck.stdout, /check: ok/i);
  }
  assert.doesNotMatch(read("scripts/verify-deployment.sh"), /\.Config\.Env/);
  assert.match(read("scripts/verify-deployment.sh"), /podman image exists "\$\{runner_image\}"/);
  const runtime = read("deploy/verify_runtime.py");
  assert.match(runtime, /lil_tweak\.runtime_probe/);
  assert.match(runtime, /MemorySwapMax/);
  assert.match(runtime, /memory\.swap\.max/);
  assert.match(runtime, /MAX_PROBE_OUTPUT_BYTES/);
  assert.doesNotMatch(runtime, /"podman",\s*"run"/);
  assert.doesNotMatch(runtime, /def smoke_runner/);
  const ready = read("deploy/verify_ready.py");
  assert.match(ready, /\[\s*"v2",\s*key_id,\s*"GET",\s*"\/readyz"/);
  assert.match(ready, /request_id,\s*"",\s*owner/);
  assert.doesNotMatch(ready, /\["v1",\s*"GET"/);
});

test("runbook makes Cloudflare the only ingress and documents lifecycle drills", () => {
  const readme = read("README.md");
  const runbook = read("docs/operations/digitalocean.md");

  for (const phrase of [
    "galor-private-cloud-01",
    "Cloudflare Tunnel",
    "never open port 8017",
    "dedicated `lil-tweak` Unix user",
    "migration",
    "backup",
    "restore",
    "signing-key rotation",
    "rollback",
    "directly owns",
    "no intermediary runner control plane",
    "/healthz",
    "/readyz",
    "1 GiB",
    "204,800",
    "256 MiB",
    "65,536",
  ]) {
    assert.ok(runbook.toLowerCase().includes(phrase.toLowerCase()), `missing ${phrase}`);
  }
  for (const phrase of [
    "galor-private-cloud-01 is being qualified as a dedicated Lil Tweak host.",
    "GALOR Hub is abandoned and is not a Lil Tweak dependency.",
    "Four-GiB deployment remains blocked until live headroom qualification",
  ]) {
    for (const document of [readme, runbook]) {
      const normalized = document.replaceAll("`", "");
      assert.ok(normalized.includes(phrase), `missing dedicated-host declaration: ${phrase}`);
    }
  }
  assert.doesNotMatch(runbook, /https?:\/\/(?!127\.0\.0\.1)(?:\d{1,3}\.){3}\d{1,3}/);
});

test("four-GiB standalone deployment stays blocked pending live evidence", () => {
  const readme = read("README.md").toLowerCase();
  const runbook = read("docs/operations/digitalocean.md").toLowerCase();

  for (const value of [readme, runbook]) {
    assert.match(value, /four[- ]gib|4 gib/);
    assert.match(value, /eight[- ]gib|8 gib/);
    assert.match(value, /blocked|do not qualify|before production qualification/);
    assert.match(value, /dedicated|another host|move/);
  }
});

test("ships an explicit D1 migration gate before Worker cutover", () => {
  const runbook = read("docs/operations/cloudflare-d1.md");
  const config = JSON.parse(read("deploy/cloudflare/wrangler.d1.example.jsonc"));
  const probe = read("deploy/cloudflare/d1-schema-probe.sql");

  assert.equal(config.d1_databases[0].binding, "DB");
  assert.equal(config.d1_databases[0].migrations_dir, "../../drizzle");
  for (const phrase of [
    "wrangler d1 info",
    "wrangler d1 export",
    "wrangler d1 time-travel info",
    "wrangler d1 migrations list",
    "wrangler d1 migrations apply",
    "d1-schema-probe.sql",
    "do not cut over",
    "oai-authenticated",
  ]) {
    assert.ok(runbook.includes(phrase), `D1 runbook is missing ${phrase}`);
  }
  for (const table of [
    "workspace_projects",
    "engineering_jobs",
    "engineering_sources",
    "engineering_evidence",
    "engineering_audit_events",
  ]) {
    assert.ok(probe.includes(table), `D1 schema probe is missing ${table}`);
  }
  assert.match(probe, /foreign_key_check/i);
});

test("D1 gate detects malformed runtime-required columns, checks, and indexes", () => {
  const root = new URL("..", import.meta.url).pathname;
  const script = String.raw`
import json, sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
def probe(tamper):
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys=ON")
    for name in ("0000_gifted_sharon_ventura.sql", "0001_lil_tweak_engineering.sql", "0002_workspace_creation_idempotency.sql"):
        db.executescript((root / "drizzle" / name).read_text().replace("--> statement-breakpoint", ""))
    db.executescript("CREATE TABLE d1_migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL); INSERT INTO d1_migrations VALUES (1,'0000_gifted_sharon_ventura.sql','now'),(2,'0001_lil_tweak_engineering.sql','now'),(3,'0002_workspace_creation_idempotency.sql','now');")
    if tamper == "drop_etag":
        db.execute("ALTER TABLE engineering_sources DROP COLUMN r2_etag")
    if tamper == "wrong_owner_index":
        db.executescript("DROP INDEX idx_engineering_jobs_owner_create_key; CREATE UNIQUE INDEX idx_engineering_jobs_owner_create_key ON engineering_jobs(id);")
    if tamper == "drop_workspace_digest":
        db.execute("ALTER TABLE workspace_projects DROP COLUMN create_request_digest")
    if tamper == "wrong_workspace_index":
        db.executescript("DROP INDEX idx_workspace_projects_owner_create_key; CREATE UNIQUE INDEX idx_workspace_projects_owner_create_key ON workspace_projects(create_idempotency_key, owner_email) WHERE create_idempotency_key IS NOT NULL;")
    if tamper == "wrong_workspace_predicate":
        db.executescript("DROP INDEX idx_workspace_projects_owner_create_key; CREATE UNIQUE INDEX idx_workspace_projects_owner_create_key ON workspace_projects(owner_email, create_idempotency_key) WHERE owner_email IS NOT NULL;")
    if tamper == "wrong_workspace_check":
        db.execute("PRAGMA writable_schema=ON")
        db.execute("UPDATE sqlite_master SET sql=replace(sql, 'in (0,1)', 'in (0,1,2)') WHERE type='table' AND name='workspace_projects'")
        db.execute("PRAGMA writable_schema=OFF")
        schema_version = db.execute("PRAGMA schema_version").fetchone()[0]
        db.execute(f"PRAGMA schema_version={schema_version + 1}")
    if tamper == "missing_workspace_migration":
        db.execute("DELETE FROM d1_migrations WHERE name='0002_workspace_creation_idempotency.sql'")
    results = []
    for statement in (root / "deploy/cloudflare/d1-schema-probe.sql").read_text().split(";"):
        if statement.strip():
            results.append(db.execute(statement).fetchall())
    return results
print(json.dumps({
    "healthy": probe(None),
    "missing_etag": probe("drop_etag"),
    "wrong_owner_index": probe("wrong_owner_index"),
    "missing_workspace_digest": probe("drop_workspace_digest"),
    "wrong_workspace_index": probe("wrong_workspace_index"),
    "wrong_workspace_predicate": probe("wrong_workspace_predicate"),
    "wrong_workspace_check": probe("wrong_workspace_check"),
    "missing_workspace_migration": probe("missing_workspace_migration"),
}))
`;
  const result = spawnSync("python3", ["-c", script, root], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.ok(output.healthy.slice(0, -1).every((rows) => rows.length === 0));
  assert.ok(
    output.missing_etag[1].some(([table, column]) => table === "engineering_sources" && column === "r2_etag"),
    "the release gate must reject a source schema without r2_etag",
  );
  assert.ok(
    output.wrong_owner_index.slice(0, -1).flat(3).includes("idx_engineering_jobs_owner_create_key"),
    "the release gate must reject an owner-create index on the wrong columns",
  );
  assert.ok(
    output.missing_workspace_digest.slice(0, -1).flat(3).includes("create_request_digest"),
    "the release gate must reject a workspace schema without the request digest",
  );
  assert.ok(
    output.wrong_workspace_index.slice(0, -1).flat(3).includes("idx_workspace_projects_owner_create_key"),
    "the release gate must reject a workspace idempotency index with reversed columns",
  );
  assert.ok(
    output.wrong_workspace_predicate.slice(0, -1).flat(3).includes("idx_workspace_projects_owner_create_key"),
    "the release gate must reject a workspace idempotency index with the wrong predicate",
  );
  assert.ok(
    output.wrong_workspace_check.slice(0, -1).flat(3).includes("workspace_projects_create_complete_check"),
    "the release gate must reject a workspace completion constraint with invalid values",
  );
  assert.ok(
    output.missing_workspace_migration.slice(0, -1).flat(3).includes("0002_workspace_creation_idempotency.sql"),
    "the release gate must reject a database without the 0002 migration record",
  );
});

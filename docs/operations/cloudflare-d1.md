# Cloudflare D1 migration and cutover

This is a blocking production gate. Run it from an authenticated administration workstation in the exact reviewed release checkout. It changes D1 only when the explicit `migrations apply` command is run; none of the repository verification commands change Cloudflare resources.

Lil Tweak uses Wrangler-managed, forward-only migrations from `drizzle/`. The checked example configuration exists only to select that directory. It is not a deploy configuration and its placeholder database identity must never be used.

## 1. Prepare and bind the exact database

Install the locked dependencies and confirm Wrangler 4.x or newer:

```bash
npm ci
./node_modules/.bin/wrangler --version
cp deploy/cloudflare/wrangler.d1.example.jsonc deploy/cloudflare/wrangler.d1.local.jsonc
chmod 0600 deploy/cloudflare/wrangler.d1.local.jsonc
```

Edit only `database_name` and `database_id` in the local file. Copy both values from the production D1 resource bound to the Sites project as `DB`. Then verify the resolved resource before doing anything else:

```bash
D1_OPS_CONFIG=deploy/cloudflare/wrangler.d1.local.jsonc
./node_modules/.bin/wrangler d1 list --json --config "$D1_OPS_CONFIG"
./node_modules/.bin/wrangler d1 info DB --json --config "$D1_OPS_CONFIG"
```

Stop if the returned name or UUID differs from the production `DB` binding. Do not infer the target from an account default, a preview database, or a similarly named resource.

## 2. Capture recovery points

Create a private backup directory outside the repository, record the UTC cutover time, export schema and data, and record the current Time Travel bookmark:

```bash
D1_BACKUP_DIR=/absolute/private/lil-tweak-d1-precutover
install -d -m 0700 "$D1_BACKUP_DIR"
./node_modules/.bin/wrangler d1 export DB --remote --config "$D1_OPS_CONFIG" --output "$D1_BACKUP_DIR/pre-migration.sql" --skip-confirmation
./node_modules/.bin/wrangler d1 time-travel info DB --json --config "$D1_OPS_CONFIG" > "$D1_BACKUP_DIR/time-travel.json"
sha256sum "$D1_BACKUP_DIR/pre-migration.sql" "$D1_BACKUP_DIR/time-travel.json"
```

Keep the export and its hash encrypted and separate from the application host. A Time Travel restore overwrites the database in place, so it is a disaster-recovery action, not a routine migration step.

## 3. Review and apply migrations

List the exact pending files. The reviewed Lil Tweak migration sequence must be `0000_gifted_sharon_ventura.sql`, then `0001_lil_tweak_engineering.sql`, then `0002_workspace_creation_idempotency.sql`. The remote pending list may be an ordered suffix of that sequence: a new database lists all three, while a database already at 0001 lists only 0002.

```bash
./node_modules/.bin/wrangler d1 migrations list DB --remote --config "$D1_OPS_CONFIG"
```

Compare the pending files with the reviewed release. If the list is not the expected ordered suffix, `0002_workspace_creation_idempotency.sql` is absent when the workspace idempotency release is being cut over, an applied migration is unexpectedly pending, or the backup is missing, stop. Apply once:

```bash
./node_modules/.bin/wrangler d1 migrations apply DB --remote --config "$D1_OPS_CONFIG"
```

Wrangler applies each migration transactionally, records it in `d1_migrations`, and captures a platform backup. If any migration reports an error, do not cut over the Worker. Preserve the output and investigate the failed migration; do not run ad hoc reverse SQL.

## 4. Prove the resulting schema

Re-list migrations and run the checked, read-only probe:

```bash
./node_modules/.bin/wrangler d1 migrations list DB --remote --config "$D1_OPS_CONFIG"
./node_modules/.bin/wrangler d1 execute DB --remote --config "$D1_OPS_CONFIG" --file deploy/cloudflare/d1-schema-probe.sql --yes
```

The migration list must be empty. Every missing-or-incompatible table, column, index, check-constraint, partial-index, and migration-history query must return zero rows; `pragma_foreign_key_check` must also return zero rows. In particular, the probe requires the three workspace idempotency columns, the boolean completion check, and the partial unique owner/idempotency index with its runtime column order and predicate. The final `d1_migrations` result must show `0000_gifted_sharon_ventura.sql`, `0001_lil_tweak_engineering.sql`, and `0002_workspace_creation_idempotency.sql` in order. A missing or malformed 0002 schema or migration record, or any other unexpected result, blocks cutover.

## 5. Worker and identity cutover gate

Only after the schema gate passes may the matching Worker/Sites release be selected. Before routing owner traffic, prove all of these from an external client:

- the exact configured Sites production origin is the only accepted browser origin;
- direct Worker and service origins are unreachable;
- private Sites custom access reports one owner, zero groups, zero visitors, and zero custom domains;
- an anonymous request is denied by native Sites access;
- a request with forged `oai-authenticated-*` values but no authenticated dispatch session is denied;
- an alternate-host request is rejected because it differs from the unchanged `PUBLIC_ORIGIN`;
- D1 is bound as `DB`, R2 is bound as `FILES`, and an authenticated owner can perform a read-only project/job lookup;
- a non-owner identity cannot read that owner data; and
- an authenticated owner same-origin flow passes the server allowlist and existing mutation checks.

If any native Sites access, dispatch-owned identity, exact-origin, owner allowlist, or mutation same-origin probe fails, do not cut over. Do not substitute a custom-domain proxy or caller-controlled identity mechanism.

## 6. Rollback

For a code-only failure, move traffic back to the preceding schema-compatible Worker release and retain the forward schema. For a failed migration, Wrangler leaves prior successful migrations applied; fix forward in a reviewed release. Restore D1 with `wrangler d1 time-travel restore` only under an explicit incident decision after capturing a new export, pausing owner writes, selecting the recorded bookmark, and acknowledging that the restore overwrites production data.

Cloudflare command behavior is defined by the current [D1 Wrangler command reference](https://developers.cloudflare.com/d1/wrangler-commands/); recovery semantics are documented in [D1 Time Travel and backups](https://developers.cloudflare.com/d1/reference/time-travel/).

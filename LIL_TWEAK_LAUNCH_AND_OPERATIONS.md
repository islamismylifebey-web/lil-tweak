# Lil Tweak Private Launch and Operations

## Supported launch

Lil Tweak is a private localhost application. Bind only to `127.0.0.1`; do not use `0.0.0.0`, a
public tunnel, a hosted preview, or a public deployment.

Create private state directories outside the repository, supply an owner-generated access key,
and start the application:

```bash
install -d -m 700 /tmp/liltweak-private /tmp/liltweak-private/data /tmp/liltweak-private/uv-cache

UV_CACHE_DIR=/tmp/liltweak-private/uv-cache \
LILTWEAK_ENVIRONMENT=development \
LILTWEAK_DB_PATH=/tmp/liltweak-private/data/liltweak.db \
LILTWEAK_DEV_API_KEY='<owner-generated-local-key>' \
LILTWEAK_WORKBENCH_ENABLED=true \
LILTWEAK_SERVER_HOST=127.0.0.1 \
LILTWEAK_WORKBENCH_MODEL_ENABLED=false \
LILTWEAK_WORKBENCH_WORKSPACE_ROOT=/tmp/liltweak-private/workbench-tasks \
LILTWEAK_WORKSPACE_ROOT=/absolute/path/to/registered-repository-parent \
LILTWEAK_REPOSITORIES_JSON='{"local:repo_local":"repository-directory-name"}' \
LILTWEAK_ARTIFACT_ROOT=/tmp/liltweak-private/artifacts \
LILTWEAK_EXECUTION_RUNTIME_ROOT=/tmp/liltweak-private/runtime \
PORT=8765 \
uv run --no-sync --offline python main.py
```

The built-in launcher defaults to `127.0.0.1`. When Workbench is enabled, configuration rejects
wildcard, hostname, and non-loopback bind targets; this release has no public Workbench deployment
override.

Open `http://127.0.0.1:8765/workbench`, authenticate with the owner key, and select only a
server-configured opaque repository ID. Repository mappings must be relative directory names
under `LILTWEAK_WORKSPACE_ROOT`; the API never accepts or returns their host paths. Public task
creation is available only at the repository-bound task route. There is no public endpoint for a
caller-constructed `TaskImport`, source digest, filesystem path, or clone URL.

## Server-bound acceptance

Run acceptance requests only against the loopback server. Use the repository IDs returned by the
server; never substitute a host path or clone URL. The following commands check the public health
surface, establish an owner session, and confirm authenticated Workbench status and repository
registration without enabling the model or runner:

```bash
curl --fail --silent --show-error http://127.0.0.1:8765/health
curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8765/workbench
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  http://127.0.0.1:8765/v1/workbench/health)" = 401

read -r -s -p 'Owner key: ' LILTWEAK_ACCEPTANCE_OWNER_KEY
echo
curl --fail --silent --show-error \
  --cookie-jar /tmp/liltweak-private/owner.cookies \
  --header 'Content-Type: application/json' \
  --data "$(LILTWEAK_ACCEPTANCE_OWNER_KEY="$LILTWEAK_ACCEPTANCE_OWNER_KEY" \
    python -c 'import json, os; print(json.dumps({"owner_key": os.environ["LILTWEAK_ACCEPTANCE_OWNER_KEY"]}))')" \
  http://127.0.0.1:8765/v1/workbench/session \
  > /tmp/liltweak-private/session.json
unset LILTWEAK_ACCEPTANCE_OWNER_KEY

curl --fail --silent --show-error \
  --cookie /tmp/liltweak-private/owner.cookies \
  http://127.0.0.1:8765/v1/workbench/health
curl --fail --silent --show-error \
  --cookie /tmp/liltweak-private/owner.cookies \
  http://127.0.0.1:8765/v1/workbench/repositories
```

The expected Workbench health response remains truthful: the model is disabled, the runner is
disconnected/unqualified, network is denied, and execution permission is false. Delete the private
cookie and session files after acceptance:

```bash
rm -f /tmp/liltweak-private/owner.cookies /tmp/liltweak-private/session.json
```

## Expected status on this host

| Field | Expected value |
|---|---|
| Backend | Ready / HTTP 200 |
| Workbench UI | HTTP 200 |
| Unauthenticated Workbench API | HTTP 401 |
| Model | `disabled` |
| Runner qualification | `unavailable` or `unqualified` |
| Runner connection | `disconnected` |
| Network | `denied` |
| Execution permission | `false` |
| Evidence integrity | `durable_hmac` when launched with configured server key material |
| GCP | Not connected |
| Public deployment | None |

The final private acceptance run bound to `127.0.0.1:8770`; public health, UI, owner login, and
authenticated Workbench health returned 200; an unauthenticated Workbench health request returned
401. A clean disposable Git repository registered under an opaque server ID was listed and
inspected, and its repository-bound task route returned 202 with state `RECEIVED`. Health remained
truthful throughout: model disabled, runner disconnected, network denied, execution false, and
evidence integrity `durable_hmac`. The process exited cleanly after the check.

## Operating sequence

1. Register repositories only through server configuration.
2. Inspect the repository in the Projects / Repositories view.
3. Create one immutable repository-bound task.
4. Inspect the task copy and review the source fingerprint and Git facts.
5. Produce an exact plan only when the model adapter is connected.
6. Review the full plan and binding digest before approval.
7. If an exact approval expires, reissue only that task-bound approval through
   `POST /v1/workbench/tasks/{task_id}/approvals/{approval_id}/reissue`; review and decide the new
   digest rather than reusing the expired one.
8. Start execution only when health reports a qualified connected runner.
9. Review tests, verification, final tree digest, patch, artifacts, and evidence.
10. Request a separate rollback approval after a failed attempted execution.
11. Stop with `Ctrl+C`; confirm the Uvicorn process exits.

## Emergency and recovery controls

- Emergency Stop is server-side and prevents new approvals and execution.
- Reset requires a fresh owner-key reauthentication at `POST /v1/workbench/emergency-stop/reset`,
  a disconnected runner, and no nonterminal task. The signed control audit records both actions.
- Reset clears only the global stop; tasks canceled by the stop remain terminal and are not resumed.
- Cancel marks the task canceled and signals the runner cancellation boundary.
- A recovery snapshot is created only after runner preflight and exact approval validation, and
  before the first attempted tool.
- Rollback requires a distinct purpose-bound owner approval and verifies the restored tree digest.
- Storage paths, encryption material, provider keys, and repository host paths are not returned to
  the browser.

Approval reissue, emergency engage, and emergency reset are authenticated, CSRF-protected server
mutations. The reset request body is `{"owner_key":"<fresh owner key>"}`. Do not put the owner key
in a URL, checked-in script, browser storage, or shell history.

## Model activation

See `LOCAL_AGENT_MODEL_ACTIVATION.md`. Model activation and runner activation are independent; a
model credential cannot enable command execution.

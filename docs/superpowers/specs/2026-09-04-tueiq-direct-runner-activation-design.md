# Tueiq Direct Runner Activation Design

Date: 2026-09-04
Status: approved for implementation and live qualification
Scope: Tueiq/Lil Tweak only

## Outcome

Tueiq controls one qualified engineering runner on the existing DigitalOcean
Droplet. The complete path is owner-only, direct, authenticated, bounded, and
proven on the live host. The system must not report the runner as connected or
qualified before fresh evidence satisfies every gate in this document.

## Immutable target

- Provider: `DigitalOcean`
- Droplet ID: `597343619`
- Hostname: `galor-tweak-runner-01`
- Region: `nyc1`
- Operating system: Ubuntu 24.04 LTS x64
- Size: `s-4vcpu-8gb`
- Role: `role-tweak-runner`
- Owner: `tueiq`
- Canonical Core owner scope: `a0885bc0b2c079e996629061a723c74d`
- Policy: `ENGINEERING_EXECUTION_ONLY`

Provider, Droplet ID, and hostname form one immutable identity. A matching
hostname on another Droplet, a matching Droplet with another hostname, missing
metadata, malformed metadata, or a metadata timeout must fail before any
installation or rollback mutation.

The legacy word `galor` survives only inside the immutable provider hostname
recorded above. It grants no relationship, credential, transport, process,
network, repository, or authority.

## Direct control path

The only permitted execution path is:

`owner-authenticated Tueiq Site -> HMAC-signed Tueiq Core API -> Core-local durable scheduler -> local rootless Podman socket -> fresh disposable sandbox`

The Core, PostgreSQL journal, and rootless Podman runtime run on Droplet
`597343619`. Cloudflare Tunnel and Access may transport requests to the
loopback-only Core. They are ingress controls, not a job broker or runner
control plane. No Worker Durable Object, GALOR service, GitHub self-hosted
runner, generic offer/claim broker, or other dispatcher is permitted between
Tueiq and its Core-local runner.

The browser boundary is native private Sites custom access: exactly one owner,
zero groups, zero visitors, and zero custom domains. Dispatch-owned SIWC identity
headers still pass through the server's exact owner allowlist and mutation
same-origin checks. Production requests must match the unchanged canonical
`PUBLIC_ORIGIN`. Live activation must prove anonymous denial, forged-identity
denial, alternate-host rejection, and a successful owner same-origin flow.
Any failed probe stops activation; no custom-domain proxy, front Worker,
Transform Rule, or identity-header fallback may replace that boundary. The Core
path remains independently protected by Access service-token and HMAC checks.

## GALOR Hub retirement boundary

The release must contain no GALOR Hub adapter, configuration, environment
value, fetched context, status object, provenance, UI panel, workflow,
container label, or operational dependency. The retired
`LIL_TWEAK_GALOR_READONLY_URL` variable must fail closed when present, including
when its value is blank. Its exact name may survive only as a denylist sentinel
in Core configuration enforcement and its direct regression tests; that is a
rejection boundary, not configuration or compatibility. Documentation must not
suggest co-residency, later enablement, or fallback to Hub.

Closed Hub work and its evidence are not activation inputs. Concepts may be
reimplemented only in Tueiq-owned code and must receive fresh tests and live
evidence.

## Runtime boundary

- Core and PostgreSQL images are strict digest-pinned references.
- The runner image is a strict digest-pinned reference and must exist locally.
- Core listens only on `127.0.0.1:8017`.
- The sandbox is rootless, read-only except for bounded mounts, network-disabled,
  capability-dropped, resource-limited, and deleted after each job.
- Only one engineering or Test World execution may hold the shared runtime lock.
- The service account is unprivileged and owns only bounded service/work paths.
- The runner receives no OpenAI key, database/R2 credentials, signing keys,
  production/deployment credentials, browser authority, or host environment.
- The runner cannot push, merge, deploy, target an arbitrary repository, escape
  the workspace, or invoke an unrestricted host shell.

## Source baseline

The activation branch begins at the current Sites source commit
`e76996970e816c4cce7b8334e0495e1e0de48e7d` so the owner-facing Site and its
mobile/UI work are preserved. It imports the Test World implementation merged
by GitHub PR #29 at merge commit
`97acede665df94ea7002b6eb7eceb8dc28ea94f7`, then ports the Hub-detachment work
from PR #28. The self-mutating workflow
`.github/workflows/tueiq-main-wiring-patch.yml` must not survive the import.

Known PR #29 review defects are part of activation scope:

- `fail_attempt` must bind owner, world, attempt state, generation, and worker;
- failure summaries must be bounded to 65,536 UTF-8 bytes before persistence in
  both in-memory and PostgreSQL stores;
- world listing must not load complete attempt payloads merely to count them;
- CI must not rewrite and push repository code.

## Connection truth

An unsigned `/healthz` response proves only that an HTTP process answered. It
must not be labeled a connected runner. The owner-only status route must derive
the same 32-lower-hex owner scope used by ordinary job traffic and use the same
HMAC v2 request contract to probe `/readyz`, including that canonical owner,
nonce, request ID, body digest, signing key ID, signature, and Cloudflare Access
headers when required. The Site's established D1 partition key hashes to
`a0885bc0b2c079e996629061a723c74d`; Core configuration, examples, tests, and
live secrets must use that exact scope. The authenticated login email is an
authorization identity, not the Core/D1 partition key.

The connection surface may report:

- `pending_configuration`: required bindings are absent or invalid;
- `configured_pending_probe`: bindings validate but no probe was requested;
- `ready`: a fresh signed `/readyz` returned the exact ready schema with every
  dependency check true;
- `unreachable`: the signed probe failed, timed out, redirected, exceeded its
  byte limit, returned malformed JSON, or reported any failed check.

The status response must describe owner `tueiq`, route
`direct_core_to_local_podman`, intermediary `none`, exact provider/Droplet/host/
role identity, and digest-pinned image policy. It must expose no secret,
credential, token, signature, origin URL, internal IP, or raw probe body.

`runner.connection` is the only serialized connection state. There is no
second `bridge.state` that can disagree with it. Transport diagnostics remain
descriptive only, and the browser must parse the complete response at runtime:
unknown or missing fields, a non-literal runner identity, an unsupported state,
or a transport/readiness combination inconsistent with `runner.connection`
fails closed instead of being type-cast into the UI. The owner-only route must
be exercised as a route, not accepted by source-text inspection: an authorized
request derives `ownerFor(request) -> ownerScope(owner)` and an unauthorized or
wrong owner performs no Core fetch.

For the bodyless readiness request, the HMAC v2 canonical idempotency field is
the empty string and the HTTP `Idempotency-Key` header is omitted. The Core's
verifier maps the absent header to that same empty canonical field. Tests must
independently compute this signature and reject either a different canonical
field order or a surprise idempotency header.

Signed readiness proves connection, not qualification. Qualification remains
`not_reported` until the live gates below have been completed and independently
checked.

## Test World import acceptance

The durable Test World remains an owner-scoped Core feature backed by schema
version 3. It shares the production runtime lock and existing sandbox policy.
Its retry, lease, judge, persistence, and failure paths must pass focused tests
before activation. The branch must preserve the current Site source even when
GitHub `main` has moved independently.

## Evidence truth boundary

The executable local harness produces only a canonical
`tueiq-direct-runner-local-qualification-v1` receipt. That receipt may prove the
guest identity, provider-evidence binding, local runtime, Job A, Job B, nine
negative cases, cleanup, and loopback signed readiness. It is necessary but is
not sufficient to establish live connection, overall qualification, or
readiness to work. It contains no `CONNECTED`, `QUALIFIED`, or `READY_TO_WORK`
fields and its verifier prints none of those truths.

Activation uses two explicit phases separated by an independent witness. In
phase one, the activation validator may produce only
`tueiq-direct-runner-activation-candidate-v1`; the candidate
contains no `CONNECTED`, `QUALIFIED`, or `READY_TO_WORK` fields and no candidate
command prints them. It receives the original local qualification, provider,
runtime, completed rollback, production, deployed-Site primary responses,
owner-flow decision/job, independently collected D1/Core/guest cross-checks,
and session change-record artifacts plus the exact source checkout. It reopens
each secure artifact and recomputes its canonical digest and cross-artifact
identity, source, image, deployment, Site-version, owner, job, cleanup, and time
bindings. Merely copying digests out of another receipt is not verification.

Between phases, an independent witness must verify the candidate against those primary
artifacts and separately collected cross-checks. The witness must observe and
hash each authenticated raw provider response before those raw bytes are
discarded, because forbidden provider fields may not be retained. It publishes
only a canonical sanitized `tueiq-direct-runner-independent-review-v1` artifact
with lowercase decision `pass`, bound to the candidate and all retained
primary-artifact hashes; that artifact also contains and prints no final
uppercase truth.

In phase two, and only after the independent-review artifact exists, the
reviewed finalizer may create `tueiq-direct-runner-activation-v1`. The three final
uppercase booleans may appear only in this receipt, set to true immediately
before atomic publication after candidate and review validation both pass. Only
independent verification of this post-review receipt may print the uppercase
truth lines.

## Live activation gates

### Gate 1 — Exact host and secure access

Capture DigitalOcean provider state with the authenticated read-only Droplet-get
operation for ID `597343619`, hash the exact raw response, and normalize only the
allowlisted identity/capacity fields into fresh canonical provider evidence.
Bind that normalized document and digest into the local receipt and recompute it
again for the activation receipt. Inside the guest, verify hostname plus the
metadata-service Droplet ID. Administrative access must use an approved console
or SSH path. No private key, password, token, signing secret, API key, network
address, gateway, or VPC identifier may appear in Git, workflow output, chat,
screenshots, or qualification evidence.

### Gate 2 — Hardened installation

After a collision-free external-resource and Site-binding inventory, create the
new Tunnel/Access/service-token and HMAC inputs and stage their matching
root-owned secrets before installation. Install the reviewed exact source and
digest-pinned Core, PostgreSQL, runner, and cloudflared artifacts through the
repository's transactional release path.
Verify unprivileged users, file modes/ownership, systemd/Quadlet hardening,
firewall policy, loopback-only Core, private Podman network, one-job limit,
schema version 3, data integrity, and rollback receipt.

### Gate 3 — Direct authenticated connection

Configure the Site's Core origin/private binding, Access service-token pair,
and HMAC key pair to match the live Core. A fresh owner-scoped signed `/readyz`
must pass from the deployed Site. No Hub service may be installed, configured,
called, or reachable from the Tueiq stack.

After the Site version and deployment IDs exist, a harmless owner-authenticated
request must traverse the deployed Site, D1, the signed Core API, the Core-local
scheduler, and the local runner. It uses an immutable repository revision,
performs no edit or external action, and yields a sanitized canonical owner-flow
job receipt whose D1/Core identities, job/Core revisions, ordered event IDs and
timestamps, evidence digests, empty patch, and cleanup can be independently
checked. The receipt must come from an executable in-page collector that uses
the existing owner-authenticated browser session without reading or exporting
its cookie. Exact allowlisted Site response bodies are retained as primary
evidence and are checked against a separately collected owner-only D1 export,
signed loopback Core observation, and guest/runtime observation. Readiness or a
self-authored normalized summary cannot stand in for this owner flow.

All activation-managed Site binding names must be absent at preflight. Existing
environment, public-origin, and owner-only OpenAI settings remain unchanged. A
collision stops the activation; rollback removes only resources and keys created
in the current session and redeploys the recorded prior Site version. This
no-read/no-restore rule applies to previously absent Site binding keys. It does
not alter the protected transactional host rollback, which must continue to
capture and, when invoked, restore pre-existing sensitive Core/Tunnel bytes
without exposing them.

The six absent binding names are `CORE_ORIGIN`, `CORE_ACCESS_CLIENT_ID`,
`CORE_ACCESS_CLIENT_SECRET`, `CORE_SIGNING_KEY_ID`, `CORE_SIGNING_SECRET`, and
`CUSTOMER_HTTP_LIL_TWEAK_CORE`. Activation adds only the first five; the unused
private-binding alternative remains absent. Resource creation order is Tunnel,
Access application, service token, policy, fixed secret directory, then DNS.
The policy consumes the previously created token ID. Combined host installation
occurs after protected staging and before DNS routing. Names are validated by
resource kind and matched exactly between preflight and creation observations.

### Gate 4 — Runtime lifecycle proof

Run `scripts/verify-deployment.sh` on the exact host, including signed readiness,
the installed production sandbox lifecycle probe, cgroup/swap isolation,
container cleanup, image-digest checks, database integrity, and R2 when live
credentials are configured. A configuration-only or mocked probe is not proof.

### Gate 5 — Qualification Job A

Run a harmless no-write job against an immutable repository revision. Capture
the exact input revision, authorization/request binding, target runner identity,
bounded execution record, output SHA-256, sandbox/runtime image digests, cleanup
proof, and independent verification. The job must not create an accepted patch.
Its evidence-bundle proposal digest and `changes.patch` descriptor are expected
to exist; the no-write proof is an empty patch of zero bytes with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
`approvalProposal = null`, `approvalConsumed = false`, and equal baseline/final
source digests.

### Gate 6 — Qualification Job B

Run a bounded disposable patch job against the same immutable lineage. Capture
its candidate patch SHA-256 and verify the patch independently in a clean
replay. Reject it through the normal decision endpoint without approval or
export. Prove that the job cannot push, merge, deploy, reach production, use
browser authority, or escape the authorized workspace.

### Gate 7 — Adversarial rejection

Fresh tests must prove rejection of all nine cases: stale lease, wrong runner
identity, wrong source revision, expired authorization, forbidden action, path
escape, production/deployment request, replay, and mismatched evidence digest.
Jobs A/B and these rejection results enter the local-qualification receipt only;
they cannot set final activation truth.

## Definition of done

The job is done only when all repository checks pass on the exact activation
head, the exact source is installed on Droplet `597343619`, the live Site is
bound to that Core, Gates 1-7 have fresh independently checked evidence, and an
owner-authenticated end-to-end request reaches only the direct local Podman
runner. The activation finalizer and an independent replay must both recompute
all original evidence bindings, the independent witness must issue PASS, and the
post-review finalizer plus independent final verification must accept the same
canonical activation receipt. Only then may the result be stated as:

- `CONNECTED = YES`
- `QUALIFIED = YES`
- `READY_TO_WORK = YES`

An active Droplet, a passing offline test, a local-qualification receipt, an
unsigned health response, a stale workflow run, or a written plan cannot satisfy
the definition of done.

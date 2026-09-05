# Tueiq direct-runner activation

This is an unexecuted live procedure for the independently accepted Task 6 head.
Task 6 runs only local/offline fixtures. Task 7 needs separate authorization for
every live action. No live evidence exists yet. The retired intermediary grants
no authority or runtime relationship. The only topology is Site → D1 → signed
Core → direct local rootless Podman, under `ENGINEERING_EXECUTION_ONLY`.

A local receipt is insufficient. `CONNECTED = YES`, `QUALIFIED = YES`, and
`READY_TO_WORK = YES` are forbidden until the finalizer and independent replay
accept every original artifact from one fresh session and an independent-review
`decision: "pass"` artifact exists. Candidate construction/verification and
review never print those lines. Only `verify-final` prints them.

All uppercase path placeholders below denote approved non-secret artifact paths,
not values to paste literally. Secret values enter approved secret stores or the
protected console only: never source, command history, output, receipts, examples,
support bundles, or browser automation logs. Disable page-evaluation result
logging and console/history recording before collecting. Do not read cookies.
Use a new root-owned mode-0700 session parent; do not reuse existing outputs.

## Provider preflight and witness

The independent reviewer and operator first agree on one session nonce and exact
clean 40-hex source head/tree, preserving Sites base
`e76996970e816c4cce7b8334e0495e1e0de48e7d` as ancestor. Obtain the authenticated
`mcp__codex_apps__digitalocean_droplet_get` response for the immutable target.
Normalize only Task 5's exact provider projection and its raw-byte SHA-256 into
`PREFLIGHT_PROVIDER`; never persist the full response. Before discarding its raw
bytes, the independent reviewer streams those same authenticated bytes through a
non-logging stdin to:

```bash
python3 scripts/lil-tweak-independent-review.py witness-provider \
  --normalized PREFLIGHT_PROVIDER --raw-response-stdin --witness PREFLIGHT_WITNESS
```

The witness must occur within 120 seconds of capture and before mutation. The
projection identifies DigitalOcean droplet `597343619`, immutable short hostname
`galor-tweak-runner-01`, active status, `nyc1`, Ubuntu 24.04 LTS x64,
`s-4vcpu-8gb`, and role `role-tweak-runner`; raw networks/IPs/tokens are discarded.
Record only normalized facts and hashes, not the authenticated transport data.

## Approved guest entry

Use the approved guest console/SSH entry. Do not infer a host from an IP in an
artifact. Run the exact-target verifier on the approved guest; metadata ID,
hostname, Ubuntu release and architecture must match. A mismatch stops all work.
No origin, host, metadata URL, or secret-value override is available in Task 6.

## Exact source and images

Require a clean checkout at the accepted committed head; verify the source
manifest's complete tree/archive inventory and preserved base before installation.
Use `source-manifest`, `verify-extract`, and `runtime-manifest` from
`scripts/lil-tweak-release.py`, with the existing release contract. Source,
runtime, and production manifests retain newline-canonical JSON and mode 0444.
All new evidence/decision files are no-newline canonical JSON or the explicitly
ordered decision text, root-owned mode 0600. Every parent is root-owned mode 0700.
No link, extra file, unsafe owner/mode, unstable descriptor, or digest literal
can substitute for an original artifact.

Build the exact source with five digest-pinned image roles: `core`, `runner`,
`postgres`, `python_base`, `runner_base`. Independently audit installed Syft and
Grype versions. For each final core/runner image, collect SBOM and scan JSON and
retain the exact non-secret projection: `descriptor:{name,version}`,
`source:{image}`, and either `artifacts:[{id,name,version}]` for Syft or
`matches:[{id,severity}]` for Grype. Do not use filenames as proof of a scan.
Retain every observed vulnerability; `High`, `Critical`, unknown severity, tool
failure, an empty SBOM, or an incomplete projection stops activation. Package
names/versions retain bounded package punctuation, not arbitrary metadata. The reviewer compares the
projection with the tool output before discarding nonallowlisted tool metadata.

The secure release evidence directory contains exactly:

```text
source-manifest.json
source.tar.gz
verification-receipt.json
host-go.txt
base-images.txt
scan-hashes.txt
core.sbom.json
core.grype.json
runner.sbom.json
runner.grype.json
```

The source manifest's tracked `verification_receipt` remains the historical
source receipt; it is not the fresh post-gate receipt and must not be replaced
with an untracked file or a circular hash of the head it would create.

The fresh `verification-receipt.json` has exactly
`schema,verifiedAt,sourceHead,sourceTree,sourceManifestSha256,sourceArchiveSha256,tools,policy,checks`;
schema is `tueiq-release-verification-v1`, `tools` has the audited `syft,grype`
versions, `policy` is `{name:"no-high-or-critical",decision:"PASS"}`, and
`checks` has exactly true `source,npmVerify,deployTests,installerCheck,deploymentCheck`.
The four source bindings are recomputed from the exact accepted checkout,
source manifest and archive. The host-GO v3 receipt binds source/tree/archive,
all five images, base-image and scan receipts, then
`activation_verification_sha256` before the existing `issued_at,expires_at,nonce`
fields. It has an unexpired decision, issued after fresh verification and before
rollback capture/mutation. Supply `--activation-verification-receipt
VERIFICATION_RECEIPT` to `runtime-manifest`; runtime then binds the v3 host-GO
digest. Legacy v2 parsing remains strict for other releases, but activation
rejects v2 and always reopens this complete v3 evidence chain.
The scan-hash receipt uses the existing release format and resolves only the
four listed artifacts inside that same directory.

## Pre-mutation inventory

Before resource creation, independently inventory Cloudflare and Sites names,
binding revisions and owner-only access. Open the protected transactional host
rollback directory before mutation. Bind its source/runtime/image ledger; do not
mark incomplete or dirty rollback as clean. It must eventually end with
`transaction_state=completed` and `rollback_outcome=clean`.

All seven activation-managed binding names must be absent, including the unused
alternative `CUSTOMER_HTTP_LIL_TWEAK_CORE`. Any collision stops activation.
Existing `LIL_TWEAK_ENVIRONMENT`, `PUBLIC_ORIGIN`, and owner-only direct-chat
`OPENAI_API_KEY` remain untouched; never read or rewrite their secret values.
Record prior Site version ID/number and access revision/mode/counts, never prior
binding secrets. Preserve D1/R2 resource IDs and schema/binding revisions.

Create one `tueiq-session-change-record-v1` with exactly
`schema,sessionNonce,startedAt,mutationStartedAt,completedAt,preflightProviderSha256,sourceHead,sourceTree,priorSite,managedBindings,resources,additions,rollbackOrder,resourceObservationsSha256`.
`priorSite` has `versionId,versionNumber,accessRevision,accessMode,allowedOwnerCount,allowedGroupCount,allowedVisitorCount`.
`managedBindings` contains the seven names with the literal value `absent`.
`resources` is an ordered list of `{kind,name,preflight,createdId}`: kinds are
`tunnel,access_application,access_policy,service_token,secret_directory,dns,managed_rule`.
This is creation order: protected staging precedes combined installation, then
DNS and the managed ingress rule precede the six Site keys and deployment.
All names are checked absent before mutation; every `createdId` is observed from
this session, never unknown/pre-existing. Record only non-secret opaque IDs.

The change record is a rollback claim, not proof of resource creation. Retain
separate sanitized operation projections in one
`tueiq-session-resource-observations-v1` object with exactly
`schema,sessionNonce,sourceHead,sourceTree,preflight,creations`. Capture the
preflight before mutation directly from the authorized Cloudflare resource-name
queries, Sites key-name inventory and fixed-directory lstat; do not derive it
from the change record. Capture each creation ID directly from that session's
creation result. Never retain raw responses, addresses, credential values or
unrelated inventory entries. Missing, ambiguous or present resources stop work.

| Observation | Exact fields and required values |
| --- | --- |
| `preflight` | `observedAt,priorSite,bindingOperation,managedBindings,resources`; binding operation `sites-environment-list`; prior Site fields as above |
| Preflight binding entry | `name,present`; exactly the seven ordered names above, every `present=false` |
| Preflight resource entry | `kind,name,operation,matchingIds`; seven ordered kinds above; empty matching IDs; `cloudflare-resource-list`, or `filesystem-lstat` for staging |
| Creation entry | `kind,name,operation,createdId,observedAt,preflightSha256,filesystem`; same ordered kinds/names; `cloudflare-resource-create`, or `filesystem-mkdir` for staging |
| Directory identity | `createdId,device,inode,uid,gid,mode`; `createdId=directory-DEVICE-INODE`, numeric device/inode, root UID/GID and `mode=0700` |

Each creation binds the SHA-256 of canonical `preflight`, is after mutation and
before deployment, and has `filesystem=null` except staging's directory identity.
Use the fixed absent-before-mutation `/var/lib/lil-tweak-activation/secrets`
directory for staging. Preserve it until independent review/verification.
Project its creation-time device/inode without reading secret contents; the
independent guest collector later reopens this fixed directory and checks that
identity independently. Existing/symlinked/insecure staging is a hard stop.

After all seven creations, stream only this sanitized object to:

```bash
python3 scripts/lil-tweak-live-evidence.py seal-resource-observations \
  --observations-stdin --output RESOURCE_OBSERVATIONS
```

Keep the canonical root-owned `0600` result in a protected directory. Set the
non-secret `ACTIVATION_OBSERVATIONS=RESOURCE_OBSERVATIONS` path in release state
before `production-manifest`. Its original `0444` production manifest retains
the full object as `resource_observations`; activation rejects its absence.
`resourceObservationsSha256` in the change record and candidate production
projection binds that object's canonical bytes. Candidate, review and final
replay reopen production, revalidate every absence/creation observation and
cross-check all seven IDs/names/session/source/times, prior Site state and the
independent guest directory identity. Observation provenance depends on direct
authorized capture: do not replace operation projections with authored claims.

## New credentials and protected staging

Create the new Tunnel, Access application/policy/service token, and matching
HMAC pair only after the inventory gate. Create protected secret directories
outside the repository, and stage matching Core/cloudflared inputs using the
approved secret-entry channel and existing strict validators. Do not print a
secret, use command-line secret values, or copy a prior Site secret. Track the
exact session-created directory identity in the change record.

## Combined installation

Use only the combined release installer:

```bash
scripts/install-lil-tweak-release.sh --install
```

Supply its existing approved protected state/receipt inputs as documented in
`digitalocean.md`. There is no direct child-installer fallback. Preserve its
lease, exact-target gate, pinned images, migration and host rollback semantics.
Host rollback must still capture and, when invoked, restore the exact
pre-existing sensitive `core.env` and Tunnel bytes inside its root-only receipt,
without printing, exporting, or weakening their protection.

## DNS and private Site deployment

Create the session DNS route and private Site binding/deployment. Select
`CORE_ORIGIN` and leave `CUSTOMER_HTTP_LIL_TWEAK_CORE` absent. This release adds
exactly the six values below; it does not add or change any other Site key.

<!-- exact-site-additions -->
```text
MANAGED_INGRESS_SECRET
CORE_ORIGIN
CORE_ACCESS_CLIENT_ID
CORE_ACCESS_CLIENT_SECRET
CORE_SIGNING_KEY_ID
CORE_SIGNING_SECRET
```

Capture actual Site source head/tree, version ID/number, deployment ID, archive
SHA-256, environment/access revisions and deployed time into
`tueiq-site-deployment-record-v1`: exact fields are
`schema,sourceHead,sourceTree,versionId,versionNumber,deploymentId,archiveSha256,environmentRevision,accessRevision,accessMode,allowedOwnerCount,allowedGroupCount,allowedVisitorCount,deployedAt`.
Access is exactly `custom`, one owner, zero groups, zero visitors. Cross-check
these platform observations against the deployed page before collection.

## Second provider witness

Perform a fresh authenticated provider capture for the same immutable target.
Normalize to `LIVE_PROVIDER`. The independent reviewer repeats `witness-provider`
with that raw response on non-logging stdin and new `LIVE_WITNESS`, before raw
discard and before the Site collector. The live normalized file must later be
byte/digest-equal to the document embedded by local qualification.

## Primary Site collection

In the authenticated deployed Site page, invoke the bundled function exactly
once with a new UUIDv4; no caller repository/commit/instruction override exists:

```javascript
await window.collectTueiqActivationEvidence({ requestId: crypto.randomUUID() })
```

Stream the one returned value directly through the approved non-logging bridge
to stdin, without console printing, screenshotting, headers or cookie access:

```bash
python3 scripts/lil-tweak-live-evidence.py seal-site \
  --collector-stdin --site-deployment-record SITE_DEPLOYMENT_RECORD --output-dir SITE_PRIMARY
```

The collector uses relative same-origin fetch with `credentials:"same-origin"`,
creates one immutable architect job, dispatches it, polls completion, and previews
exactly five evidence bodies without decision/export. It retains only the nine
allowlisted original body byte sequences, status code, media type, declared length
and applicable content SHA-256. It reads no cookie and serializes no request
header or response metadata beyond that allowlist. Intermediate polls are not
retained. Error, reuse, overflow, unsigned/non-ready status, approval, nonzero
patch, wrong immutable source or evidence mismatch stops activation.

`SITE_PRIMARY` has exactly `manifest.json`, `status.body`, `create.body`,
`dispatch.body`, `poll-final.body`, five `evidence:DESCRIPTOR_ID.body` files,
`site-status-evidence.json`, and `owner-flow-job.json`. The manifest has
`schema,requestId,startedAt,completedAt,deployment,responses`; each response has
`id,status,mediaType,declaredLength,contentSha256,sha256,sizeBytes`.
No original body bytes are rewritten. The two derived records are recomputed
from primary files, not accepted as independent evidence.

## Independent cross-checks

The reviewer performs a separate owner-authenticated page evaluation, not a read
of the collector return value: fetch
`GET /api/engineering/jobs/{id}/activation-evidence` once with same-origin
credentials. Stream only that response body to:

```bash
python3 scripts/lil-tweak-live-evidence.py seal-d1 \
  --response-stdin --job-id PUBLIC_JOB_ID --output D1_CROSS_CHECK
python3 scripts/lil-tweak-live-evidence.py collect-core \
  --core-env CORE_ENV_PATH --d1-cross-check D1_CROSS_CHECK --output CORE_CROSS_CHECK
python3 scripts/lil-tweak-live-evidence.py seal-guest \
  --provider-evidence LIVE_PROVIDER --runtime-manifest RUNTIME_MANIFEST \
  --verification-receipt VERIFICATION_RECEIPT --output GUEST_EVIDENCE
python3 scripts/lil-tweak-live-evidence.py collect-guest \
  --source-root SOURCE_ROOT --provider-evidence LIVE_PROVIDER \
  --runtime-manifest RUNTIME_MANIFEST --job-id PUBLIC_JOB_ID --output GUEST_CROSS_CHECK
```

`CORE_ENV_PATH` must be the existing fixed installed Core environment path; its
secret bytes never enter an artifact. `collect-core` uses signed fixed loopback
reads and downloads all five original Core evidence bodies to independently
recompute the proposal digest, source identity, command result and no-edit proof.
`collect-guest` freshly checks metadata/hostname, OS/architecture, installed
source head, effective runtime images, cleanup and the fixed staging directory's
device/inode/root ownership/mode. Its cross-check adds the exact `secretDirectory`
identity above. It never consumes the derived
guest file. D1, Core and guest may share only correlation IDs/digests, never Site
collector summaries. The owner-only D1 route authenticates before any binding
fetch and exposes only the matching job/evidence row projection and ordered
`{id,type,createdAt}` event triples. Events have no invented revision field;
unique IDs/nondecreasing timestamps/type order bind to exported job/Core revisions.

The cross-checks must prove public/remote linkage, same owner, immutable Git
source, equal D1/R2/Core evidence digests, network-disabled successful execution,
equal baseline/final tree, expected README digest, zero-byte patch, no approval,
decision or export, recomputed non-null proposal digest, and no leftover runner.
Agreement among authored summaries without primary bodies is insufficient.

## Post-deployment owner flow

Only now add observed non-secret Site identifiers, `SITES_DEPLOYED_AT`, and the
canonical `OWNER_FLOW_JOB` path to the protected release state. The v3 receipt
must not exist before both the deployment and owner job evidence exist:

```bash
python3 scripts/lil-tweak-release.py owner-flow-receipt \
  --runtime-manifest RUNTIME_MANIFEST --release-state RELEASE_STATE \
  --owner-flow-job OWNER_FLOW_JOB --output OWNER_FLOW_RECEIPT
python3 scripts/lil-tweak-release.py production-manifest \
  --runtime-manifest RUNTIME_MANIFEST --release-state RELEASE_STATE \
  --owner-flow-receipt OWNER_FLOW_RECEIPT --output PRODUCTION_MANIFEST
```

Both bind runtime/source/tree, Site version/deployment/archive and the recomputed
`owner_flow_job_sha256`. Old receipts, pre-deployment issue time and changed job
digests fail. Preserve the exact D1/R2/ingress revision bindings.

## Local qualification

Run the unchanged Task 5 `run` command against the fixed installed environment,
exact source root and `LIVE_PROVIDER`, with a nonexistent child evidence directory.
Keep `tueiq-direct-runner-local-qualification-v1` unchanged; all negative and
cleanup checks must remain true. Finish the change record: additions are
`resource:0` through `resource:6`, the six `binding:NAME` entries in the displayed
order, then `site:VERSION_ID`; `rollbackOrder` is their exact reverse. Nothing
pre-existing may appear as session-created. All times fit one 30-minute session;
local evidence is at most 15 minutes old and independent review at most five.
Expired sessions restart from fresh preflight; never backdate artifacts.

## Candidate replay

Run from the exact reviewed clean committed source, with every original path:

```bash
originals=(
  --source-root SOURCE_ROOT
  --local-qualification LOCAL_QUALIFICATION
  --preflight-provider-evidence PREFLIGHT_PROVIDER
  --provider-evidence LIVE_PROVIDER
  --release-evidence-root RELEASE_EVIDENCE_ROOT
  --runtime-manifest RUNTIME_MANIFEST
  --rollback-receipt ROLLBACK_RECEIPT
  --production-manifest PRODUCTION_MANIFEST
  --owner-flow-receipt OWNER_FLOW_RECEIPT
  --owner-flow-job OWNER_FLOW_JOB
  --site-status-evidence SITE_STATUS_EVIDENCE
  --guest-evidence GUEST_EVIDENCE
  --site-primary-evidence SITE_PRIMARY
  --d1-cross-check D1_CROSS_CHECK
  --core-cross-check CORE_CROSS_CHECK
  --guest-cross-check GUEST_CROSS_CHECK
  --change-record CHANGE_RECORD
  --candidate CANDIDATE
)
python3 scripts/lil-tweak-activation-finalizer.py build-candidate "${originals[@]}"
python3 scripts/lil-tweak-activation-finalizer.py verify-candidate "${originals[@]}"
```

Both print only a canonical SHA-256, never activation truth. The candidate schema
is `tueiq-direct-runner-activation-candidate-v1` with exact top-level fields
`schema,startedAt,completedAt,sourceHead,artifactDigests,identity,topology,images,provider,guest,runtime,rollback,production,site,ownerFlow,localQualification,changeRecord`.
All nested allowlists are executable in `deploy/tests/test_activation_finalizer.py`.
The receipt contains no prompts, stdout/stderr, credentials, origins, IPs or
secret paths; only allowlisted separate primary bodies retain public prose.

The following are exact key sets, not extensible metadata bags. Unknown keys at
any depth fail. Reused identity/topology/image/descriptor objects have the same
shape in the candidate, derived records and independent cross-checks.

| Object | Exact fields |
| --- | --- |
| Status evidence | `schema,checkedAt,deployment,statusSha256,runner,controlPlane,bridge` |
| Guest evidence | `schema,checkedAt,providerSha256,runtimeSha256,verificationSha256,sourceHead,identity,operatingSystem,architecture,topology,images` |
| Owner-flow job | `schema,checkedAt,requestId,jobId,ownerScope,jobRevision,mode,state,gitSource,sourceDigest,proposalDigest,approvalProposal,approvalConsumed,evidence,baselineTreeSha256,finalTreeSha256,fileSha256,commandDigest,editJournalDigest` |
| Identity | `owner,ownerScope,provider,dropletId,host,region,os,size,role` |
| Topology | `route,intermediary,policy` |
| Runtime image descriptor | `reference,digest`; exactly five named roles |
| Guest image map | `core,postgres,runner`; digest values only |
| Git source | `repositoryUrl,commit`; immutable module constants only |
| Evidence descriptor | `id,category,filename,mediaType,sizeBytes,sha256,createdAt` |
| Runtime projection | `manifestSha256,sourceTree,archiveSha256` |
| Rollback projection | `manifestSha256,forwardSha256,inventorySha256,capturedAt,transactionState,rollbackOutcome` |
| Production projection | `runtimeSha256,ownerFlowSha256,ownerFlowJobSha256,resourceObservationsSha256,d1,r2,ingress` |
| D1 resource | `database_id,schema_revision,binding_revision` |
| R2 resource | `account_id,bucket_name,binding_revision` |
| Ingress projection | `tunnel_id,access_application_id,access_policy_id,access_policy_revision,managed_rule_id,managed_rule_revision` |
| Provider projection | `preflightSha256,liveSha256` |
| Local qualification projection | `sha256,startedAt,completedAt,negativeChecks,cleanup`; nested sets are the unchanged Task 5 sets |
| Review witness digest map | `preflight,live` |
| Review cross-check digest map | `d1-cross-check,core-cross-check,guest-cross-check` |

`artifactDigests` names exactly the sixteen explicit original artifact arguments
(all except `source-root`), including canonical directory-inventory digests.
Review `primaryArtifactDigests` names exactly the reopened `release/`, `site/`
and `rollback/` inventory entries. Those descriptor-addressed maps cannot accept
an extra key or a copied digest in place of a reopened file. Final receipts
contain no nested objects. The status/deployment, provider witness and session
change-record key sets are pinned in their collection sections above.

## Independent candidate review

Review retains validated canonical-byte digests, not freshly reread unvalidated
hashes. Immediately before review/final publication or final truth output, it
reopens the complete original set, both witnesses, candidate and review (where
applicable) against those snapshots. Any mid-phase substitution fails with no
publication and no truth output.

A different reviewer independently reopens all original paths and both witnesses:

```bash
python3 scripts/lil-tweak-independent-review.py review-candidate "${originals[@]}" \
  --preflight-provider-witness PREFLIGHT_WITNESS --provider-witness LIVE_WITNESS \
  --review INDEPENDENT_REVIEW
```

Do not pass a candidate hash list as a substitute for original paths. The review
has exactly `schema,reviewedAt,reviewerNonce,candidateSha256,providerWitnessDigests,primaryArtifactDigests,crossCheckDigests,decision`;
schema is `tueiq-direct-runner-independent-review-v1` and decision is `pass`.
The command prints only the review SHA-256. Provider witnesses have exactly
`schema,witnessedAt,operation,rawResponseSha256,normalizedSha256,projectionSha256,reviewerNonce`.
Reviewer identity/independent credential custody is an operational trust boundary:
root ownership alone is not proof that another human performed the review.

## Reviewed finalization

Only after the fresh review passes:

```bash
python3 scripts/lil-tweak-activation-finalizer.py finalize-reviewed "${originals[@]}" \
  --preflight-provider-witness PREFLIGHT_WITNESS --provider-witness LIVE_WITNESS \
  --independent-review INDEPENDENT_REVIEW --activation ACTIVATION
```

This alone may create `tueiq-direct-runner-activation-v1`, with exactly
`schema,completedAt,candidateSha256,independentReviewSha256,CONNECTED,QUALIFIED,READY_TO_WORK`.
Its three booleans are true only after replay succeeds. Publication is exclusive,
atomic, root-owned mode 0600, descriptor-relative, fsynced and single-link.
Finalization prints only the receipt hash.

## Independent final verification

The independent verifier reopens final/candidate/review/witnesses and every
original artifact, without network or job action:

```bash
python3 scripts/lil-tweak-activation-finalizer.py verify-final "${originals[@]}" \
  --preflight-provider-witness PREFLIGHT_WITNESS --provider-witness LIVE_WITNESS \
  --independent-review INDEPENDENT_REVIEW --activation ACTIVATION
```

Only successful complete replay prints the three final truth lines and receipt
SHA-256. Mutation of any retained original invalidates review and final truth.

## Redaction and rollback decision

Retain only the validated sanitized originals. Discard authenticated provider raw
responses immediately after independent witness; never retain transport headers,
cookies, signatures, origin/IP metadata or credentials. Preserve protected host
rollback payloads in their existing root-only receipt, separate from reports.
Publish only sanitized final status after independent final replay. Until then,
state “activation not yet independently verified”; do not infer live readiness
from local fixtures or a receipt's existence.

For Site rollback, first redeploy the recorded prior Site version, then undo only
the six previously absent Site keys and session-created resources/files in the
recorded reverse order. Never read, copy or restore a prior Site binding secret.
Do not delete unknown or pre-existing resources. Protected host rollback still
restores exact sensitive pre-existing bytes through its transaction helper.
An ambiguous resource identity, wider rollback scope, dirty/quarantined outcome,
or failed cleanup stops the process for operator review.

## Exact-head offline release gate

Commit the approved literal Task 6 inventory before this gate. A fresh reviewer
must approve the exact newline-delimited unstaged inventory before staging; stage
literal paths only and compare cached inventory byte-for-byte. Include the
minimal `app/engineering-client.ts` in-page registration regression fix.

Require clean worktree, record `activation_head=$(git rev-parse --verify HEAD)`,
require a 40-hex head and the preserved base as ancestor, and show its commit
stat. On that committed head run exactly in order:

```bash
npm run verify
python3 -m unittest discover -s deploy/tests -p 'test_*.py' -v
bash scripts/install-lil-tweak-release.sh --check
bash scripts/verify-deployment.sh --check
git diff --check
```

Run the approved Task 2 retirement scanner verbatim, then require clean unchanged
HEAD equal to the recorded value and the base still an ancestor. Independently
review the exact Task 1–6 diff and gate evidence. Any new commit invalidates the
head/gate/scanner/review and requires all four again. Only that final accepted
head may enter live activation. All helper `--check` paths are strictly offline.

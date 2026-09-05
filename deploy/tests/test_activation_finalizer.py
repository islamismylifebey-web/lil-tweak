"""Task 6: independent literal schemas and real, offline release replay."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
import base64
import io
from contextlib import redirect_stdout, redirect_stderr
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/lil-tweak-activation-finalizer.py"
CANDIDATE_KEYS = set("schema startedAt completedAt sourceHead artifactDigests identity topology images provider guest runtime rollback production site ownerFlow localQualification changeRecord".split())
FINAL_KEYS = set("schema completedAt candidateSha256 independentReviewSha256 CONNECTED QUALIFIED READY_TO_WORK".split())
REVIEW_KEYS = set("schema reviewedAt reviewerNonce candidateSha256 providerWitnessDigests primaryArtifactDigests crossCheckDigests decision".split())
WITNESS_KEYS = set("schema witnessedAt operation rawResponseSha256 normalizedSha256 projectionSha256 reviewerNonce".split())
STATUS_KEYS = set("schema checkedAt deployment statusSha256 runner controlPlane bridge".split())
GUEST_KEYS = set("schema checkedAt providerSha256 runtimeSha256 verificationSha256 sourceHead identity operatingSystem architecture topology images".split())
JOB_KEYS = set("schema checkedAt requestId jobId ownerScope jobRevision mode state gitSource sourceDigest proposalDigest approvalProposal approvalConsumed evidence baselineTreeSha256 finalTreeSha256 fileSha256 commandDigest editJournalDigest".split())
CHANGE_KEYS = set("schema sessionNonce startedAt mutationStartedAt completedAt preflightProviderSha256 sourceHead sourceTree priorSite managedBindings resources additions rollbackOrder resourceObservationsSha256".split())
ORIGINAL_ARGUMENTS = "source-root local-qualification preflight-provider-evidence provider-evidence release-evidence-root runtime-manifest rollback-receipt production-manifest owner-flow-receipt owner-flow-job site-status-evidence guest-evidence site-primary-evidence d1-cross-check core-cross-check guest-cross-check change-record".split()
# These independent literals pin every object, not implementation-owned schema constants.
IDENTITY_KEYS = set("owner ownerScope provider dropletId host region os size role".split())
TOPOLOGY_KEYS = set("route intermediary policy".split())
DESCRIPTOR_KEYS = set("id category filename mediaType sizeBytes sha256 createdAt".split())
DEPLOYMENT_KEYS = set("schema sourceHead sourceTree versionId versionNumber deploymentId archiveSha256 environmentRevision accessRevision accessMode allowedOwnerCount allowedGroupCount allowedVisitorCount productionOrigin customDomainCount anonymousDenied forgedIdentityDenied alternateHostRejected ownerSameOriginSucceeded deployedAt".split())
MANAGED_BINDINGS = ("CORE_ORIGIN", "CORE_ACCESS_CLIENT_ID", "CORE_ACCESS_CLIENT_SECRET", "CORE_SIGNING_KEY_ID", "CORE_SIGNING_SECRET", "CUSTOMER_HTTP_LIL_TWEAK_CORE")
ADDED_BINDINGS = MANAGED_BINDINGS[:-1]
RESOURCE_FIXTURES = (
    ("tunnel", "Lil Tweak core tunnel", "tunnel-id"),
    ("access_application", "Lil Tweak private core", "access-app"),
    ("service_token", "Lil Tweak Worker service token", "service-token-id"),
    ("access_policy", "Lil Tweak Worker service token only", "access-policy"),
    ("secret_directory", "/var/lib/lil-tweak-activation/secrets", "session-files"),
    ("dns", "core.lil-tweak.invalid", "dns-id"),
)
CANDIDATE_OBJECT_KEYS = {
    "": CANDIDATE_KEYS,
    "artifactDigests": set("local-qualification preflight-provider-evidence provider-evidence runtime-manifest production-manifest owner-flow-receipt owner-flow-job site-status-evidence guest-evidence d1-cross-check core-cross-check guest-cross-check change-record release-evidence-root rollback-receipt site-primary-evidence".split()),
    "identity": IDENTITY_KEYS, "topology": TOPOLOGY_KEYS,
    "images": set("core runner postgres python_base runner_base".split()),
    **{"images." + role: {"reference", "digest"} for role in ("core", "runner", "postgres", "python_base", "runner_base")},
    "provider": {"preflightSha256", "liveSha256"}, "guest": GUEST_KEYS,
    "guest.identity": IDENTITY_KEYS, "guest.topology": TOPOLOGY_KEYS, "guest.images": {"core", "postgres", "runner"},
    "runtime": {"manifestSha256", "sourceTree", "archiveSha256"},
    "rollback": set("manifestSha256 forwardSha256 inventorySha256 capturedAt transactionState rollbackOutcome".split()),
    "production": set("runtimeSha256 ownerFlowSha256 ownerFlowJobSha256 resourceObservationsSha256 d1 r2 ingress".split()),
    "production.d1": {"database_id", "schema_revision", "binding_revision"},
    "production.r2": {"account_id", "bucket_name", "binding_revision"},
    "production.ingress": set("tunnel_id access_application_id access_policy_id access_policy_revision".split()),
    "site": STATUS_KEYS, "site.deployment": DEPLOYMENT_KEYS,
    "site.runner": set("owner provider dropletId host role route intermediary imagePolicy connection qualification".split()),
    "site.controlPlane": {"storage", "d1", "r2"}, "site.bridge": {"origin", "transport", "signing", "access", "missing"},
    "ownerFlow": JOB_KEYS, "ownerFlow.gitSource": {"repositoryUrl", "commit"}, "ownerFlow.evidence[]": DESCRIPTOR_KEYS,
    "localQualification": {"sha256", "startedAt", "completedAt", "negativeChecks", "cleanup"},
    "localQualification.negativeChecks": set("stale_lease wrong_runner_identity wrong_source_revision expired_authorization forbidden_action path_escape production_deployment_request replay mismatched_evidence_digest".split()),
    "localQualification.cleanup": set("checkedAt noContainers allJobsTerminal sacrificialJobId sacrificialState wrongRevisionJobId wrongRevisionState".split()),
    "changeRecord": CHANGE_KEYS,
    "changeRecord.priorSite": set("versionId versionNumber accessRevision accessMode allowedOwnerCount allowedGroupCount allowedVisitorCount".split()),
    "changeRecord.managedBindings": set(MANAGED_BINDINGS),
    "changeRecord.resources[]": {"kind", "name", "preflight", "createdId"},
}


def objects(value, path="", trail=()):
    if isinstance(value, dict):
        yield path, trail, value
        for key, child in value.items():
            yield from objects(child, path + ("." if path else "") + key, trail + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from objects(child, path + "[]", trail + (index,))


def replace_at(value, trail, field, replacement=None, *, remove=False):
    changed = copy.deepcopy(value)
    target = changed
    for item in trail: target = target[item]
    if remove: del target[field]
    else: target[field] = replacement
    return changed


def load(name="lil-tweak-activation-finalizer"):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ActivationFixture:
    """Real Git/source/runtime/rollback and signed Core fixtures; no live host."""
    def __init__(self, root):
        from deploy.tests.test_qualification import Fixture, provider
        from deploy.tests.test_release_tooling import write_host_go_receipt
        from deploy.tests.test_release_rollback import RollbackFixture, populate_complete_forward_ledger
        self.root, self.a = root, load()
        a, q, release = self.a, self.a.q, self.a.release
        self.now = int(time.time()) - 400
        self.t = lambda offset: q.iso(self.now + offset)
        self.repo = root / "repo"
        subprocess.run(["git", "clone", "--quiet", "--shared", "--no-hardlinks", str(ROOT), str(self.repo)], check=True, capture_output=True)
        self.head = release._git(self.repo, "rev-parse", "HEAD")
        self.tree = release._git(self.repo, "rev-parse", "HEAD^{tree}")
        self.primary = root / "release"
        self.primary.mkdir(mode=0o700)
        self.images = {role: "registry.example/" + role + "@sha256:" + str(index) * 64 for index, role in enumerate(("core", "postgres", "runner", "python_base", "runner_base"), 1)}
        for role in ("core", "runner"): self.images[role] = self.images[role].replace("registry.example/", "registry.example/lil-tweak/")
        source = self.primary / "source-manifest.json"
        release.create_source_manifest(repo=self.repo, base="e76996970e816c4cce7b8334e0495e1e0de48e7d", commit=self.head,
            verification_receipt=Path("README.md"), preserves=[Path("public/favicon.ico")], output=source)
        archive = self.primary / "source.tar.gz"
        subprocess.run(["git", "-c", "tar.umask=0022", "archive", "--format=tar.gz", "--output=" + str(archive), self.head], cwd=self.repo, check=True)
        archive.chmod(0o600)
        self.write(self.primary / "verification-receipt.json", {"schema": "tueiq-release-verification-v1", "verifiedAt": self.t(-175),
            "sourceHead": self.head, "sourceTree": self.tree, "sourceManifestSha256": a.sha(source.read_bytes()), "sourceArchiveSha256": a.sha(archive.read_bytes()),
            "tools": {"syft": "1.42.0", "grype": "0.110.0"}, "policy": {"name": "no-high-or-critical", "decision": "PASS"},
            "checks": {"source": True, "npmVerify": True, "deployTests": True, "installerCheck": True, "deploymentCheck": True}})
        for role in ("core", "runner"):
            self.write(self.primary / (role + ".sbom.json"), {"descriptor": {"name": "syft", "version": "1.42.0"}, "source": {"image": self.images[role]}, "artifacts": [{"id": "package-1", "name": "libstdc++6", "version": "12.2.0-14+deb12u1"}]})
            self.write(self.primary / (role + ".grype.json"), {"descriptor": {"name": "grype", "version": "0.110.0"}, "source": {"image": self.images[role]}, "matches": []})
        base = self.primary / "base-images.txt"
        self.raw(base, "".join(self.images[role] + " " + self.images[role].split("@")[1] + "\n" for role in ("python_base", "runner_base", "postgres")).encode())
        scan = self.primary / "scan-hashes.txt"
        self.raw(scan, "".join(a.sha((self.primary / name).read_bytes()) + "  " + str(self.primary / name) + "\n" for name in sorted([role + "." + kind + ".json" for role in ("core", "runner") for kind in ("sbom", "grype")])).encode())
        go = self.primary / "host-go.txt"
        write_host_go_receipt(go, source, archive, {k + "_image": v for k, v in self.images.items()}, base, scan,
                              overrides={"issued_at": self.t(-172), "expires_at": self.t(600)})
        self.raw(go, go.read_bytes().replace(b"lil-tweak-host-go-receipt-v2", b"lil-tweak-host-go-receipt-v3").replace(b"issued_at=", ("activation_verification_sha256=" + a.sha((self.primary / "verification-receipt.json").read_bytes()) + "\nissued_at=").encode()))
        runtime = root / "runtime.json"
        release.create_runtime_manifest(source_manifest=source, source_archive=archive, host_go_receipt=go, base_image_receipt=base,
            image_scan_hashes=scan, activation_verification_receipt=self.primary / "verification-receipt.json", output=runtime, **{k + "_image": v for k, v in self.images.items()})
        self.runtime = json.loads(runtime.read_bytes())
        self.providers = []
        self.raw_providers = []
        for name, offset in (("preflight", -180), ("provider", -130)):
            document = provider(self.now + offset)
            raw = json.dumps({"droplet": {"id": 597343619, "name": "galor-tweak-runner-01", "status": "active", "region": {"slug": "nyc1"},
                "image": document["droplet"]["image"], "size": {"slug": "s-4vcpu-8gb", "memory": 8192, "vcpus": 4, "disk": 160}, "tags": ["role-tweak-runner"]}}).encode()
            document["rawResponseSha256"] = a.sha(raw)
            self.write(root / (name + ".json"), document)
            self.providers.append(document); self.raw_providers.append(raw)
        rollback = a.rollback_helper()
        rb = RollbackFixture(root / "host", rollback)
        rb.commit = self.head
        stamp = datetime.fromtimestamp(self.now - 170, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rb.receipt = rb.receipt.parent / (stamp + "-" + self.head[:12])
        with patch.object(rollback, "_verify_exact_target", return_value=None):
            digest = rb.capture()
            populate_complete_forward_ledger(rb, digest)
            rollback.mark_completed(rb.receipt, digest)
        self.f = Fixture(q, root / "jobs")
        self.f.clock.value = self.now - 120
        self.f.source_head = lambda: self.head
        owner_core = self.f.client.json("POST", "/v1/jobs", q.submission("architect"), status=202)
        self.core = self.f.client.json("GET", "/v1/jobs/" + owner_core["id"])
        self.retained, self.bodies, self.run = q.verify_job_evidence(self.f.client, self.core, mode="architect", started=self.now - 120, now=self.now - 119)
        self.request_id = str(uuid.uuid4())
        self.jobid = "job:" + a.sha(("engineering-job-v1\0" + q.OWNER_SCOPE + "\0" + self.request_id).encode())[:32]
        event_types = ["job_created", "dispatch_reserved", "core_dispatched", "core_status_mirrored"]
        events = [{"id": "audit:" + str(i) * 32, "type": kind, "createdAt": self.t(-120)} for i, kind in enumerate(event_types, 1)]
        descriptors = [{k: d[k] for k in ("id", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt")} for d in self.core["evidence"]]
        public = {"id": self.jobid, "projectId": None, "mode": "architect", "promptPreview": q.PROMPT_A, "state": "completed", "revision": 3,
            "summary": "Findings CANARY-RAW", "proposalDigest": self.core["proposalDigest"], "sourceDigest": q.BASELINE_TREE_SHA256,
            "approvalProposal": None, "approvalConsumed": False, "gitSource": q.submission("architect")["gitSource"], "createdAt": self.t(-120), "updatedAt": self.t(-120),
            "sources": [], "evidence": [{**d, "jobId": self.jobid} for d in descriptors], "events": [{**e, "summary": ""} for e in events]}
        self.deployment = {"schema": "tueiq-site-deployment-record-v1", "sourceHead": self.head, "sourceTree": self.tree,
            "versionId": "site-project~site-version", "versionNumber": 2, "deploymentId": "site-project~site-deployment", "archiveSha256": "c" * 64,
            "environmentRevision": "env-r1", "accessRevision": "access-r2", "accessMode": "custom", "allowedOwnerCount": 1,
            "allowedGroupCount": 0, "allowedVisitorCount": 0, "productionOrigin": "https://tweak.example.invalid", "customDomainCount": 0,
            "anonymousDenied": True, "forgedIdentityDenied": True, "alternateHostRejected": True, "ownerSameOriginSucceeded": True,
            "deployedAt": self.t(-140)}
        self.write(root / "site-deployment.json", self.deployment)
        status = {"generatedAt": self.t(-121), "controlPlane": dict.fromkeys(("storage", "d1", "r2"), "configured"),
            "bridge": {"origin": "core_origin", "transport": "configured", "signing": "configured", "access": "configured", "missing": []},
            "runner": {"owner": "tueiq", "provider": "digitalocean", "dropletId": "597343619", "host": "galor-tweak-runner-01", "role": "role-tweak-runner",
                "route": "direct_core_to_local_podman", "intermediary": "none", "imagePolicy": "digest_pinned", "connection": "ready", "qualification": "not_reported"}}
        created = {**public, "state": "queued", "revision": 0, "proposalDigest": None, "sourceDigest": None, "evidence": [], "events": public["events"][:1], "summary": ""}
        dispatch = {**created, "revision": 2, "events": public["events"][:3]}
        responses = []
        for ident, value, code in (("status", {"status": status}, 200), ("create", {"job": created}, 201), ("dispatch", {"job": dispatch}, 200), ("poll-final", {"job": public}, 200)):
            responses.append(self.response(ident, json.dumps(value).encode(), code, "application/json", None))
        for d in descriptors:
            responses.append(self.response(d["id"], self.bodies[d["filename"]], 200, "text/plain", d["sha256"]))
        self.capture = {"schema": "tueiq-site-primary-capture-v1", "requestId": self.request_id, "startedAt": self.t(-122), "completedAt": self.t(-119), "responses": responses}
        live = load("lil-tweak-live-evidence")
        live.seal_site(self.capture, root / "site-deployment.json", root / "site-primary")
        self.d1 = {"schema": "tueiq-d1-activation-cross-check-v1", "observedAt": self.t(-118), "jobId": self.jobid, "remoteJobId": self.core["id"], "ownerScope": q.OWNER_SCOPE,
            "jobRevision": 3, "coreRevision": self.core["coreRevision"], "mode": "architect", "state": "completed", "gitSource": public["gitSource"],
            "sourceDigest": q.BASELINE_TREE_SHA256, "proposalDigest": self.core["proposalDigest"], "approvalProposal": None, "approvalConsumed": False,
            "decisionCount": 0, "exportCount": 0, "evidence": descriptors, "events": events}
        self.write(root / "d1.json", self.d1)
        live.collect_core(root / "unused.env", root / "d1.json", root / "core.json", client=self.f.client, now=self.now - 117)
        live.seal_guest(root / "provider.json", runtime, self.primary / "verification-receipt.json", root / "guest.json", now=self.now - 116)
        self.secret_directory = root / "session-secrets"
        self.secret_directory.mkdir(mode=0o700)
        info = self.secret_directory.stat()
        self.directory_observation = {"createdId": "directory-" + str(info.st_dev) + "-" + str(info.st_ino), "device": info.st_dev, "inode": info.st_ino, "uid": 0, "gid": 0, "mode": "0700"}
        self.guest = {"schema": "tueiq-guest-activation-cross-check-v1", "observedAt": self.t(-115), "jobId": self.jobid,
            "providerSha256": a.sha((root / "provider.json").read_bytes()), "runtimeSha256": a.sha(runtime.read_bytes()), "sourceHead": self.head,
            "identity": q.identity(self.providers[1]), "operatingSystem": "Ubuntu 24.04 LTS", "architecture": "x86_64", "topology": {"route": "direct_core_to_local_podman", "intermediary": "none", "policy": "ENGINEERING_EXECUTION_ONLY"},
            "images": {k: self.runtime["images"][k]["digest"] for k in ("core", "postgres", "runner")}, "noContainers": True, "secretDirectory": self.directory_observation}
        self.write(root / "guest-cross.json", self.guest)
        self.f.clock.value = self.now - 100
        local = q.Qualification(self.f.client, self.f, clock=self.f.clock.now, monotonic=self.f.clock.monotonic, sleep=self.f.clock.sleep).run(root / "provider.json", root / "qualification")
        job_path = root / "site-primary/owner-flow-job.json"
        self.state = {"RUNTIME_MANIFEST": str(runtime), "RUNTIME_MANIFEST_SHA256": a.sha(runtime.read_bytes()), "SOURCE_COMMIT": self.head, "SOURCE_TREE": self.tree,
            "D1_DATABASE_ID": "d1-database", "D1_SCHEMA_REVISION": "0002", "D1_BINDING_REVISION": "d1-r1", "R2_ACCOUNT_ID": "r2-account", "R2_BUCKET_NAME": "evidence-bucket", "R2_BINDING_REVISION": "r2-r1",
            "LIL_TWEAK_TUNNEL_ID": "tunnel-id", "ACCESS_APPLICATION_ID": "access-app", "ACCESS_POLICY_ID": "access-policy", "ACCESS_POLICY_REVISION": "access-r1",
            "CORE_ORIGIN": "https://core.example.invalid", "SITES_SOURCE_COMMIT": self.head, "SITES_VERSION_ID": "site-project~site-version", "SITES_VERSION_NUMBER": "2", "SITES_DEPLOYMENT_ID": "site-project~site-deployment", "SITES_ARCHIVE_HASH": "c" * 64,
            "SITES_ENVIRONMENT_REVISION": "env-r1", "SITES_ACCESS_REVISION": "access-r2", "SITES_ACCESS_MODE": "custom", "SITES_ALLOWED_OWNER_COUNT": "1", "SITES_ALLOWED_GROUP_COUNT": "0", "SITES_ALLOWED_VISITOR_COUNT": "0",
            "SITES_CUSTOM_DOMAIN_COUNT": "0", "SITES_ANONYMOUS_DENIED": "true", "SITES_FORGED_IDENTITY_DENIED": "true", "SITES_ALTERNATE_HOST_REJECTED": "true", "SITES_OWNER_SAME_ORIGIN_SUCCEEDED": "true",
            "PRODUCTION_URL": "https://tweak.example.invalid", "PUBLIC_ORIGIN": "https://tweak.example.invalid", "PRIOR_SITES_VERSION_NUMBER": "1", "SITES_DEPLOYED_AT": self.t(-140), "OWNER_FLOW_JOB": str(job_path)}
        self.raw(root / "state.env", "".join(k + "=" + v + "\n" for k, v in self.state.items()).encode())
        class FixtureDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.fromtimestamp(self.now - 110, tz or timezone.utc)
        with patch.object(release, "datetime", FixtureDatetime):
            release.create_owner_flow_receipt(runtime, root / "state.env", job_path, root / "owner-flow.txt")
        self.change = {"schema": "tueiq-session-change-record-v1", "sessionNonce": "a" * 48, "startedAt": self.t(-180), "mutationStartedAt": self.t(-160), "completedAt": self.t(210),
            "preflightProviderSha256": a.sha((root / "preflight.json").read_bytes()), "sourceHead": self.head, "sourceTree": self.tree,
            "priorSite": {"versionId": "site-project~prior-version", "versionNumber": 1, "accessRevision": "prior-access", "accessMode": "custom", "allowedOwnerCount": 1, "allowedGroupCount": 0, "allowedVisitorCount": 0},
            "managedBindings": dict.fromkeys(MANAGED_BINDINGS, "absent"),
            "resources": [{"kind": kind, "name": name, "preflight": "absent", "createdId": ident} for kind, name, ident in RESOURCE_FIXTURES],
            "additions": ["resource:" + str(i) for i in range(6)] + ["binding:" + k for k in ADDED_BINDINGS] + ["site:site-project~site-version"], "rollbackOrder": []}
        self.change["rollbackOrder"] = list(reversed(self.change["additions"]))
        self.change["resources"][4]["createdId"] = self.directory_observation["createdId"]
        preflight = {"observedAt": self.t(-165), "priorSite": copy.deepcopy(self.change["priorSite"]), "bindingOperation": "sites-environment-list",
            "managedBindings": [{"name": name, "present": False} for name in self.change["managedBindings"]],
            "resources": [{"kind": r["kind"], "name": r["name"], "operation": "filesystem-lstat" if r["kind"] == "secret_directory" else "cloudflare-resource-list", "matchingIds": []} for r in self.change["resources"]]}
        self.observations = {"schema": "tueiq-session-resource-observations-v1", "sessionNonce": "a" * 48, "sourceHead": self.head, "sourceTree": self.tree,
            "preflight": preflight, "creations": [{"kind": r["kind"], "name": r["name"], "createdId": r["createdId"], "operation": "filesystem-mkdir" if r["kind"] == "secret_directory" else "cloudflare-resource-create",
                "observedAt": self.t(-159 + i), "preflightSha256": a.sha(a.canonical(preflight)), "filesystem": self.directory_observation if r["kind"] == "secret_directory" else None} for i, r in enumerate(self.change["resources"])]}
        self.write(root / "resource-observations.json", self.observations)
        self.state["ACTIVATION_OBSERVATIONS"] = str(root / "resource-observations.json")
        self.raw(root / "state.env", "".join(k + "=" + v + "\n" for k, v in self.state.items()).encode())
        release.create_production_manifest(runtime, root / "state.env", root / "owner-flow.txt", root / "production.json")
        self.change["resourceObservationsSha256"] = a.sha(a.canonical(self.observations))
        self.write(root / "change.json", self.change)
        paths = [self.repo, local, root / "preflight.json", root / "provider.json", self.primary, runtime, rb.receipt, root / "production.json", root / "owner-flow.txt", job_path,
            root / "site-primary/site-status-evidence.json", root / "guest.json", root / "site-primary", root / "d1.json", root / "core.json", root / "guest-cross.json", root / "change.json"]
        self.args = SimpleNamespace(**dict(zip([k.replace("-", "_") for k in ORIGINAL_ARGUMENTS], paths)), candidate=root / "candidate.json")

    def close(self):
        self.f.close()

    def raw(self, path, raw):
        path.write_bytes(raw); path.chmod(0o600)

    def write(self, path, value):
        self.raw(path, self.a.canonical(value))

    def response(self, ident, body, status, media, digest):
        return {"id": ident, "status": status, "mediaType": media, "declaredLength": len(body), "contentSha256": digest, "bodyBase64": base64.b64encode(body).decode()}

    def cli(self, command, *, script=SCRIPT, extras=()):
        args = [sys.executable, str(script), command]
        for name in ORIGINAL_ARGUMENTS: args += ["--" + name, str(getattr(self.args, name.replace("-", "_")))]
        return subprocess.run(args + ["--candidate", str(self.args.candidate)] + list(extras), capture_output=True, text=True)


class ActivationFinalizerTests(unittest.TestCase):
    def test_every_original_and_directory_member_is_snapshot_bound_without_hidden_release_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                snapshots = f.a.EvidenceSnapshots()
                expected = set()
                for name in ORIGINAL_ARGUMENTS:
                    if name == "source-root": continue
                    path = getattr(f.args, name.replace("-", "_"))
                    expected.update(p.absolute() for p in path.rglob("*") if p.is_file()) if path.is_dir() else expected.add(path.absolute())
                # Legacy release validators must consume explicit snapshot bytes,
                # not reopen an artifact behind the shared snapshot boundary.
                with patch.object(f.a, "read_json", wraps=f.a.read_json) as reads, \
                     patch.object(f.a.release, "_read_secure", side_effect=AssertionError("hidden release read")), \
                     patch.object(f.a.release, "_secure_file_spool", side_effect=AssertionError("hidden archive read")):
                    candidate, _ = f.a.replay(f.args, snapshots=snapshots)
                self.assertEqual(set(snapshots.files), expected)
                self.assertTrue(reads.call_args_list)
                self.assertTrue(all(call.kwargs.get("snapshots") is snapshots for call in reads.call_args_list))
                for path, (raw, limit, mode) in snapshots.files.items():
                    self.assertEqual(path.read_bytes(), raw)
                    try:
                        path.chmod(0o600); path.write_bytes(b"substituted"); path.chmod(mode)
                        with self.subTest(path=str(path.relative_to(f.root))), self.assertRaises(Exception):
                            snapshots.read_bytes(path, limit, mode=mode)
                    finally:
                        path.chmod(0o600); path.write_bytes(raw); path.chmod(mode)
                snapshots.recheck()
                for directory in snapshots.directories:
                    extra = directory / "unobserved-directory"
                    extra.mkdir(mode=0o700)
                    try:
                        with self.subTest(directory=str(directory.relative_to(f.root))), self.assertRaises(Exception):
                            snapshots.recheck()
                    finally: extra.rmdir()
                self.assertEqual(candidate["artifactDigests"]["d1-cross-check"], f.a.sha(snapshots.files[f.args.d1_cross_check][0]))
            finally: f.close()

    def test_rollback_directory_membership_aba_is_rejected_at_the_helper_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                rb = f.a.rollback_helper()
                extra = f.args.rollback_receipt / "unobserved-directory"
                extra.mkdir(mode=0o700)
                verify = rb.verify_receipt
                def temporarily_absent(*args, **kwargs):
                    extra.rmdir()
                    try: return verify(*args, **kwargs)
                    finally: extra.mkdir(mode=0o700)
                output = io.StringIO()
                arguments = ["build-candidate", "--candidate", str(f.args.candidate)]
                for name in ORIGINAL_ARGUMENTS: arguments += ["--" + name, str(getattr(f.args, name.replace("-", "_")))]
                with patch.object(rb, "verify_receipt", side_effect=temporarily_absent), redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(f.a.main(arguments), 1)
                self.assertFalse(f.args.candidate.exists())
                self.assertNotRegex(output.getvalue(), r"CONNECTED|QUALIFIED|READY_TO_WORK")
                self.assertTrue(extra.is_dir())
            finally: f.close()

    def test_rollback_forward_aba_is_rejected_at_the_legacy_helper_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                rb = f.a.rollback_helper()
                path = f.args.rollback_receipt / "forward-state.json"
                valid = path.read_bytes()
                f.write(path, {})
                read = rb._read_regular
                def temporarily_valid(requested, *args, **kwargs):
                    if Path(requested) != path: return read(requested, *args, **kwargs)
                    f.raw(path, valid)
                    try: return read(requested, *args, **kwargs)
                    finally: f.write(path, {})
                output = io.StringIO()
                arguments = ["build-candidate", "--candidate", str(f.args.candidate)]
                for name in ORIGINAL_ARGUMENTS: arguments += ["--" + name, str(getattr(f.args, name.replace("-", "_")))]
                with patch.object(rb, "_read_regular", side_effect=temporarily_valid), redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(f.a.main(arguments), 1)
                self.assertFalse(f.args.candidate.exists())
                self.assertNotRegex(output.getvalue(), r"CONNECTED|QUALIFIED|READY_TO_WORK")
                self.assertEqual(path.read_bytes(), b"{}")
            finally: f.close()

    def test_retained_absence_and_creation_observations_are_load_bearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                original = f.a.read_json(f.args.production_manifest, legacy=True)
                source_inventory = f.a.release._git_inventory(f.repo, f.head, verify_checkout=True)
                cases = [("binding-" + str(i), ("preflight", "managedBindings", i), "present", True) for i in range(6)]
                cases += [("preexisting-" + str(i), ("preflight", "resources", i), "matchingIds", ["pre-existing-id"]) for i in range(6)]
                cases += [("creation-" + str(i), ("creations", i), "createdId", "unobserved-id") for i in range(6)]
                cases += [("session", (), "sessionNonce", "b" * 48), ("head", (), "sourceHead", "0" * 40),
                    ("tree", (), "sourceTree", "0" * 40), ("preflight-time", ("preflight",), "observedAt", f.t(-150)),
                    ("creation-time", ("creations", 0), "observedAt", f.t(-161)),
                    ("prior-site", ("preflight", "priorSite"), "versionId", "unobserved-version")]
                for name, trail, field, replacement in cases:
                    observed = replace_at(f.observations, trail, field, replacement)
                    # Rebind hashes to force semantic rejection, not stale-hash rejection.
                    for creation in observed["creations"]: creation["preflightSha256"] = f.a.sha(f.a.canonical(observed["preflight"]))
                    production = {**original, "resource_observations": observed}
                    f.args.production_manifest.chmod(0o600)
                    f.raw(f.args.production_manifest, f.a.canonical(production) + b"\n")
                    f.args.production_manifest.chmod(0o444)
                    f.write(f.args.change_record, {**f.change, "resourceObservationsSha256": f.a.sha(f.a.canonical(observed))})
                    # Cache only unchanged fixture Git inventory, as in the
                    # existing evidence matrix; execute all resource replay.
                    with self.subTest(case=name), patch.object(f.a.release, "_git_inventory", return_value=source_inventory), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        args = ["build-candidate"]
                        for key in ORIGINAL_ARGUMENTS: args += ["--" + key, str(getattr(f.args, key.replace("-", "_")))]
                        args += ["--candidate", str(f.args.candidate)]
                        self.assertEqual(f.a.main(args), 1)
                        self.assertFalse(f.args.candidate.exists())
            finally: f.close()

    def test_guest_directory_identity_is_independent_of_both_authored_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                observed = copy.deepcopy(f.observations)
                directory = observed["creations"][4]["filesystem"]
                directory["inode"] += 1
                directory["createdId"] = "directory-" + str(directory["device"]) + "-" + str(directory["inode"])
                observed["creations"][4]["createdId"] = directory["createdId"]
                production = f.a.read_json(f.args.production_manifest, legacy=True)
                production["resource_observations"] = observed
                f.args.production_manifest.chmod(0o600)
                f.raw(f.args.production_manifest, f.a.canonical(production) + b"\n")
                f.args.production_manifest.chmod(0o444)
                change = copy.deepcopy(f.change)
                change["resources"][4]["createdId"] = directory["createdId"]
                change["resourceObservationsSha256"] = f.a.sha(f.a.canonical(observed))
                f.write(f.args.change_record, change)
                result = f.cli("build-candidate")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(f.args.candidate.exists())
            finally: f.close()

    def test_candidate_requires_retained_resource_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                production = f.a.read_json(f.args.production_manifest, legacy=True)
                production.pop("resource_observations", None)
                f.args.production_manifest.chmod(0o600)
                f.raw(f.args.production_manifest, f.a.canonical(production) + b"\n")
                f.args.production_manifest.chmod(0o444)
                result = f.cli("build-candidate")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(f.args.candidate.exists())
            finally: f.close()

    def test_each_resource_id_must_match_retained_creation_observation(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                original = f.args.change_record.read_bytes()
                for index, resource in enumerate(f.change["resources"]):
                    changed = copy.deepcopy(f.change)
                    changed["resources"][index]["createdId"] = "unobserved-pre-existing-id"
                    f.write(f.args.change_record, changed)
                    try:
                        result = f.cli("build-candidate")
                        with self.subTest(kind=resource["kind"]):
                            self.assertNotEqual(result.returncode, 0)
                            self.assertFalse(f.args.candidate.exists())
                            self.assertNotRegex(result.stdout + result.stderr, r"CONNECTED|QUALIFIED|READY_TO_WORK")
                    finally:
                        f.raw(f.args.change_record, original)
                        if f.args.candidate.exists(): f.args.candidate.unlink()
            finally: f.close()

    def test_semantic_scan_accepts_real_package_versions_and_rejects_empty_sbom(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                f.a.validate_release(f.primary, f.runtime, f.head, f.tree, time.time())
                path = f.primary / "core.sbom.json"
                value = f.a.read_json(path); value["artifacts"] = []
                f.write(path, value)
                with self.assertRaises(Exception): f.a.validate_release(f.primary, f.runtime, f.head, f.tree, time.time())
            finally: f.close()

    def test_resource_creation_order_requires_service_token_before_policy(self):
        a = load()
        self.assertEqual(a.RESOURCE_KINDS, ("tunnel", "access_application", "service_token", "access_policy", "secret_directory", "dns"))

        before = {
            "observedAt": "2026-09-04T16:00:00Z",
            "priorSite": {"versionId": "site-project~prior-version", "versionNumber": 1, "accessRevision": "prior-access", "accessMode": "custom", "allowedOwnerCount": 1, "allowedGroupCount": 0, "allowedVisitorCount": 0},
            "bindingOperation": "sites-environment-list",
            "managedBindings": [{"name": name, "present": False} for name in MANAGED_BINDINGS],
            "resources": [{"kind": kind, "name": name, "operation": "filesystem-lstat" if kind == "secret_directory" else "cloudflare-resource-list", "matchingIds": []} for kind, name, _ in RESOURCE_FIXTURES],
        }
        directory = {"createdId": "directory-1-2", "device": 1, "inode": 2, "uid": 0, "gid": 0, "mode": "0700"}

        def observations(offsets):
            creations = []
            for (kind, name, created_id), minute in zip(RESOURCE_FIXTURES, offsets):
                created_id = directory["createdId"] if kind == "secret_directory" else created_id
                creations.append({"kind": kind, "name": name, "operation": "filesystem-mkdir" if kind == "secret_directory" else "cloudflare-resource-create",
                    "createdId": created_id, "observedAt": f"2026-09-04T16:{minute:02d}:00Z", "preflightSha256": a.sha(a.canonical(before)),
                    "filesystem": directory if kind == "secret_directory" else None})
            return {"schema": "tueiq-session-resource-observations-v1", "sessionNonce": "a" * 48, "sourceHead": "b" * 40, "sourceTree": "c" * 40,
                "preflight": before, "creations": creations}

        a.validate_resource_observations(observations((1, 2, 3, 4, 5, 6)))
        with self.assertRaises(Exception):
            a.validate_resource_observations(observations((1, 2, 4, 3, 5, 6)))

    def test_native_sites_identifiers_remain_opaque_and_bounded(self):
        a = load()
        native = "appgprj_6a7c11351b548191a9f9e936ae8ff837~appgver_51bb788eee4481919fa8cb280a126f89"
        self.assertEqual(a.site_identifier(native), native)
        for invalid in (" " + native, native + "\n", "https://site.invalid/id", "x" * 257):
            with self.subTest(invalid=invalid), self.assertRaises(Exception):
                a.site_identifier(invalid)
        with self.assertRaises(Exception):
            a.identifier(native)

    def test_resource_names_use_kind_specific_contracts(self):
        a = load()
        for kind, name, _ in RESOURCE_FIXTURES:
            with self.subTest(kind=kind, name=name):
                self.assertEqual(a.resource_name(kind, name), name)

        invalid = {
            "access_application": ("Lil-Tweak-private-core", "Lil Tweak private core ", "lil tweak private core"),
            "access_policy": ("Lil Tweak Worker token only", "Lil Tweak Worker service token only "),
            "dns": ("CORE.lil-tweak.invalid", "https://core.lil-tweak.invalid", "core.lil-tweak.invalid/path", "core.lil-tweak.invalid:443", "*.lil-tweak.invalid", "core..invalid", "localhost"),
            "secret_directory": ("/var/lib/lil-tweak-activation/secret", "var/lib/lil-tweak-activation/secrets", "/tmp/secrets"),
            "tunnel": (" leading", "trailing ", "line\nbreak", "é", "x" * 101),
            "service_token": (" leading", "trailing ", "tab\tname", "é", "x" * 101),
        }
        for kind, values in invalid.items():
            for value in values:
                with self.subTest(kind=kind, invalid=value), self.assertRaises(Exception):
                    a.resource_name(kind, value)

        a.identifier("opaque-id_123")
        for created_id in ("opaque.id", "created id", "/var/lib/value"):
            with self.subTest(created_id=created_id), self.assertRaises(Exception):
                a.identifier(created_id)

    def test_original_evidence_fault_matrix_rejects_without_candidate_or_truth(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                a = f.a
                command = ["build-candidate", "--candidate", str(f.args.candidate)]
                for name in ORIGINAL_ARGUMENTS: command += ["--" + name, str(getattr(f.args, name.replace("-", "_")))]
                source_inventory = a.release._git_inventory(f.repo, f.head, verify_checkout=True)
                f.args.rollback_forward = f.args.rollback_receipt / "forward-state.json"
                f.args.scan_primary = f.primary / "core.grype.json"
                f.args.verification_primary = f.primary / "verification-receipt.json"
                cases = [
                    ("rollback_forward", ("transaction_state",), "open"),
                    ("rollback_forward", ("rollback_outcome",), "dirty"),
                    ("rollback_forward", ("images", "core", "reference"), "registry.example/lil-tweak/core@sha256:" + "0" * 64),
                    ("rollback_forward", ("files", "unowned"), {}),
                    ("scan_primary", ("matches",), [{"id": "CVE-2026-1234", "severity": "High"}]),
                    ("verification_primary", ("policy", "decision"), "FAIL"),
                    ("verification_primary", ("tools", "grype"), "unaudited"),
                    ("preflight_provider_evidence", ("observedAt",), f.t(-2000)),
                    ("preflight_provider_evidence", ("droplet", "id"), "1"),
                    ("provider_evidence", ("droplet", "name"), "wrong-target"),
                    ("provider_evidence", ("rawResponseSha256",), "0" * 64),
                    ("local_qualification", ("sourceHead",), "0" * 40),
                    ("local_qualification", ("identity", "dropletId"), "1"),
                    ("local_qualification", ("images", "core"), "sha256:" + "0" * 64),
                    ("local_qualification", ("negativeChecks", "replay"), False),
                    ("local_qualification", ("cleanup", "noContainers"), False),
                    ("runtime_manifest", ("source", "tree"), "0" * 40),
                    ("runtime_manifest", ("images", "runner", "digest"), "sha256:" + "0" * 64),
                    ("guest_evidence", ("identity", "dropletId"), "1"),
                    ("guest_evidence", ("sourceHead",), "0" * 40),
                    ("guest_evidence", ("operatingSystem",), "other"),
                    ("guest_evidence", ("architecture",), "aarch64"),
                    ("guest_evidence", ("runtimeSha256",), "0" * 64),
                    ("guest_evidence", ("checkedAt",), f.t(-2000)),
                    ("guest_cross_check", ("noContainers",), False),
                    ("guest_cross_check", ("jobId",), "job:" + "0" * 32),
                    ("guest_cross_check", ("observedAt",), f.t(-2000)),
                    ("owner_flow_job", ("jobRevision",), 4),
                    ("owner_flow_job", ("baselineTreeSha256",), "0" * 64),
                    ("owner_flow_job", ("finalTreeSha256",), "0" * 64),
                    ("owner_flow_job", ("proposalDigest",), None),
                    ("owner_flow_job", ("editJournalDigest",), "0" * 64),
                    ("owner_flow_job", ("evidence", 0, "sizeBytes"), 1),
                    ("site_status_evidence", ("deployment", "sourceHead"), "0" * 40),
                    ("site_status_evidence", ("deployment", "versionId"), "different"),
                    ("site_status_evidence", ("deployment", "deploymentId"), "different"),
                    ("site_status_evidence", ("deployment", "allowedVisitorCount"), 1),
                    ("site_status_evidence", ("deployment", "productionOrigin"), "https://other.example.invalid"),
                    ("site_status_evidence", ("deployment", "customDomainCount"), 1),
                    ("site_status_evidence", ("deployment", "anonymousDenied"), False),
                    ("site_status_evidence", ("deployment", "forgedIdentityDenied"), False),
                    ("site_status_evidence", ("deployment", "alternateHostRejected"), False),
                    ("site_status_evidence", ("deployment", "ownerSameOriginSucceeded"), False),
                    ("site_status_evidence", ("runner", "connection"), "failed"),
                    ("site_status_evidence", ("bridge", "signing"), "missing"),
                    ("site_status_evidence", ("runner", "connectionState"), "connected"),
                    ("d1_cross_check", ("jobId",), "job:" + "0" * 32),
                    ("d1_cross_check", ("remoteJobId",), "00000000-0000-4000-8000-000000000000"),
                    ("d1_cross_check", ("ownerScope",), "0" * 30),
                    ("d1_cross_check", ("jobRevision",), 4),
                    ("d1_cross_check", ("coreRevision",), 999),
                    ("d1_cross_check", ("gitSource", "commit"), "0" * 40),
                    ("d1_cross_check", ("state",), "failed"),
                    ("d1_cross_check", ("evidence", 0, "sha256"), "0" * 64),
                    ("d1_cross_check", ("decisionCount",), 1),
                    ("d1_cross_check", ("exportCount",), 1),
                    ("d1_cross_check", ("events", 1, "id"), "audit:" + "1" * 32),
                    ("d1_cross_check", ("events", 1, "type"), "decision_authorized"),
                    ("d1_cross_check", ("events", 1, "createdAt"), f.t(-200)),
                    ("core_cross_check", ("signedRead",), False),
                    ("core_cross_check", ("coreRevision",), 999),
                    ("core_cross_check", ("state",), "failed"),
                    ("core_cross_check", ("sourceDigest",), "0" * 64),
                    ("core_cross_check", ("jobRevision",), 4),
                    ("core_cross_check", ("remoteJobId",), "00000000-0000-4000-8000-000000000000"),
                    ("core_cross_check", ("d1Sha256",), "0" * 64),
                    ("core_cross_check", ("proposalDigest",), "0" * 64),
                    ("core_cross_check", ("evidence", 0, "sha256"), "0" * 64),
                    ("production_manifest", ("sites", "version_id"), "different"),
                    ("production_manifest", ("sites", "production_url"), "https://other.example.invalid"),
                    ("production_manifest", ("sites", "custom_domain_count"), 1),
                    ("production_manifest", ("sites", "anonymous_denied"), False),
                    ("production_manifest", ("sites", "forged_identity_denied"), False),
                    ("production_manifest", ("sites", "alternate_host_rejected"), False),
                    ("production_manifest", ("sites", "owner_same_origin_succeeded"), False),
                    ("production_manifest", ("owner_flow_job_sha256",), "0" * 64),
                    ("production_manifest", ("runtime", "manifest_sha256"), "0" * 64),
                    ("change_record", ("managedBindings", "CORE_ORIGIN"), "present"),
                    ("change_record", ("resources", 0, "preflight"), "unknown"),
                    ("change_record", ("resources", 0, "createdId"), "pre-existing"),
                    ("change_record", ("rollbackOrder",), ["delete:pre-existing"]),
                    ("change_record", ("mutationStartedAt",), f.t(-171)),
                    ("change_record", ("sourceTree",), "0" * 40),
                ]
                # Only the immutable fixture Git inventory is cached. Every
                # artifact, hash, parser, semantic validator and CLI executes.
                with patch.object(a.release, "_git_inventory", return_value=source_inventory):
                    for argument, trail, replacement in cases:
                        path = getattr(f.args, argument)
                        original, mode = path.read_bytes(), path.stat().st_mode & 0o777
                        value = json.loads(original)
                        changed = replace_at(value, trail[:-1], trail[-1], replacement)
                        path.chmod(0o600)
                        path.write_bytes(a.canonical(changed) + (b"\n" if original.endswith(b"\n") else b""))
                        path.chmod(mode)
                        output = io.StringIO()
                        try:
                            with self.subTest(argument=argument, field=trail), redirect_stdout(output), redirect_stderr(output):
                                self.assertEqual(a.main(command), 1)
                                self.assertFalse(f.args.candidate.exists())
                                self.assertNotRegex(output.getvalue(), r"CONNECTED|QUALIFIED|READY_TO_WORK")
                        finally:
                            path.chmod(0o600); path.write_bytes(original); path.chmod(mode)
                            if f.args.candidate.exists(): f.args.candidate.unlink()
                self.assertEqual(len(cases), 83)
                for kind in ("dirty-source", "changed-head"):
                    if kind == "dirty-source":
                        (f.repo / "untracked.txt").write_text("fixture mutation")
                    else:
                        (f.repo / "untracked.txt").unlink()
                        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "--allow-empty", "-m", "fixture head mutation"], cwd=f.repo, check=True)
                    result = f.cli("build-candidate")
                    self.assertNotEqual(result.returncode, 0, kind)
                    self.assertFalse(f.args.candidate.exists())
                    self.assertNotRegex(result.stdout + result.stderr, r"CONNECTED|QUALIFIED|READY_TO_WORK")
            finally: f.close()

    def test_source_manifest_unknown_fields_are_rejected_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                path = f.primary / "source-manifest.json"
                original = path.read_bytes()
                f.a.validate_source_manifest(json.loads(original))
                for trail in ((), ("source",), ("official_base",), ("packages",), ("verification_receipt",)):
                    value = replace_at(json.loads(original), trail, "authorization", "SECRET-CANARY")
                    path.chmod(0o600)
                    path.write_bytes(f.a.canonical(value) + b"\n")
                    path.chmod(0o444)
                    # Rebind source byte hash to isolate shape validation, not
                    # merely rejection by a previously computed digest.
                    runtime = copy.deepcopy(f.runtime)
                    runtime["source"]["manifest_sha256"] = f.a.sha(path.read_bytes())
                    runtime["source"]["manifest_size"] = len(path.read_bytes())
                    with self.subTest(trail=trail), self.assertRaises(Exception):
                        f.a.validate_source_manifest(value)
            finally: f.close()

    def test_every_original_nested_field_has_an_independent_fail_closed_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                a = f.a
                live = load("lil-tweak-live-evidence")
                pairs = [
                    (a.read_json(f.args.owner_flow_job), a.validate_owner_job),
                    (a.read_json(f.args.guest_evidence), a.validate_guest),
                    (a.read_json(f.args.guest_cross_check), lambda value: a.validate_guest(value, cross=True)),
                    (a.read_json(f.args.d1_cross_check), a.validate_d1),
                    (a.read_json(f.args.core_cross_check), live.validate_core),
                    (f.providers[1], a.q.validate_provider),
                    (a.read_json(f.args.local_qualification), a.q.validate_receipt),
                    (f.deployment, a.validate_deployment),
                    (f.observations, a.validate_resource_observations),
                    (f.change, lambda value: a.validate_change(value, head=f.head, tree=f.tree, preflight=a.sha(f.args.preflight_provider_evidence.read_bytes()), deployment=f.deployment, rollback_time=f.now - 170, now=time.time(), observations=f.observations)),
                    (json.loads((f.args.site_primary_evidence / "status.body").read_bytes()), live.validate_status),
                ]
                checked = 0
                for original, validate in pairs:
                    validate(original)
                    for path, trail, obj in objects(original):
                        for field in list(obj) + ["authorization"]:
                            with self.subTest(schema=original.get("schema", "status"), path=path, field=field), self.assertRaises(Exception):
                                validate(replace_at(original, trail, field, "SECRET-CANARY", remove=field in obj))
                            checked += 1
                self.assertEqual(checked, 785)
            finally: f.close()

    def test_fresh_verification_binds_exact_source_and_is_bound_by_host_go(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                value = f.a.read_json(f.primary / "verification-receipt.json")
                for field, replacement in (("sourceHead", "0" * 40), ("sourceTree", "0" * 40), ("sourceManifestSha256", "0" * 64), ("sourceArchiveSha256", "0" * 64), ("verifiedAt", f.t(-174))):
                    with self.subTest(field=field):
                        bad = copy.deepcopy(value); bad[field] = replacement
                        f.write(f.primary / "verification-receipt.json", bad)
                        with self.assertRaises(Exception):
                            f.a.validate_release(f.primary, f.runtime, f.head, f.tree, time.time())
            finally: f.close()

    def test_complete_primary_chain_builds_and_reopens_candidate_without_truth(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                result = f.cli("build-candidate")
                self.assertEqual(result.returncode, 0, result.stderr)
                candidate = f.a.read_json(f.args.candidate)
                self.assertEqual(set(candidate), CANDIDATE_KEYS)
                observed = set()
                for path, trail, value in objects(candidate):
                    self.assertIn(path, CANDIDATE_OBJECT_KEYS)
                    self.assertEqual(set(value), CANDIDATE_OBJECT_KEYS[path], path)
                    observed.add(path)
                self.assertEqual(observed, set(CANDIDATE_OBJECT_KEYS))
                self.assertEqual(set(f.a.read_json(f.args.site_status_evidence)), STATUS_KEYS)
                self.assertEqual(set(f.a.read_json(f.args.guest_evidence)), GUEST_KEYS)
                self.assertEqual(set(f.a.read_json(f.args.owner_flow_job)), JOB_KEYS)
                self.assertEqual(set(f.change), CHANGE_KEYS)
                self.assertNotIn("CONNECTED", f.args.candidate.read_text() + result.stdout)
                result = f.cli("verify-candidate")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), f.a.sha(f.args.candidate.read_bytes()))
                # Replay was executed above with all real originals. Cache only
                # that expensive recomputation for exhaustive projection mutations;
                # secure reads and the real candidate equality check still execute.
                checks = 0
                with patch.object(f.a, "replay", return_value=(candidate, {})):
                    for path, trail, value in objects(candidate):
                        for field in list(value) + ["authorization"]:
                            bad = replace_at(candidate, trail, field, "SECRET-CANARY", remove=field in value)
                            f.write(f.args.candidate, bad)
                            with self.subTest(path=path, field=field), self.assertRaises(Exception): f.a.verify_candidate(f.args)
                            checks += 1
                self.assertEqual(checks, 332)
                f.write(f.args.candidate, candidate)
                f.args.d1_cross_check.write_bytes(b"{}")
                result = f.cli("verify-candidate")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("READY_TO_WORK", result.stdout)
            finally: f.close()

    def test_executable_offline_check_and_explicit_paths(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("build-candidate", "verify-candidate", "finalize-reviewed", "verify-final"):
            result = subprocess.run([sys.executable, str(SCRIPT), command, "--help"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ORIGINAL_ARGUMENTS:
                self.assertIn("--" + name, result.stdout)
            self.assertNotIn("--source-head", result.stdout)
            self.assertNotIn("--candidate-sha256", result.stdout)

    def test_secure_canonical_inputs_and_exclusive_outputs(self):
        a = load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "value.json"
            a.publish(path, {"schema": "fixture"})
            self.assertEqual(a.read_json(path), {"schema": "fixture"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(Exception): a.publish(path, {})
            for raw in (b' {"schema":"fixture"}', b'{"schema":"fixture","schema":"fixture"}', b'{"schema":NaN}', b'x' * (a.MAX_BYTES + 1)):
                path.write_bytes(raw)
                with self.assertRaises(Exception): a.read_json(path)
            path.write_bytes(a.canonical({"schema": "fixture"}))
            path.chmod(0o644)
            with self.assertRaises(Exception): a.read_json(path)
            path.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(path)
            with self.assertRaises(Exception): a.read_json(alias)
            alias.unlink()
            os.link(path, alias)
            with self.assertRaises(Exception): a.read_json(path)
            alias.unlink()
            # The test runtime maps only uid/gid 0. Inject the fstat ownership
            # observation instead of attempting an unavailable chown identity.
            original_stat = a.os.stat
            def foreign_owner(*args, **kwargs):
                info = original_stat(*args, **kwargs)
                if a.stat.S_ISREG(info.st_mode):
                    return SimpleNamespace(**{name: (65534 if name in {"st_uid", "st_gid"} else getattr(info, name)) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
                return info
            with patch.object(a.os, "stat", side_effect=foreign_owner):
                with self.assertRaises(Exception): a.read_json(path)
            original = a.q.signature
            with patch.object(a.q, "signature", side_effect=lambda info: original(info) + (time.monotonic_ns(),)):
                with self.assertRaises(Exception): a.read_json(path)
            root.chmod(0o755)
            with self.assertRaises(Exception): a.read_json(path)
            root.chmod(0o700)
            legacy = root / "legacy.json"
            a.publish(legacy, raw=a.canonical({"schema": "fixture"}) + b"\n")
            legacy.chmod(0o444)
            self.assertEqual(a.read_json(legacy, legacy=True), {"schema": "fixture"})
            with self.assertRaises(Exception): a.read_json(legacy)
            legacy.chmod(0o600)
            with self.assertRaises(Exception): a.read_json(legacy, legacy=True)

    def test_candidate_reopen_rejects_substitution_after_semantic_replay(self):
        a = load()
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.json"
            a.publish(candidate, {"completedAt": "fixture"})
            expected = {"completedAt": "fixture"}
            def replay(*args, **kwargs):
                candidate.write_bytes(a.canonical({"completedAt": "substituted"}))
                return expected, {}
            with patch.object(a, "replay", side_effect=replay), self.assertRaises(Exception):
                a.verify_candidate(SimpleNamespace(candidate=candidate))

    def test_every_missing_original_fails_without_candidate_or_truth(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "candidate.json"
            for missing in ORIGINAL_ARGUMENTS:
                args = [sys.executable, str(SCRIPT), "build-candidate", "--candidate", str(output)]
                for name in ORIGINAL_ARGUMENTS:
                    if name != missing: args += ["--" + name, str(Path(temporary) / name)]
                result = subprocess.run(args, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                for name in FINAL_KEYS - {"schema", "completedAt", "candidateSha256", "independentReviewSha256"}:
                    self.assertNotIn(name + " = YES", result.stdout + result.stderr)

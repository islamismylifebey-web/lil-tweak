#!/usr/bin/env python3
"""Offline replay of a direct activation. Only reviewed finalization creates truth.

Task 6 JSON is UTF-8, sorted compact JSON with no trailing newline. Existing
release/rollback JSON keeps its exact Task 1-5 newline convention.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
BASE = "e76996970e816c4cce7b8334e0495e1e0de48e7d"
MAX_BYTES = 16 * 1024 * 1024
MAX_SESSION = 1800
ORIGINALS = ("source-root", "local-qualification", "preflight-provider-evidence", "provider-evidence", "release-evidence-root",
             "runtime-manifest", "rollback-receipt", "production-manifest", "owner-flow-receipt", "owner-flow-job",
             "site-status-evidence", "guest-evidence", "site-primary-evidence", "d1-cross-check", "core-cross-check", "guest-cross-check", "change-record")
MANAGED = ("MANAGED_INGRESS_SECRET", "CORE_ORIGIN", "CORE_ACCESS_CLIENT_ID", "CORE_ACCESS_CLIENT_SECRET", "CORE_SIGNING_KEY_ID", "CORE_SIGNING_SECRET", "CUSTOMER_HTTP_LIL_TWEAK_CORE")
ADDED = MANAGED[:-1]
RESOURCE_KINDS = ("tunnel", "access_application", "access_policy", "service_token", "secret_directory", "dns", "managed_rule")
SESSION_SECRET_DIRECTORY = Path("/var/lib/lil-tweak-activation/secrets")
RELEASE_FILES = ("source-manifest.json", "source.tar.gz", "verification-receipt.json", "host-go.txt", "base-images.txt", "scan-hashes.txt",
                 "core.sbom.json", "core.grype.json", "runner.sbom.json", "runner.grype.json")
TOPOLOGY = {"route": "direct_core_to_local_podman", "intermediary": "none", "policy": "ENGINEERING_EXECUTION_ONLY"}


def helper(name):
    key = "activation_" + name.replace("-", "_")
    if key not in sys.modules:
        spec = importlib.util.spec_from_file_location(key, ROOT / "scripts" / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
    return sys.modules[key]


q = helper("lil-tweak-qualification")
release = helper("lil-tweak-release")
canonical, sha, require, exact, fields = q.canonical, q.sha, q.require, q.exact, q.fields


def rollback_helper():
    return helper("lil-tweak-rollback")


def timestamp(value):
    return q.production_epoch(value)


def fresh(value, now=None):
    now = time.time() if now is None else now
    observed = timestamp(value)
    require(0 <= now - observed <= MAX_SESSION)
    return observed


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value) is not None)


def uuid4(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value) is not None)


@contextmanager
def secure_directory(path):
    path = Path(path).absolute()
    with release._open_bound_parent(path / "sentinel", "activation_input_unsafe") as (fd, _, revalidate):
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o700 and before.st_uid == 0 and before.st_gid == 0)
        yield fd
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid) ==
                (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid))
        revalidate()


def read_bytes(path, limit=MAX_BYTES, *, mode=0o600):
    path = Path(path).absolute()
    with secure_directory(path.parent) as parent:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == mode and before.st_uid == 0 and before.st_gid == 0
                and before.st_nlink == 1 and 0 <= before.st_size <= limit)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as handle:
            require(q.signature(os.fstat(handle.fileno())) == q.signature(before))
            raw = handle.read(limit + 1)
            require(len(raw) == before.st_size and q.signature(os.fstat(handle.fileno())) == q.signature(before))
        require(q.signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == q.signature(before))
        return raw


def read_json(path, *, legacy=False):
    raw = read_bytes(path, mode=0o444 if legacy else 0o600)
    value = q.parse_json(raw)
    require(raw == canonical(value) + (b"\n" if legacy else b""))
    return value


def publish(path, value=None, *, raw=None):
    """Exclusive publication: pin parent, fsync temp, link without clobber, fsync.

    link/unlink is the portable no-replace rename equivalent; link count is one
    again before success. Failure removes only our verified inode.
    """
    require(os.geteuid() == 0 and os.getegid() == 0)
    path = Path(path).absolute()
    data = canonical(value) if raw is None else raw
    require(type(data) is bytes and len(data) <= MAX_BYTES)
    with secure_directory(path.parent) as parent:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(False)
        temporary = ".pending-" + secrets.token_hex(24)
        published = False
        inode = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
                info = os.fstat(handle.fileno())
                inode = (info.st_dev, info.st_ino)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_uid == 0 and info.st_gid == 0 and info.st_size == len(data))
            # Reopen named parent before publishing, catching renamed ancestors.
            with secure_directory(path.parent) as reopened:
                require((os.fstat(reopened).st_dev, os.fstat(reopened).st_ino) == (os.fstat(parent).st_dev, os.fstat(parent).st_ino))
            os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            published = True
            os.unlink(temporary, dir_fd=parent)
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == inode and info.st_nlink == 1 and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
            os.fsync(parent)
            require(read_bytes(path) == data)
        except BaseException:
            for name in ([path.name] if published else []) + [temporary]:
                try:
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if inode is not None and (info.st_dev, info.st_ino) == inode: os.unlink(name, dir_fd=parent)
                except FileNotFoundError:
                    pass
            raise
    return sha(data)


def require_new_output(path):
    """Reject unsafe/existing destinations before any independent live read."""
    path = Path(path).absolute()
    with secure_directory(path.parent) as parent:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        require(False)


def inventory(path, expected=None, *, recursive=False):
    result = {}
    with secure_directory(path) as fd:
        names = sorted(os.listdir(fd))
        require(len(names) <= 256)
        if expected is not None: exact(names, sorted(expected))
        for name in names:
            require(re.fullmatch(r"[A-Za-z0-9_.:-]+", name) is not None)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if recursive and stat.S_ISDIR(info.st_mode):
                for nested, digest in inventory(Path(path) / name, recursive=True).items(): result[name + "/" + nested] = digest
            else:
                result[name] = sha(read_bytes(Path(path) / name, limit=release.MAX_ARCHIVE_BYTES if name == "source.tar.gz" else MAX_BYTES, mode=0o444 if name == "source-manifest.json" else 0o600))
        exact(sorted(os.listdir(fd)), names)
    return result


def validate_deployment(value):
    fields(value, ("schema", "sourceHead", "sourceTree", "versionId", "versionNumber", "deploymentId", "archiveSha256", "environmentRevision", "accessRevision", "accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount", "deployedAt"))
    exact(value["schema"], "tueiq-site-deployment-record-v1")
    for name in ("sourceHead", "sourceTree"): require(type(value[name]) is str and re.fullmatch(r"[0-9a-f]{40}", value[name]) is not None)
    for name in ("versionId", "deploymentId", "environmentRevision", "accessRevision"): identifier(value[name])
    q.integer(value["versionNumber"], 1); q.digest(value["archiveSha256"]); timestamp(value["deployedAt"])
    exact([value[k] for k in ("accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount")], ["custom", 1, 0, 0])
    return value


def validate_descriptor(value):
    fields(value, ("id", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt"))
    require(re.fullmatch(r"evidence:[0-9a-f]{32}", value["id"]) is not None)
    require(value["filename"] in q.ARTIFACTS)
    exact(value["mediaType"], q.ARTIFACTS[value["filename"]]); exact(value["category"], q.CATEGORIES[value["filename"]])
    q.integer(value["sizeBytes"], 0, q.MAX_EVIDENCE_BYTES); q.digest(value["sha256"]); timestamp(value["createdAt"])


def validate_descriptors(values):
    require(type(values) is list and len(values) == 5)
    for d in values: validate_descriptor(d)
    require(len({d["id"] for d in values}) == 5 and {d["filename"] for d in values} == set(q.ARTIFACTS))


def validate_events(values):
    require(type(values) is list and 4 <= len(values) <= 250)
    ids, times, types = [], [], []
    for e in values:
        fields(e, ("id", "type", "createdAt"))
        require(type(e["id"]) is str and re.fullmatch(r"audit:[0-9a-f]{32}", e["id"]) is not None)
        ids.append(e["id"]); times.append(timestamp(e["createdAt"])); types.append(e["type"])
    require(len(set(ids)) == len(ids) and times == sorted(times))
    exact(types[:3], ["job_created", "dispatch_reserved", "core_dispatched"])
    exact(types[3:], ["core_status_mirrored"] * (len(types) - 3))


def validate_owner_job(value):
    fields(value, ("schema", "checkedAt", "requestId", "jobId", "ownerScope", "jobRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "evidence", "baselineTreeSha256", "finalTreeSha256", "fileSha256", "commandDigest", "editJournalDigest"))
    exact(value["schema"], "tueiq-owner-flow-job-v1"); timestamp(value["checkedAt"]); uuid4(value["requestId"])
    require(type(value["jobId"]) is str and re.fullmatch(r"job:[0-9a-f]{32}", value["jobId"]) is not None)
    exact(value["ownerScope"], q.OWNER_SCOPE); q.integer(value["jobRevision"], 3)
    exact(value["mode"], "architect"); exact(value["state"], "completed")
    exact(value["gitSource"], q.submission("architect")["gitSource"])
    for name in ("sourceDigest", "baselineTreeSha256", "finalTreeSha256"): exact(value[name], q.BASELINE_TREE_SHA256)
    exact(value["fileSha256"], q.SOURCE_SHA256); exact(value["approvalProposal"], None); exact(value["approvalConsumed"], False)
    for name in ("proposalDigest", "commandDigest", "editJournalDigest"): q.digest(value[name])
    validate_descriptors(value["evidence"])
    empty = next(d for d in value["evidence"] if d["filename"] == "changes.patch")
    exact([empty["sha256"], empty["sizeBytes"]], [q.EMPTY_SHA256, 0])
    return value


def validate_d1(value):
    fields(value, ("schema", "observedAt", "jobId", "remoteJobId", "ownerScope", "jobRevision", "coreRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "decisionCount", "exportCount", "evidence", "events"))
    exact(value["schema"], "tueiq-d1-activation-cross-check-v1"); timestamp(value["observedAt"])
    require(type(value["jobId"]) is str and re.fullmatch(r"job:[0-9a-f]{32}", value["jobId"]) is not None)
    q.job_id(value["remoteJobId"]); exact(value["ownerScope"], q.OWNER_SCOPE)
    q.integer(value["jobRevision"], 3); q.integer(value["coreRevision"], 1)
    exact(value["gitSource"], q.submission("architect")["gitSource"])
    exact([value[k] for k in ("mode", "state", "sourceDigest", "approvalProposal", "approvalConsumed", "decisionCount", "exportCount")],
          ["architect", "completed", q.BASELINE_TREE_SHA256, None, False, 0, 0])
    q.digest(value["proposalDigest"]); validate_descriptors(value["evidence"]); validate_events(value["events"])
    for descriptor in value["evidence"]: exact(descriptor["id"], q.evidence_id(value["remoteJobId"], descriptor["filename"]))
    return value


def validate_guest(value, *, cross=False):
    names = {"schema", "providerSha256", "runtimeSha256", "sourceHead", "identity", "operatingSystem", "architecture", "topology", "images"}
    fields(value, names | ({"observedAt", "jobId", "noContainers", "secretDirectory"} if cross else {"checkedAt", "verificationSha256"}))
    exact(value["schema"], "tueiq-guest-activation-cross-check-v1" if cross else "tueiq-guest-evidence-v1")
    timestamp(value["observedAt" if cross else "checkedAt"])
    for name in ("providerSha256", "runtimeSha256"): q.digest(value[name])
    if cross:
        require(re.fullmatch(r"job:[0-9a-f]{32}", value["jobId"]) is not None); exact(value["noContainers"], True)
        validate_directory_observation(value["secretDirectory"])
    else: q.digest(value["verificationSha256"])
    require(re.fullmatch(r"[0-9a-f]{40}", value["sourceHead"]) is not None)
    exact(value["operatingSystem"], "Ubuntu 24.04 LTS"); exact(value["architecture"], "x86_64"); exact(value["topology"], TOPOLOGY)
    fields(value["images"], ("core", "postgres", "runner"))
    for d in value["images"].values(): require(re.fullmatch(r"sha256:[0-9a-f]{64}", d) is not None)
    fields(value["identity"], ("owner", "ownerScope", "provider", "dropletId", "host", "region", "os", "size", "role"))
    return value


def validate_directory_observation(value):
    fields(value, ("createdId", "device", "inode", "uid", "gid", "mode"))
    q.integer(value["device"], 0); q.integer(value["inode"], 1)
    exact([value["uid"], value["gid"], value["mode"]], [0, 0, "0700"])
    exact(value["createdId"], "directory-" + str(value["device"]) + "-" + str(value["inode"]))
    return value


def observe_secret_directory():
    # Fixed session staging location, no secret reads or path override.
    with secure_directory(SESSION_SECRET_DIRECTORY) as fd:
        info = os.fstat(fd)
        return validate_directory_observation({"createdId": "directory-" + str(info.st_dev) + "-" + str(info.st_ino),
            "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": "0700"})


def validate_resource_observations(value):
    """Sanitized operation projections, retained separately from rollback claims."""
    fields(value, ("schema", "sessionNonce", "sourceHead", "sourceTree", "preflight", "creations"))
    exact(value["schema"], "tueiq-session-resource-observations-v1")
    require(type(value["sessionNonce"]) is str and re.fullmatch(r"[0-9a-f]{48}", value["sessionNonce"]) is not None)
    for key in ("sourceHead", "sourceTree"): require(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{40}", value[key]) is not None)
    before = value["preflight"]
    fields(before, ("observedAt", "priorSite", "bindingOperation", "managedBindings", "resources"))
    timestamp(before["observedAt"]); exact(before["bindingOperation"], "sites-environment-list")
    fields(before["priorSite"], ("versionId", "versionNumber", "accessRevision", "accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount"))
    identifier(before["priorSite"]["versionId"]); identifier(before["priorSite"]["accessRevision"]); q.integer(before["priorSite"]["versionNumber"], 1)
    exact([before["priorSite"][k] for k in ("accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount")], ["custom", 1, 0, 0])
    require(type(before["managedBindings"]) is list and len(before["managedBindings"]) == len(MANAGED))
    for name, observed in zip(MANAGED, before["managedBindings"]):
        fields(observed, ("name", "present")); exact(observed, {"name": name, "present": False})
    require(type(before["resources"]) is list and len(before["resources"]) == len(RESOURCE_KINDS))
    require(type(value["creations"]) is list and len(value["creations"]) == len(RESOURCE_KINDS))
    previous = timestamp(before["observedAt"])
    for kind, absent, created in zip(RESOURCE_KINDS, before["resources"], value["creations"]):
        fields(absent, ("kind", "name", "operation", "matchingIds"))
        exact(absent["kind"], kind); identifier(absent["name"]); exact(absent["matchingIds"], [])
        exact(absent["operation"], "filesystem-lstat" if kind == "secret_directory" else "cloudflare-resource-list")
        fields(created, ("kind", "name", "operation", "createdId", "observedAt", "preflightSha256", "filesystem"))
        exact(created["kind"], kind); exact(created["name"], absent["name"]); identifier(created["createdId"])
        exact(created["operation"], "filesystem-mkdir" if kind == "secret_directory" else "cloudflare-resource-create")
        exact(created["preflightSha256"], sha(canonical(before)))
        observed = timestamp(created["observedAt"]); require(previous <= observed); previous = observed
        if kind == "secret_directory":
            validate_directory_observation(created["filesystem"]); exact(created["createdId"], created["filesystem"]["createdId"])
        else: exact(created["filesystem"], None)
    require(len({r["name"] for r in value["creations"]}) == len(RESOURCE_KINDS))
    require(len({r["createdId"] for r in value["creations"]}) == len(RESOURCE_KINDS))
    return value


def validate_change(value, *, head, tree, preflight, deployment, rollback_time, now, observations):
    fields(value, ("schema", "sessionNonce", "startedAt", "mutationStartedAt", "completedAt", "preflightProviderSha256", "sourceHead", "sourceTree", "priorSite", "managedBindings", "resources", "additions", "rollbackOrder", "resourceObservationsSha256"))
    exact(value["schema"], "tueiq-session-change-record-v1")
    require(re.fullmatch(r"[0-9a-f]{48}", value["sessionNonce"]) is not None)
    exact(value["sourceHead"], head); exact(value["sourceTree"], tree); exact(value["preflightProviderSha256"], preflight)
    start, mutation, finish = (fresh(value[k], now) for k in ("startedAt", "mutationStartedAt", "completedAt"))
    require(start <= rollback_time < mutation < timestamp(deployment["deployedAt"]) <= finish)
    exact(value["managedBindings"], dict.fromkeys(MANAGED, "absent"))
    prior = value["priorSite"]
    fields(prior, ("versionId", "versionNumber", "accessRevision", "accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount"))
    identifier(prior["versionId"]); identifier(prior["accessRevision"]); q.integer(prior["versionNumber"], 1)
    require(prior["versionId"] != deployment["versionId"] and prior["versionNumber"] < deployment["versionNumber"])
    exact([prior[k] for k in ("accessMode", "allowedOwnerCount", "allowedGroupCount", "allowedVisitorCount")], ["custom", 1, 0, 0])
    resources = value["resources"]
    require(type(resources) is list and len(resources) == len(RESOURCE_KINDS))
    for expected, resource in zip(RESOURCE_KINDS, resources):
        fields(resource, ("kind", "name", "preflight", "createdId")); exact(resource["kind"], expected)
        exact(resource["preflight"], "absent"); identifier(resource["name"]); identifier(resource["createdId"])
    require(len({r["name"] for r in resources}) == len(resources) and len({r["createdId"] for r in resources}) == len(resources))
    validate_resource_observations(observations)
    exact(value["resourceObservationsSha256"], sha(canonical(observations)))
    for key in ("sessionNonce", "sourceHead", "sourceTree"): exact(observations[key], value[key])
    exact(observations["preflight"]["priorSite"], prior)
    require(start <= fresh(observations["preflight"]["observedAt"], now) < mutation)
    for resource, creation in zip(resources, observations["creations"]):
        exact({k: creation[k] for k in ("kind", "name", "createdId")}, {k: resource[k] for k in ("kind", "name", "createdId")})
        require(mutation <= fresh(creation["observedAt"], now) <= timestamp(deployment["deployedAt"]))
    additions = ["resource:" + str(i) for i in range(len(resources))] + ["binding:" + name for name in ADDED] + ["site:" + deployment["versionId"]]
    exact(value["additions"], additions); exact(value["rollbackOrder"], list(reversed(additions)))
    return value


def validate_source_manifest(source):
    fields(source, ("schema", "official_base", "source", "archive_policy", "packages", "verification_receipt", "preserved", "changes", "files"))
    exact(source["schema"], release.SOURCE_SCHEMA)
    for key in ("official_base", "source"):
        fields(source[key], ("commit", "tree"))
        for value in source[key].values(): require(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None)
    exact(source["archive_policy"], {"tar_umask": "0022", "regular_mode": "0644", "executable_mode": "0755", "directory_mode": "0755"})
    entries, _ = release._validated_manifest_inventory(source)
    fields(source["packages"], ("package_json", "package_lock_json"))
    for key, path in (("package_json", "package.json"), ("package_lock_json", "package-lock.json")):
        exact(source["packages"][key], entries[path])
    verification = source["verification_receipt"]
    require(type(verification) is dict and verification.get("path") in entries)
    exact(verification, entries[verification["path"]])
    require(type(source["preserved"]) is list and 1 <= len(source["preserved"]) <= len(entries))
    for item in source["preserved"]:
        require(type(item) is dict and item.get("path") in entries); exact(item, entries[item["path"]])
    require(type(source["changes"]) is list and len(source["changes"]) <= release.MAX_SOURCE_FILES)
    for change in source["changes"]:
        fields(change, ("status", "path", "before", "after"))
        require(change["status"] in {"add", "delete", "modify"})
        release._safe_source_path(change["path"])
        for side in ("before", "after"):
            if change[side] is not None:
                fields(change[side], ("path", "git_mode", "archive_mode", "extracted_mode", "git_blob", "size", "sha256"))
                exact(change[side]["path"], change["path"])
        exact(change["after"], entries.get(change["path"]))
    return source


def validate_verification(verification, head, tree, manifest_digest, archive_digest, now=None):
    fields(verification, ("schema", "verifiedAt", "sourceHead", "sourceTree", "sourceManifestSha256", "sourceArchiveSha256", "tools", "policy", "checks"))
    exact(verification["schema"], "tueiq-release-verification-v1"); fresh(verification["verifiedAt"], now)
    exact(verification["sourceHead"], head); exact(verification["sourceTree"], tree)
    exact(verification["sourceManifestSha256"], manifest_digest); exact(verification["sourceArchiveSha256"], archive_digest)
    fields(verification["tools"], ("syft", "grype"))
    for version in verification["tools"].values(): require(type(version) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None)
    exact(verification["policy"], {"name": "no-high-or-critical", "decision": "PASS"})
    exact(verification["checks"], dict.fromkeys(("source", "npmVerify", "deployTests", "installerCheck", "deploymentCheck"), True))


def validate_release(root, runtime, head, tree, now):
    digests = inventory(root, RELEASE_FILES)
    source = read_json(root / "source-manifest.json", legacy=True)
    validate_source_manifest(source)
    exact(source["source"], {"commit": head, "tree": tree}); exact(source["official_base"]["commit"], BASE)
    require(source["preserved"])
    archive_hash, archive_size, _ = release._archive_inventory(root / "source.tar.gz", source)
    exact(runtime["source"], {"commit": head, "tree": tree, "manifest_sha256": digests["source-manifest.json"], "manifest_size": len(read_bytes(root / "source-manifest.json", mode=0o444)), "archive_sha256": archive_hash, "archive_size": archive_size})
    verification = read_json(root / "verification-receipt.json")
    validate_verification(verification, head, tree, digests["source-manifest.json"], archive_hash, now)
    # Retain exact bounded non-secret tool projections, and inspect semantics.
    for role in ("core", "runner"):
        for suffix, tool, collection in (("sbom", "syft", "artifacts"), ("grype", "grype", "matches")):
            scan = read_json(root / (role + "." + suffix + ".json"))
            fields(scan, ("descriptor", "source", collection))
            exact(scan["descriptor"], {"name": tool, "version": verification["tools"][tool]})
            exact(scan["source"], {"image": runtime["images"][role]["reference"]})
            require(type(scan[collection]) is list and len(scan[collection]) <= 65536)
            if tool == "syft": require(bool(scan[collection]))
            for entry in scan[collection]:
                if tool == "grype":
                    fields(entry, ("id", "severity")); identifier(entry["id"])
                    require(entry["severity"] in {"Negligible", "Low", "Medium"})
                else:
                    fields(entry, ("id", "name", "version")); identifier(entry["id"])
                    require(type(entry["name"]) is str and re.fullmatch(r"(?:@[a-z0-9._-]+/)?[A-Za-z0-9][A-Za-z0-9+._-]{0,127}", entry["name"]) is not None)
                    require(type(entry["version"]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}", entry["version"]) is not None)
    images = runtime["images"]
    exact(runtime["receipts"]["base_images"], release._base_image_receipt(root / "base-images.txt", [images[k]["reference"] for k in ("python_base", "runner_base", "postgres")]))
    exact(runtime["receipts"]["image_scans"], release._scan_receipt(root / "scan-hashes.txt"))
    expected = [("schema", "lil-tweak-host-go-receipt-v3"), ("decision", "GO"), ("source_commit", head), ("source_tree", tree), ("source_manifest_sha256", digests["source-manifest.json"]), ("source_archive_sha256", archive_hash)]
    expected += [(k + "_image", images[k]["reference"]) for k in ("core", "runner", "postgres", "python_base", "runner_base")]
    expected += [("base_image_receipt_sha256", digests["base-images.txt"]), ("image_scan_receipt_sha256", digests["scan-hashes.txt"])]
    expected += [("activation_verification_sha256", digests["verification-receipt.json"])]
    exact(runtime["receipts"]["host_go"], release._decision_receipt(root / "host-go.txt", expected, "activation_release_rejected"))
    host_times = dict(line.split("=", 1) for line in read_bytes(root / "host-go.txt").decode("ascii").splitlines())
    require(timestamp(verification["verifiedAt"]) <= timestamp(host_times["issued_at"]))
    return digests, verification


def validate_production(value, runtime, deployment, job, owner_receipt, digests):
    fields(value, ("schema", "runtime", "cloudflare", "sites", "owner_flow_receipt", "owner_flow_job_sha256", "resource_observations"))
    exact(value["schema"], release.PRODUCTION_SCHEMA)
    exact(value["runtime"], {"manifest_sha256": digests["runtime-manifest"], "source_commit": runtime["source"]["commit"], "source_tree": runtime["source"]["tree"]})
    fields(value["cloudflare"], ("d1", "r2", "ingress"))
    cf = value["cloudflare"]
    fields(cf["d1"], ("database_id", "schema_revision", "binding_revision")); fields(cf["r2"], ("account_id", "bucket_name", "binding_revision"))
    fields(cf["ingress"], ("core_origin", "tunnel_id", "access_application_id", "access_policy_id", "access_policy_revision", "managed_rule_id", "managed_rule_revision"))
    for group in cf.values():
        for key, ident in group.items():
            if key == "core_origin": release._https_origin(ident)
            else: identifier(ident)
    sites = value["sites"]
    fields(sites, ("source_commit", "version_id", "version_number", "deployment_id", "archive_sha256", "environment_revision", "access_revision", "access_mode", "allowed_owner_count", "allowed_group_count", "allowed_visitor_count", "production_url", "prior_version_number"))
    mapping = {"source_commit": "sourceHead", "version_id": "versionId", "version_number": "versionNumber", "deployment_id": "deploymentId", "archive_sha256": "archiveSha256", "environment_revision": "environmentRevision", "access_revision": "accessRevision", "access_mode": "accessMode", "allowed_owner_count": "allowedOwnerCount", "allowed_group_count": "allowedGroupCount", "allowed_visitor_count": "allowedVisitorCount"}
    for key, name in mapping.items(): exact(sites[key], deployment[name])
    release._https_origin(sites["production_url"]); q.integer(sites["prior_version_number"], 1)
    exact(value["owner_flow_job_sha256"], digests["owner-flow-job"])
    expected = release.owner_flow_expected(runtime, digests["runtime-manifest"], sites, digests["owner-flow-job"], deployment["deployedAt"])
    exact(value["owner_flow_receipt"], release._decision_receipt(owner_receipt, expected, "activation_owner_flow_rejected"))
    times = dict(line.split("=", 1) for line in read_bytes(owner_receipt).decode("ascii").splitlines())
    require(timestamp(deployment["deployedAt"]) <= timestamp(job["checkedAt"]) <= timestamp(times["issued_at"]))
    validate_resource_observations(value["resource_observations"])
    return {"runtimeSha256": digests["runtime-manifest"], "ownerFlowSha256": digests["owner-flow-receipt"], "ownerFlowJobSha256": digests["owner-flow-job"], "resourceObservationsSha256": sha(canonical(value["resource_observations"])),
            "d1": cf["d1"], "r2": cf["r2"], "ingress": {k: v for k, v in cf["ingress"].items() if k != "core_origin"}}


def replay(args, *, completed_at=None, now=None):
    """Reopen the originals. Never use candidate data as provenance input."""
    now = time.time() if now is None else now
    require(os.geteuid() == 0 and os.getegid() == 0)
    root = Path(args.source_root).absolute()
    with release._open_bound_parent(root / "sentinel", "activation_source_unsafe"):
        require(release._git(root, "status", "--porcelain=v1", "-z", binary=True) == b"")
        head, tree = release._git(root, "rev-parse", "HEAD"), release._git(root, "rev-parse", "HEAD^{tree}")
        require(re.fullmatch(r"[0-9a-f]{40}", head) is not None and re.fullmatch(r"[0-9a-f]{40}", tree) is not None)
        release._git(root, "merge-base", "--is-ancestor", BASE, head)
    digests = {key: sha(read_bytes(getattr(args, key.replace("-", "_")), mode=0o444 if key in {"runtime-manifest", "production-manifest"} else 0o600)) for key in ORIGINALS if key not in {"source-root", "release-evidence-root", "rollback-receipt", "site-primary-evidence"}}
    preflight, provider = (q.validate_provider(read_json(path), now=now) for path in (args.preflight_provider_evidence, args.provider_evidence))
    local = q.validate_receipt(read_json(args.local_qualification), now=now)
    exact(local["providerEvidence"], {"document": provider, "sha256": digests["provider-evidence"]}); exact(local["sourceHead"], head)
    exact(preflight["droplet"], provider["droplet"]); exact(local["topology"], TOPOLOGY)
    runtime = release._validated_runtime_manifest(read_json(args.runtime_manifest, legacy=True))
    exact(runtime["source"]["commit"], head); exact(runtime["source"]["tree"], tree)
    exact(local["images"], {k: runtime["images"][k]["digest"] for k in ("core", "postgres", "runner")})
    release_digests, verification = validate_release(Path(args.release_evidence_root), runtime, head, tree, now)
    source = read_json(Path(args.release_evidence_root) / "source-manifest.json", legacy=True)
    release._git_inventory(root, head, verify_checkout=True)
    exact(source["files"], [v for _, v in sorted(release._git_inventory(root, head, verify_checkout=True).items())])
    rb = rollback_helper()
    rollback_inventory = inventory(args.rollback_receipt, recursive=True)
    rollback_digest = rb.verify_receipt(Path(args.rollback_receipt))
    manifest, _ = rb._load_manifest(Path(args.rollback_receipt), rollback_digest)
    forward = rb._load_forward(Path(args.rollback_receipt), rollback_digest)
    exact(manifest["source_commit"], head); exact(manifest["hostname"], local["identity"]["host"])
    exact([forward["transaction_state"], forward["rollback_outcome"]], ["completed", "clean"])
    require(set(forward["files"]) == {p for p, kind, _ in rb.MANAGED_PATHS if kind == "regular"})
    require(set(forward["objects"]) == {kind + ":" + name for kind, name in rb.PODMAN_NAMES if kind != "volume"})
    require(all(v["state"] == "finalized" for v in forward["objects"].values()))
    fields(forward["images"], ("core", "postgres", "runner"))
    for role, image in forward["images"].items(): exact(image["reference"], runtime["images"][role]["reference"])
    require("quarantine" not in os.listdir(args.rollback_receipt))
    live = helper("lil-tweak-live-evidence")
    site_inventory, status, owner_job, primary = live.reopen_site(args.site_primary_evidence)
    exact(read_json(args.site_status_evidence), status); exact(read_json(args.owner_flow_job), owner_job)
    validate_owner_job(owner_job); deployment = validate_deployment(status["deployment"])
    exact([deployment["sourceHead"], deployment["sourceTree"]], [head, tree])
    d1 = validate_d1(read_json(args.d1_cross_check))
    for key in ("jobId", "ownerScope", "jobRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "evidence"):
        exact(d1[key], owner_job[key])
    exact(d1["events"], primary["events"])
    core = live.validate_core(read_json(args.core_cross_check))
    exact(core["d1Sha256"], digests["d1-cross-check"])
    for key in ("jobId", "remoteJobId", "ownerScope", "jobRevision", "coreRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "decisionCount", "exportCount", "evidence"):
        exact(core[key], d1[key])
    for key in ("baselineTreeSha256", "finalTreeSha256", "fileSha256", "commandDigest", "editJournalDigest"): exact(core[key], owner_job[key])
    guest, guest_cross = validate_guest(read_json(args.guest_evidence)), validate_guest(read_json(args.guest_cross_check), cross=True)
    for value in (guest, guest_cross):
        exact(value["providerSha256"], digests["provider-evidence"]); exact(value["runtimeSha256"], digests["runtime-manifest"])
        exact(value["identity"], local["identity"]); exact(value["sourceHead"], head); exact(value["images"], local["images"])
    exact(guest["verificationSha256"], release_digests["verification-receipt.json"]); exact(guest_cross["jobId"], owner_job["jobId"])
    production_original = read_json(args.production_manifest, legacy=True)
    production = validate_production(production_original, runtime, deployment, owner_job, args.owner_flow_receipt, digests)
    observations = production_original["resource_observations"]
    change = validate_change(read_json(args.change_record), head=head, tree=tree, preflight=digests["preflight-provider-evidence"], deployment=deployment, rollback_time=timestamp(manifest["captured_at_iso"]), now=now, observations=observations)
    exact(production_original["sites"]["prior_version_number"], change["priorSite"]["versionNumber"])
    exact(guest_cross["secretDirectory"], observations["creations"][RESOURCE_KINDS.index("secret_directory")]["filesystem"])
    resource_ids = {r["kind"]: r["createdId"] for r in change["resources"]}
    for kind, key in (("tunnel", "tunnel_id"), ("access_application", "access_application_id"), ("access_policy", "access_policy_id"), ("managed_rule", "managed_rule_id")):
        exact(resource_ids[kind], production["ingress"][key])
    finish = q.iso(now) if completed_at is None else completed_at
    host_issued = dict(line.split("=", 1) for line in read_bytes(Path(args.release_evidence_root) / "host-go.txt").decode("ascii").splitlines())["issued_at"]
    order = [change["startedAt"], preflight["observedAt"], verification["verifiedAt"], host_issued, manifest["captured_at_iso"], change["mutationStartedAt"], deployment["deployedAt"], provider["observedAt"], primary["startedAt"], status["checkedAt"], owner_job["checkedAt"], d1["observedAt"], core["observedAt"], guest["checkedAt"], guest_cross["observedAt"], local["startedAt"], local["completedAt"], change["completedAt"], finish]
    epochs = [fresh(value, now) for value in order]
    require(epochs == sorted(epochs) and now - timestamp(finish) <= 900)
    for e in d1["events"]: require(timestamp(primary["startedAt"]) <= timestamp(e["createdAt"]) <= timestamp(owner_job["checkedAt"]))
    for descriptor in d1["evidence"]: require(timestamp(primary["startedAt"]) <= timestamp(descriptor["createdAt"]) <= timestamp(owner_job["checkedAt"]))
    require(owner_job["requestId"] not in {local["jobA"]["submission"]["requestId"], local["jobB"]["submission"]["requestId"]})
    require(d1["remoteJobId"] not in {local["jobA"]["id"], local["jobB"]["id"]})
    digests.update({"release-evidence-root": sha(canonical(release_digests)), "rollback-receipt": sha(canonical(rollback_inventory)), "site-primary-evidence": sha(canonical(site_inventory))})
    candidate = {"schema": "tueiq-direct-runner-activation-candidate-v1", "startedAt": change["startedAt"], "completedAt": finish, "sourceHead": head,
        "artifactDigests": digests, "identity": local["identity"], "topology": TOPOLOGY, "images": runtime["images"],
        "provider": {"preflightSha256": digests["preflight-provider-evidence"], "liveSha256": digests["provider-evidence"]}, "guest": guest,
        "runtime": {"manifestSha256": digests["runtime-manifest"], "sourceTree": tree, "archiveSha256": runtime["source"]["archive_sha256"]},
        "rollback": {"manifestSha256": rollback_digest, "forwardSha256": rollback_inventory["forward-state.json"], "inventorySha256": digests["rollback-receipt"], "capturedAt": manifest["captured_at_iso"], "transactionState": "completed", "rollbackOutcome": "clean"},
        "production": production, "site": status, "ownerFlow": owner_job,
        "localQualification": {"sha256": digests["local-qualification"], "startedAt": local["startedAt"], "completedAt": local["completedAt"], "negativeChecks": local["negativeChecks"], "cleanup": local["cleanup"]}, "changeRecord": change}
    recheck_originals(args, candidate)
    return candidate, {"release": release_digests, "site": site_inventory, "rollback": rollback_inventory}


def recheck_originals(args, candidate):
    """Compare all reopened inputs to the retained, semantically validated snapshot."""
    for key, digest in candidate["artifactDigests"].items():
        path = getattr(args, key.replace("-", "_"))
        if key == "release-evidence-root": observed = sha(canonical(inventory(path, RELEASE_FILES)))
        elif key == "rollback-receipt": observed = sha(canonical(inventory(path, recursive=True)))
        elif key == "site-primary-evidence": observed = sha(canonical(inventory(path)))
        else: observed = sha(read_bytes(path, mode=0o444 if key in {"runtime-manifest", "production-manifest"} else 0o600))
        exact(observed, digest)
    root = Path(args.source_root).absolute()
    exact(release._git(root, "rev-parse", "HEAD"), candidate["sourceHead"])
    exact(release._git(root, "rev-parse", "HEAD^{tree}"), candidate["runtime"]["sourceTree"])
    require(release._git(root, "status", "--porcelain=v1", "-z", binary=True) == b"")


def verify_candidate(args):
    value = read_json(args.candidate)
    expected, primary = replay(args, completed_at=value.get("completedAt"))
    exact(value, expected)
    raw = read_bytes(args.candidate)
    require(raw == canonical(value))
    return sha(raw), value, primary


def add_originals(parser):
    for name in ORIGINALS: parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)


def add_witnesses(parser):
    parser.add_argument("--preflight-provider-witness", required=True, type=Path)
    parser.add_argument("--provider-witness", required=True, type=Path)


def offline_check():
    require(BASE == "e76996970e816c4cce7b8334e0495e1e0de48e7d" and len(ORIGINALS) == 17 and len(MANAGED) == 7 and len(ADDED) == 6)
    exact(TOPOLOGY, {"route": "direct_core_to_local_podman", "intermediary": "none", "policy": "ENGINEERING_EXECUTION_ONLY"})
    for name in ("lil-tweak-activation-finalizer", "lil-tweak-independent-review", "lil-tweak-live-evidence", "lil-tweak-qualification", "lil-tweak-release", "lil-tweak-rollback"):
        path = ROOT / "scripts" / (name + ".py")
        require(path.is_file() and not path.is_symlink())
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
        try: q.parse_json(raw)
        except Exception: continue
        require(False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    subs = parser.add_subparsers(dest="command")
    for name in ("build-candidate", "verify-candidate", "finalize-reviewed", "verify-final"):
        sub = subs.add_parser(name); add_originals(sub)
        if name in {"finalize-reviewed", "verify-final"}:
            add_witnesses(sub)
            sub.add_argument("--independent-review", required=True, type=Path)
            sub.add_argument("--activation", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.check:
            require(args.command is None); offline_check(); print("activation check: ok"); return 0
        if args.command == "build-candidate":
            candidate, _ = replay(args)
            print(publish(args.candidate, candidate))
        elif args.command == "verify-candidate":
            print(verify_candidate(args)[0])
        elif args.command in {"finalize-reviewed", "verify-final"}:
            reviewer = helper("lil-tweak-independent-review")
            review_digest, candidate_digest = reviewer.verify_review(args)
            if args.command == "finalize-reviewed":
                final = {"schema": "tueiq-direct-runner-activation-v1", "completedAt": q.iso(time.time()), "candidateSha256": candidate_digest, "independentReviewSha256": review_digest,
                         "CONNECTED": True, "QUALIFIED": True, "READY_TO_WORK": True}
                reviewer.recheck_review(args, review_digest, candidate_digest)
                print(publish(args.activation, final))
            else:
                final = read_json(args.activation)
                fields(final, ("schema", "completedAt", "candidateSha256", "independentReviewSha256", "CONNECTED", "QUALIFIED", "READY_TO_WORK"))
                exact(final["schema"], "tueiq-direct-runner-activation-v1")
                exact(final["candidateSha256"], candidate_digest); exact(final["independentReviewSha256"], review_digest)
                for key in ("CONNECTED", "QUALIFIED", "READY_TO_WORK"): exact(final[key], True)
                require(timestamp(read_json(args.independent_review)["reviewedAt"]) <= fresh(final["completedAt"]))
                raw = read_bytes(args.activation)
                require(raw == canonical(final))
                digest = sha(raw)
                reviewer.recheck_review(args, review_digest, candidate_digest)
                require(read_bytes(args.activation) == raw)
                print("CONNECTED = YES\nQUALIFIED = YES\nREADY_TO_WORK = YES\n" + digest)
        else: parser.error("choose --check or an explicit phase")
        return 0
    except (Exception, KeyboardInterrupt):
        print("activation evidence rejected", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

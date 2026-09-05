#!/usr/bin/env python3
"""Primary byte sealing and independent bounded observations; --check is offline."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import os
from pathlib import Path
import platform
import pwd
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("activation_finalizer_shared", ROOT / "scripts/lil-tweak-activation-finalizer.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
q, require, exact, fields = a.q, a.require, a.exact, a.fields
MAX_CAPTURE = 15 * 1024 * 1024
RESPONSE_NAMES = ("status", "create", "dispatch", "poll-final")
PUBLIC_JOB_KEYS = ("id", "projectId", "mode", "promptPreview", "state", "revision", "summary", "proposalDigest", "sourceDigest", "approvalProposal", "approvalConsumed", "gitSource", "createdAt", "updatedAt", "sources", "evidence", "events")
RUN_KEYS = ("commands", "command_hashes", "commands_digest", "argv_truncated", "operations", "exit_statuses", "timeouts", "truncation", "edit_journal", "edit_journal_count", "edit_journal_digest", "source_digest", "proposal_source_digest", "approval", "limits", "started_at_epoch", "finished_at_epoch", "model_usage")


def nonsecret_text(raw):
    text = raw.decode("utf-8", "strict")
    require(not re.search(r"(?i)(?:authorization|set-cookie|bearer\s|-----BEGIN|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:secret|token|password|api_key)\s*[:=])", text))
    return text


def public_job(value, *, completed):
    fields(value, PUBLIC_JOB_KEYS)
    require(type(value["id"]) is str and re.fullmatch(r"job:[0-9a-f]{32}", value["id"]) is not None)
    exact(value["projectId"], None); exact(value["mode"], "architect"); exact(value["promptPreview"], q.PROMPT_A)
    exact(value["gitSource"], q.submission("architect")["gitSource"]); exact(value["sources"], [])
    exact(value["approvalProposal"], None); exact(value["approvalConsumed"], False)
    q.integer(value["revision"]); a.timestamp(value["createdAt"]); a.timestamp(value["updatedAt"])
    require(type(value["summary"]) is str and len(value["summary"]) <= 2000)
    descriptors = []
    require(type(value["evidence"]) is list and len(value["evidence"]) <= 5)
    for descriptor in value["evidence"]:
        fields(descriptor, ("id", "jobId", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt"))
        exact(descriptor["jobId"], value["id"])
        normalized = {k: v for k, v in descriptor.items() if k != "jobId"}
        a.validate_descriptor(normalized); descriptors.append(normalized)
    require(type(value["events"]) is list and len(value["events"]) <= 250)
    events = []
    for event in value["events"]:
        fields(event, ("id", "type", "summary", "createdAt")); require(type(event["summary"]) is str and len(event["summary"]) <= 2000)
        events.append({k: event[k] for k in ("id", "type", "createdAt")})
    if completed:
        exact(value["state"], "completed"); q.integer(value["revision"], 3); a.validate_descriptors(descriptors); a.validate_events(events)
        exact(value["sourceDigest"], q.BASELINE_TREE_SHA256); q.digest(value["proposalDigest"])
    else:
        require(value["state"] in {"queued", "completed"})
        if value["state"] == "queued":
            exact(value["sourceDigest"], None); exact(value["proposalDigest"], None); exact(descriptors, [])
    return sorted(descriptors, key=lambda descriptor: descriptor["filename"]), events


def validate_status(value):
    fields(value, ("status",)); status = value["status"]
    fields(status, ("generatedAt", "controlPlane", "bridge", "runner")); a.timestamp(status["generatedAt"])
    exact(status["controlPlane"], dict.fromkeys(("storage", "d1", "r2"), "configured"))
    exact(status["bridge"], {"origin": "core_origin", "transport": "configured", "signing": "configured", "access": "configured", "missing": []})
    exact(status["runner"], {"owner": "tueiq", "provider": "digitalocean", "dropletId": "597343619", "host": "galor-tweak-runner-01", "role": "role-tweak-runner", "route": "direct_core_to_local_podman", "intermediary": "none", "imagePolicy": "digest_pinned", "connection": "ready", "qualification": "not_reported"})
    return status


def validate_bodies(bodies, descriptors, proposal_digest, start, finish):
    exact(sorted(bodies), sorted(q.ARTIFACTS))
    for d in descriptors:
        raw = bodies[d["filename"]]
        require(len(raw) == d["sizeBytes"]); exact(a.sha(raw), d["sha256"]); nonsecret_text(raw)
    manifest = q.parse_json(bodies["manifest.json"])
    require(q.canonical(manifest) + b"\n" == bodies["manifest.json"])
    fields(manifest, ("version", "artifacts", "run", "proposal_digest")); exact(manifest["version"], 1)
    exact(manifest["artifacts"], {name: {"sha256": a.sha(raw), "bytes": len(raw)} for name, raw in bodies.items() if name != "manifest.json"})
    recomputed = a.sha(a.canonical({k: manifest[k] for k in ("version", "artifacts", "run")}))
    exact(manifest["proposal_digest"], recomputed); exact(proposal_digest, recomputed)
    run = manifest["run"]; fields(run, RUN_KEYS)
    exact(run["source_digest"], q.BASELINE_TREE_SHA256); exact(run["proposal_source_digest"], q.BASELINE_TREE_SHA256)
    exact(run["limits"], {"network": "none", "max_tool_rounds": 40}); exact(run["approval"], None)
    require(type(run["started_at_epoch"]) in (int, float) and type(run["finished_at_epoch"]) in (int, float))
    require(start <= run["started_at_epoch"] <= run["finished_at_epoch"] <= finish)
    commands = run["commands"]
    require(type(commands) is list and 1 <= len(commands) <= 128)
    for command in commands: exact(command, ["sha256sum", "README"])
    hashes = [a.sha(a.canonical(command)) for command in commands]
    exact(run["command_hashes"], hashes); exact(run["commands_digest"], a.sha(a.canonical(hashes)))
    exact(run["operations"], ["run_command"] * len(commands)); exact(run["exit_statuses"], [0] * len(commands))
    for key in ("argv_truncated", "timeouts", "truncation"): exact(run[key], [False] * len(commands))
    exact(run["edit_journal"], [])
    for key, value in q.build_edit_journal_evidence([]).items(): exact(run[key], value)
    fields(run["model_usage"], ("calls", "input_tokens", "output_tokens", "total_tokens"))
    for count in run["model_usage"].values(): q.integer(count)
    require(run["model_usage"]["total_tokens"] == run["model_usage"]["input_tokens"] + run["model_usage"]["output_tokens"])
    require(bodies["changes.patch"] == b"")
    q.verify_test_log(bodies["tests.log"], commands, run["operations"], ["sha256sum", "README"])
    return {"baselineTreeSha256": q.BASELINE_TREE_SHA256, "finalTreeSha256": q.BASELINE_TREE_SHA256, "fileSha256": q.SOURCE_SHA256, "commandDigest": run["commands_digest"], "editJournalDigest": run["edit_journal_digest"]}


def derive_site(capture, deployment):
    fields(capture, ("schema", "requestId", "startedAt", "completedAt", "responses"))
    exact(capture["schema"], "tueiq-site-primary-capture-v1"); a.uuid4(capture["requestId"]); a.validate_deployment(deployment)
    start, finish = a.timestamp(capture["startedAt"]), a.timestamp(capture["completedAt"])
    require(a.timestamp(deployment["deployedAt"]) <= start <= finish and finish - start <= 1200)
    responses = capture["responses"]
    require(type(responses) is list and len(responses) == 9)
    raw_bodies, metadata = {}, []
    for index, response in enumerate(responses):
        fields(response, ("id", "status", "mediaType", "declaredLength", "contentSha256", "bodyBase64"))
        ident = response["id"]
        if index < 4: exact(ident, RESPONSE_NAMES[index])
        else: require(type(ident) is str and re.fullmatch(r"evidence:[0-9a-f]{32}", ident) is not None)
        require(ident not in raw_bodies and type(response["bodyBase64"]) is str and len(response["bodyBase64"]) <= 3 * 1024 * 1024)
        raw = base64.b64decode(response["bodyBase64"], validate=True)
        exact(base64.b64encode(raw).decode(), response["bodyBase64"])
        require(len(raw) <= (256 * 1024 if index < 4 else q.MAX_EVIDENCE_BYTES))
        exact(response["status"], 201 if ident == "create" else 200)
        exact(response["mediaType"], "application/json" if index < 4 else "text/plain")
        declared = response["declaredLength"]
        if declared is not None: q.integer(declared, 0, q.MAX_EVIDENCE_BYTES); exact(declared, len(raw))
        if index >= 4: exact(response["contentSha256"], a.sha(raw)); exact(declared, len(raw))
        else: exact(response["contentSha256"], None)
        nonsecret_text(raw)
        raw_bodies[ident] = raw
        metadata.append({k: response[k] for k in ("id", "status", "mediaType", "declaredLength", "contentSha256")} | {"sha256": a.sha(raw), "sizeBytes": len(raw)})
    status = validate_status(q.parse_json(raw_bodies["status"]))
    jobs = []
    for name in RESPONSE_NAMES[1:]:
        value = q.parse_json(raw_bodies[name]); fields(value, ("job",)); public_job(value["job"], completed=name == "poll-final")
        jobs.append(value["job"])
    created, dispatched, final = jobs
    require(created["revision"] == 0 and created["state"] == "queued" and dispatched["revision"] >= 2 and final["revision"] >= dispatched["revision"])
    require(len({job["id"] for job in jobs}) == 1)
    # Public job IDs are derived from the exact authenticated create identity.
    expected_id = "job:" + a.sha(("engineering-job-v1\0" + q.OWNER_SCOPE + "\0" + capture["requestId"]).encode())[:32]
    exact(final["id"], expected_id)
    descriptors, events = public_job(final, completed=True)
    require({r["id"] for r in metadata[4:]} == {d["id"] for d in descriptors})
    bodies = {d["filename"]: raw_bodies[d["id"]] for d in descriptors}
    proof = validate_bodies(bodies, descriptors, final["proposalDigest"], start, finish)
    status_record = {"schema": "tueiq-site-status-evidence-v1", "checkedAt": status["generatedAt"], "deployment": deployment, "statusSha256": a.sha(raw_bodies["status"]),
                     "runner": status["runner"], "controlPlane": status["controlPlane"], "bridge": status["bridge"]}
    job = {"schema": "tueiq-owner-flow-job-v1", "checkedAt": capture["completedAt"], "requestId": capture["requestId"], "jobId": final["id"], "ownerScope": q.OWNER_SCOPE, "jobRevision": final["revision"],
           **{k: final[k] for k in ("mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed")}, "evidence": descriptors, **proof}
    a.validate_owner_job(job)
    manifest = {"schema": "tueiq-site-primary-evidence-v1", "requestId": capture["requestId"], "startedAt": capture["startedAt"], "completedAt": capture["completedAt"], "deployment": deployment, "responses": metadata}
    return manifest, raw_bodies, status_record, job, events


def seal_site(capture, deployment_path, output):
    a.require_new_output(output)
    deployment = a.read_json(deployment_path)
    manifest, bodies, status, job, _ = derive_site(capture, deployment)
    a.fresh(capture["completedAt"])
    output = Path(output).absolute()
    with a.secure_directory(output.parent) as parent:
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        for ident, raw in bodies.items(): a.publish(output / (ident + ".body"), raw=raw)
        a.publish(output / "site-status-evidence.json", status); a.publish(output / "owner-flow-job.json", job)
        a.publish(output / "manifest.json", manifest)
        os.fsync(parent)
    reopen_site(output)
    return a.sha(a.read_bytes(output / "manifest.json"))


def reopen_site(path):
    path = Path(path)
    manifest = a.read_json(path / "manifest.json")
    fields(manifest, ("schema", "requestId", "startedAt", "completedAt", "deployment", "responses"))
    exact(manifest["schema"], "tueiq-site-primary-evidence-v1")
    responses = []
    require(type(manifest["responses"]) is list and len(manifest["responses"]) == 9)
    for m in manifest["responses"]:
        fields(m, ("id", "status", "mediaType", "declaredLength", "contentSha256", "sha256", "sizeBytes"))
        require(m["id"] in RESPONSE_NAMES or re.fullmatch(r"evidence:[0-9a-f]{32}", m["id"]) is not None)
        raw = a.read_bytes(path / (m["id"] + ".body"))
        exact(a.sha(raw), m["sha256"]); exact(len(raw), m["sizeBytes"])
        responses.append({k: m[k] for k in ("id", "status", "mediaType", "declaredLength", "contentSha256")} | {"bodyBase64": base64.b64encode(raw).decode()})
    capture = {"schema": "tueiq-site-primary-capture-v1", **{k: manifest[k] for k in ("requestId", "startedAt", "completedAt")}, "responses": responses}
    expected, _, status, job, events = derive_site(capture, manifest["deployment"])
    exact(manifest, expected); exact(a.read_json(path / "site-status-evidence.json"), status); exact(a.read_json(path / "owner-flow-job.json"), job)
    files = [r["id"] + ".body" for r in responses] + ["manifest.json", "site-status-evidence.json", "owner-flow-job.json"]
    return a.inventory(path, files), status, job, {"events": events, "startedAt": manifest["startedAt"]}


def seal_d1(raw, job_id, output):
    a.require_new_output(output)
    value = a.validate_d1(q.parse_json(raw)); exact(value["jobId"], job_id); a.fresh(value["observedAt"])
    nonsecret_text(raw)
    return a.publish(output, value)


def validate_core(value):
    fields(value, ("schema", "observedAt", "d1Sha256", "jobId", "remoteJobId", "ownerScope", "jobRevision", "coreRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "decisionCount", "exportCount", "evidence", "baselineTreeSha256", "finalTreeSha256", "fileSha256", "commandDigest", "editJournalDigest", "signedRead"))
    exact(value["schema"], "tueiq-core-activation-cross-check-v1"); a.timestamp(value["observedAt"]); q.digest(value["d1Sha256"])
    exact(value["signedRead"], True); q.job_id(value["remoteJobId"])
    a.validate_owner_job({"schema": "tueiq-owner-flow-job-v1", "checkedAt": value["observedAt"], "requestId": "00000000-0000-4000-8000-000000000000", **{k: value[k] for k in ("jobId", "ownerScope", "jobRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "evidence", "baselineTreeSha256", "finalTreeSha256", "fileSha256", "commandDigest", "editJournalDigest")}})
    exact(value["decisionCount"], 0); exact(value["exportCount"], 0); q.integer(value["coreRevision"], 1)
    return value


def collect_core(core_env, d1_path, output, *, client=None, now=None):
    a.require_new_output(output)
    now = time.time() if now is None else now
    d1 = a.validate_d1(a.read_json(d1_path)); a.fresh(d1["observedAt"], now)
    if client is None:
        exact(Path(core_env).absolute().as_posix(), q.CORE_ENV_PATH.as_posix())
        service = pwd.getpwnam("lil-tweak")
        client = q.CoreClient(q.load_core_environment(Path(core_env), service))
    core = client.json("GET", "/v1/jobs/" + d1["remoteJobId"])
    retained, bodies, _ = q.verify_job_evidence(client, core, mode="architect", started=now - 1200, now=now)
    descriptors = [{k: d[k] for k in ("id", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt")} for d in core["evidence"]]
    proof = validate_bodies(bodies, descriptors, core["proposalDigest"], now - 1200, now)
    exact(core["id"], d1["remoteJobId"]); exact(core["coreRevision"], d1["coreRevision"])
    for key in ("mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed"): exact(core[key], d1[key])
    exact(descriptors, d1["evidence"])
    # These zeros are derived from Core state/approval plus the independent D1
    # decision/export ledger, never from collector summaries.
    value = {"schema": "tueiq-core-activation-cross-check-v1", "observedAt": q.iso(now), "d1Sha256": a.sha(a.read_bytes(d1_path)),
        **{k: d1[k] for k in ("jobId", "remoteJobId", "ownerScope", "jobRevision")}, "coreRevision": core["coreRevision"],
        **{k: core[k] for k in ("mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed")},
        "decisionCount": 0, "exportCount": 0, "evidence": descriptors, **proof, "signedRead": True}
    validate_core(value)
    return a.publish(output, value)


def guest_base(provider_path, runtime_path):
    provider = q.validate_provider(a.read_json(provider_path))
    runtime = a.release._validated_runtime_manifest(a.read_json(runtime_path, legacy=True))
    return {"providerSha256": a.sha(a.read_bytes(provider_path)), "runtimeSha256": a.sha(a.read_bytes(runtime_path, mode=0o444)), "sourceHead": runtime["source"]["commit"],
            "identity": q.identity(provider), "operatingSystem": "Ubuntu 24.04 LTS", "architecture": "x86_64", "topology": a.TOPOLOGY,
            "images": {k: runtime["images"][k]["digest"] for k in ("core", "postgres", "runner")}}


def seal_guest(provider_path, runtime_path, verification_path, output, *, now=None):
    a.require_new_output(output)
    value = {"schema": "tueiq-guest-evidence-v1", "checkedAt": q.iso(time.time() if now is None else now), **guest_base(provider_path, runtime_path), "verificationSha256": a.sha(a.read_bytes(verification_path))}
    a.validate_guest(value)
    return a.publish(output, value)


def collect_guest(source_root, provider_path, runtime_path, job_id, output):
    a.require_new_output(output)
    start = time.time()
    base = guest_base(provider_path, runtime_path)
    target = q.target_module().verify_target()
    exact(target.droplet_id, base["identity"]["dropletId"]); exact(target.hostname, base["identity"]["host"])
    exact(platform.machine(), "x86_64")
    release = platform.freedesktop_os_release()
    exact([release.get("ID"), release.get("VERSION_ID")], ["ubuntu", "24.04"])
    service = pwd.getpwnam("lil-tweak")
    environment = q.load_core_environment(q.CORE_ENV_PATH, service)
    boundaries = q.InstalledBoundaries(source_root, service, environment, start)
    exact(boundaries.source_head(), base["sourceHead"]); exact(boundaries.images(), base["images"])
    exact(boundaries.runtime_snapshot()["containers"], [])
    value = {"schema": "tueiq-guest-activation-cross-check-v1", "observedAt": q.iso(time.time()), "jobId": job_id, **base, "noContainers": True, "secretDirectory": a.observe_secret_directory()}
    a.validate_guest(value, cross=True)
    return a.publish(output, value)


def seal_resource_observations(raw, output):
    a.require_new_output(output)
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    value = a.validate_resource_observations(q.parse_json(raw))
    return a.publish(output, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--check", action="store_true")
    subs = parser.add_subparsers(dest="command")
    site = subs.add_parser("seal-site"); site.add_argument("--collector-stdin", required=True, action="store_true"); site.add_argument("--site-deployment-record", required=True, type=Path); site.add_argument("--output-dir", required=True, type=Path)
    d1 = subs.add_parser("seal-d1"); d1.add_argument("--response-stdin", required=True, action="store_true"); d1.add_argument("--job-id", required=True); d1.add_argument("--output", required=True, type=Path)
    resources = subs.add_parser("seal-resource-observations"); resources.add_argument("--observations-stdin", required=True, action="store_true"); resources.add_argument("--output", required=True, type=Path)
    guest = subs.add_parser("seal-guest")
    for name in ("provider-evidence", "runtime-manifest", "verification-receipt", "output"): guest.add_argument("--" + name, required=True, type=Path)
    core = subs.add_parser("collect-core")
    for name in ("core-env", "d1-cross-check", "output"): core.add_argument("--" + name, required=True, type=Path)
    live_guest = subs.add_parser("collect-guest")
    for name in ("source-root", "provider-evidence", "runtime-manifest", "output"): live_guest.add_argument("--" + name, required=True, type=Path)
    live_guest.add_argument("--job-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.check:
            require(args.command is None); a.offline_check(); exact(RESPONSE_NAMES, ("status", "create", "dispatch", "poll-final")); print("live evidence check: ok"); return 0
        if args.command in {"seal-site", "seal-d1"}:
            raw = sys.stdin.buffer.read(MAX_CAPTURE + 1); require(len(raw) <= MAX_CAPTURE)
            digest = seal_site(q.parse_json(raw), args.site_deployment_record, args.output_dir) if args.command == "seal-site" else seal_d1(raw, args.job_id, args.output)
        elif args.command == "seal-resource-observations": digest = seal_resource_observations(sys.stdin.buffer.read(65537), args.output)
        elif args.command == "seal-guest": digest = seal_guest(args.provider_evidence, args.runtime_manifest, args.verification_receipt, args.output)
        elif args.command == "collect-core": digest = collect_core(args.core_env, args.d1_cross_check, args.output)
        elif args.command == "collect-guest": digest = collect_guest(args.source_root, args.provider_evidence, args.runtime_manifest, args.job_id, args.output)
        else: parser.error("choose --check or an explicit observation")
        print(digest); return 0
    except (Exception, KeyboardInterrupt):
        print("live evidence rejected", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

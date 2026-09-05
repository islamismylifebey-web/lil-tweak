#!/usr/bin/env python3
"""Independent replay protocol. Raw provider bytes exist only in bounded stdin."""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_finalizer_shared", ROOT / "scripts/lil-tweak-activation-finalizer.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
q, require, exact, fields = a.q, a.require, a.exact, a.fields


def provider_projection(value):
    # Full provider responses contain addresses and credentials. Select fields
    # directly; never serialize the object or include it in an exception.
    require(type(value) is dict and type(value.get("droplet")) is dict)
    d = value["droplet"]
    require(type(d["id"]) is int and type(d["tags"]) is list and d["tags"].count("role-tweak-runner") == 1)
    projection = {"id": str(d["id"]), "name": d["name"], "status": d["status"], "region": d["region"]["slug"],
        "image": {k: d["image"][k] for k in ("distribution", "slug", "name")},
        "size": {"slug": d["size"]["slug"], "memoryMiB": d["size"]["memory"], "vcpus": d["size"]["vcpus"], "diskGiB": d["size"]["disk"]}, "roleTag": "role-tweak-runner"}
    q.validate_provider({"schema": "tueiq-digitalocean-provider-evidence-v1", "observedAt": q.iso(time.time()), "operation": "mcp__codex_apps__digitalocean_droplet_get", "rawResponseSha256": "0" * 64, "provider": "DigitalOcean", "droplet": projection})
    return projection


def witness_provider(normalized_path, raw, output):
    a.require_new_output(output)
    snapshots = a.EvidenceSnapshots()
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024)
    normalized = q.validate_provider(snapshots.read_json(normalized_path))
    projection = provider_projection(q.parse_json(raw))
    exact(normalized["rawResponseSha256"], a.sha(raw)); exact(normalized["droplet"], projection)
    require(snapshots.read_bytes(normalized_path) == a.canonical(normalized))
    value = {"schema": "tueiq-provider-response-witness-v1", "witnessedAt": q.iso(time.time()), "operation": normalized["operation"], "rawResponseSha256": a.sha(raw),
        "normalizedSha256": a.sha(a.canonical(normalized)), "projectionSha256": a.sha(a.canonical(projection)), "reviewerNonce": secrets.token_hex(24)}
    require(snapshots.read_bytes(normalized_path) == a.canonical(normalized))
    snapshots.recheck()
    return a.publish(output, value)


def validate_witness(path, normalized_path, *, candidate, preflight, snapshots=None):
    snapshots = a.EvidenceSnapshots() if snapshots is None else snapshots
    value = snapshots.read_json(path)
    fields(value, ("schema", "witnessedAt", "operation", "rawResponseSha256", "normalizedSha256", "projectionSha256", "reviewerNonce"))
    exact(value["schema"], "tueiq-provider-response-witness-v1")
    normalized = q.validate_provider(snapshots.read_json(normalized_path))
    exact(value["operation"], normalized["operation"]); exact(value["rawResponseSha256"], normalized["rawResponseSha256"])
    exact(value["normalizedSha256"], a.sha(a.canonical(normalized))); exact(value["projectionSha256"], a.sha(a.canonical(normalized["droplet"])))
    exact(value["normalizedSha256"], candidate["artifactDigests"]["preflight-provider-evidence" if preflight else "provider-evidence"])
    require(type(value["reviewerNonce"]) is str and re.fullmatch(r"[0-9a-f]{48}", value["reviewerNonce"]) is not None)
    observed, witnessed = a.timestamp(normalized["observedAt"]), a.fresh(value["witnessedAt"])
    require(observed <= witnessed <= observed + 120)
    boundary = candidate["changeRecord"]["mutationStartedAt"] if preflight else candidate["site"]["checkedAt"]
    require(witnessed <= a.timestamp(boundary))
    require(snapshots.read_bytes(normalized_path) == a.canonical(normalized))
    require(snapshots.read_bytes(path) == a.canonical(value))
    return value


def review_facts(args, reviewed_at=None, *, snapshots=None):
    snapshots = a.EvidenceSnapshots() if snapshots is None else snapshots
    digest, candidate, primary = a.verify_candidate(args, snapshots=snapshots)
    witnesses = [validate_witness(args.preflight_provider_witness, args.preflight_provider_evidence, candidate=candidate, preflight=True, snapshots=snapshots),
                 validate_witness(args.provider_witness, args.provider_evidence, candidate=candidate, preflight=False, snapshots=snapshots)]
    require(len({w["reviewerNonce"] for w in witnesses} | {candidate["changeRecord"]["sessionNonce"]}) == 3)
    reviewed_at = q.iso(time.time()) if reviewed_at is None else reviewed_at
    require(a.timestamp(candidate["completedAt"]) <= a.fresh(reviewed_at) and time.time() - a.timestamp(reviewed_at) <= 300)
    primary_digests = {kind + "/" + name: digest for kind, items in primary.items() for name, digest in items.items()}
    cross = {name: candidate["artifactDigests"][name] for name in ("d1-cross-check", "core-cross-check", "guest-cross-check")}
    return {"schema": "tueiq-direct-runner-independent-review-v1", "reviewedAt": reviewed_at, "candidateSha256": digest,
        "providerWitnessDigests": {name: a.sha(a.canonical(witness)) for name, witness in zip(("preflight", "live"), witnesses)},
        "primaryArtifactDigests": primary_digests, "crossCheckDigests": cross, "decision": "pass"}, witnesses


def review_candidate(args):
    a.require_new_output(args.review)
    snapshots = a.EvidenceSnapshots()
    value, witnesses = review_facts(args, snapshots=snapshots)
    value["reviewerNonce"] = secrets.token_hex(24)
    require(value["reviewerNonce"] not in {w["reviewerNonce"] for w in witnesses})
    recheck_review_inputs(args, value["candidateSha256"], value["providerWitnessDigests"], snapshots=snapshots)
    return a.publish(args.review, value)


def recheck_review_inputs(args, candidate_digest, witness_digests, *, snapshots=None):
    snapshots = a.EvidenceSnapshots() if snapshots is None else snapshots
    candidate = snapshots.read_json(args.candidate)
    exact(a.sha(a.canonical(candidate)), candidate_digest)
    a.recheck_originals(args, candidate, snapshots=snapshots)
    for name, path in (("preflight", args.preflight_provider_witness), ("live", args.provider_witness)):
        exact(a.sha(snapshots.read_bytes(path)), witness_digests[name])
    require(snapshots.read_bytes(args.candidate) == a.canonical(candidate))
    snapshots.recheck()


def recheck_review(args, review_digest, candidate_digest, *, snapshots=None):
    snapshots = a.EvidenceSnapshots() if snapshots is None else snapshots
    value = snapshots.read_json(args.independent_review)
    exact(a.sha(a.canonical(value)), review_digest)
    exact(value["candidateSha256"], candidate_digest)
    recheck_review_inputs(args, candidate_digest, value["providerWitnessDigests"], snapshots=snapshots)
    require(snapshots.read_bytes(args.independent_review) == a.canonical(value))


def verify_review(args, *, snapshots=None):
    snapshots = a.EvidenceSnapshots() if snapshots is None else snapshots
    value = snapshots.read_json(args.independent_review)
    fields(value, ("schema", "reviewedAt", "reviewerNonce", "candidateSha256", "providerWitnessDigests", "primaryArtifactDigests", "crossCheckDigests", "decision"))
    expected, witnesses = review_facts(args, value["reviewedAt"], snapshots=snapshots)
    require(type(value["reviewerNonce"]) is str and re.fullmatch(r"[0-9a-f]{48}", value["reviewerNonce"]) is not None)
    require(value["reviewerNonce"] not in {w["reviewerNonce"] for w in witnesses} | {snapshots.read_json(args.candidate)["changeRecord"]["sessionNonce"]})
    exact(value, {**expected, "reviewerNonce": value["reviewerNonce"]})
    raw = snapshots.read_bytes(args.independent_review)
    require(raw == a.canonical(value))
    recheck_review_inputs(args, expected["candidateSha256"], expected["providerWitnessDigests"], snapshots=snapshots)
    require(snapshots.read_bytes(args.independent_review) == raw)
    return a.sha(raw), expected["candidateSha256"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--check", action="store_true")
    subs = parser.add_subparsers(dest="command")
    witness = subs.add_parser("witness-provider")
    witness.add_argument("--normalized", required=True, type=Path); witness.add_argument("--raw-response-stdin", required=True, action="store_true"); witness.add_argument("--witness", required=True, type=Path)
    review = subs.add_parser("review-candidate"); a.add_originals(review); a.add_witnesses(review); review.add_argument("--review", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.check:
            require(args.command is None); a.offline_check(); print("independent review check: ok"); return 0
        if args.command == "witness-provider":
            raw = sys.stdin.buffer.read(1024 * 1024 + 1)
            digest = witness_provider(args.normalized, raw, args.witness)
        elif args.command == "review-candidate": digest = review_candidate(args)
        else: parser.error("choose --check or a review phase")
        print(digest); return 0
    except (Exception, KeyboardInterrupt):
        print("independent review rejected", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

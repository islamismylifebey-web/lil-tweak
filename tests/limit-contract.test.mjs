import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { parseCoreSnapshot } from "../lib/core-protocol.ts";
import {
  MAX_ENGINEERING_EVIDENCE_BYTES,
} from "../lib/engineering.ts";
import { verifyPatchBeforeConsume } from "../lib/evidence-access.ts";
import {
  immutableEvidenceMatches,
  mirrorCoreEvidence,
} from "../lib/evidence-mirror.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const EXPANDED_SOURCE_LIMIT = 128 * 1024 * 1024;
const EVIDENCE_LIMIT = 2 * 1024 * 1024;
const REMOTE_JOB_ID = "remote-job-1";
const JOB_ID = `job:${"1".repeat(32)}`;
const EVIDENCE_ID = `evidence:${"2".repeat(32)}`;
const SHA256 = "a".repeat(64);

function descriptor(sizeBytes) {
  return {
    id: EVIDENCE_ID,
    category: "summary",
    filename: "summary.md",
    mediaType: "text/markdown",
    sizeBytes,
    sha256: SHA256,
    createdAt: "2026-08-14T12:00:00.000Z",
    corePath: `/v1/jobs/${REMOTE_JOB_ID}/evidence/summary.md`,
  };
}

test("enforces one v1 byte-limit contract across core, Worker, D1, and operations", async () => {
  const python = String.raw`
import inspect
import json
import sqlite3
from pathlib import Path

from core.lil_tweak import api, evidence
from core.lil_tweak.archive import ArchiveLimits
from core.lil_tweak.git_source import ingest_git_source
from core.lil_tweak.limits import MAX_EVIDENCE_BYTES, MAX_EXPANDED_SOURCE_BYTES
from core.lil_tweak.openai_agent import WorkspaceTools

db = sqlite3.connect(":memory:")
db.executescript(Path("drizzle/0001_lil_tweak_engineering.sql").read_text())
row = (
    "evidence:at-limit", "job:limit-contract", "owner", "summary",
    "summary.md", "text/markdown", MAX_EVIDENCE_BYTES, "a" * 64,
    "engineering/limit/summary.md", "2026-08-14T12:00:00.000Z",
)
db.execute("INSERT INTO engineering_evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row)
oversize_rejected = False
try:
    db.execute(
        "INSERT INTO engineering_evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("evidence:over-limit", *row[1:6], MAX_EVIDENCE_BYTES + 1, *row[7:]),
    )
except sqlite3.IntegrityError:
    oversize_rejected = True

bundle_at_limit = evidence.build_evidence_bundle(
    plan=b"x" * MAX_EVIDENCE_BYTES,
    patch=b"",
    tests=b"",
    summary=b"",
)
bundle_oversize_error = None
try:
    evidence.build_evidence_bundle(
        plan=b"x" * (MAX_EVIDENCE_BYTES + 1),
        patch=b"",
        tests=b"",
        summary=b"",
    )
except evidence.WorkspaceEvidenceError as error:
    bundle_oversize_error = str(error)

print(json.dumps({
    "expanded": {
        "constant": MAX_EXPANDED_SOURCE_BYTES,
        "archive": ArchiveLimits().max_total_bytes,
        "git": inspect.signature(ingest_git_source).parameters["max_total_bytes"].default,
    },
    "evidence": {
        "constant": MAX_EVIDENCE_BYTES,
        "api": api.MAX_EVIDENCE_BYTES,
        "patch": inspect.signature(evidence.build_workspace_patch).parameters["max_bytes"].default,
        "commands": inspect.signature(evidence.build_command_evidence).parameters["max_bytes"].default,
        "protocol_store": inspect.signature(evidence.EvidenceStore.get).parameters["max_bytes"].default,
        "local_store": inspect.signature(evidence.LocalEvidenceStore.get).parameters["max_bytes"].default,
        "r2_store": inspect.signature(evidence.R2EvidenceStore.get).parameters["max_bytes"].default,
        "manifest": inspect.signature(evidence.build_evidence_bundle).parameters["max_manifest_bytes"].default,
        "workspace_patch": inspect.signature(WorkspaceTools).parameters["max_patch_bytes"].default,
    },
    "d1": {
        "at_limit_rows": db.execute(
            "SELECT count(*) FROM engineering_evidence WHERE size_bytes = ?",
            (MAX_EVIDENCE_BYTES,),
        ).fetchone()[0],
        "oversize_rejected": oversize_rejected,
    },
    "bundle": {
        "at_limit_bytes": len(bundle_at_limit.files["plan.md"]),
        "oversize_error": bundle_oversize_error,
    },
}))
`;
  const result = spawnSync("python3", ["-c", python], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const core = JSON.parse(result.stdout);
  assert.deepEqual(core.expanded, {
    constant: EXPANDED_SOURCE_LIMIT,
    archive: EXPANDED_SOURCE_LIMIT,
    git: EXPANDED_SOURCE_LIMIT,
  });
  assert.deepEqual(core.evidence, {
    constant: EVIDENCE_LIMIT,
    api: EVIDENCE_LIMIT,
    patch: EVIDENCE_LIMIT,
    commands: EVIDENCE_LIMIT,
    protocol_store: EVIDENCE_LIMIT,
    local_store: EVIDENCE_LIMIT,
    r2_store: EVIDENCE_LIMIT,
    manifest: EVIDENCE_LIMIT,
    workspace_patch: EVIDENCE_LIMIT,
  });
  assert.deepEqual(core.d1, { at_limit_rows: 1, oversize_rejected: true });
  assert.deepEqual(core.bundle, {
    at_limit_bytes: EVIDENCE_LIMIT,
    oversize_error: "evidence_artifact_too_large",
  });
  assert.equal(MAX_ENGINEERING_EVIDENCE_BYTES, EVIDENCE_LIMIT);

  const atLimit = descriptor(MAX_ENGINEERING_EVIDENCE_BYTES);
  const snapshotPayload = {
    id: REMOTE_JOB_ID,
    state: "completed",
    revision: 1,
    summary: "Bounded evidence",
    evidence: [atLimit],
  };
  assert.equal(
    parseCoreSnapshot(snapshotPayload).snapshot.evidence[0].sizeBytes,
    EVIDENCE_LIMIT,
  );
  assert.throws(
    () => parseCoreSnapshot({
      ...snapshotPayload,
      evidence: [descriptor(MAX_ENGINEERING_EVIDENCE_BYTES + 1)],
    }),
    /core response is invalid/i,
  );

  const matchingObject = {
    size: MAX_ENGINEERING_EVIDENCE_BYTES,
    customMetadata: { sha256: SHA256 },
  };
  assert.equal(immutableEvidenceMatches(matchingObject, atLimit), true);
  assert.equal(
    immutableEvidenceMatches(
      { ...matchingObject, size: MAX_ENGINEERING_EVIDENCE_BYTES + 1 },
      descriptor(MAX_ENGINEERING_EVIDENCE_BYTES + 1),
    ),
    false,
  );
  const mirrored = await mirrorCoreEvidence({
    ownerScope: "owner-scope",
    jobId: JOB_ID,
    remoteJobId: REMOTE_JOB_ID,
    evidence: [atLimit],
    bucket: {
      async head() { return matchingObject; },
      async put() { throw new Error("at-limit metadata must not be rewritten"); },
    },
    async fetchEvidence() { throw new Error("at-limit metadata must not be fetched"); },
  });
  assert.equal(mirrored[0].sizeBytes, EVIDENCE_LIMIT);
  await assert.rejects(
    mirrorCoreEvidence({
      ownerScope: "owner-scope",
      jobId: JOB_ID,
      remoteJobId: REMOTE_JOB_ID,
      evidence: [descriptor(MAX_ENGINEERING_EVIDENCE_BYTES + 1)],
      bucket: {
        async head() {
          return {
            ...matchingObject,
            size: MAX_ENGINEERING_EVIDENCE_BYTES + 1,
          };
        },
        async put() { throw new Error("oversized metadata must not be written"); },
      },
      async fetchEvidence() { throw new Error("oversized metadata must not be fetched"); },
    }),
    /evidence integrity/i,
  );

  let consumes = 0;
  await assert.rejects(
    verifyPatchBeforeConsume(
      {
        size: MAX_ENGINEERING_EVIDENCE_BYTES + 1,
        customMetadata: { sha256: SHA256 },
        body: new ReadableStream({ start(controller) { controller.close(); } }),
      },
      { sizeBytes: MAX_ENGINEERING_EVIDENCE_BYTES + 1, sha256: SHA256 },
      async () => { consumes += 1; },
    ),
    /evidence integrity/i,
  );
  assert.equal(consumes, 0);

  const schema = await readFile(new URL("../db/schema.ts", import.meta.url), "utf8");
  assert.match(
    schema,
    /engineering_evidence_size_check[\s\S]{0,240}sizeBytes[^\n]*>= 0[^\n]*<= 2097152/,
  );
  for (const name of ["0001_snapshot.json", "0002_snapshot.json"]) {
    const snapshot = JSON.parse(await readFile(
      new URL(`../drizzle/meta/${name}`, import.meta.url),
      "utf8",
    ));
    assert.equal(
      snapshot.tables.engineering_evidence.checkConstraints
        .engineering_evidence_size_check.value,
      '"engineering_evidence"."size_bytes" >= 0 and "engineering_evidence"."size_bytes" <= 2097152',
    );
  }

  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  assert.match(readme, /Safety amendment — 2026-08-14: v1 byte-limit profile/);
  assert.match(readme, /500 MiB expanded-source and 50 MiB evidence targets[\s\S]*superseded for v1/);
  assert.match(readme, /128 MiB \(134,217,728 bytes\) maximum expanded source/);
  assert.match(readme, /2 MiB \(2,097,152 bytes\) maximum per evidence artifact/);
  assert.match(readme, /not a one-line configuration change/);

  const offlineGuide = await readFile(
    new URL("../docs/operations/offline-dependencies.md", import.meta.url),
    "utf8",
  );
  assert.match(offlineGuide, /128 MiB validated decompressed total/);
  assert.doesNotMatch(offlineGuide, /500 MiB validated decompressed total/);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { D1EngineeringStore, EngineeringConflictError } from "../lib/engineering-d1.ts";
import { engineeringCreateRequestDigest } from "../lib/engineering-store.ts";

class D1Statement {
  constructor(database, sql) {
    this.database = database;
    this.sql = sql;
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async first() {
    return this.database.prepare(this.sql).get(...this.values) ?? null;
  }

  async all() {
    return { results: this.database.prepare(this.sql).all(...this.values) };
  }

  runSync() {
    const result = this.database.prepare(this.sql).run(...this.values);
    return { meta: { changes: Number(result.changes) } };
  }

  async run() {
    return this.runSync();
  }
}

class LocalD1 {
  constructor(database) {
    this.database = database;
  }

  prepare(sql) {
    return new D1Statement(this.database, sql);
  }

  async batch(statements) {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const results = statements.map((statement) => statement.runSync());
      this.database.exec("COMMIT");
      return results;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}

async function freshStore() {
  const database = new DatabaseSync(":memory:");
  database.exec("PRAGMA foreign_keys=ON");
  const migration = await readFile(
    new URL("../drizzle/0001_lil_tweak_engineering.sql", import.meta.url),
    "utf8",
  );
  database.exec(migration.replaceAll("--> statement-breakpoint", ""));
  return { database, store: new D1EngineeringStore(new LocalD1(database)) };
}

test("D1 source upload is transactional and retry-idempotent", async (context) => {
  const { database, store } = await freshStore();
  context.after(() => database.close());
  const owner = "abcdef0123456789abcdef0123456789";
  const created = await store.createJob(owner, {
    mode: "build",
    prompt: "Build the exact requested change.",
    projectId: null,
    gitSource: {
      repositoryUrl: "https://github.com/example/project.git",
      commit: "f".repeat(40),
    },
    sources: [
      { filename: "a.zip", mediaType: "application/zip", sizeBytes: 10 },
      { filename: "notes.txt", mediaType: "text/plain", sizeBytes: 5 },
    ],
  });
  assert.deepEqual(created.gitSource, {
    repositoryUrl: "https://github.com/example/project.git",
    commit: "f".repeat(40),
  });

  const digestA = "a".repeat(64);
  const digestB = "b".repeat(64);
  const first = await store.markSourceUploaded(owner, created.id, created.sources[0].id, "etag-a", digestA);
  assert.equal(first.state, "uploading");
  assert.equal(first.revision, 1);
  assert.equal(first.sources[0].sha256, digestA);

  const retried = await store.markSourceUploaded(owner, created.id, created.sources[0].id, "etag-a", digestA);
  assert.equal(retried.revision, first.revision);
  assert.equal(retried.events.filter((event) => event.type === "source_uploaded").length, 1);
  await assert.rejects(
    store.markSourceUploaded(owner, created.id, created.sources[0].id, "different-etag", digestA),
    EngineeringConflictError,
  );
  await assert.rejects(
    store.markSourceUploaded(owner, created.id, created.sources[0].id, "etag-a", digestB),
    EngineeringConflictError,
  );
  const ready = await store.markSourceUploaded(owner, created.id, created.sources[1].id, "etag-b", digestB);
  assert.equal(ready.state, "queued");
  assert.equal(ready.revision, 2);
  assert.equal(ready.sources[1].sha256, digestB);
  assert.equal(ready.events.filter((event) => event.type === "source_uploaded").length, 2);
  assert.equal(ready.events.filter((event) => event.type === "sources_ready").length, 1);
});

test("D1 job creation reuses only an identical owner request", async (context) => {
  const { database, store } = await freshStore();
  context.after(() => database.close());
  const owner = "abcdef0123456789abcdef0123456789";
  const input = {
    mode: "build",
    prompt: "Build once.",
    projectId: null,
    sources: [],
    gitSource: null,
  };
  const key = "11111111-2222-4333-8444-555555555555";
  const digest = await engineeringCreateRequestDigest(input);
  const first = await store.createJobWithIdempotency(owner, input, key, digest);
  const retried = await store.createJobWithIdempotency(owner, input, key, digest);
  assert.equal(first.created, true);
  assert.equal(retried.created, false);
  assert.equal(retried.job.id, first.job.id);
  await assert.rejects(
    store.createJobWithIdempotency(
      owner,
      { ...input, prompt: "Different." },
      key,
      await engineeringCreateRequestDigest({ ...input, prompt: "Different." }),
    ),
    EngineeringConflictError,
  );
  await assert.rejects(
    store.createJobWithIdempotency(
      owner,
      input,
      "22222222-3333-4333-8444-666666666666",
      "f".repeat(64),
    ),
    /digest/i,
  );
  assert.equal((await store.listJobs(owner, 20)).length, 1);
});

test("D1 mirrors authoritative core revisions and recovers an exact durable approval", async (context) => {
  const { database, store } = await freshStore();
  context.after(() => database.close());
  const owner = "abcdef0123456789abcdef0123456789";
  const created = await store.createJob(owner, {
    mode: "debug",
    prompt: "Fix the failure.",
    projectId: null,
    sources: [],
  });
  const reserved = await store.reserveDispatch(owner, created.id, 0);
  assert.equal(reserved.revision, 1);
  assert.equal(await store.dispatchIsReserved(owner, created.id), true);
  const repeatedReservation = await store.reserveDispatch(owner, created.id, 0);
  assert.equal(repeatedReservation.revision, reserved.revision);
  assert.equal(repeatedReservation.events.filter((event) => event.type === "dispatch_reserved").length, 1);
  await assert.rejects(
    store.transition(owner, created.id, "cancelled", reserved.revision, "job_cancelled"),
    EngineeringConflictError,
  );
  const dispatched = await store.setRemoteJob(owner, created.id, reserved.revision, "remote-job-1", "Dispatched.");
  assert.equal(await store.dispatchIsReserved(owner, created.id), false);
  assert.equal(await store.getCoreRevision(owner, created.id), null);
  const repeatedDispatch = await store.setRemoteJob(owner, created.id, reserved.revision, "remote-job-1", "Dispatched.");
  assert.equal(repeatedDispatch.revision, dispatched.revision);
  assert.equal(repeatedDispatch.events.filter((event) => event.type === "core_dispatched").length, 1);
  await assert.rejects(
    store.setRemoteJob(owner, created.id, reserved.revision, "different-remote-job", "Dispatched."),
    EngineeringConflictError,
  );
  const accepted = await store.applyCoreSnapshot(owner, created.id, {
    state: "queued",
    summary: "",
    coreRevision: 0,
    evidence: [],
  });
  assert.equal(accepted.summary, "queued");
  assert.equal(await store.getCoreRevision(owner, created.id), 0);
  await store.applyCoreSnapshot(owner, created.id, {
    state: "ingesting",
    summary: "Inspecting.",
    coreRevision: 1,
    evidence: [],
  });
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "planning",
      summary: "Equivocated without advancing the core revision.",
      coreRevision: 1,
      evidence: [],
    }),
    EngineeringConflictError,
  );

  const digest = "a".repeat(64);
  const sourceDigest = "d".repeat(64);
  const approvalProposal = {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1, memory: "1g", pids: 256, wallSeconds: 1200 },
    sourceDigest,
    proposalDigest: digest,
    expiresAt: "2026-08-13T16:05:00Z",
  };
  const evidence = {
    id: `evidence:${"b".repeat(32)}`,
    category: "patch",
    filename: "changes.patch",
    mediaType: "text/x-diff",
    sizeBytes: 0,
    sha256: "c".repeat(64),
    createdAt: "2026-08-13T12:00:00.000Z",
    corePath: "/v1/jobs/remote-job-1/evidence/changes.patch",
  };
  const review = await store.applyCoreSnapshot(owner, created.id, {
    state: "awaiting_approval",
    summary: "Ready for review.",
    coreRevision: 2,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: false,
    evidence: [evidence],
  });
  assert.equal(review.state, "awaiting_approval");
  assert.equal(review.evidence[0].sizeBytes, 0);
  assert.deepEqual(review.approvalProposal, approvalProposal);
  assert.equal(review.approvalConsumed, false);
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "awaiting_approval",
      summary: "Dropped the immutable evidence manifest.",
      coreRevision: 3,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: false,
      evidence: [],
    }),
    EngineeringConflictError,
  );
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "awaiting_approval",
      summary: "Changed an immutable evidence descriptor.",
      coreRevision: 3,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: false,
      evidence: [{ ...evidence, sha256: "e".repeat(64) }],
    }),
    EngineeringConflictError,
  );

  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "completed",
      summary: "Claimed approval without an owner decision.",
      coreRevision: 3,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: true,
      evidence: [evidence],
    }),
    EngineeringConflictError,
  );

  await store.recordDecisionIntent(owner, created.id, review.revision, "approve", digest);
  await store.recordDecisionIntent(owner, created.id, review.revision, "approve", digest);
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "applying",
      summary: "Consumed before the private bytes were ready.",
      coreRevision: 4,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: true,
      evidence: [evidence],
    }),
    EngineeringConflictError,
  );
  const applying = await store.applyCoreSnapshot(owner, created.id, {
    state: "applying",
    summary: "Approved export is pending its one-time download.",
    coreRevision: 4,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: false,
    evidence: [evidence],
  });
  assert.equal(applying.state, "applying");
  assert.equal(applying.approvalConsumed, false);
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "completed",
      summary: "Did not consume the approved action.",
      coreRevision: 5,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: false,
      evidence: [evidence],
    }),
    EngineeringConflictError,
  );
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "completed",
      summary: "Tried to append evidence after owner review.",
      coreRevision: 5,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: true,
      evidence: [evidence, {
        ...evidence,
        id: `evidence:${"f".repeat(32)}`,
        category: "summary",
        filename: "late-summary.md",
        sha256: "f".repeat(64),
        corePath: "/v1/jobs/remote-job-1/evidence/late-summary.md",
      }],
    }),
    EngineeringConflictError,
  );
  const completed = await store.applyCoreSnapshot(owner, created.id, {
    state: "completed",
    summary: "Export authorized.",
    coreRevision: 5,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: true,
    evidence: [evidence],
  });
  assert.equal(completed.state, "completed");
  assert.equal(completed.approvalConsumed, true);
  const retried = await store.applyCoreSnapshot(owner, created.id, {
    state: "completed",
    summary: "Export authorized.",
    coreRevision: 5,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: true,
    evidence: [evidence],
  });
  assert.equal(retried.revision, completed.revision);
  assert.equal(retried.events.filter((event) => event.type === "decision_authorized").length, 1);
  await assert.rejects(
    store.applyCoreSnapshot(owner, created.id, {
      state: "completed",
      summary: "Changed after terminal completion.",
      coreRevision: 5,
      proposalDigest: digest,
      sourceDigest,
      approvalProposal,
      approvalConsumed: true,
      evidence: [evidence],
    }),
    EngineeringConflictError,
  );
});

test("a losing concurrent state transition cannot append a false audit event", async (context) => {
  const { database, store } = await freshStore();
  context.after(() => database.close());
  const owner = "abcdef0123456789abcdef0123456789";
  const created = await store.createJob(owner, {
    mode: "chat",
    prompt: "Race two terminal transitions.",
    projectId: null,
    sources: [],
  });

  const results = await Promise.allSettled([
    store.transition(owner, created.id, "cancelled", created.revision, "concurrent_cancel"),
    store.transition(owner, created.id, "failed", created.revision, "concurrent_fail"),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 1);

  const final = await store.getJob(owner, created.id);
  assert.ok(final);
  const racedEvents = final.events.filter((event) => (
    event.type === "concurrent_cancel" || event.type === "concurrent_fail"
  ));
  assert.equal(racedEvents.length, 1, "only the winning transition may be audited");
  assert.equal(
    racedEvents[0].type,
    final.state === "cancelled" ? "concurrent_cancel" : "concurrent_fail",
  );
});

test("D1 mirrors cancellation of an unconsumed applying export", async (context) => {
  const { database, store } = await freshStore();
  context.after(() => database.close());
  const owner = "abcdef0123456789abcdef0123456789";
  const digest = "a".repeat(64);
  const sourceDigest = "d".repeat(64);
  const created = await store.createJob(owner, {
    mode: "debug",
    prompt: "Cancel the pending export.",
    projectId: null,
    sources: [],
  });
  const reserved = await store.reserveDispatch(owner, created.id, created.revision);
  await store.setRemoteJob(owner, created.id, reserved.revision, "remote-job-cancel", "Dispatched.");
  await store.applyCoreSnapshot(owner, created.id, {
    state: "queued", summary: "Queued.", coreRevision: 0, evidence: [],
  });
  const collected = await store.applyCoreSnapshot(owner, created.id, {
    state: "collecting", summary: "Collected.", coreRevision: 1, sourceDigest, evidence: [],
  });
  const approvalProposal = {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1 },
    sourceDigest,
    proposalDigest: digest,
    expiresAt: "2026-08-13T12:05:00.000Z",
  };
  const evidence = {
    id: `evidence:${"b".repeat(32)}`,
    category: "patch",
    filename: "changes.patch",
    mediaType: "text/x-diff",
    sizeBytes: 4,
    sha256: "c".repeat(64),
    createdAt: "2026-08-13T12:00:00.000Z",
    corePath: "/v1/jobs/remote-job-cancel/evidence/changes.patch",
  };
  const review = await store.applyCoreSnapshot(owner, created.id, {
    state: "awaiting_approval",
    summary: "Review.",
    coreRevision: 2,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: false,
    evidence: [evidence],
  });
  assert.ok(review.revision > collected.revision);
  await store.recordDecisionIntent(owner, created.id, review.revision, "approve", digest);
  const applying = await store.applyCoreSnapshot(owner, created.id, {
    state: "applying",
    summary: "Export pending.",
    coreRevision: 3,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: false,
    evidence: [evidence],
  });
  const cancelled = await store.applyCoreSnapshot(owner, created.id, {
    state: "cancelled",
    summary: "Export cancelled.",
    coreRevision: 4,
    proposalDigest: digest,
    sourceDigest,
    approvalProposal,
    approvalConsumed: false,
    evidence: [evidence],
  });
  assert.equal(applying.state, "applying");
  assert.equal(cancelled.state, "cancelled");
  assert.equal(cancelled.approvalConsumed, false);
});

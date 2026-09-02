import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  asArrayBuffer,
  canonicalJson,
  fromBase64Url,
  sha256Hex,
  toBase64Url,
  verifyDispatchAttestation,
  type DispatchAttestationPayload,
} from "../src/attestation";
import { parseEvidenceRequest } from "../src/protocol";
import goldenFixture from "./fixtures/dispatch-attestation-v1.json";

const CONTROL_AUTH = "Bearer test-control-token-not-operational";
const RUNNER_AUTH = "Bearer test-runner-token-not-operational";
const RUNNER_REQUEST_SCHEMA = "lil-tweak.runner-request/v1";
const MANIFEST_SCHEMA = "lil-tweak.runner-job-manifest/v1";
const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const QUALIFICATION_CONTENT_SHA256 =
  "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91";
const RUNTIME_IMAGE =
  "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36";
const SECCOMP_SHA256 =
  "50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23";

function digest(letter: string): string {
  return letter.repeat(64);
}

async function signPayload(payload: DispatchAttestationPayload): Promise<string> {
  const testBindings = env as unknown as {
    TEST_ATTESTATION_PRIVATE_KEY: string;
  };
  const key = await crypto.subtle.importKey(
    "pkcs8",
    asArrayBuffer(fromBase64Url(testBindings.TEST_ATTESTATION_PRIVATE_KEY)),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "Ed25519",
    key,
    new TextEncoder().encode(canonicalJson(payload)),
  );
  return toBase64Url(new Uint8Array(signature));
}

function readOnlyManifest() {
  return {
    schema_version: MANIFEST_SCHEMA,
    job_type: "read_only",
    action: "qualification_read_only_v1",
    source: {
      repository: "islamismylifebey-web/lil-tweak",
      commit_sha: "1".repeat(40),
      tree_sha: "2".repeat(40),
    },
    verification_profile: "runner_qualification_subset_v1",
    timeout_seconds: 900,
    network_scope: "github_repository_only",
    allow_package_install: false,
    allow_production_access: false,
    allow_deploy: false,
  } as const;
}

function boundedWriteManifest() {
  return {
    ...readOnlyManifest(),
    job_type: "bounded_write",
    action: "qualification_bounded_docs_v1",
    qualification_branch: "qualification/galor-tweak-runner-01/live-proof",
    artifact: {
      path: "docs/runner-qualification/galor-tweak-runner-01.md",
      expected_before_sha256: EMPTY_SHA256,
      content_sha256: QUALIFICATION_CONTENT_SHA256,
    },
  } as const;
}

function baseReceipt() {
  return {
    runner_id: "galor-tweak-runner-01",
    runtime_image: RUNTIME_IMAGE,
    seccomp_sha256: SECCOMP_SHA256,
    apparmor_profile: "liltweak-runner-job",
    network_denied: true,
    package_install_allowed: false,
    production_access_allowed: false,
    deploy_allowed: false,
    workspace_cleaned: true,
    cgroup_cleaned: true,
  } as const;
}

function readOnlyReceipt(manifest = readOnlyManifest()) {
  return {
    ...baseReceipt(),
    candidate_sha: null,
    source_commit: manifest.source.commit_sha,
    source_tree: manifest.source.tree_sha,
    source_mutated: false,
  } as const;
}

function boundedWriteReceipt(
  executionId: string,
  manifest = boundedWriteManifest(),
) {
  return {
    ...baseReceipt(),
    artifact_path: manifest.artifact.path,
    artifact_sha256: manifest.artifact.content_sha256,
    candidate_sha: "3".repeat(40),
    candidate_tree: "4".repeat(40),
    source_commit: manifest.source.commit_sha,
    source_tree: manifest.source.tree_sha,
    source_mutated: true,
    bundle_sha256: digest("5"),
    bundle_size: 42_000,
    candidate_store_id: executionId,
    created_at_ms: Date.now() - 500,
    qualification_branch: manifest.qualification_branch,
  } as const;
}

async function runnerEvidence(
  operationDigest: string,
  receipt: Record<string, unknown>,
  overrides: Partial<{
    outcome: "succeeded" | "failed" | "cancelled";
    exit_code: number;
  }> = {},
) {
  const now = Date.now();
  return {
    schema_version: "lil-tweak.runner-evidence/v2",
    outcome: "succeeded" as const,
    operation_digest: operationDigest,
    stdout_digest: digest("b"),
    stderr_digest: digest("c"),
    receipt_digest: await sha256Hex(canonicalJson(receipt)),
    receipt,
    exit_code: 0,
    started_at_ms: now - 1_000,
    finished_at_ms: now,
    ...overrides,
  };
}

type RunnerOperation = "poll" | "claim" | "status" | "evidence";

async function signedRunnerRequest(
  operation: RunnerOperation,
  payload: unknown,
  overrides: Partial<{
    runner_id: string;
    request_nonce: string;
    issued_at_ms: number;
  }> = {},
) {
  const requestPayload = {
    schema_version: RUNNER_REQUEST_SCHEMA,
    runner_id: "galor-tweak-runner-01",
    operation,
    request_nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    issued_at_ms: Date.now(),
    payload,
    ...overrides,
  };
  const testBindings = env as unknown as {
    TEST_RUNNER_SIGNING_PRIVATE_KEY: string;
  };
  const key = await crypto.subtle.importKey(
    "pkcs8",
    asArrayBuffer(fromBase64Url(testBindings.TEST_RUNNER_SIGNING_PRIVATE_KEY)),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const message = `lil-tweak.runner-request/${operation}/v1\n${canonicalJson(requestPayload)}`;
  const signature = await crypto.subtle.sign(
    "Ed25519",
    key,
    new TextEncoder().encode(message),
  );
  return {
    request: requestPayload,
    signature: toBase64Url(new Uint8Array(signature)),
  };
}

async function attestation(
  executionId: string,
  overrides: Partial<DispatchAttestationPayload> = {},
) {
  const now = Date.now();
  const payload: DispatchAttestationPayload = {
    schema_version: "lil-tweak.dispatch-attestation/v1",
    execution_id: executionId,
    runner_id: "galor-tweak-runner-01",
    runner_role: "role-tweak-runner",
    lease_digest: digest("b"),
    contract_digest: digest("c"),
    commands_digest: digest("d"),
    approval_digest: digest("e"),
    policy_digest: digest("f"),
    attempt_nonce: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    issued_at_ms: now - 1_000,
    expires_at_ms: now + 60_000,
    ...overrides,
  };
  return {
    key_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    attestation: payload,
    signature: await signPayload(payload),
  };
}

async function request(
  path: string,
  authorization: string | undefined,
  body?: unknown,
): Promise<Response> {
  return SELF.fetch(`https://control-plane.example${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      ...(authorization ? { authorization } : {}),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function offer(
  executionId: string,
  manifest: ReturnType<typeof readOnlyManifest> | ReturnType<typeof boundedWriteManifest> =
    readOnlyManifest(),
  overrides: Partial<DispatchAttestationPayload> = {},
) {
  const signed = await attestation(executionId, {
    commands_digest: await sha256Hex(canonicalJson(manifest)),
    ...overrides,
  });
  const response = await request("/v1/control/offer", CONTROL_AUTH, {
    attestation: signed,
    manifest,
  });
  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({
    execution_id: signed.attestation.execution_id,
    runner_id: "galor-tweak-runner-01",
    lease_digest: signed.attestation.lease_digest,
    contract_digest: signed.attestation.contract_digest,
    commands_digest: signed.attestation.commands_digest,
    status: "OFFERED",
    expires_at_ms: signed.attestation.expires_at_ms,
  });
  return { ...signed, manifest };
}

describe("Lil Tweak runner control plane", () => {
  it("verifies the non-secret cross-language Ed25519 golden attestation", async () => {
    const verified = await verifyDispatchAttestation(
      goldenFixture.attestation,
      {
        LIL_TWEAK_ATTESTATION_KEY_ID: goldenFixture.key_id,
        LIL_TWEAK_ATTESTATION_PUBLIC_KEY: goldenFixture.public_key,
      },
      goldenFixture.attestation.attestation.issued_at_ms + 1,
    );

    expect(verified.attestation.attestation.execution_id).toBe("golden-fixture-001");
    expect(verified.attestation_digest).toMatch(/^[a-f0-9]{64}$/);
  });

  it("requires server-to-server bearer authentication for typed routes", async () => {
    const response = await request("/v1/control/offer", undefined, {
      attestation: await attestation("auth-required"),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("rejects unsigned, expired, or untyped dispatch offers", async () => {
    const manifest = readOnlyManifest();
    const expired = await attestation("expired", {
      commands_digest: await sha256Hex(canonicalJson(manifest)),
      issued_at_ms: Date.now() - 120_000,
      expires_at_ms: Date.now() - 60_000,
    });
    expired.signature = await signPayload(expired.attestation);

    const expiredResponse = await request("/v1/control/offer", CONTROL_AUTH, {
      attestation: expired,
      manifest,
    });
    expect(expiredResponse.status).toBe(400);

    const rawCommandResponse = await request("/v1/control/offer", CONTROL_AUTH, {
      attestation: {
        ...(await attestation("raw-command")),
        attestation: {
          ...(await attestation("raw-command")).attestation,
          command: "whoami",
        },
      },
      manifest,
    });
    expect(rawCommandResponse.status).toBe(400);
  });

  it("stores a canonical typed manifest and returns it only through signed runner poll", async () => {
    const manifest = boundedWriteManifest();
    const offered = await offer("typed-poll", manifest);
    const { manifest: _storedManifest, ...attestationEnvelope } = offered;
    const poll = await signedRunnerRequest("poll", {});

    const withoutBearer = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      undefined,
      poll,
    );
    expect(withoutBearer.status).toBe(401);

    const response = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      poll,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      execution_id: "typed-poll",
      status: "OFFERED",
      expires_at_ms: offered.attestation.expires_at_ms,
      attestation: attestationEnvelope,
      manifest,
    });
  });

  it("rejects a manifest whose canonical digest differs from the signed digest", async () => {
    const manifest = readOnlyManifest();
    const signed = await attestation("wrong-manifest-digest", {
      commands_digest: digest("9"),
    });

    const response = await request("/v1/control/offer", CONTROL_AUTH, {
      attestation: signed,
      manifest,
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid_request" });
  });

  it("rejects extra manifest fields, including arbitrary shell and argv", async () => {
    for (const extra of [
      { shell: "whoami" },
      { argv: ["git", "status"] },
      { secret: "not-allowed" },
    ]) {
      const manifest = { ...readOnlyManifest(), ...extra };
      const signed = await attestation(`extra-${Object.keys(extra)[0]}`, {
        commands_digest: await sha256Hex(canonicalJson(manifest)),
      });
      const response = await request("/v1/control/offer", CONTROL_AUTH, {
        attestation: signed,
        manifest,
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_request" });
    }
  });

  it("rejects a bearer holder that cannot prove the pinned runner signing key", async () => {
    await offer("runner-signature-required");
    const envelope = await signedRunnerRequest("poll", {});
    envelope.signature = `${envelope.signature.startsWith("A") ? "B" : "A"}${
      envelope.signature.slice(1)
    }`;

    const response = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      envelope,
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "unauthorized" });
  });

  it("domain-separates runner operations and rejects stale signed requests", async () => {
    await offer("runner-domain-separation");
    const wrongOperation = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      await signedRunnerRequest("status", {}),
    );
    expect(wrongOperation.status).toBe(401);

    const stale = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      await signedRunnerRequest("poll", {}, { issued_at_ms: Date.now() - 30_001 }),
    );
    expect(stale.status).toBe(401);
  });

  it("rejects replay of the same signed runner poll nonce", async () => {
    await offer("poll-replay");
    const envelope = await signedRunnerRequest("poll", {});
    const first = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      envelope,
    );
    expect(first.status).toBe(200);

    const replay = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      envelope,
    );
    expect(replay.status).toBe(409);
  });

  it("uses the deterministic runner object and atomically consumes a nonce", async () => {
    const signed = await offer("atomic-claim");
    const claimBody = {
      execution_id: signed.attestation.execution_id,
      attempt_nonce: signed.attestation.attempt_nonce,
    };

    const claimEnvelopes = await Promise.all([
      signedRunnerRequest("claim", claimBody),
      signedRunnerRequest("claim", claimBody),
    ]);
    const claims = await Promise.all([
      request(
        "/v1/runners/galor-tweak-runner-01/claim",
        RUNNER_AUTH,
        claimEnvelopes[0],
      ),
      request(
        "/v1/runners/galor-tweak-runner-01/claim",
        RUNNER_AUTH,
        claimEnvelopes[1],
      ),
    ]);

    const statuses = claims.map((response) => response.status).sort();
    expect(statuses).toEqual([200, 409]);
    const successful = claims.find((response) => response.status === 200);
    const receipt = await successful!.json<{
      runner_id: string;
      status: string;
      claim_receipt_digest: string;
    }>();
    expect(receipt.runner_id).toBe("galor-tweak-runner-01");
    expect(receipt.status).toBe("CLAIMED");
    expect(receipt.claim_receipt_digest).toMatch(/^[a-f0-9]{64}$/);

    const successfulIndex = claims.findIndex((response) => response.status === 200);
    const replay = await request(
      "/v1/runners/galor-tweak-runner-01/claim",
      RUNNER_AUTH,
      claimEnvelopes[successfulIndex],
    );
    expect(replay.status).toBe(409);
  });

  it("hides expired and cancelled offers while exposing cancellation to the runner", async () => {
    const now = Date.now();
    await offer("expires-before-poll", readOnlyManifest(), {
      issued_at_ms: now - 1_000,
      expires_at_ms: now + 200,
    });
    const cancelled = await offer("cancelled-before-poll");
    const cancellation = await request(
      "/v1/control/executions/cancelled-before-poll/cancel",
      CONTROL_AUTH,
      { reason_digest: digest("8") },
    );
    expect(cancellation.status).toBe(202);

    await new Promise((resolve) => setTimeout(resolve, 250));
    const poll = await request(
      "/v1/runners/galor-tweak-runner-01/next",
      RUNNER_AUTH,
      await signedRunnerRequest("poll", {}),
    );
    if (poll.status === 200) {
      const visible = await poll.json<{ execution_id: string; status: string }>();
      expect(visible.status).toBe("OFFERED");
      expect(visible.execution_id).not.toBe("expires-before-poll");
      expect(visible.execution_id).not.toBe("cancelled-before-poll");
    } else {
      expect(poll.status).toBe(404);
    }

    const runnerStatus = await request(
      "/v1/runners/galor-tweak-runner-01/status",
      RUNNER_AUTH,
      await signedRunnerRequest("status", {
        execution_id: cancelled.attestation.execution_id,
      }),
    );
    expect(runnerStatus.status).toBe(200);
    expect(await runnerStatus.json()).toMatchObject({
      execution_id: "cancelled-before-poll",
      status: "CANCEL_REQUESTED",
      cancellation_reason_digest: digest("8"),
    });

    const expiredStatus = await request(
      "/v1/runners/galor-tweak-runner-01/status",
      RUNNER_AUTH,
      await signedRunnerRequest("status", {
        execution_id: "expires-before-poll",
      }),
    );
    expect(expiredStatus.status).toBe(200);
    expect(await expiredStatus.json()).toMatchObject({
      execution_id: "expires-before-poll",
      status: "EXPIRED",
    });
  });

  it("persists the normalized signed v2 evidence envelope for controller status only", async () => {
    const signed = await offer("evidence-only");
    const identifiers = {
      execution_id: signed.attestation.execution_id,
      attempt_nonce: signed.attestation.attempt_nonce,
    };
    expect(
      (
        await request(
          "/v1/runners/galor-tweak-runner-01/claim",
          RUNNER_AUTH,
          await signedRunnerRequest("claim", identifiers),
        )
      ).status,
    ).toBe(200);

    const evidenceBody = {
      ...identifiers,
      evidence: await runnerEvidence(
        signed.attestation.commands_digest,
        readOnlyReceipt(),
      ),
    };
    const bearerOnlyEvidence = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      evidenceBody,
    );
    expect(bearerOnlyEvidence.status).toBe(401);

    const signedEvidence = await signedRunnerRequest("evidence", evidenceBody);
    const evidenceResponse = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      signedEvidence,
    );
    expect(evidenceResponse.status).toBe(202);
    const submission = await evidenceResponse.json<Record<string, unknown>>();
    expect(submission).toMatchObject({
      execution_id: "evidence-only",
      status: "EVIDENCE_RECORDED",
      evidence_digest: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(submission).not.toHaveProperty("evidence_envelope");

    const statusResponse = await request(
      "/v1/control/executions/evidence-only",
      CONTROL_AUTH,
    );
    const status = await statusResponse.json<Record<string, unknown>>();
    expect(statusResponse.status).toBe(200);
    expect(status.status).toBe("EVIDENCE_RECORDED");
    expect(status.evidence_envelope).toEqual(signedEvidence);
    expect(JSON.stringify(status)).not.toContain("COMPLETE");
    expect(JSON.stringify(status)).not.toContain("QUALIFIED");
    expect(JSON.stringify(status)).not.toContain('"command"');
    expect(JSON.stringify(status)).not.toContain('"stdout"');

    const runnerStatusResponse = await request(
      "/v1/runners/galor-tweak-runner-01/status",
      RUNNER_AUTH,
      await signedRunnerRequest("status", { execution_id: "evidence-only" }),
    );
    expect(runnerStatusResponse.status).toBe(200);
    expect(
      await runnerStatusResponse.json<Record<string, unknown>>(),
    ).not.toHaveProperty("evidence_envelope");
  });

  it("accepts the exact successful bounded-write receipt produced by the host executor", async () => {
    const manifest = boundedWriteManifest();
    const signed = await offer("bounded-write-evidence", manifest);
    const identifiers = {
      execution_id: signed.attestation.execution_id,
      attempt_nonce: signed.attestation.attempt_nonce,
    };
    expect(
      (
        await request(
          "/v1/runners/galor-tweak-runner-01/claim",
          RUNNER_AUTH,
          await signedRunnerRequest("claim", identifiers),
        )
      ).status,
    ).toBe(200);
    const evidenceBody = {
      ...identifiers,
      evidence: await runnerEvidence(
        signed.attestation.commands_digest,
        boundedWriteReceipt("bounded-write-evidence", manifest),
      ),
    };

    const response = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      await signedRunnerRequest("evidence", evidenceBody),
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({
      execution_id: "bounded-write-evidence",
      status: "EVIDENCE_RECORDED",
    });
  });

  it("accepts bounded failure and exact pre-execution cancellation receipts without qualifying", async () => {
    const identifiers = {
      execution_id: "bounded-non-success",
      attempt_nonce: "A".repeat(43),
    };
    const failed = parseEvidenceRequest({
      ...identifiers,
      evidence: await runnerEvidence(digest("a"), baseReceipt(), {
        outcome: "failed",
        exit_code: 70,
      }),
    });
    expect(failed.evidence.receipt).toEqual(baseReceipt());

    const cancellationReceipt = { cancelled_before_execution: true } as const;
    const cancelled = parseEvidenceRequest({
      ...identifiers,
      evidence: await runnerEvidence(digest("a"), cancellationReceipt, {
        outcome: "cancelled",
        exit_code: 0,
      }),
    });
    expect(cancelled.evidence.receipt).toEqual(cancellationReceipt);

    expect(() =>
      parseEvidenceRequest({
        ...identifiers,
        evidence: {
          schema_version: "lil-tweak.runner-evidence/v2",
          outcome: "succeeded",
          operation_digest: digest("a"),
          stdout_digest: digest("b"),
          stderr_digest: digest("c"),
          receipt_digest: digest("d"),
          receipt: baseReceipt(),
          exit_code: 0,
          started_at_ms: 1,
          finished_at_ms: 2,
        },
      }),
    ).toThrow(/completed job receipt/);
  });

  it("rejects v1, digest-only v2, and receipt fields outside the bounded contract", async () => {
    const signed = await offer("reject-raw-evidence");
    const wrongRunner = await request(
      "/v1/runners/not-a-runner/claim",
      RUNNER_AUTH,
      {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
      },
    );
    expect(wrongRunner.status).toBe(404);

    const claim = await request(
      "/v1/runners/galor-tweak-runner-01/claim",
      RUNNER_AUTH,
      await signedRunnerRequest("claim", {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
      }),
    );
    expect(claim.status).toBe(200);

    const v1EvidenceBody = {
      execution_id: signed.attestation.execution_id,
      attempt_nonce: signed.attestation.attempt_nonce,
      evidence: {
        schema_version: "lil-tweak.runner-evidence/v1",
        outcome: "succeeded",
        operation_digest: signed.attestation.commands_digest,
        stdout_digest: digest("b"),
        stderr_digest: digest("c"),
        receipt_digest: digest("d"),
        exit_code: 0,
        started_at_ms: Date.now() - 1_000,
        finished_at_ms: Date.now(),
      },
    };
    const v1Evidence = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      await signedRunnerRequest("evidence", v1EvidenceBody),
    );
    expect(v1Evidence.status).toBe(400);

    const receipt = {
      ...readOnlyReceipt(),
      stdout: "raw output is forbidden",
    };
    const rawEvidence = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      await signedRunnerRequest("evidence", {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
        evidence: await runnerEvidence(signed.attestation.commands_digest, receipt),
      }),
    );
    expect(rawEvidence.status).toBe(400);

    const v2 = await runnerEvidence(
      signed.attestation.commands_digest,
      readOnlyReceipt(),
    );
    const { receipt: _omittedReceipt, ...digestOnlyV2 } = v2;
    const digestOnly = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      await signedRunnerRequest("evidence", {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
        evidence: digestOnlyV2,
      }),
    );
    expect(digestOnly.status).toBe(400);

    const mismatchedDigestEvidence = await runnerEvidence(
      signed.attestation.commands_digest,
      readOnlyReceipt(),
    );
    mismatchedDigestEvidence.receipt_digest = digest("f");
    const mismatchedDigest = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      await signedRunnerRequest("evidence", {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
        evidence: mismatchedDigestEvidence,
      }),
    );
    expect(mismatchedDigest.status).toBe(400);
  });

  it("records cancellation as a request, never as completion", async () => {
    await offer("cancel-request");
    const response = await request(
      "/v1/control/executions/cancel-request/cancel",
      CONTROL_AUTH,
      { reason_digest: digest("9") },
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      execution_id: "cancel-request",
      status: "CANCEL_REQUESTED",
      reason_digest: digest("9"),
    });
  });
});

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  asArrayBuffer,
  canonicalJson,
  fromBase64Url,
  toBase64Url,
  verifyDispatchAttestation,
  type DispatchAttestationPayload,
} from "../src/attestation";
import goldenFixture from "./fixtures/dispatch-attestation-v1.json";

const CONTROL_AUTH = "Bearer test-control-token-not-operational";
const RUNNER_AUTH = "Bearer test-runner-token-not-operational";
const DIGEST = "a".repeat(64);

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

async function offer(executionId: string) {
  const signed = await attestation(executionId);
  const response = await request("/v1/control/offer", CONTROL_AUTH, {
    attestation: signed,
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
  return signed;
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
    const expired = await attestation("expired", {
      issued_at_ms: Date.now() - 120_000,
      expires_at_ms: Date.now() - 60_000,
    });
    expired.signature = await signPayload(expired.attestation);

    const expiredResponse = await request("/v1/control/offer", CONTROL_AUTH, {
      attestation: expired,
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
    });
    expect(rawCommandResponse.status).toBe(400);
  });

  it("uses the deterministic runner object and atomically consumes a nonce", async () => {
    const signed = await offer("atomic-claim");
    const claimBody = {
      execution_id: signed.attestation.execution_id,
      attempt_nonce: signed.attestation.attempt_nonce,
    };

    const claims = await Promise.all([
      request("/v1/runners/galor-tweak-runner-01/claim", RUNNER_AUTH, claimBody),
      request("/v1/runners/galor-tweak-runner-01/claim", RUNNER_AUTH, claimBody),
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
  });

  it("records digest-only evidence without completing or qualifying an execution", async () => {
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
          identifiers,
        )
      ).status,
    ).toBe(200);

    const evidenceResponse = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      {
        ...identifiers,
        evidence: {
          schema_version: "lil-tweak.runner-evidence/v1",
          outcome: "succeeded",
          operation_digest: digest("d"),
          stdout_digest: digest("b"),
          stderr_digest: digest("c"),
          receipt_digest: digest("d"),
          exit_code: 0,
          started_at_ms: Date.now() - 1_000,
          finished_at_ms: Date.now(),
        },
      },
    );
    expect(evidenceResponse.status).toBe(202);
    expect(await evidenceResponse.json()).toMatchObject({
      execution_id: "evidence-only",
      status: "EVIDENCE_RECORDED",
      evidence_digest: expect.stringMatching(/^[a-f0-9]{64}$/),
    });

    const statusResponse = await request(
      "/v1/control/executions/evidence-only",
      CONTROL_AUTH,
    );
    const status = await statusResponse.json<Record<string, unknown>>();
    expect(statusResponse.status).toBe(200);
    expect(status.status).toBe("EVIDENCE_RECORDED");
    expect(JSON.stringify(status)).not.toContain("COMPLETE");
    expect(JSON.stringify(status)).not.toContain("QUALIFIED");
    expect(JSON.stringify(status)).not.toContain('"command"');
    expect(JSON.stringify(status)).not.toContain('"stdout"');
  });

  it("rejects raw evidence and disallows every runner identity but the pinned runner", async () => {
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
      {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
      },
    );
    expect(claim.status).toBe(200);

    const rawEvidence = await request(
      "/v1/runners/galor-tweak-runner-01/evidence",
      RUNNER_AUTH,
      {
        execution_id: signed.attestation.execution_id,
        attempt_nonce: signed.attestation.attempt_nonce,
        evidence: {
          schema_version: "lil-tweak.runner-evidence/v1",
          outcome: "succeeded",
          operation_digest: DIGEST,
          stdout_digest: digest("b"),
          stderr_digest: digest("c"),
          receipt_digest: digest("d"),
          exit_code: 0,
          started_at_ms: Date.now() - 1_000,
          finished_at_ms: Date.now(),
          stdout: "raw output is forbidden",
        },
      },
    );
    expect(rawEvidence.status).toBe(400);
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

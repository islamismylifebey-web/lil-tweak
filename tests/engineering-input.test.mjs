import assert from "node:assert/strict";
import test from "node:test";

import { boundedProjectContext, enforceModeSourcePolicy, parseGitSource } from "../lib/engineering-input.ts";

test("accepts only HTTPS Git repositories frozen to exact object IDs", () => {
  assert.deepEqual(parseGitSource({
    repositoryUrl: "https://github.com/example/project.git",
    commit: "A".repeat(40),
  }), {
    repositoryUrl: "https://github.com/example/project.git",
    commit: "a".repeat(40),
  });
  assert.equal(parseGitSource(undefined), null);
  for (const invalid of [
    { repositoryUrl: "https://github.com/example/project.git", commit: "main" },
    { repositoryUrl: "ssh://git@github.com/example/project.git", commit: "a".repeat(40) },
    { repositoryUrl: "https://user:token@example.com/project.git", commit: "a".repeat(40) },
    { repositoryUrl: "https://example.com/project.git#main", commit: "a".repeat(40) },
  ]) assert.throws(() => parseGitSource(invalid), /Git source/i);
});

test("Chat accepts selected-project context only", () => {
  assert.doesNotThrow(() => enforceModeSourcePolicy("chat", "project:1", [], null));
  assert.throws(() => enforceModeSourcePolicy("chat", null, [], null), /selected project/i);
  assert.throws(() => enforceModeSourcePolicy("chat", "project:1", [{ filename: "a" }], null), /does not accept source/i);
  assert.throws(() => enforceModeSourcePolicy("chat", "project:1", [], {
    repositoryUrl: "https://example.com/a.git",
    commit: "a".repeat(40),
  }), /does not accept source/i);
});

test("builds bounded project context without attachment bodies", () => {
  const context = boundedProjectContext({
    id: "project:123",
    name: "Example",
    description: "d".repeat(20_000),
    status: "active",
    requirements: [{ id: "r", text: "Ship it", status: "active" }],
    milestones: [],
    board: [],
    notes: [{ id: "n", text: "Private note", created_at: "2026-08-13T00:00:00Z" }],
    attachments: [{ filename: "secret.txt", content_base64: "must-not-leak" }],
  });
  assert.equal(context.schemaVersion, "project-context-v1");
  assert.equal(context.projectId, "project:123");
  assert.ok(new TextEncoder().encode(JSON.stringify(context)).byteLength <= 8 * 1024);
  assert.doesNotMatch(JSON.stringify(context), /must-not-leak|content_base64/);
});

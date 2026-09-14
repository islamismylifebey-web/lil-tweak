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

test("first launch accepts GitHub projects only for every engineering mode", () => {
  const git = { repositoryUrl: "https://github.com/example/project", commit: "a".repeat(40) };
  for (const mode of ["build", "debug", "refactor", "test", "architect"]) {
    assert.doesNotThrow(() => enforceModeSourcePolicy(mode, null, [], git));
    assert.throws(() => enforceModeSourcePolicy(mode, null, [], null), /Git source.*required/i);
    assert.throws(() => enforceModeSourcePolicy(mode, null, [{ filename: "legacy.txt" }], git), /Git source.*uploaded-project/i);
    assert.throws(() => enforceModeSourcePolicy(mode, null, [], { ...git, repositoryUrl: "https://example.com/owner/repo" }), /Git source/i);
  }
});

test("GitHub repository URLs reject alternate hosts, extra paths and normalization aliases", () => {
  for (const repositoryUrl of [
    "https://example.com/owner/repo", "https://github.com.evil.example/owner/repo",
    "https://github.com:8443/owner/repo", "https://github.com/owner/repo/tree/main",
    "https://github.com/owner/%72epo", "https://github.com/owner/../repo",
    "https://github.com/owner/./repo", "https://github.com/./repo",
    "https://github.com/owner/..", "https://github.com/owner/.git",
    "https://github.com/owner/repo?", "https://github.com/owner/repo#",
    "https://github.com/owner\\repo", "https://github.com//owner/repo",
  ]) assert.throws(() => parseGitSource({ repositoryUrl, commit: "a".repeat(40) }), /Git source/i, repositoryUrl);
  assert.equal(parseGitSource({ repositoryUrl: "https://github.com:443/owner/repo.git/", commit: "a".repeat(40) }).repositoryUrl,
    "https://github.com/owner/repo.git/");
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

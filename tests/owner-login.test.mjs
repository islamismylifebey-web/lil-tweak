import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

async function source(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

test("root and login pages use the private password session gate", async () => {
  const [home, loginPage, loginForm] = await Promise.all([
    source("app/page.tsx"),
    source("app/login/page.tsx"),
    source("app/login/login-form.tsx"),
  ]);

  assert.match(home, /currentOwner/);
  assert.match(home, /redirect\("\/login"\)/);
  assert.doesNotMatch(home, /chatGPTSignInPath|signin-with-chatgpt/);

  assert.match(loginPage, /currentOwner/);
  assert.match(loginPage, /LoginForm/);
  assert.match(loginForm, /type="password"/);
  assert.match(loginForm, /\/api\/auth\/login/);
  assert.doesNotMatch(loginForm, /type="email"|name="email"/i);
});

test("login and logout routes set and clear the strict owner session cookie", async () => {
  const [login, logout] = await Promise.all([
    source("app/api/auth/login/route.ts"),
    source("app/api/auth/logout/route.ts"),
  ]);

  assert.match(login, /verifyOwnerPassword/);
  assert.match(login, /createOwnerSessionToken/);
  assert.match(login, /sessionCookie/);
  assert.match(login, /readBoundedJson/);
  assert.match(login, /cache-control/i);

  assert.match(logout, /expiredSessionCookie/);
  assert.match(logout, /mutationRequestIsSafe/);
  assert.match(logout, /set-cookie/i);
});

test("owner APIs await session-backed authorization without weakening same-origin checks", async () => {
  const [workspace, engineeringApi] = await Promise.all([
    source("app/api/workspace/route.ts"),
    source("lib/engineering-api.ts"),
  ]);

  assert.match(workspace, /owner-auth-server/);
  assert.match(workspace, /await authenticatedOwner\(request\)/);
  assert.match(workspace, /mutationRequestIsSafe/);

  assert.match(engineeringApi, /owner-auth-server/);
  assert.match(engineeringApi, /export async function ownerFor/);
  assert.match(engineeringApi, /await authenticatedOwner\(request\)/);
});

test("every engineering route awaits the asynchronous owner gate", async () => {
  const routes = [
    "app/api/chat/route.ts",
    "app/api/engineering/status/route.ts",
    "app/api/engineering/jobs/route.ts",
    "app/api/engineering/jobs/[id]/route.ts",
    "app/api/engineering/jobs/[id]/sources/route.ts",
    "app/api/engineering/jobs/[id]/cancel/route.ts",
    "app/api/engineering/jobs/[id]/decision/route.ts",
    "app/api/engineering/evidence/[id]/route.ts",
  ];
  const contents = await Promise.all(routes.map(source));
  for (let index = 0; index < routes.length; index += 1) {
    assert.match(contents[index], /await ownerFor\(request\)/, routes[index]);
  }
});

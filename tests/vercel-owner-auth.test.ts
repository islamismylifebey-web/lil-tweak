import test from "node:test";
import assert from "node:assert/strict";
import {
  authenticatedOwner,
  protectedVercelOwnerEmail,
} from "../lib/owner-auth.ts";

test("only the protected generated Vercel deployment can become owner", () => {
  const previous = process.env.VERCEL_URL;
  process.env.VERCEL_URL = "lil-tweak-abc123-galor-web-works.vercel.app";
  try {
    assert.equal(
      protectedVercelOwnerEmail("lil-tweak-abc123-galor-web-works.vercel.app"),
      "islamismylifebey@gmail.com",
    );
    assert.equal(
      authenticatedOwner(new Request("https://lil-tweak-abc123-galor-web-works.vercel.app/api/workspace")),
      "beythetruth4ever@paradigmshiftingthepodcast.net",
    );
    assert.equal(protectedVercelOwnerEmail("lil-tweak.vercel.app"), null);
    assert.equal(authenticatedOwner(new Request("https://lil-tweak.vercel.app/api/workspace")), null);
    assert.equal(protectedVercelOwnerEmail("lil-tweak-other-galor-web-works.vercel.app"), null);
  } finally {
    if (previous === undefined) delete process.env.VERCEL_URL;
    else process.env.VERCEL_URL = previous;
  }
});

test("the page recognizes the protected Vercel owner surface", async () => {
  const source = await (await import("node:fs/promises")).readFile(
    new URL("../app/chatgpt-auth.ts", import.meta.url),
    "utf8",
  );
  assert.match(source, /protectedVercelOwnerEmail/);
  assert.match(source, /requestHeaders\.get\("host"\)/);
});

import assert from "node:assert/strict";
import test from "node:test";

import { withBrowserSecurityHeaders } from "../lib/security-headers.ts";

test("prevents framing without weakening a route-specific CSP", async () => {
  const response = withBrowserSecurityHeaders(new Response("patch", {
    headers: { "Content-Security-Policy": "default-src 'none'; sandbox" },
  }));
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy") ?? "", /default-src 'none'; sandbox/);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(await response.text(), "patch");
});

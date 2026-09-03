export function withBrowserSecurityHeaders(response: Response) {
  const hardened = new Response(response.body, response);
  const existingPolicy = hardened.headers.get("Content-Security-Policy")?.trim();
  const framePolicy = "frame-ancestors 'none'";
  hardened.headers.set(
    "Content-Security-Policy",
    existingPolicy
      ? `${existingPolicy.replace(/;\s*$/, "")}; ${framePolicy}`
      : framePolicy,
  );
  hardened.headers.set("X-Frame-Options", "DENY");
  hardened.headers.set("Referrer-Policy", "no-referrer");
  return hardened;
}

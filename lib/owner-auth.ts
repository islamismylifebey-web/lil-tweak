// Keep the established D1 partition key so existing workspace records remain reachable.
// Login authorization is controlled separately by OWNER_IDENTITIES.
const CANONICAL_OWNER_KEY = "beythetruth4ever@paradigmshiftingthepodcast.net";
const PRIMARY_OWNER_EMAIL = "islamismylifebey@gmail.com";
const OWNER_IDENTITIES = new Set([PRIMARY_OWNER_EMAIL]);
const PROTECTED_VERCEL_DEPLOYMENT =
  /^lil-tweak-[a-z0-9]+-galor-web-works\.vercel\.app$/;

function normalizedHost(value: string | null | undefined) {
  return value?.trim().toLowerCase().replace(/:\d+$/, "") ?? "";
}

export function protectedVercelOwnerEmail(
  requestHost: string | null | undefined,
  deploymentHost = process.env.VERCEL_URL,
) {
  const host = normalizedHost(requestHost);
  const deployed = normalizedHost(deploymentHost);
  return host && host === deployed && PROTECTED_VERCEL_DEPLOYMENT.test(host)
    ? PRIMARY_OWNER_EMAIL
    : null;
}

export function ownerIdentityIsAllowed(value: string | null | undefined) {
  return OWNER_IDENTITIES.has(value?.trim().toLowerCase() ?? "");
}

export function authenticatedOwner(request: Request) {
  const forwardedId = request.headers.get("oai-authenticated-user-id")?.trim();
  const forwarded = request.headers
    .get("oai-authenticated-user-email")
    ?.trim()
    .toLowerCase();
  if (forwardedId && ownerIdentityIsAllowed(forwarded)) {
    return CANONICAL_OWNER_KEY;
  }
  return protectedVercelOwnerEmail(new URL(request.url).hostname)
    ? CANONICAL_OWNER_KEY
    : null;
}

export function mutationRequestIsSafe(request: Request) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  return origin === new URL(request.url).origin && (!fetchSite || fetchSite === "same-origin");
}

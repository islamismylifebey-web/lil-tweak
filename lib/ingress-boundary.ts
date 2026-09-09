export interface SiteIngressConfig {
  environment?: string;
  publicOrigin?: string;
}

function exactHttpsOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash
    ) return null;
    return url.origin === value ? value : null;
  } catch {
    return null;
  }
}

export async function enforceSiteIngress(
  request: Request,
  config: SiteIngressConfig,
): Promise<boolean> {
  const environment = config.environment?.trim() || "";
  if (!["development", "test", "production"].includes(environment)) {
    throw new Error("Site ingress configuration is invalid.");
  }
  if (environment !== "production") return true;
  const expectedOrigin = exactHttpsOrigin(config.publicOrigin);
  if (!expectedOrigin) {
    throw new Error("Site ingress configuration is incomplete.");
  }
  return new URL(request.url).origin === expectedOrigin;
}

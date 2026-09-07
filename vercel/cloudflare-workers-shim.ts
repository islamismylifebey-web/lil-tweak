// Vercel frontend build shim. Cloudflare bindings intentionally remain unavailable here.
// API paths that require D1/R2/core bindings fail closed instead of receiving fake state.
export const env: Record<string, never> = Object.freeze({});

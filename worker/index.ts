/** Cloudflare Worker entry point for Lil Tweak's owner-only control plane. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { enforceManagedIngress } from "../lib/ingress-boundary";
import { withBrowserSecurityHeaders } from "../lib/security-headers";

interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  FILES: R2Bucket;
  CORE_ORIGIN?: string;
  CORE_SIGNING_KEY_ID?: string;
  CORE_SIGNING_SECRET?: string;
  CORE_ACCESS_CLIENT_ID?: string;
  CORE_ACCESS_CLIENT_SECRET?: string;
  LIL_TWEAK_ENVIRONMENT?: string;
  PUBLIC_ORIGIN?: string;
  MANAGED_INGRESS_SECRET?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const allowed = await enforceManagedIngress(request, {
        environment: env.LIL_TWEAK_ENVIRONMENT,
        publicOrigin: env.PUBLIC_ORIGIN,
        managedIngressSecret: env.MANAGED_INGRESS_SECRET,
      });
      if (!allowed) {
        return withBrowserSecurityHeaders(new Response("Not found", {
          status: 404,
          headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
        }));
      }
    } catch (error) {
      console.error("Lil Tweak ingress configuration failed", error);
      return withBrowserSecurityHeaders(new Response("Service unavailable", {
        status: 503,
        headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
      }));
    }
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return withBrowserSecurityHeaders(await handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths));
    }

    return withBrowserSecurityHeaders(await handler.fetch(request, env, ctx));
  },
};

export default worker;

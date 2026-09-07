import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import vinext from "vinext";
import { nitro } from "nitro/vite";

const cloudflareWorkersShim = fileURLToPath(
  new URL("./vercel/cloudflare-workers-shim.ts", import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": cloudflareWorkersShim,
    },
  },
  plugins: [vinext(), nitro()],
});

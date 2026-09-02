import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest(({ inject }) => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          CONTROL_PLANE_BEARER_TOKEN: "test-control-token-not-operational",
          RUNNER_BEARER_TOKEN: "test-runner-token-not-operational",
          LIL_TWEAK_ATTESTATION_KEY_ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          LIL_TWEAK_ATTESTATION_PUBLIC_KEY: inject("testAttestationPublicKey"),
          TEST_ATTESTATION_PRIVATE_KEY: inject("testAttestationPrivateKey"),
          LIL_TWEAK_RUNNER_SIGNING_PUBLIC_KEY: inject("testRunnerSigningPublicKey"),
          TEST_RUNNER_SIGNING_PRIVATE_KEY: inject("testRunnerSigningPrivateKey"),
        },
      },
    })),
  ],
  test: {
    globalSetup: ["./test/global-setup.ts"],
  },
});

import "vitest";

declare module "vitest" {
  export interface ProvidedContext {
    testAttestationPublicKey: string;
    testAttestationPrivateKey: string;
    testRunnerSigningPublicKey: string;
    testRunnerSigningPrivateKey: string;
  }
}

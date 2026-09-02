import { webcrypto } from "node:crypto";

interface SetupContext {
  provide(key: string, value: unknown): void;
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export default async function ({ provide }: SetupContext): Promise<void> {
  for (const prefix of ["testAttestation", "testRunnerSigning"] as const) {
    const keyPair = await webcrypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    );
    if (!("publicKey" in keyPair)) {
      throw new Error("Ed25519 key generation did not produce a key pair");
    }
    const publicKey = new Uint8Array(
      await webcrypto.subtle.exportKey("raw", keyPair.publicKey),
    );
    const privateKey = new Uint8Array(
      await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    );
    provide(`${prefix}PublicKey`, base64Url(publicKey));
    provide(`${prefix}PrivateKey`, base64Url(privateKey));
  }
}

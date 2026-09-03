const repositoryRoot = new URL("../", import.meta.url);

export function resolve(specifier, context, nextResolve) {
  if (specifier === "cloudflare:workers") {
    return {
      url: "data:text/javascript,export const env=globalThis.__lilTweakWorkspaceTestEnv",
      shortCircuit: true,
    };
  }
  if (specifier.startsWith("@/")) {
    return {
      url: new URL(`${specifier.slice(2)}.ts`, repositoryRoot).href,
      shortCircuit: true,
    };
  }
  return nextResolve(specifier, context);
}

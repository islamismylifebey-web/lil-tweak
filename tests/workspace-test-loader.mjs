const repositoryRoot = new URL("../", import.meta.url);

export async function resolve(specifier, context, nextResolve) {
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
  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    if (
      error?.code === "ERR_MODULE_NOT_FOUND" &&
      specifier.startsWith(".") &&
      !/\.[A-Za-z0-9]+$/.test(specifier)
    ) {
      return nextResolve(`${specifier}.ts`, context);
    }
    throw error;
  }
}

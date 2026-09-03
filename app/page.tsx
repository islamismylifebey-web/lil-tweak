import { chatGPTSignInPath, chatGPTSignOutPath, getChatGPTUser } from "./chatgpt-auth";
import { PublicShell } from "./public-shell";
import { LilTweakWorkbench } from "./workbench";
import { ownerIdentityIsAllowed } from "@/lib/owner-auth";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await getChatGPTUser();
  if (!user) {
    return (
      <PublicShell
        signedIn={false}
        signInPath={chatGPTSignInPath("/")}
        signOutPath={chatGPTSignOutPath("/")}
      />
    );
  }

  if (!ownerIdentityIsAllowed(user.email)) {
    return (
      <PublicShell
        signedIn
        signInPath={chatGPTSignInPath("/")}
        signOutPath={chatGPTSignOutPath("/")}
      />
    );
  }

  return (
    <LilTweakWorkbench
      signedIn={Boolean(user)}
    />
  );
}

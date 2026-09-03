import { UdjatSignal } from "./udjat-signal";

type PublicShellProps = {
  signedIn: boolean;
  signInPath: string;
  signOutPath: string;
};

export function PublicShell({ signedIn, signInPath, signOutPath }: PublicShellProps) {
  return (
    <div className="public-shell" data-surface="lil-tweak-entry">
      <main className="public-entry" aria-labelledby="public-title">
        <UdjatSignal />
        <h1 id="public-title">Lil&apos;Tweak.AI</h1>
        <p className={signedIn ? "access-denied" : "access-private"} role={signedIn ? "alert" : "status"}>
          {signedIn ? "Not authorized" : "Private"}
        </p>
        <a className="primary-action" href={signedIn ? signOutPath : signInPath}>
          {signedIn ? "Switch account" : "Sign in"}
        </a>
      </main>
    </div>
  );
}

type PublicShellProps = {
  signedIn: boolean;
  signInPath: string;
  signOutPath: string;
};

export function PublicShell({ signedIn, signInPath, signOutPath }: PublicShellProps) {
  return (
    <div className="public-shell" data-surface="lil-tweak-entry">
      <main className="public-entry" aria-labelledby="public-title">
        <img className="public-entry-avatar" src="/icons/lil-tueeq-galor-icon.jpg" alt="Lil'Tweak.AI" />
        <span className="owner-access">Owner access</span>
        <h1 id="public-title">Enter Lil&apos;Tweak.AI</h1>
        <p className={signedIn ? "access-denied" : "access-private"} role={signedIn ? "alert" : "status"}>
          {signedIn ? "This account is not authorized." : "Your projects, source, and engineering work are protected."}
        </p>
        <a className="primary-action" href={signedIn ? signOutPath : signInPath}>
          {signedIn ? "Switch account" : "Open Lil'Tweak.AI"}
        </a>
        {!signedIn && <small>This device will stay securely signed in.</small>}
      </main>
    </div>
  );
}

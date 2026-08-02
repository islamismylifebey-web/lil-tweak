# Known Limitations

- The default command transport is deliberately disconnected.
- No Workbench execution provider is implemented. `QualifiedProcessTransport` is a dormant
  descriptor that always reports disconnected; a signed qualification decision, provider-owned
  sandbox enforcement, network enforcement, identity binding, and provider wiring must be authored
  and independently qualified before connection.
- Public Workbench task ingress is repository-only. The API does not accept a caller-constructed
  `TaskImport`, filesystem path, or clone URL. An opaque repository identity must already exist in
  `LILTWEAK_REPOSITORIES_JSON`; the server inspects it, captures dirty and untracked work, screens
  secrets, and creates the immutable Git-free task copy.
- Task, approval, run, and submission rows are authenticated and redundant database columns are
  cross-checked. Emergency-stop engage/reset actions have a separate authenticated control audit.
  These controls detect local mutation but do not replace a monotonic external anti-rollback
  checkpoint.
- Expired exact approvals can be reissued only through the authenticated, CSRF-protected task
  route. Emergency reset additionally requires fresh owner-key reauthentication, a disconnected
  runner, and only terminal tasks; neither action silently resumes canceled work.
- Recovery retention cleanup is not automatic in this increment.
- Sessions are single-owner and in-process rate limiting is not distributed.
- GCP execution is deferred and unavailable. Direct HTTP and Kubernetes clients are denied, and no
  runner is connected. The remaining GCP policy is defense in depth, not an activation path.
- The frontend uses a compact server-served application rather than a separately bundled framework.
- A real Chromium browser is unavailable on this build host, so browser-level keyboard, touch, and
  responsive acceptance remains pending even though static frontend and API tests pass.
- Applying a verified task patch to the owner repository and creating a local commit are not yet
  implemented as separate purpose-bound actions. Push and merge remain intentionally absent.
- Live model cost reconciliation remains estimated.
- Sol's independent GCP verification remains outside this candidate interface.

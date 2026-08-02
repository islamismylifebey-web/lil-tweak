# Known Limitations

- The default command transport is deliberately disconnected.
- QualifiedProcessTransport is a candidate adapter; production connection requires independent runner qualification and injection.
- Workbench source preparation is server-owned; the UI does not upload repositories. When a repository identity is supplied it must exist in `LILTWEAK_REPOSITORIES_JSON`; the builder must stage the corresponding immutable source in the dedicated task workspace and use the exact Workbench tree digest.
- Recovery retention cleanup is not automatic in this increment.
- Sessions are single-owner and in-process rate limiting is not distributed.
- GCP command policy is defense in depth, not a replacement for IAM, organization policy, budgets, and isolated credentials.
- The frontend uses a compact server-served application rather than a separately bundled framework.
- Live model cost reconciliation remains estimated.
- Sol's independent GCP verification remains outside this candidate interface.

# Live Acceptance Test

This procedure is for the builder after all offline tests succeed.

1. Start the API on localhost with model and runner disabled.
2. Verify the Workbench requires owner login and does not expose a prefilled email.
3. Verify cookies are HttpOnly, SameSite Strict, Secure on HTTPS, and mutation requests require CSRF.
4. Import an engineering task bound to a prepared disposable workspace.
5. Verify the status truthfully reports model and runner disconnected.
6. Inject only the approved fake model and fake transport in the test harness.
7. Exercise inspect, plan, approval, rejection, revision, exact approval, execution, tests, evidence export, submission, and lock.
8. Confirm changed source or plan invalidates approval.
9. Confirm emergency stop cancels active execution.
10. Confirm GCP policy tests use mocks only and make zero network or cloud calls.

Do not enable a paid provider, production runner, deployment, or GCP during this acceptance procedure.


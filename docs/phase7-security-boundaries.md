# Phase 7 Security Boundaries

## Threat model

Repository files, filenames, Git objects, tests, build scripts, dependencies, output, runner
responses, and concurrent source writers are hostile. The registered repository, other tenants,
credentials, state database, signing keys, host processes, sockets, and the integrity of
completion evidence are protected assets.

## Enforced in 0.7.0

- Only a server-owned recipe can become a plan.
- Plans bind job, organization, project, brief, route, exact commit, source manifest, configured
  immutable image-reference label, runtime profile, commands, limits, expiry, and prohibited
  authorities.
- Only a complete clean Git commit with no working-tree or ignored state is eligible.
- Snapshot materialization excludes `.git`, symlinks, special files, sensitive paths, and
  credential-shaped content.
- The registered repository is reverified before dispatch and is never mounted into the sandbox.
- Approval is exact, expiring, Founder-only, and atomically consumed once.
- Cancellation, terminal job state, and emergency stop are checked in the atomic claim.
- Command observations must be exact, complete, ordered, unique, bounded, and successful.
- Source before and after must equal the approved tree digest.
- Unexpected artifacts and unverified cleanup prohibit completion.
- Completed outcomes are digest-bound and HMAC-signed.
- Configuration, controller, and runner gates are conjunctive.
- The 0.7 Bubblewrap candidate is permanently unable to report connected.

## Connection gates not yet satisfied

The candidate adapter must not be treated as production isolation until a dedicated target proves:

- cgroup or equivalent hard CPU, memory, PID, disk, inode, and aggregate time limits;
- active cancellation and emergency-stop polling that kills the entire sandbox after dispatch;
- a non-forgeable, nonce-bound remote runner identity and attestation;
- mandatory access control and a reviewed syscall policy;
- denial of IPv4, IPv6, DNS, loopback services, metadata addresses, proxies, and host Unix
  sockets;
- denial of secret files, other repositories, host process environments, devices, container
  engines, SSH agents, and control-plane state;
- timeout, OOM, fork-bomb, output-flood, sleeping-child, and disk/inode-flood termination;
- crash recovery that reaps orphaned sandboxes without retrying an attempt;
- cleanup, process death, mount detachment, and destruction evidence;
- a separate descriptor-pinned, credential-scanned artifact pipeline before any artifact support.

## Required adversarial qualification

At minimum, a target runner must reject altered plan fields, substituted jobs or commits, stale
source, approval replay, concurrent claims, shell/interpreter evaluation, unsafe paths, symlinks,
special files, archive traversal, network clients, package installation, source writes, forged
observations, missing/reordered/extra observations, wrong source digests, replayed session
identifiers, cancellation races, emergency-stop races, cleanup failure, and resource floods.

Exactly one dispatch may result from concurrent approval consumers. A dispatch failure consumes
the attempt. No failure may become a completion claim.

## Current decision

`execution_connected=false` is mandatory for this build host. The Linux namespace probe failed
with `Operation not permitted`, and the remaining target-host gates above have not been run. This
is an enforced status, not a roadmap claim. A successful smoke probe on another host would still
leave the 0.7 candidate disconnected.

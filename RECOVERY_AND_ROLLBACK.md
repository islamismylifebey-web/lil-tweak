# Recovery and Rollback

The controller snapshots the dedicated task workspace before the first approved mutation. The snapshot is outside the task root and its path is not returned by the API. Snapshot digest and attempt are recorded as recovery evidence.

Rollback must be a separately approved operation in production. The workspace manager stages the snapshot, atomically swaps the task tree, removes the displaced tree, inventories the result, and records post-rollback verification.

Rollback does not erase evidence, approvals, or run records. It never rewrites the original registered repository. Failed rollback leaves the task failed and requires operator investigation.

Only after an approved rollback restores and hashes the immutable original source may the owner use Retry Eligible Step. Retry returns the task to ANALYZED; a revised plan and a new exact approval are still required.

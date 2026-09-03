"""Coherent byte and inode budgets shared by trusted-core boundaries."""

MIB = 1024 * 1024

# Maximum immutable evidence object accepted at trusted-core HTTP boundaries.
MAX_EVIDENCE_BYTES = 2 * MIB

# Uploaded archives and immutable Git trees must fit alongside their trusted
# baseline and final snapshots on the dedicated work-root tmpfs.
MAX_EXPANDED_SOURCE_BYTES = 128 * MIB

# The untrusted runner can create build products beyond the source tree, but its
# writable filesystem remains below one quarter of the runner's 1 GiB cgroup.
RUNNER_WORKSPACE_BYTES = 256 * MIB
RUNNER_WORKSPACE_INODES = 65_536

# Deployment mounts LIL_TWEAK_WORK_ROOT as a distinct tmpfs with exact capacity.
# The third tree slot is shared by patch candidate/old-proposal staging and
# final capture: reconciliation removes the former before allocating the latter.
# The reserve covers the shared lock, journals, patch files, snapshot directories,
# and bounded host bookkeeping.
TRUSTED_WORK_ROOT_BYTES = 1024 * MIB
TRUSTED_WORK_ROOT_TREE_SLOTS = 3
TRUSTED_WORK_ROOT_BOOKKEEPING_INODES = 8_192
TRUSTED_WORK_ROOT_INODES = (
    TRUSTED_WORK_ROOT_TREE_SLOTS * RUNNER_WORKSPACE_INODES
    + TRUSTED_WORK_ROOT_BOOKKEEPING_INODES
)

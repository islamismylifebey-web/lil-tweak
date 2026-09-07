import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.runtime_lock import (
    RUNTIME_PROBE_LATCH_NAME,
    RuntimeExecutionBusy,
    runtime_execution_lock,
)


class RuntimeExecutionLockTests(unittest.TestCase):
    def test_lock_is_validated_nonblocking_and_reusable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with runtime_execution_lock(root):
                lock = root / ".execution.lock"
                metadata = lock.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_nlink, 1)
                self.assertEqual(metadata.st_uid, os.getuid())
                self.assertEqual(metadata.st_gid, os.getgid())
                with self.assertRaisesRegex(
                    RuntimeExecutionBusy, "^runtime execution busy$"
                ):
                    with runtime_execution_lock(root):
                        self.fail("a second execution must never acquire the lock")

            with runtime_execution_lock(root):
                pass

            with self.assertRaisesRegex(ValueError, "^job failed$"):
                with runtime_execution_lock(root):
                    raise ValueError("job failed")

    def test_unprovable_lock_identity_fails_closed_without_details(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("not a lock", encoding="utf-8")
            (root / ".execution.lock").symlink_to(target)
            with self.assertRaisesRegex(
                RuntimeExecutionBusy, "^runtime execution busy$"
            ):
                with runtime_execution_lock(root):
                    pass

    def test_probe_latch_keeps_admission_closed_after_process_lock_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            latch = root / RUNTIME_PROBE_LATCH_NAME
            latch.write_text("lil-tweak-runtime-probe-v1\n", encoding="utf-8")
            latch.chmod(0o600)

            with self.assertRaisesRegex(
                RuntimeExecutionBusy, "^runtime execution busy$"
            ):
                with runtime_execution_lock(root):
                    pass


if __name__ == "__main__":
    unittest.main()

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.evidence import (
    EvidenceConflict,
    EvidenceTooLarge,
    LocalEvidenceStore,
    WorkspaceSnapshot,
    WorkspaceEvidenceError,
    R2EvidenceStore,
    SnapshotFile,
    build_command_evidence,
    build_edit_journal_evidence,
    build_evidence_bundle,
    build_workspace_patch,
    capture_workspace,
    workspace_changed_paths,
    workspace_delta_digest,
)
from core.lil_tweak.limits import MAX_EVIDENCE_BYTES


class EvidenceTests(unittest.TestCase):
    def test_capture_rejects_root_symlink_and_hardlinked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir()
            (actual / "one.txt").write_text("one")
            (actual / "two.txt").hardlink_to(actual / "one.txt")
            alias = root / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(WorkspaceEvidenceError, "workspace_root_symlink"):
                capture_workspace(alias)
            with self.assertRaisesRegex(WorkspaceEvidenceError, "workspace_hardlink"):
                capture_workspace(actual)

    def test_capture_counts_directories_against_inode_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one" / "two").mkdir(parents=True)
            with self.assertRaisesRegex(WorkspaceEvidenceError, "workspace_inode_limit"):
                capture_workspace(root, max_inodes=2)

    def test_capture_rejects_intermediate_directory_replacement_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "file.txt").write_text("safe")
            moved = root / "moved"

            def mutate(relative):
                if relative == "nested":
                    nested.rename(moved)
                    nested.symlink_to(moved, target_is_directory=True)

            with self.assertRaisesRegex(
                WorkspaceEvidenceError, "workspace_changed_during_snapshot"
            ):
                capture_workspace(root, _scan_hook=mutate)

    def test_capture_second_pass_rejects_same_size_nested_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            target = nested / "file.txt"
            target.write_text("old")
            changed = False

            def mutate(relative):
                nonlocal changed
                if relative == "nested" and not changed:
                    changed = True
                    target.write_text("new")

            with self.assertRaisesRegex(
                WorkspaceEvidenceError, "workspace_changed_during_snapshot"
            ):
                capture_workspace(root, _scan_hook=mutate)

    def test_changed_paths_delta_and_journal_are_host_deterministic(self):
        before = WorkspaceSnapshot(
            {"changed.txt": b"old\n", "gone.txt": b"gone\n"}, "a" * 64
        )
        after = WorkspaceSnapshot(
            {"changed.txt": b"new\n", "added.txt": b"added\n"}, "b" * 64
        )
        paths = workspace_changed_paths(before, after)
        self.assertEqual(paths, ("added.txt", "changed.txt", "gone.txt"))
        delta = workspace_delta_digest(before, after, paths)
        self.assertRegex(delta, r"^[0-9a-f]{64}$")
        entry = {
            "ordinal": 0,
            "before_source_digest": before.source_digest,
            "after_source_digest": after.source_digest,
            "actual_changed_paths": list(paths),
            "delta_digest": delta,
            "result": "promoted",
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
            "rejection_code": None,
        }
        first = build_edit_journal_evidence([entry])
        second = build_edit_journal_evidence([dict(reversed(list(entry.items())))])
        self.assertEqual(first, second)
        self.assertEqual(first["edit_journal_count"], 1)
        self.assertRegex(first["edit_journal_digest"], r"^[0-9a-f]{64}$")
        self.assertNotIn("patch", json.dumps(first))

    def test_edit_journal_rejects_oversize_instead_of_truncating_paths(self):
        entry = {
            "ordinal": 0,
            "before_source_digest": "a" * 64,
            "after_source_digest": "b" * 64,
            "actual_changed_paths": ["x" * 200],
            "delta_digest": "c" * 64,
            "result": "rejected",
            "exit_code": 1,
            "timed_out": False,
            "truncated": False,
            "rejection_code": "patch_exit_nonzero",
        }
        with self.assertRaisesRegex(WorkspaceEvidenceError, "edit_journal_too_large"):
            build_edit_journal_evidence([entry], max_bytes=64)

    def test_unchanged_binary_is_not_decoded_or_rejected(self):
        binary = b"\x00\xffsame"
        baseline = WorkspaceSnapshot({"asset.bin": binary}, "a" * 64)
        final = WorkspaceSnapshot({"asset.bin": binary}, "a" * 64)
        self.assertEqual(build_workspace_patch(baseline, final), b"")

    def test_r2_get_never_materializes_more_than_the_caller_limit(self):
        class Body:
            def __init__(self):
                self.read_size = None
                self.closed = False

            def read(self, size=None):
                self.read_size = size
                if size is None:
                    raise AssertionError("unbounded read")
                return b"x" * size

            def close(self):
                self.closed = True

        body = Body()

        class Client:
            def get_object(self, **_kwargs):
                return {"Body": body}

        with self.assertRaises(EvidenceTooLarge):
            R2EvidenceStore(Client(), "bucket").get("owner/job/plan.md", max_bytes=8)
        self.assertEqual(body.read_size, 9)
        self.assertTrue(body.closed)

    def test_workspace_snapshot_rejects_command_created_unsafe_path_before_copying(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as staging:
            root = Path(directory)
            (root / "a-safe.txt").write_bytes(b"safe\n")
            capture_workspace(root)
            (root / "z-bad\nname.txt").write_bytes(b"unsafe\n")

            with self.assertRaisesRegex(
                WorkspaceEvidenceError, "workspace_unsafe_path"
            ):
                capture_workspace(root, staging_root=staging)

            self.assertEqual(list(Path(staging).rglob("*")), [])

    def test_workspace_snapshot_rejects_sensitive_vcs_and_overdeep_paths(self):
        unsafe_paths = (
            ("empty VCS directory", (".git",)),
            ("sensitive file", (".env",)),
            ("overdeep directory", tuple("d" for _ in range(33))),
        )
        for label, parts in unsafe_paths:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root.joinpath(*parts)
                if label == "sensitive file":
                    target.write_bytes(b"SECRET=value\n")
                else:
                    target.mkdir(parents=True)

                with self.assertRaisesRegex(
                    WorkspaceEvidenceError, "workspace_unsafe_path"
                ):
                    capture_workspace(root)

    def test_workspace_snapshot_rejects_casefold_path_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Readme.md").write_bytes(b"first\n")
            capture_workspace(root)
            (root / "README.MD").write_bytes(b"second\n")

            with self.assertRaisesRegex(
                WorkspaceEvidenceError, "workspace_path_collision"
            ):
                capture_workspace(root)

    def test_workspace_snapshot_can_stream_to_bounded_staging_files(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as staging:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "main.py").write_bytes(b"print('ok')\n")
            memory = capture_workspace(root)
            streamed = capture_workspace(root, staging_root=staging)
            self.assertEqual(streamed.source_digest, memory.source_digest)
            value = streamed.files["src/main.py"]
            self.assertIsInstance(value, SnapshotFile)
            self.assertEqual(value.path.read_bytes(), b"print('ok')\n")
            self.assertEqual(build_workspace_patch(streamed, memory), b"")

    def test_r2_immutable_retry_accepts_only_identical_existing_bytes(self):
        class Conflict(Exception):
            response = {"ResponseMetadata": {"HTTPStatusCode": 412}}

        class Client:
            def put_object(self, **kwargs):
                raise Conflict()

            def get_object(self, **kwargs):
                import io

                return {"Body": io.BytesIO(b"same")}

        stored = R2EvidenceStore(Client(), "bucket").put("owner/job/plan.md", b"same")
        self.assertEqual(stored.sha256, hashlib.sha256(b"same").hexdigest())

    def test_bundle_contains_required_artifacts_and_verified_hashes(self):
        bundle = build_evidence_bundle(
            plan="# Plan\nDo one thing.\n",
            patch="diff --git a/a b/a\n",
            tests="1 test passed\n",
            summary="# Summary\nDone.\n",
            metadata={
                "commands": [["python", "-m", "unittest"]],
                "limits": {"cpus": 1},
                "exit_statuses": [0],
                "started_at": "2026-08-13T00:00:00Z",
                "finished_at": "2026-08-13T00:00:01Z",
            },
        )
        self.assertEqual(
            set(bundle.files),
            {"plan.md", "changes.patch", "tests.log", "summary.md", "manifest.json"},
        )
        manifest = json.loads(bundle.files["manifest.json"])
        for name in ("plan.md", "changes.patch", "tests.log", "summary.md"):
            expected = hashlib.sha256(bundle.files[name]).hexdigest()
            self.assertEqual(manifest["artifacts"][name]["sha256"], expected)
            self.assertEqual(manifest["artifacts"][name]["bytes"], len(bundle.files[name]))

    def test_proposal_digest_is_deterministic_and_changes_with_artifact(self):
        args = dict(
            plan="plan",
            patch="patch",
            tests="tests",
            summary="summary",
            metadata={"commands": [], "limits": {}, "exit_statuses": []},
        )
        first = build_evidence_bundle(**args)
        second = build_evidence_bundle(**args)
        changed = build_evidence_bundle(**{**args, "patch": "changed"})
        self.assertEqual(first.proposal_digest, second.proposal_digest)
        self.assertNotEqual(first.proposal_digest, changed.proposal_digest)

    def test_bundle_accepts_every_artifact_at_cross_plane_limit(self):
        exact = b"x" * MAX_EVIDENCE_BYTES
        artifacts = {
            "plan": "plan.md",
            "patch": "changes.patch",
            "tests": "tests.log",
            "summary": "summary.md",
        }
        for argument, filename in artifacts.items():
            with self.subTest(filename=filename):
                inputs = {name: b"" for name in artifacts}
                inputs[argument] = exact
                bundle = build_evidence_bundle(**inputs)
                self.assertEqual(len(bundle.files[filename]), MAX_EVIDENCE_BYTES)

    def test_bundle_rejects_every_artifact_one_byte_above_cross_plane_limit(self):
        oversized = b"x" * (MAX_EVIDENCE_BYTES + 1)
        artifacts = {
            "plan": "plan.md",
            "patch": "changes.patch",
            "tests": "tests.log",
            "summary": "summary.md",
        }
        for argument, filename in artifacts.items():
            with self.subTest(filename=filename):
                inputs = {name: b"" for name in artifacts}
                inputs[argument] = oversized
                with self.assertRaisesRegex(
                    WorkspaceEvidenceError, "evidence_artifact_too_large"
                ):
                    build_evidence_bundle(**inputs)

    def test_bundle_limit_counts_encoded_utf8_bytes(self):
        exact = "é" * (MAX_EVIDENCE_BYTES // 2)
        bundle = build_evidence_bundle(plan=exact, patch="", tests="", summary="")
        self.assertEqual(len(bundle.files["plan.md"]), MAX_EVIDENCE_BYTES)
        with self.assertRaisesRegex(
            WorkspaceEvidenceError, "evidence_artifact_too_large"
        ):
            build_evidence_bundle(plan=exact + "a", patch="", tests="", summary="")

    def test_bundle_manifest_accepts_exact_limit_and_rejects_one_more_byte(self):
        inputs = {"plan": b"", "patch": b"", "tests": b"", "summary": b""}
        probe = build_evidence_bundle(**inputs, metadata={"padding": ""})
        padding = MAX_EVIDENCE_BYTES - len(probe.files["manifest.json"])
        exact = build_evidence_bundle(
            **inputs, metadata={"padding": "x" * padding}
        )
        self.assertEqual(len(exact.files["manifest.json"]), MAX_EVIDENCE_BYTES)
        with self.assertRaisesRegex(WorkspaceEvidenceError, "manifest_too_large"):
            build_evidence_bundle(
                **inputs, metadata={"padding": "x" * (padding + 1)}
            )
        with self.assertRaisesRegex(WorkspaceEvidenceError, "manifest_too_large"):
            build_evidence_bundle(
                **inputs,
                metadata={"padding": "x" * (padding + 1)},
                max_manifest_bytes=MAX_EVIDENCE_BYTES + 1,
            )

    def test_manifest_fails_closed_above_cross_plane_limit(self):
        with self.assertRaisesRegex(WorkspaceEvidenceError, "manifest_too_large"):
            build_evidence_bundle(
                plan="",
                patch="",
                tests="",
                summary="",
                metadata={"oversized": "x" * MAX_EVIDENCE_BYTES},
            )

    def test_local_store_is_immutable_and_verifies_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalEvidenceStore(directory)
            digest = hashlib.sha256(b"artifact").hexdigest()
            stored = store.put("owner/job/summary.md", b"artifact", digest)
            self.assertEqual(stored.sha256, digest)
            self.assertEqual(store.get("owner/job/summary.md"), b"artifact")
            with self.assertRaises(EvidenceConflict):
                store.put("owner/job/summary.md", b"changed")
            with self.assertRaises(ValueError):
                store.put("owner/job/bad.md", b"artifact", "0" * 64)
            with self.assertRaises(ValueError):
                store.put("../escape", b"bad")
            self.assertFalse((Path(directory).parent / "escape").exists())

    def test_bounded_log_still_reports_every_observed_command(self):
        observations = [
            {
                "command": ["python", "first.py"],
                "exit_code": 0,
                "timed_out": False,
                "truncated": False,
                "stdout": "first output",
                "stderr": "",
            },
            {
                "command": ["python", "second.py"],
                "exit_code": None,
                "timed_out": True,
                "truncated": False,
                "stdout": "",
                "stderr": "second timeout",
            },
        ]
        log, metadata = build_command_evidence(observations, max_bytes=1)
        self.assertEqual(len(log), 1)
        self.assertEqual(
            metadata,
            {
                "commands": [["python", "first.py"], ["python", "second.py"]],
                "command_hashes": [
                    hashlib.sha256(b'["python","first.py"]').hexdigest(),
                    hashlib.sha256(b'["python","second.py"]').hexdigest(),
                ],
                "commands_digest": hashlib.sha256(
                    json.dumps(
                        [
                            hashlib.sha256(b'["python","first.py"]').hexdigest(),
                            hashlib.sha256(b'["python","second.py"]').hexdigest(),
                        ],
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
                "argv_truncated": [False, False],
                "operations": ["run_command", "run_command"],
                "exit_statuses": [0, None],
                "timeouts": [False, True],
                "truncation": [True, True],
            },
        )

    def test_command_argv_metadata_is_redacted_hashed_and_bounded(self):
        secret = "super-secret-value"
        observations = [
            {
                "operation": "run_command",
                "command": [
                    "python",
                    "--api-key",
                    secret,
                    "x" * 100_000,
                ],
                "exit_code": 0,
                "timed_out": False,
                "truncated": False,
                "stdout": "",
                "stderr": "",
            }
        ]
        log, metadata = build_command_evidence(observations)
        encoded = json.dumps(metadata, sort_keys=True).encode()
        self.assertNotIn(secret.encode(), encoded + log)
        self.assertLess(len(encoded), 8 * 1024)
        self.assertTrue(metadata["argv_truncated"])
        self.assertRegex(metadata["command_hashes"][0], r"^[0-9a-f]{64}$")
        self.assertRegex(metadata["commands_digest"], r"^[0-9a-f]{64}$")

    def test_workspace_patch_preserves_missing_final_newline(self):
        baseline = WorkspaceSnapshot({"file.txt": b"before"}, "a" * 64)
        final = WorkspaceSnapshot({"file.txt": b"after"}, "b" * 64)
        patch = build_workspace_patch(baseline, final)
        self.assertIn(
            b"-before\n\\ No newline at end of file\n"
            b"+after\n\\ No newline at end of file\n",
            patch,
        )

    def test_workspace_patch_stops_before_loading_later_snapshot_after_limit(self):
        missing = Path("/definitely/not/a/snapshot")
        baseline = WorkspaceSnapshot(
            {
                "a.txt": b"before\n",
                "z.txt": SnapshotFile(missing, 1, "0" * 64),
            },
            "a" * 64,
        )
        final = WorkspaceSnapshot(
            {
                "a.txt": (b"after" * 100) + b"\n",
                "z.txt": SnapshotFile(missing, 2, "1" * 64),
            },
            "b" * 64,
        )

        with self.assertRaisesRegex(WorkspaceEvidenceError, "patch_too_large"):
            build_workspace_patch(baseline, final, max_bytes=64)

    def test_binary_workspace_change_fails_closed(self):
        baseline = WorkspaceSnapshot({"image.bin": b"\x00old"}, "a" * 64)
        final = WorkspaceSnapshot({"image.bin": b"\x00new"}, "b" * 64)
        with self.assertRaisesRegex(
            WorkspaceEvidenceError, "binary_change_unsupported"
        ):
            build_workspace_patch(baseline, final)

    def test_invalid_utf8_workspace_change_fails_closed(self):
        baseline = WorkspaceSnapshot({"asset.dat": b"plain"}, "a" * 64)
        final = WorkspaceSnapshot({"asset.dat": b"\xff\xfe"}, "b" * 64)
        with self.assertRaisesRegex(
            WorkspaceEvidenceError, "binary_change_unsupported"
        ):
            build_workspace_patch(baseline, final)


if __name__ == "__main__":
    unittest.main()

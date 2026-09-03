import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.lil_tweak.contracts import JobMode
from core.lil_tweak.evidence import WorkspaceEvidenceError, capture_workspace
from core.lil_tweak.openai_agent import (
    AgentLimitError,
    AgentDeadlineError,
    AgentProtocolError,
    PromotionRecoveryRequired,
    CodeEngineer,
    DEFAULT_INSTRUCTIONS,
    ResponsesClient,
    TOOL_SCHEMAS,
    WorkspaceTools,
    _canonical_promotion_marker,
    _canonical_json,
    _validate_tool_arguments,
    cleanup_patch_remnants,
    reconcile_promotion_markers,
    load_reviewed_instructions,
)
from core.lil_tweak.sandbox import CommandResult


class FakeResponsesClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def create(self, **request):
        self.requests.append(request)
        return self.responses.pop(0)


class RecordingTools:
    def __init__(self):
        self.calls = []

    def execute(self, name, arguments):
        self.calls.append((name, arguments))
        return {"content": "hello"}


class AgentLoopTests(unittest.TestCase):
    def test_promotion_recovery_error_from_tool_is_fatal_to_agent_loop(self):
        class RecoveryTools:
            def execute(self, name, arguments):
                raise PromotionRecoveryRequired("patch_reconciliation_required")

        client = FakeResponsesClient(
            [
                {
                    "id": "recovery",
                    "status": "completed",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "call-1",
                            "name": "apply_patch",
                            "arguments": json.dumps({"patch": "patch"}),
                        }
                    ],
                }
            ]
        )
        with self.assertRaises(PromotionRecoveryRequired):
            CodeEngineer(client, RecoveryTools(), model="test-model").run(
                mode=JobMode.BUILD, prompt="Edit", source_inventory=[]
            )

    def test_agent_contract_explains_scratch_only_commands_and_patch_persistence(self):
        descriptions = {tool["name"]: tool["description"] for tool in TOOL_SCHEMAS}
        for text in (
            descriptions["run_command"],
            descriptions["apply_patch"],
            DEFAULT_INSTRUCTIONS,
            (Path(__file__).parents[1] / "prompts" / "code_engineer.md").read_text(),
        ):
            self.assertIn("scratch-only", text)
            self.assertIn("apply_patch", text)

    def test_tool_output_truncation_remains_valid_byte_bounded_json(self):
        for value in ("💥\\\n" * 10_000, "\x00\x01\"" * 10_000):
            with self.subTest(prefix=value[:3]):
                encoded = _canonical_json({"value": value}, 256)
                self.assertLessEqual(len(encoded.encode("utf-8")), 256)
                parsed = json.loads(encoded)
                self.assertEqual(parsed["error"], "tool_output_truncated")

    def test_reviewed_instructions_are_loaded_from_a_bounded_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            prompt = Path(directory) / "code_engineer.md"
            prompt.write_text("reviewed prompt\n")
            self.assertEqual(load_reviewed_instructions(prompt), "reviewed prompt\n")
            prompt.write_text("x" * 33)
            with self.assertRaises(ValueError):
                load_reviewed_instructions(prompt, max_bytes=32)

    def test_model_timeout_is_classified_as_job_deadline(self):
        class TimeoutClient:
            def create(self, **request):
                raise TimeoutError("request timed out")

        with self.assertRaises(AgentDeadlineError):
            CodeEngineer(TimeoutClient(), RecordingTools(), model="test-model").run(
                mode=JobMode.BUILD,
                prompt="Build",
                source_inventory=[],
                deadline=100,
                monotonic=lambda: 10,
            )

    def test_chat_rejects_unsolicited_tool_call_without_execution(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "chat-tool",
                    "status": "completed",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "call-1",
                            "name": "read_file",
                            "arguments": '{"path":"README.md"}',
                        }
                    ],
                }
            ]
        )
        tools = RecordingTools()
        with self.assertRaises(AgentProtocolError):
            CodeEngineer(client, tools, model="test-model").run(
                mode=JobMode.CHAT,
                prompt="Answer only",
                source_inventory=[],
            )
        self.assertEqual(tools.calls, [])

    def test_expired_job_deadline_prevents_model_call(self):
        client = FakeResponsesClient([])
        engineer = CodeEngineer(client, RecordingTools(), model="test-model")
        with self.assertRaises(AgentDeadlineError):
            engineer.run(
                mode=JobMode.BUILD,
                prompt="Build",
                source_inventory=[],
                deadline=10,
                monotonic=lambda: 10,
            )
        self.assertEqual(client.requests, [])

    def test_selected_project_context_is_in_initial_request(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "response",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": json.dumps(
                                        {
                                            "plan": "Answer",
                                            "summary": "Done",
                                            "tests": "",
                                            "patch": "",
                                            "external_action": None,
                                        }
                                    ),
                                }
                            ],
                        }
                    ],
                }
            ]
        )
        engineer = CodeEngineer(client, RecordingTools(), model="test-model")
        engineer.run(
            mode=JobMode.CHAT,
            prompt="What is next?",
            source_inventory=[],
            project_context={
                "schemaVersion": "project-context-v1",
                "projectId": "project:one",
                "name": "One",
            },
        )
        initial = json.loads(client.requests[0]["input"][0]["content"])
        self.assertEqual(initial["project_context"]["projectId"], "project:one")

    def test_initial_inventory_is_bounded_by_entries_and_utf8_bytes(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "response",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"Inspect","summary":"Done","tests":"","patch":"","external_action":null}',
                                }
                            ],
                        }
                    ],
                }
            ]
        )
        inventory = [f"src/{index:05d}-" + ("x" * 100) for index in range(5_000)]
        CodeEngineer(client, RecordingTools(), model="test-model").run(
            mode=JobMode.BUILD,
            prompt="Inspect",
            source_inventory=inventory,
        )
        initial = json.loads(client.requests[0]["input"][0]["content"])
        included = initial["source_inventory"]
        metadata = initial["source_inventory_meta"]
        self.assertLessEqual(len(included), 2_000)
        self.assertLessEqual(
            sum(len(path.encode("utf-8")) + 1 for path in included),
            64 * 1024,
        )
        self.assertEqual(metadata["providedEntries"], 5_000)
        self.assertEqual(metadata["includedEntries"], len(included))
        self.assertEqual(
            metadata["includedUtf8Bytes"],
            sum(len(path.encode("utf-8")) + 1 for path in included),
        )
        self.assertTrue(metadata["truncated"])

    def test_tool_call_is_executed_and_continued_by_response_id(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "resp-1",
                    "status": "completed",
                    "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "call-1",
                            "name": "read_file",
                            "arguments": '{"path":"README.md"}',
                        }
                    ],
                },
                {
                    "id": "resp-2",
                    "status": "completed",
                    "usage": {"input_tokens": 20, "output_tokens": 7, "total_tokens": 27},
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": json.dumps(
                                        {
                                            "plan": "Inspect and fix.",
                                            "summary": "Fixed.",
                                            "tests": "Tests passed.",
                                        }
                                    ),
                                }
                            ],
                        }
                    ],
                },
            ]
        )
        tools = RecordingTools()
        result = CodeEngineer(client, tools, model="fake-model").run(
            mode=JobMode.DEBUG,
            prompt="Fix the bug",
            source_inventory=["README.md"],
        )

        self.assertEqual(tools.calls, [("read_file", {"path": "README.md"})])
        self.assertEqual(
            client.requests[1]["input"],
            [
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "mode": "debug",
                            "request": "Fix the bug",
                            "source_inventory": ["README.md"],
                            "source_inventory_meta": {
                                "providedEntries": 1,
                                "includedEntries": 1,
                                "includedUtf8Bytes": 10,
                                "truncated": False,
                            },
                            "project_context": {},
                            "policy": {
                                "network": "disabled",
                                "external_actions": "proposal_only",
                                "max_tool_rounds": 40,
                                "max_tool_calls": 128,
                            },
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                },
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "read_file",
                    "arguments": '{"path":"README.md"}',
                },
                {
                    "type": "function_call_output",
                    "call_id": "call-1",
                    "output": '{"content":"hello"}',
                }
            ],
        )
        self.assertEqual(result.summary, "Fixed.")
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(result.input_tokens, 30)
        self.assertEqual(result.output_tokens, 12)
        self.assertEqual(result.total_tokens, 42)
        for request in client.requests:
            self.assertEqual(request["max_output_tokens"], 32_000)
            self.assertTrue(request["text"]["format"]["strict"])
            self.assertEqual(request["text"]["format"]["type"], "json_schema")

    def test_stateless_tool_continuation_replays_every_response_output_item(self):
        reasoning = {
            "id": "reasoning-1",
            "type": "reasoning",
            "encrypted_content": "opaque-reasoning-sentinel",
            "summary": [{"type": "summary_text", "text": "Inspect first."}],
        }
        function_call = {
            "id": "function-1",
            "type": "function_call",
            "status": "completed",
            "call_id": "call-1",
            "name": "read_file",
            "arguments": '{"path":"README.md"}',
        }
        client = FakeResponsesClient(
            [
                {
                    "id": "resp-1",
                    "status": "completed",
                    "output": [reasoning, function_call],
                },
                {
                    "id": "resp-2",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"Inspect","summary":"Done","tests":"passed","patch":"","external_action":null}',
                                }
                            ],
                        }
                    ],
                },
            ]
        )

        CodeEngineer(client, RecordingTools(), model="fake-model").run(
            mode=JobMode.DEBUG,
            prompt="Fix the bug",
            source_inventory=["README.md"],
        )

        replay = client.requests[1]["input"]
        self.assertEqual(replay[-3:], [
            reasoning,
            function_call,
            {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": '{"content":"hello"}',
            },
        ])

    def test_responses_client_forwards_to_injected_sdk_without_live_call(self):
        class Responses:
            def __init__(self):
                self.request = None

            def create(self, **request):
                self.request = request
                return {"id": "response"}

        class Sdk:
            def __init__(self):
                self.responses = Responses()

        sdk = Sdk()
        result = ResponsesClient(sdk=sdk).create(model="fake", input=[])
        self.assertEqual(result, {"id": "response"})
        self.assertEqual(sdk.responses.request, {"model": "fake", "input": []})

    def test_chat_mode_exposes_no_executable_tools(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "resp-chat",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"Explain","summary":"Answer","tests":"not run"}',
                                }
                            ],
                        }
                    ],
                }
            ]
        )
        CodeEngineer(client, RecordingTools(), model="fake").run(
            mode=JobMode.CHAT,
            prompt="Explain",
            source_inventory=["README.md"],
        )
        self.assertEqual(client.requests[0]["tools"], [])

    def test_incomplete_and_refusal_responses_fail_closed(self):
        cases = (
            {"id": "incomplete", "status": "incomplete", "output": []},
            {
                "id": "refused",
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "no"}],
                    }
                ],
            },
        )
        for response in cases:
            with self.subTest(response=response["id"]):
                with self.assertRaisesRegex(Exception, "response"):
                    CodeEngineer(
                        FakeResponsesClient([response]), RecordingTools(), model="fake"
                    ).run(mode=JobMode.CHAT, prompt="Explain", source_inventory=[])

    def test_invalid_tool_arguments_return_bounded_error_to_model(self):
        client = FakeResponsesClient(
            [
                {
                    "id": "resp-1",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "bad",
                            "name": "run_command",
                            "arguments": '{"command":"rm -rf /"}',
                        }
                    ],
                },
                {
                    "id": "resp-2",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"none","summary":"stopped","tests":"none"}',
                                }
                            ],
                        }
                    ],
                },
            ]
        )
        tools = RecordingTools()
        CodeEngineer(client, tools, model="fake").run(
            mode=JobMode.BUILD, prompt="Build", source_inventory=[]
        )
        output = json.loads(client.requests[1]["input"][-1]["output"])
        self.assertEqual(output["error"], "invalid_tool_arguments")
        self.assertEqual(tools.calls, [])

    def test_maximum_rounds_stops_an_unbounded_tool_loop(self):
        responses = [
            {
                "id": f"resp-{index}",
                "output": [
                    {
                        "type": "function_call",
                        "call_id": f"call-{index}",
                        "name": "list_files",
                        "arguments": "{}",
                    }
                ],
            }
            for index in range(3)
        ]
        with self.assertRaises(AgentLimitError):
            CodeEngineer(
                FakeResponsesClient(responses), RecordingTools(), model="fake", max_rounds=2
            ).run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])

    def test_final_model_round_tool_call_is_refused_before_execution(self):
        response = {
            "id": "last-round-tool",
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "apply_patch",
                    "arguments": '{"patch":"persistent-side-effect-sentinel"}',
                }
            ],
        }
        tools = RecordingTools()

        with self.assertRaisesRegex(AgentLimitError, "maximum tool rounds"):
            CodeEngineer(
                FakeResponsesClient([response]),
                tools,
                model="fake",
                max_rounds=1,
            ).run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])
        self.assertEqual(tools.calls, [])

    def test_many_tool_calls_in_one_response_stop_at_total_call_budget(self):
        response = {
            "id": "many-tools",
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "call_id": f"call-{index}",
                    "name": "list_files",
                    "arguments": '{"path":null,"max_entries":1}',
                }
                for index in range(10)
            ],
        }
        tools = RecordingTools()
        engineer = CodeEngineer(
            FakeResponsesClient([response]),
            tools,
            model="fake",
            max_tool_calls=2,
        )
        with self.assertRaises(AgentLimitError):
            engineer.run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])
        self.assertEqual(tools.calls, [])

    def test_later_oversize_response_item_prevents_earlier_tool_execution(self):
        response = {
            "id": "late-oversize",
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "list_files",
                    "arguments": '{"path":null,"max_entries":1}',
                },
                {
                    "type": "reasoning",
                    "encrypted_content": "x" * 1_000,
                    "summary": [],
                },
            ],
        }
        tools = RecordingTools()
        engineer = CodeEngineer(
            FakeResponsesClient([response]),
            tools,
            model="fake",
            max_tool_output_bytes=1,
            max_tool_history_bytes=512,
        )

        with self.assertRaises(AgentLimitError):
            engineer.run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])
        self.assertEqual(tools.calls, [])

    def test_default_history_budget_accepts_three_tiny_tool_calls(self):
        calls = [
            {
                "type": "function_call",
                "call_id": f"call-{index}",
                "name": "list_files",
                "arguments": "{}",
            }
            for index in range(3)
        ]
        client = FakeResponsesClient(
            [
                {"id": "three-tools", "status": "completed", "output": calls},
                {
                    "id": "done",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"Inspect","summary":"Done","tests":"passed","patch":"","external_action":null}',
                                }
                            ],
                        }
                    ],
                },
            ]
        )
        tools = RecordingTools()

        CodeEngineer(client, tools, model="fake").run(
            mode=JobMode.BUILD, prompt="Build", source_inventory=[]
        )

        self.assertEqual(len(tools.calls), 3)
        self.assertEqual(client.requests[1]["input"][-6:-3], calls)

    def test_history_reservation_bounds_nested_json_escaping_tightly(self):
        max_output_bytes = 64
        function_call = {
            "type": "function_call",
            "call_id": 'call-"-\\-\u0000-\n',
            "name": "list_files",
            "arguments": "{}",
        }
        assistant_size = len(
            json.dumps(
                function_call,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        empty_output_size = len(
            json.dumps(
                {
                    "type": "function_call_output",
                    "call_id": function_call["call_id"],
                    "output": "",
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        history_limit = assistant_size + empty_output_size + 2 * max_output_bytes

        class EscapingTools:
            def execute(self, name, arguments):
                return {"content": ('"\\\b\f\n\r\t' * 100)}

        client = FakeResponsesClient(
            [
                {
                    "id": "escaped-tool",
                    "status": "completed",
                    "output": [function_call],
                },
                {
                    "id": "done",
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": '{"plan":"Inspect","summary":"Done","tests":"passed","patch":"","external_action":null}',
                                }
                            ],
                        }
                    ],
                },
            ]
        )

        CodeEngineer(
            client,
            EscapingTools(),
            model="fake",
            max_tool_output_bytes=max_output_bytes,
            max_tool_history_bytes=history_limit,
        ).run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])

        retained = client.requests[1]["input"][-2:]
        retained_size = sum(
            len(
                json.dumps(
                    item,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            for item in retained
        )
        self.assertLessEqual(retained_size, history_limit)

    def test_oversize_tool_history_is_refused_before_tool_execution(self):
        response = {
            "id": "oversize-tool",
            "status": "completed",
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call-large",
                    "name": "read_file",
                    "arguments": json.dumps({"path": "x" * 1_000}),
                }
            ],
        }
        tools = RecordingTools()
        engineer = CodeEngineer(
            FakeResponsesClient([response]),
            tools,
            model="fake",
            max_tool_output_bytes=64,
            max_tool_history_bytes=256,
        )
        with self.assertRaises(AgentLimitError):
            engineer.run(mode=JobMode.BUILD, prompt="Build", source_inventory=[])
        self.assertEqual(tools.calls, [])


class WorkspaceToolTests(unittest.TestCase):
    def test_promotion_marker_version_rejects_bool_and_float(self):
        value = {
            "schema": "lil-tweak-promotion",
            "version": 1,
            "workspace": "proposal",
            "candidate": ".proposal-candidate-deadbeef",
            "before": {"dev": 1, "ino": 2, "source_digest": "0" * 64},
            "after": {"dev": 1, "ino": 3, "source_digest": "1" * 64},
            "delta_digest": "2" * 64,
            "journal_entry_digest": "3" * 64,
        }
        for invalid in (True, 1.0):
            with self.subTest(version=invalid), self.assertRaises(
                PromotionRecoveryRequired
            ):
                _canonical_promotion_marker({**value, "version": invalid})

        for invalid_after in (
            {"dev": 2, "ino": 3, "source_digest": "1" * 64},
            {"dev": 1, "ino": 2, "source_digest": "1" * 64},
            {"dev": True, "ino": 3, "source_digest": "1" * 64},
            {"dev": 1, "ino": -1, "source_digest": "1" * 64},
            {"dev": 1, "ino": 3, "source_digest": "not-a-digest"},
        ):
            with self.subTest(after=invalid_after), self.assertRaises(
                PromotionRecoveryRequired
            ):
                _canonical_promotion_marker({**value, "after": invalid_after})

    def test_final_capture_holds_patch_lock_and_removes_candidate_before_staging(self):
        class LockedTools(WorkspaceTools):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.lock_depth = 0

            def _patch_lock(self):
                outer = super()._patch_lock()

                class Lock:
                    def __enter__(lock_self):
                        outer.__enter__()
                        self.lock_depth += 1

                    def __exit__(lock_self, *exc):
                        self.lock_depth -= 1
                        return outer.__exit__(*exc)

                return Lock()

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            baseline = capture_workspace(root)
            candidate = parent / ".proposal-candidate-deadbeef"
            candidate.mkdir()
            (candidate / "scratch.txt").write_text("scratch\n")
            final_stage = parent / ".snapshots" / "job" / "final"
            tools = LockedTools(root, None)
            original_capture = capture_workspace
            staging_observations = []

            def observing_capture(path, **kwargs):
                if kwargs.get("staging_root") is not None:
                    staging_observations.append(
                        (tools.lock_depth, candidate.exists(), final_stage.exists())
                    )
                return original_capture(path, **kwargs)

            with patch(
                "core.lil_tweak.openai_agent.capture_workspace",
                side_effect=observing_capture,
            ):
                final = tools.capture_final_snapshot(baseline, final_stage)

            self.assertEqual(final.source_digest, baseline.source_digest)
            self.assertEqual(staging_observations, [(1, False, False)])
            self.assertFalse(candidate.exists())

    def test_patch_remnant_cleanup_is_job_scoped_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / ".job-candidate-deadbeef"
            candidate.mkdir()
            (candidate / "old.txt").write_text("old")
            raw_patch = root / ".job-patch-deadbeef.diff"
            raw_patch.write_text("secret model patch")
            marker_temp = root / ".job-promotion-tmp-deadbeef"
            marker_temp.write_text("torn marker")
            other = root / ".other-candidate-livefeed"
            other.mkdir()

            cleanup_patch_remnants(root, workspace_name="job")

            self.assertFalse(candidate.exists())
            self.assertFalse(raw_patch.exists())
            self.assertFalse(marker_temp.exists())
            self.assertTrue(other.exists())

            blocked = root / ".job-candidate-blocked0"
            blocked.mkdir()
            with self.assertRaisesRegex(PromotionRecoveryRequired, "patch_cleanup_failed"):
                cleanup_patch_remnants(
                    root,
                    workspace_name="job",
                    tree_remove=lambda _path: (_ for _ in ()).throw(OSError("busy")),
                )
            self.assertTrue(blocked.exists())

    def test_observation_budget_refuses_before_more_commands_execute(self):
        class Limits:
            max_output_bytes = 16

        class Sandbox:
            limits = Limits()

            def __init__(self):
                self.calls = 0

            def run_ephemeral(self, command, timeout=None):
                self.calls += 1
                return CommandResult(0, "x" * 16, "")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = Sandbox()
            tools = WorkspaceTools(
                directory,
                sandbox,
                max_observations=3,
                max_observed_output_bytes=32,
            )
            results = [
                tools.execute(
                    "run_command", {"command": ["python", "-V"], "timeout": 1}
                )
                for _ in range(5)
            ]
        self.assertEqual(sandbox.calls, 2)
        self.assertEqual(len(tools.command_observations), 3)
        self.assertEqual(results[-1]["stderr"], "observation_capacity")
        self.assertEqual(tools.command_observations[-1]["stderr"], "")
        self.assertLessEqual(
            sum(
                len(item["stdout"].encode()) + len(item["stderr"].encode())
                for item in tools.command_observations
            ),
            32,
        )

    def test_tiny_observation_budget_retains_bounded_terminal_record(self):
        class Limits:
            max_output_bytes = 1024

        class Sandbox:
            limits = Limits()

            def __init__(self):
                self.calls = 0

            def run_ephemeral(self, command, timeout=None):
                self.calls += 1
                return CommandResult(0, "x" * 10_000, "y" * 10_000)

        with tempfile.TemporaryDirectory() as directory:
            sandbox = Sandbox()
            tools = WorkspaceTools(
                directory,
                sandbox,
                max_observations=1,
                max_observed_output_bytes=3,
            )
            first = tools.execute(
                "run_command", {"command": ["python", "-V"], "timeout": 1}
            )
            second = tools.execute(
                "run_command", {"command": ["python", "-V"], "timeout": 1}
            )

        self.assertEqual(first["stderr"], "observation_capacity")
        self.assertEqual(second["stderr"], "observation_capacity")
        self.assertEqual(sandbox.calls, 0)
        self.assertEqual(len(tools.command_observations), 1)
        retained = tools.command_observations[0]
        self.assertLessEqual(
            len(retained["stdout"].encode()) + len(retained["stderr"].encode()), 3
        )

    def test_apply_patch_observation_capacity_records_terminal_without_execution(self):
        class Limits:
            max_output_bytes = 1024

        class Sandbox:
            limits = Limits()

            def stage_patch_candidate(self, patch_file, candidate):
                raise AssertionError("capacity must refuse before staging")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(
                root,
                Sandbox(),
                max_observations=1,
                max_observed_output_bytes=3,
            )
            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )

        self.assertEqual(result["rejection_code"], "observation_capacity")
        self.assertEqual(len(tools.command_observations), 1)
        self.assertEqual(tools.command_observations[0]["operation"], "apply_patch")
        self.assertLessEqual(
            len(tools.command_observations[0]["stderr"].encode()), 3
        )

    def test_journal_capacity_rejects_before_candidate_execution(self):
        class Sandbox:
            def __init__(self):
                self.calls = 0

            def stage_patch_candidate(self, patch_file, candidate):
                self.calls += 1
                raise AssertionError("candidate execution must not start")

        blocks = []
        for index in range(900):
            name = f"generated/{index:04d}-" + "x" * 70 + ".txt"
            blocks.append(
                f"--- /dev/null\n+++ b/{name}\n@@ -0,0 +1 @@\n+value\n"
            )
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Sandbox()
            tools = WorkspaceTools(directory, sandbox)
            result = tools.execute("apply_patch", {"patch": "".join(blocks)})
        self.assertEqual(sandbox.calls, 0)
        self.assertEqual(result["rejection_code"], "edit_journal_capacity")
        self.assertEqual(tools.edit_journal[-1]["rejection_code"], "edit_journal_capacity")

    def test_invalid_patch_exhaustion_records_one_terminal_journal_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, None)
            results = [
                tools.execute("apply_patch", {"patch": "not a unified diff"})
                for _ in range(140)
            ]

        terminal = [
            entry
            for entry in tools.edit_journal
            if entry["rejection_code"] == "edit_journal_capacity"
        ]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(len(tools.edit_journal), 128)
        self.assertTrue(
            all(
                result["rejection_code"] == "edit_journal_capacity"
                for result in results[127:]
            )
        )

    def test_post_validation_candidate_mutation_is_rejected_before_exchange(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def mutate(candidate):
            (Path(candidate) / "file.txt").write_text("raced\n")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), pre_exchange_hook=mutate)
            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )
            self.assertEqual((root / "file.txt").read_text(), "before\n")
        self.assertEqual(result["rejection_code"], "candidate_changed")

    def test_post_validation_proposal_mutation_is_preserved_before_exchange(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def mutate(_candidate):
            (root / "concurrent.txt").write_text("host change\n")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), pre_exchange_hook=mutate)
            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertEqual((root / "concurrent.txt").read_text(), "host change\n")
            self.assertFalse(list(Path(directory).glob(".proposal-promotion-v1.json")))
        self.assertEqual(result["rejection_code"], "proposal_changed")

    def test_promoted_cleanup_failure_is_reported_as_committed_and_blocks_retry(self):
        class Sandbox:
            def __init__(self):
                self.calls = 0

            def stage_patch_candidate(self, patch_file, candidate):
                self.calls += 1
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            sandbox = Sandbox()
            def fail_remove(_path):
                raise OSError("busy")

            tools = WorkspaceTools(root, sandbox, tree_remove=fail_remove)
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-after\n+again\n"},
                )
            self.assertEqual((root / "file.txt").read_text(), "after\n")
            self.assertTrue((Path(directory) / ".proposal-promotion-v1.json").exists())
        self.assertEqual(tools.edit_journal[-1]["result"], "promoted")
        self.assertEqual(sandbox.calls, 1)

    def test_final_capture_finishes_only_journal_bound_committed_remnant(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def fail_remove(_path):
            raise OSError("busy")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            baseline = capture_workspace(root)
            tools = WorkspaceTools(root, Sandbox(), tree_remove=fail_remove)
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            tools._tree_remove = shutil.rmtree
            final_stage = parent / ".snapshots" / "job" / "final"
            final = tools.capture_final_snapshot(baseline, final_stage)

            self.assertNotEqual(final.source_digest, baseline.source_digest)
            self.assertEqual((root / "file.txt").read_text(), "after\n")
            self.assertFalse((parent / ".proposal-promotion-v1.json").exists())
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))

    def test_uncertain_exchange_is_quarantined_and_retry_fails_closed(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        calls = 0

        def exchange(left, right):
            nonlocal calls
            calls += 1
            if calls == 1:
                _test_exchange(left, right)
            raise OSError("uncertain exchange")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), directory_exchange=exchange)
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            self.assertEqual(calls, 1)
            self.assertTrue(
                (Path(directory) / ".proposal-promotion-v1.json").exists()
            )
            self.assertTrue(list(Path(directory).glob(".proposal-candidate-*")))
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-after\n+again\n"},
                )

    def test_pre_exchange_recovery_marker_preserves_candidate_across_crash_sweep(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def crash(_left, _right):
            raise SystemExit("simulated crash")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), directory_exchange=crash)
            with self.assertRaises(SystemExit):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            candidates = list(parent.glob(".proposal-candidate-*"))
            self.assertEqual(len(candidates), 1)
            self.assertTrue((parent / ".proposal-promotion-v1.json").exists())
            with self.assertRaises(PromotionRecoveryRequired):
                cleanup_patch_remnants(parent)
            self.assertTrue(candidates[0].exists())

    def test_structured_marker_is_durable_before_single_exchange_and_has_no_patch(self):
        events = []
        marker_payload = {}

        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def fsync(descriptor):
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            events.append(("fsync", Path(target).name))

        def exchange(left, right):
            marker = root.parent / ".proposal-promotion-v1.json"
            marker_payload.update(json.loads(marker.read_text()))
            events.append(("exchange", None))
            _test_exchange(left, right)

        def publish(source, destination):
            events.append(("publish", Path(destination).name))
            os.rename(source, destination)

        def remove_tree(path):
            events.append(("remove", Path(path).name))
            shutil.rmtree(path)

        patch_text = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(
                root,
                Sandbox(),
                directory_exchange=exchange,
                marker_publish=publish,
                fsync=fsync,
                tree_remove=remove_tree,
            )
            result = tools.execute("apply_patch", {"patch": patch_text})

        self.assertTrue(result["promoted"])
        self.assertEqual(marker_payload["schema"], "lil-tweak-promotion")
        self.assertEqual(marker_payload["version"], 1)
        self.assertEqual(marker_payload["workspace"], "proposal")
        self.assertRegex(marker_payload["candidate"], r"^\.proposal-candidate-")
        self.assertEqual(set(marker_payload["before"]), {"dev", "ino", "source_digest"})
        self.assertEqual(set(marker_payload["after"]), {"dev", "ino", "source_digest"})
        self.assertNotIn("before\n", json.dumps(marker_payload))
        self.assertNotIn("after\n", json.dumps(marker_payload))
        self.assertEqual(sum(event[0] == "exchange" for event in events), 1)
        exchange_index = events.index(("exchange", None))
        publish_index = next(
            index for index, event in enumerate(events) if event[0] == "publish"
        )
        marker_fsync_index = next(
            index
            for index, event in enumerate(events)
            if event[0] == "fsync" and "promotion-tmp" in event[1]
        )
        parent_fsyncs = [
            index
            for index, event in enumerate(events)
            if event[0] == "fsync" and "promotion-tmp" not in event[1]
        ]
        remove_index = next(
            index for index, event in enumerate(events) if event[0] == "remove"
        )
        self.assertLess(marker_fsync_index, publish_index)
        self.assertLess(publish_index, parent_fsyncs[0])
        self.assertLess(parent_fsyncs[0], exchange_index)
        self.assertLess(exchange_index, parent_fsyncs[1])
        self.assertLess(parent_fsyncs[1], remove_index)
        self.assertLess(remove_index, parent_fsyncs[2])

    def test_marker_fsync_failure_cleans_temp_and_never_exchanges(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        exchanges = []
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(
                root,
                Sandbox(),
                directory_exchange=lambda *_args: exchanges.append(True),
                fsync=lambda _descriptor: (_ for _ in ()).throw(OSError("fsync")),
            )
            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertEqual(result["rejection_code"], "recovery_marker_failed")
            self.assertEqual(exchanges, [])
            self.assertFalse(list(parent.glob(".proposal-promotion-tmp-*")))
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))

    def test_patch_file_allocation_failure_removes_partial_candidate(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                raise AssertionError("staging must not execute")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox())
            with patch(
                "core.lil_tweak.openai_agent.tempfile.mkstemp",
                side_effect=OSError("ENOSPC"),
            ):
                result = tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )

            self.assertEqual(result["rejection_code"], "patch_staging_failed")
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))
            self.assertFalse(list(parent.glob(".proposal-patch-*")))

    def test_transient_raw_patch_unlink_failure_is_observed_and_journaled(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "staged", "")

        real_unlink = Path.unlink
        failed_once = False

        def transient_unlink(path, *args, **kwargs):
            nonlocal failed_once
            if "-patch-" in path.name and not failed_once:
                failed_once = True
                raise OSError("transient unlink")
            return real_unlink(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox())

            with patch.object(Path, "unlink", transient_unlink):
                result = tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )

            self.assertEqual(result["rejection_code"], "patch_cleanup_failed")
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertEqual(len(tools.command_observations), 1)
            self.assertEqual(tools.command_observations[0]["exit_code"], 0)
            self.assertEqual(len(tools.edit_journal), 1)
            self.assertEqual(
                tools.edit_journal[0]["rejection_code"], "patch_cleanup_failed"
            )
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))
            self.assertFalse(list(parent.glob(".proposal-patch-*")))

    def test_raw_patch_fsync_failure_is_stably_journaled_before_execution(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                raise AssertionError("staging must not execute")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox())

            with patch(
                "core.lil_tweak.openai_agent.os.fsync",
                side_effect=OSError("raw patch fsync"),
            ):
                result = tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )

            self.assertEqual(result["rejection_code"], "patch_staging_failed")
            self.assertEqual(tools.command_observations, ())
            self.assertEqual(len(tools.edit_journal), 1)
            self.assertEqual(
                tools.edit_journal[0]["rejection_code"], "patch_staging_failed"
            )
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))
            self.assertFalse(list(parent.glob(".proposal-patch-*")))

    def test_missing_candidate_after_staging_is_observed_and_rejected(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.rmtree(candidate)
                return CommandResult(0, "staged", "")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox())

            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )

            self.assertEqual(result["rejection_code"], "candidate_invalid")
            self.assertEqual(len(tools.command_observations), 1)
            self.assertEqual(len(tools.edit_journal), 1)
            self.assertEqual((root / "file.txt").read_text(), "before\n")
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))
            self.assertFalse(list(parent.glob(".proposal-patch-*")))

    def test_fixed_marker_parent_fsync_failure_preserves_candidate_without_exchange(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        fsync_calls = 0
        exchanges = []

        def fsync(_descriptor):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 2:
                raise OSError("parent fsync")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(
                root,
                Sandbox(),
                directory_exchange=lambda *_args: exchanges.append(True),
                fsync=fsync,
            )
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            self.assertEqual(exchanges, [])
            self.assertTrue((parent / ".proposal-promotion-v1.json").exists())
            self.assertEqual(len(list(parent.glob(".proposal-candidate-*"))), 1)
            self.assertEqual((root / "file.txt").read_text(), "before\n")

    def test_post_exchange_parent_fsync_failure_is_committed_and_reconciles_once(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        fsync_calls = 0
        exchanges = 0

        def fsync(_descriptor):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 3:
                raise OSError("post exchange parent fsync")

        def exchange(left, right):
            nonlocal exchanges
            exchanges += 1
            _test_exchange(left, right)

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(
                root, Sandbox(), directory_exchange=exchange, fsync=fsync
            )
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            self.assertEqual(exchanges, 1)
            self.assertEqual((root / "file.txt").read_text(), "after\n")
            self.assertEqual(reconcile_promotion_markers(parent), ("committed",))
            self.assertEqual(exchanges, 1)

    def test_final_parent_fsync_failure_never_exposes_evidence_or_retries_exchange(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        fsync_calls = 0
        exchanges = 0

        def fsync(_descriptor):
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 5:
                raise OSError("final parent fsync")

        def exchange(left, right):
            nonlocal exchanges
            exchanges += 1
            _test_exchange(left, right)

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            baseline = capture_workspace(root)
            tools = WorkspaceTools(
                root, Sandbox(), directory_exchange=exchange, fsync=fsync
            )
            with self.assertRaises(PromotionRecoveryRequired):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            self.assertEqual(exchanges, 1)
            self.assertEqual((root / "file.txt").read_text(), "after\n")
            self.assertFalse((parent / ".proposal-promotion-v1.json").exists())
            self.assertFalse(list(parent.glob(".proposal-candidate-*")))
            self.assertEqual(tools.edit_journal[-1]["result"], "promoted")
            self.assertTrue(tools.recovery_context_exists())
            final_stage = parent / ".snapshots" / "job" / "final"
            with self.assertRaises(PromotionRecoveryRequired):
                tools.capture_final_snapshot(baseline, final_stage)
            self.assertFalse(final_stage.exists())
            self.assertEqual(exchanges, 1)

    def test_reconcile_classifies_prepared_and_committed_layouts_without_second_exchange(self):
        patch_text = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"

        for phase in ("prepared", "committed"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "proposal"
                root.mkdir()
                (root / "file.txt").write_text("before\n")
                calls = 0

                class Sandbox:
                    def stage_patch_candidate(self, patch_file, candidate):
                        shutil.copytree(root, candidate, dirs_exist_ok=True)
                        (Path(candidate) / "file.txt").write_text("after\n")
                        return CommandResult(0, "", "")

                def crash(left, right):
                    nonlocal calls
                    calls += 1
                    if phase == "committed":
                        _test_exchange(left, right)
                    raise SystemExit("crash at exchange boundary")

                tools = WorkspaceTools(root, Sandbox(), directory_exchange=crash)
                with self.assertRaises(SystemExit):
                    tools.execute("apply_patch", {"patch": patch_text})
                self.assertEqual(calls, 1)
                self.assertTrue((parent / ".proposal-promotion-v1.json").exists())
                self.assertEqual(reconcile_promotion_markers(parent), (phase,))
                self.assertEqual(
                    (root / "file.txt").read_text(),
                    "before\n" if phase == "prepared" else "after\n",
                )
                self.assertEqual(calls, 1)
                self.assertFalse((parent / ".proposal-promotion-v1.json").exists())
                self.assertFalse(list(parent.glob(".proposal-candidate-*")))

    def test_reconcile_mismatch_leaves_marker_candidate_and_workspace_untouched(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "", "")

        def crash(_left, _right):
            raise SystemExit("prepared")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), directory_exchange=crash)
            with self.assertRaises(SystemExit):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            marker = parent / ".proposal-promotion-v1.json"
            candidate = next(parent.glob(".proposal-candidate-*"))
            marker_bytes = marker.read_bytes()
            candidate_identity = candidate.stat().st_ino
            (root / "file.txt").write_text("tampered\n")

            with self.assertRaises(PromotionRecoveryRequired):
                reconcile_promotion_markers(parent)

            self.assertEqual((root / "file.txt").read_text(), "tampered\n")
            self.assertEqual(marker.read_bytes(), marker_bytes)
            self.assertEqual(candidate.stat().st_ino, candidate_identity)

    def test_reconcile_accepts_partial_or_missing_candidate_for_both_layouts(self):
        patch_text = "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"
        for phase in ("prepared", "committed"):
            for candidate_state in ("partial", "missing"):
                with (
                    self.subTest(phase=phase, candidate_state=candidate_state),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    parent = Path(directory)
                    root = parent / "proposal"
                    root.mkdir()
                    (root / "file.txt").write_text("before\n")

                    class Sandbox:
                        def stage_patch_candidate(self, patch_file, candidate):
                            shutil.copytree(root, candidate, dirs_exist_ok=True)
                            (Path(candidate) / "file.txt").write_text("after\n")
                            return CommandResult(0, "", "")

                    def crash(left, right):
                        if phase == "committed":
                            _test_exchange(left, right)
                        raise SystemExit("crash")

                    tools = WorkspaceTools(root, Sandbox(), directory_exchange=crash)
                    with self.assertRaises(SystemExit):
                        tools.execute("apply_patch", {"patch": patch_text})
                    candidate = next(parent.glob(".proposal-candidate-*"))
                    if candidate_state == "partial":
                        (candidate / "file.txt").unlink()
                    else:
                        shutil.rmtree(candidate)

                    self.assertEqual(reconcile_promotion_markers(parent), (phase,))
                    self.assertEqual(
                        (root / "file.txt").read_text(),
                        "before\n" if phase == "prepared" else "after\n",
                    )

    def test_noop_digest_recovery_uses_distinct_root_identity(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                return CommandResult(0, "", "")

        def crash(left, right):
            _test_exchange(left, right)
            raise SystemExit("committed no-op")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox(), directory_exchange=crash)
            with self.assertRaises(SystemExit):
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
            marker = json.loads(
                (parent / ".proposal-promotion-v1.json").read_text()
            )
            self.assertEqual(
                marker["before"]["source_digest"], marker["after"]["source_digest"]
            )
            self.assertNotEqual(
                (marker["before"]["dev"], marker["before"]["ino"]),
                (marker["after"]["dev"], marker["after"]["ino"]),
            )
            self.assertEqual(reconcile_promotion_markers(parent), ("committed",))


    def test_managed_runner_workspace_owns_file_reads_and_lists(self):
        class Sandbox:
            def list_files(self, relative, *, max_entries):
                self.list_request = (relative, max_entries)
                return {"paths": ["generated.txt"], "truncated": False}

            def read_file(self, relative, *, max_bytes):
                self.read_request = (relative, max_bytes)
                return {"content": "generated\n", "truncated": False}

            def run(self, command, timeout=None):
                return CommandResult(0, "applied", "")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = Sandbox()
            tools = WorkspaceTools(directory, sandbox)
            self.assertEqual(
                tools.execute("list_files", {"max_entries": 10})["paths"],
                ["generated.txt"],
            )
            self.assertEqual(
                tools.execute("read_file", {"path": "generated.txt"})["content"],
                "generated\n",
            )
        self.assertEqual(sandbox.list_request, (".", 10))
        self.assertEqual(sandbox.read_request, ("generated.txt", 64 * 1024))

    def test_file_reads_stay_inside_workspace_and_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.txt").write_text("x" * 100)
            tools = WorkspaceTools(root, sandbox=None, max_read_bytes=16)
            result = tools.execute("read_file", {"path": "large.txt"})
            self.assertEqual(result["content"], "x" * 16)
            self.assertTrue(result["truncated"])
            with self.assertRaises(ValueError):
                tools.execute("read_file", {"path": "../escape"})

    def test_sensitive_workspace_paths_are_host_blocked(self):
        class Sandbox:
            def run(self, command, timeout=None):
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".env.local").write_text("SECRET=value")
            (Path(directory) / ".git").mkdir()
            (Path(directory) / ".git" / "config").write_text("credential=bad")
            tools = WorkspaceTools(directory, Sandbox())
            for path in (".env.local", ".git/config"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    tools.execute("read_file", {"path": path})

    def test_run_command_records_trusted_observation(self):
        class Sandbox:
            def run_ephemeral(self, command, timeout=None):
                return CommandResult(3, "stdout", "stderr", timed_out=False, truncated=True)

        with tempfile.TemporaryDirectory() as directory:
            tools = WorkspaceTools(directory, Sandbox())
            tools.execute(
                "run_command",
                {"command": ["python", "-m", "unittest"], "timeout": 10},
            )
        self.assertEqual(
            tools.command_observations,
            (
                {
                    "operation": "run_command",
                    "command": ["python", "-m", "unittest"],
                    "exit_code": 3,
                    "timed_out": False,
                    "truncated": True,
                    "stdout": "stdout",
                    "stderr": "stderr",
                },
            ),
        )

    def test_apply_patch_sandbox_invocation_is_also_observed(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copy2(root / "file.txt", Path(candidate) / "file.txt")
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "applied", "", False, False)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(directory, Sandbox(), directory_exchange=_test_exchange)
            tools.execute(
                "apply_patch",
                {
                    "patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"
                },
            )
        self.assertEqual(tools.command_observations[0]["operation"], "apply_patch")
        self.assertEqual(
            tools.command_observations[0]["command"][:3],
            ["patch", "--batch", "--forward"],
        )

    def test_model_tool_arguments_reject_persistence_and_ignore_controls(self):
        for name, arguments in (
            ("run_command", {"command": ["python", "-V"], "timeout": 1, "persist": True}),
            ("run_command", {"command": ["python", "-V"], "timeout": 1, "ignore": ["dist"]}),
            ("apply_patch", {"patch": "x", "destination": "src"}),
            ("apply_patch", {"patch": "x", "promote": True}),
        ):
            with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                _validate_tool_arguments(name, arguments)

    def test_declared_patch_paths_reject_unsafe_malformed_and_colliding_headers(self):
        invalid = (
            "--- x/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n",
            "--- a/../file\n+++ b/../file\n@@ -1 +1 @@\n-a\n+b\n",
            "--- a/C:\\file\n+++ b/C:\\file\n@@ -1 +1 @@\n-a\n+b\n",
            "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-a\n+b\n",
            "--- /dev/null\n+++ /dev/null\n@@ -0,0 +1 @@\n+x\n",
            "--- a/Foo.txt\n+++ b/Foo.txt\n@@ -1 +1 @@\n-a\n+b\n--- /dev/null\n+++ b/foo.txt\n@@ -0,0 +1 @@\n+x\n",
            "--- a/file\n@@ -1 +1 @@\n-a\n+b\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_text("a\n")
            tools = WorkspaceTools(root, sandbox=None)
            for patch_text in invalid:
                with self.subTest(patch=patch_text[:30]):
                    result = tools.execute("apply_patch", {"patch": patch_text})
                    self.assertFalse(result["promoted"])
                    self.assertEqual(result["rejection_code"], "invalid_patch_declaration")
            self.assertEqual(len(tools.edit_journal), len(invalid))

    def test_exact_patch_success_atomically_promotes_and_journals_host_delta(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "file.txt").write_text("after\n")
                return CommandResult(0, "applied", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "file.txt").write_text("before\n")
            tools = WorkspaceTools(root, Sandbox())
            result = tools.execute(
                "apply_patch",
                {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
            )
            self.assertEqual((root / "file.txt").read_text(), "after\n")
        self.assertTrue(result["promoted"])
        entry = tools.edit_journal[0]
        self.assertEqual(entry["actual_changed_paths"], ["file.txt"])
        self.assertEqual(entry["result"], "promoted")
        self.assertRegex(entry["before_source_digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(entry["after_source_digest"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(entry["before_source_digest"], entry["after_source_digest"])

    def test_failed_partial_undeclared_and_invalid_candidates_leave_proposal_unchanged(self):
        def candidate(kind, root, destination):
            shutil.copytree(root, destination, dirs_exist_ok=True)
            if kind == "undeclared":
                (Path(destination) / "other.py").write_text("surprise\n")
            elif kind == "hardlink":
                (Path(destination) / "file.txt").unlink()
                (Path(destination) / "file.txt").hardlink_to(Path(destination) / "other.txt")
            elif kind == "symlink":
                (Path(destination) / "file.txt").unlink()
                (Path(destination) / "file.txt").symlink_to("other.txt")

        for kind in (
            "nonzero",
            "undeclared",
            "hardlink",
            "symlink",
            "exchange",
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "proposal"
                root.mkdir()
                (root / "file.txt").write_text("before\n")
                (root / "other.txt").write_text("other\n")

                class Sandbox:
                    def stage_patch_candidate(self, patch_file, destination):
                        if kind != "nonzero":
                            candidate(kind, root, destination)
                            if kind in ("exchange", "exchange_after_swap"):
                                (Path(destination) / "file.txt").write_text("after\n")
                        return CommandResult(1 if kind == "nonzero" else 0, "", "")

                def exchange(left, right):
                    if kind == "exchange":
                        raise OSError("exchange unavailable")
                    _test_exchange(left, right)
                    if kind == "exchange_after_swap":
                        raise OSError("post-swap verification failed")

                tools = WorkspaceTools(root, Sandbox(), directory_exchange=exchange)
                before = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                result = tools.execute(
                    "apply_patch",
                    {"patch": "--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"},
                )
                after = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                self.assertEqual(after, before)
                self.assertFalse(result["promoted"])
                self.assertEqual(tools.edit_journal[0]["result"], "rejected")

    def test_generated_looking_file_added_by_patch_is_promoted(self):
        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                target = Path(candidate) / "dist" / "generated.js"
                target.parent.mkdir()
                target.write_text("generated\n")
                return CommandResult(0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            tools = WorkspaceTools(root, Sandbox(), directory_exchange=_test_exchange)
            result = tools.execute(
                "apply_patch",
                {"patch": "--- /dev/null\n+++ b/dist/generated.js\n@@ -0,0 +1 @@\n+generated\n"},
            )
            self.assertTrue(result["promoted"])
            self.assertEqual((root / "dist" / "generated.js").read_text(), "generated\n")


def _test_exchange(left, right):
    left = Path(left)
    right = Path(right)
    temporary = left.parent / f".{left.name}-test-exchange"
    os.replace(left, temporary)
    os.replace(right, left)
    os.replace(temporary, right)


if __name__ == "__main__":
    unittest.main()

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "tueiq-runner.yml"
CHECKOUT_ACTION = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_NODE_ACTION = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"


class GitHubRunnerWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def step(self, name):
        match = re.search(
            rf"(?ms)^      - name: {re.escape(name)}\n(?P<body>.*?)(?=^      - name:|\Z)",
            self.workflow,
        )
        self.assertIsNotNone(match, f"missing workflow step: {name}")
        return match.group("body")

    def test_job_remains_read_only_on_github_hosted_ubuntu(self):
        self.assertEqual(
            re.findall(r"(?m)^\s+runs-on:\s*(\S+)\s*$", self.workflow),
            ["ubuntu-24.04"],
        )
        permissions = re.search(
            r"(?ms)^permissions:\n(?P<body>.*?)(?=^\S|\Z)", self.workflow
        )
        self.assertIsNotNone(permissions)
        self.assertEqual(permissions.group("body").strip(), "contents: read")
        self.assertNotIn("self-hosted", self.workflow.casefold())
        self.assertRegex(self.workflow, r"(?m)^    timeout-minutes: 30$")
        for action in re.findall(r"(?m)^\s+uses:\s*(\S+)\s*$", self.workflow):
            self.assertRegex(action, r"^[^@\s]+@[0-9a-f]{40}$")

    def test_job_environment_does_not_use_step_only_runner_context(self):
        environment = re.search(
            r"(?ms)^    env:\n(?P<body>.*?)(?=^    steps:)", self.workflow
        )
        self.assertIsNotNone(environment)
        self.assertNotRegex(environment.group("body"), r"\$\{\{\s*runner\.")
        for variable in ("TMPDIR", "TMP", "TEMP"):
            self.assertNotRegex(
                environment.group("body"),
                rf"(?m)^      {variable}:",
            )

    def test_private_temporary_root_is_created_before_manifest_and_execution(self):
        setup = self.step("Prepare private temporary root")
        self.assertRegex(setup, r"(?m)^        shell: bash$")
        self.assertRegex(
            setup, r"(?m)^        working-directory: \$\{\{ runner\.temp \}\}$"
        )
        self.assertIn('          umask 077\n', setup)
        self.assertIn('          runner_tmp="$RUNNER_TEMP/lil-tweak-runner"\n', setup)
        create = '          mkdir -p -- "$runner_tmp"\n'
        restrict = '          chmod 0700 -- "$runner_tmp"\n'
        publish = (
            '          printf \'TMPDIR=%s\\nTMP=%s\\nTEMP=%s\\n\' '
            '"$runner_tmp" "$runner_tmp" "$runner_tmp" >> "$GITHUB_ENV"\n'
        )
        for command in (create, restrict, publish):
            self.assertIn(command, setup)
        self.assertLess(setup.index(create), setup.index(restrict))
        self.assertLess(setup.index(restrict), setup.index(publish))
        for name in ("Prepare exact manifest", "Execute bounded Tueiq job"):
            self.assertLess(
                self.workflow.index("- name: Prepare private temporary root"),
                self.workflow.index(f"- name: {name}"),
            )

    def test_control_and_source_use_distinct_immutable_checkouts(self):
        self.assertEqual(self.workflow.count(f"uses: {CHECKOUT_ACTION}"), 2)
        control = self.step("Checkout trusted control")
        source = self.step("Checkout exact source")

        self.assertIn(f"uses: {CHECKOUT_ACTION}", control)
        self.assertIn("ref: ${{ github.workflow_sha }}", control)
        self.assertRegex(control, r"(?m)^          path: control$")

        self.assertIn(f"uses: {CHECKOUT_ACTION}", source)
        self.assertIn("inputs.expected_commit", source)
        self.assertIn("github.event.pull_request.head.sha", source)
        self.assertRegex(source, r"(?m)^          path: source$")

    def test_control_code_prepares_manifest_and_executes_against_source(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^      CONTROL_DIR: \$\{\{ github\.workspace \}\}/control$",
        )
        self.assertRegex(
            self.workflow,
            r"(?m)^      SOURCE_DIR: \$\{\{ github\.workspace \}\}/source$",
        )
        self.assertRegex(
            self.workflow,
            r"(?m)^      PYTHONPATH: \$\{\{ github\.workspace \}\}/control$",
        )
        identity_commands = [
            line for line in self.workflow.splitlines() if "rev-parse" in line
        ]
        self.assertEqual(len(identity_commands), 2)
        self.assertTrue(
            all(
                '["git", "-C", os.environ["SOURCE_DIR"], "rev-parse"' in line
                for line in identity_commands
            )
        )

        prepare = self.step("Prepare exact manifest")
        self.assertNotRegex(prepare, r"(?m)^\s+working-directory:")

        execute = self.step("Execute bounded Tueiq job")
        self.assertIn('python3 "$CONTROL_DIR/scripts/tueiq_github_runner.py"', execute)
        self.assertIn('--workspace "$SOURCE_DIR"', execute)

    def test_pinned_node_24_is_configured_before_execution(self):
        setup = self.step("Set up Node")
        self.assertIn(f"uses: {SETUP_NODE_ACTION}", setup)
        self.assertRegex(setup, r'(?m)^          node-version: "24"$')
        self.assertLess(
            self.workflow.index("- name: Set up Node"),
            self.workflow.index("- name: Execute bounded Tueiq job"),
        )


if __name__ == "__main__":
    unittest.main()

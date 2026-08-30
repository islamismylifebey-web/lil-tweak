from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "liltweak" / "galor_runner_v2.py"
TEST = ROOT / "tests" / "test_runner_gate3_connection.py"
ENV = ROOT / ".env.example"


def insert_once(text: str, marker: str, addition: str, *, after: bool = True) -> str:
    if addition.strip() in text:
        return text
    index = text.find(marker)
    if index < 0:
        raise RuntimeError(f"integration marker not found: {marker}")
    position = index + len(marker) if after else index
    return text[:position] + addition + text[position:]


def matching_parenthesis(text: str, opening: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    raise RuntimeError("unterminated constructor call")


def patch_runner() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    if "import os\n" not in text:
        text = text.replace("import json\n", "import json\nimport os\n", 1)

    import_addition = (
        "\nfrom .runner_evidence import parse_qualification_public_keys\n"
        "from .runner_gate3 import Gate3RunnerConnectionVerifier, parse_secret_keys_json\n"
    )
    if "from .runner_gate3 import" not in text:
        marker = "import httpx\n"
        text = insert_once(text, marker, import_addition)

    helper_marker = "_HEX = frozenset(\"0123456789abcdef\")\n"
    helpers = '''


def _gate3_public_keys(name: str, *, key_by_runner: bool) -> dict[str, str]:
    payload = os.getenv(name)
    if payload is None or not payload.strip():
        return {}
    return parse_qualification_public_keys(payload, key_by_runner=key_by_runner)


def _gate3_secret_keys(name: str) -> dict[str, str]:
    payload = os.getenv(name)
    if payload is None or not payload.strip():
        return {}
    return parse_secret_keys_json(payload, label="connection authorization")


def _gate3_integer(name: str, default: int, *, minimum: int, maximum: int) -> int:
    payload = os.getenv(name)
    if payload is None or not payload.strip():
        return default
    try:
        value = int(payload)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} is outside the accepted range")
    return value
'''
    if "def _gate3_public_keys(" not in text:
        text = insert_once(text, helper_marker, helpers)

    config_marker = (
        "    result_signing_keys: Mapping[str, str] = field(default_factory=dict, repr=False)\n"
    )
    config_fields = '''    gate3_qualification_issuer_public_keys: Mapping[str, str] = field(default_factory=dict, repr=False)
    gate3_qualification_runner_public_keys: Mapping[str, str] = field(default_factory=dict, repr=False)
    gate3_connection_authorization_signing_keys: Mapping[str, str] = field(default_factory=dict, repr=False)
    gate3_qualification_maximum_age_seconds: int = 86_400
    gate3_connection_authorization_minimum_sequence: int = 0
    gate3_connection_authorization_minimum_revocation_epoch: int = 1
'''
    if "gate3_qualification_issuer_public_keys" not in text:
        text = insert_once(text, config_marker, config_fields)

    start = text.find("self._connection = RunnerConnectionVerifier(")
    if start < 0:
        start = text.find("self._connection = Gate3RunnerConnectionVerifier(")
    if start < 0:
        raise RuntimeError("runner connection verifier constructor marker was not found")
    opening = text.find("(", start)
    closing = matching_parenthesis(text, opening)
    replacement = '''self._connection = Gate3RunnerConnectionVerifier(
            gateway=self._gateway,
            execution_host=config.contract.execution_host,
            contract_digest=config.expected_contract_digest,
            qualification_evidence_digest=config.qualification_evidence_digest,
            qualification_issuer_public_keys=(
                dict(config.gate3_qualification_issuer_public_keys)
                or _gate3_public_keys(
                    "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_ISSUER_KEYS_JSON",
                    key_by_runner=False,
                )
            ),
            qualification_runner_public_keys=(
                dict(config.gate3_qualification_runner_public_keys)
                or _gate3_public_keys(
                    "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_RUNNER_KEYS_JSON",
                    key_by_runner=True,
                )
            ),
            qualification_maximum_age=timedelta(
                seconds=_gate3_integer(
                    "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_MAX_AGE_SECONDS",
                    config.gate3_qualification_maximum_age_seconds,
                    minimum=1,
                    maximum=2_592_000,
                )
            ),
            authorization_digest=config.authorization_digest,
            connection_authorization_signing_keys=(
                dict(config.gate3_connection_authorization_signing_keys)
                or _gate3_secret_keys(
                    "LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_KEYS_JSON"
                )
            ),
            connection_authorization_minimum_sequence=_gate3_integer(
                "LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_MINIMUM_SEQUENCE",
                config.gate3_connection_authorization_minimum_sequence,
                minimum=0,
                maximum=9_007_199_254_740_991,
            ),
            connection_authorization_minimum_revocation_epoch=_gate3_integer(
                "LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_REVOCATION_EPOCH",
                config.gate3_connection_authorization_minimum_revocation_epoch,
                minimum=1,
                maximum=9_007_199_254_740_991,
            ),
            repository_id=config.repository_id,
            repository_commit=config.repository_commit,
            result_signing_keys=config.result_signing_keys,
            now=self._now,
            poll_interval_seconds=self._poll_interval_seconds,
        )'''
    text = text[:start] + replacement + text[closing + 1 :]

    gate_line = "        scope = f\"repo:{self._config.repository_id}@{self._config.repository_commit}\"\n"
    execution_gate = (
        "        if not self.connected:\n"
        "            await self.refresh_connection()\n"
    )
    if execution_gate not in text:
        text = insert_once(text, gate_line, execution_gate, after=False)

    RUNNER.write_text(text, encoding="utf-8")


def patch_gate3_module() -> None:
    path = ROOT / "liltweak" / "runner_gate3.py"
    text = path.read_text(encoding="utf-8")
    old = '''        _validate_secret_keys(
            connection_authorization_signing_keys,
            "connection authorization",
        )
        _validate_secret_keys(result_signing_keys, "heartbeat")
'''
    new = '''        if connection_authorization_signing_keys:
            _validate_secret_keys(
                connection_authorization_signing_keys,
                "connection authorization",
            )
        if result_signing_keys:
            _validate_secret_keys(result_signing_keys, "heartbeat")
'''
    if old in text:
        text = text.replace(old, new, 1)
    refresh_marker = "            self._proof = None\n            nonce = secrets.token_urlsafe(32)\n"
    refresh_gate = '''            self._proof = None
            if not self._qualification_issuer_public_keys:
                self._disconnect_reason = "GALOR Runner V2 qualification issuer keys are not configured"
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._qualification_runner_public_keys:
                self._disconnect_reason = "GALOR Runner V2 qualification runner keys are not configured"
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._connection_authorization_signing_keys:
                self._disconnect_reason = "GALOR Runner V2 connection authorization signing keys are not configured"
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._result_signing_keys:
                self._disconnect_reason = "GALOR Runner V2 heartbeat signing keys are not configured"
                raise ExecutorUnavailableError(self._disconnect_reason)
            nonce = secrets.token_urlsafe(32)
'''
    if refresh_marker in text:
        text = text.replace(refresh_marker, refresh_gate, 1)
    path.write_text(text, encoding="utf-8")


def patch_test() -> None:
    text = TEST.read_text(encoding="utf-8")
    pattern = re.compile(
        r"@pytest\.mark\.asyncio\nasync def test_connection_authorization_cannot_be_replayed_after_proof_expires\([\s\S]*?assert transport\.connected is False\n",
        re.MULTILINE,
    )
    replacement = '''@pytest.mark.asyncio
async def test_connection_authorization_cannot_be_replayed_after_proof_is_cleared(
    tmp_path: Path,
) -> None:
    gateway = Gateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )
    await transport.refresh_connection()
    transport._connection._proof = None

    with pytest.raises(ExecutorUnavailableError, match="replayed"):
        await transport.refresh_connection()

    assert transport.connected is False
'''
    text, count = pattern.subn(replacement, text, count=1)
    if count != 1 and "test_connection_authorization_cannot_be_replayed_after_proof_is_cleared" not in text:
        raise RuntimeError("replay test integration marker was not found")
    TEST.write_text(text, encoding="utf-8")


def patch_env() -> None:
    block = '''

# Gate 3: full runner qualification and connection-authorization trust anchors.
LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_ISSUER_KEYS_JSON={}
LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_RUNNER_KEYS_JSON={}
LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_MAX_AGE_SECONDS=86400
LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_KEYS_JSON={}
LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_MINIMUM_SEQUENCE=0
LILTWEAK_WORKBENCH_RUNNER_CONNECTION_AUTHORIZATION_REVOCATION_EPOCH=1
'''
    text = ENV.read_text(encoding="utf-8")
    if "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_ISSUER_KEYS_JSON" not in text:
        ENV.write_text(text.rstrip() + block, encoding="utf-8")


def main() -> None:
    patch_runner()
    patch_gate3_module()
    patch_test()
    patch_env()
    subprocess.run(
        [
            "git",
            "rm",
            "--ignore-unmatch",
            "scripts/gate3_integrate_liltweak.py",
            ".github/workflows/gate3-liltweak-integrate.yml",
            "tests/test_runner_connection_authorization_gate.py",
        ],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()

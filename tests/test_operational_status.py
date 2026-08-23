from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from liltweak.operational_status import build_operational_status


def _controller(*, engineering_connected: bool) -> Any:
    return SimpleNamespace(
        model=SimpleNamespace(connected=engineering_connected),
        executor=SimpleNamespace(
            connected=engineering_connected,
            disconnect_reason="runner disconnected",
        ),
        repository_ids=("local:fixture",),
    )


def _planning_chat(*, primary_connected: bool, fallback_connected: bool) -> Any:
    return SimpleNamespace(
        primary_connected=primary_connected,
        fallback_connected=fallback_connected,
    )


def test_planning_chat_status_is_not_gated_on_engineering_adapter() -> None:
    status = build_operational_status(
        controller=_controller(engineering_connected=False),
        planning_chat=_planning_chat(primary_connected=True, fallback_connected=True),
    )

    assert status.provider.state == "CONNECTED"
    assert status.primary_model.state == "CONNECTED"
    assert status.fallback_model.state == "CONNECTED"
    assert status.planning_chat.state == "CONNECTED"
    assert status.engineering_mode.state == "DISCONNECTED"


def test_engineering_adapter_does_not_self_assert_planning_chat_connection() -> None:
    status = build_operational_status(
        controller=_controller(engineering_connected=True),
        planning_chat=None,
    )

    assert status.provider.state == "DISCONNECTED"
    assert status.primary_model.state == "DISCONNECTED"
    assert status.planning_chat.state == "DISCONNECTED"
    assert status.engineering_mode.state == "CONNECTED"


def test_runner_disconnect_keeps_engineering_mode_fail_closed() -> None:
    controller = _controller(engineering_connected=True)
    controller.executor = SimpleNamespace(
        connected=False,
        disconnect_reason="GALOR Runner V2 is blocked: qualification evidence is missing",
    )

    status = build_operational_status(
        controller=controller,
        planning_chat=_planning_chat(primary_connected=True, fallback_connected=False),
    )

    assert status.runner.state == "DISCONNECTED"
    assert "qualification evidence is missing" in status.runner.detail
    assert status.execution.state == "DISCONNECTED"
    assert status.engineering_mode.state == "DISCONNECTED"

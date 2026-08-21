from __future__ import annotations

import sqlite3
from pathlib import Path

from liltweak.api import build_default_service
from liltweak.config import Settings
from liltweak.planning_chat import PlanningConversationStore


def test_canonical_database_must_be_initialized_before_operational_stores(
    tmp_path: Path,
) -> None:
    settings = Settings(
        environment="test",
        database_path=tmp_path / "liltweak.db",
        dev_api_key="owner-secret",
        auth_disabled=False,
        model="gpt-5.6-sol",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
    )
    build_default_service(settings)
    PlanningConversationStore(settings.database_path)
    with sqlite3.connect(settings.database_path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "jobs" in tables
    assert "planning_conversations" in tables

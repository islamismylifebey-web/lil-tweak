from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from liltweak.store import SQLiteStore


def schema_version(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])


def tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0])
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            ).fetchall()
        }


def test_new_database_uses_phase7_schema_and_reopens_idempotently(tmp_path: Path) -> None:
    path = tmp_path / "state" / "liltweak.db"
    first = SQLiteStore(path)
    first.close()
    assert schema_version(path) == SQLiteStore.SCHEMA_VERSION
    assert tables(path) >= SQLiteStore._PHASE7_TABLES
    second = SQLiteStore(path)
    second.close()
    assert schema_version(path) == SQLiteStore.SCHEMA_VERSION


def test_legacy_complete_schema_migrates_without_rewriting_baseline(tmp_path: Path) -> None:
    path = tmp_path / "state" / "legacy.db"
    store = SQLiteStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        for table in SQLiteStore._PHASE7_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute(
            "INSERT INTO system_state (key, value) VALUES ('legacy-marker', 'preserved')"
        )
        connection.execute("PRAGMA user_version = 0")
        connection.commit()
    before = tables(path)
    assert before >= SQLiteStore._BASELINE_TABLES
    migrated = SQLiteStore(path)
    migrated.close()
    assert tables(path) >= SQLiteStore._BASELINE_TABLES
    assert tables(path) >= SQLiteStore._PHASE7_TABLES
    assert schema_version(path) == SQLiteStore.SCHEMA_VERSION
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT value FROM system_state WHERE key = 'legacy-marker'"
            ).fetchone()[0]
            == "preserved"
        )


def test_partial_or_future_schema_fails_closed(tmp_path: Path) -> None:
    partial = tmp_path / "partial" / "state.db"
    partial.parent.mkdir(mode=0o700)
    with sqlite3.connect(partial) as connection:
        connection.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY)")
        connection.commit()
    with pytest.raises(RuntimeError, match="complete Lil Tweak baseline"):
        SQLiteStore(partial)

    future = tmp_path / "future" / "state.db"
    store = SQLiteStore(future)
    store.close()
    with sqlite3.connect(future) as connection:
        connection.execute(f"PRAGMA user_version = {SQLiteStore.SCHEMA_VERSION + 1}")
        connection.commit()
    with pytest.raises(RuntimeError, match="newer"):
        SQLiteStore(future)


def test_concurrent_startup_installs_one_complete_schema(tmp_path: Path) -> None:
    path = tmp_path / "concurrent" / "state.db"

    def open_and_close(_worker: int) -> None:
        store = SQLiteStore(path)
        store.close()

    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(open_and_close, range(8)))

    assert schema_version(path) == SQLiteStore.SCHEMA_VERSION
    assert tables(path) >= SQLiteStore._BASELINE_TABLES | SQLiteStore._PHASE7_TABLES


def test_malformed_phase7_constraints_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "malformed" / "state.db"
    store = SQLiteStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table' AND name = 'creator_repository_executions'
            """
        ).fetchone()
        malformed = row[0].replace(
            "CHECK (attempt_count >= 0 AND attempt_count <= 1)",
            "",
        )
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            """
            UPDATE sqlite_master
            SET sql = ?
            WHERE type = 'table' AND name = 'creator_repository_executions'
            """,
            (malformed,),
        )
        connection.execute("PRAGMA writable_schema = OFF")
        schema = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute(f"PRAGMA schema_version = {schema + 1}")
        connection.commit()
    with pytest.raises(RuntimeError, match="constraints"):
        SQLiteStore(path)


def test_failed_legacy_validation_rolls_back_phase7_migration(tmp_path: Path) -> None:
    path = tmp_path / "rollback" / "state.db"
    store = SQLiteStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        for table in SQLiteStore._PHASE7_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP TABLE system_state")
        connection.execute("CREATE TABLE system_state (key TEXT PRIMARY KEY)")
        connection.execute("PRAGMA user_version = 0")
        connection.commit()
    with pytest.raises(RuntimeError, match="system_state"):
        SQLiteStore(path)
    assert schema_version(path) == 0
    assert not (tables(path) & SQLiteStore._PHASE7_TABLES)


def test_weakened_legacy_constraint_fails_closed_and_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "weakened-baseline" / "state.db"
    store = SQLiteStore(path)
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        for table in SQLiteStore._PHASE7_TABLES:
            connection.execute(f"DROP TABLE {table}")
        connection.execute("DROP TABLE system_state")
        connection.execute("CREATE TABLE system_state (key TEXT PRIMARY KEY, value TEXT)")
        connection.execute("PRAGMA user_version = 0")
        connection.commit()

    with pytest.raises(RuntimeError, match="baseline constraints"):
        SQLiteStore(path)
    assert schema_version(path) == 0
    assert not (tables(path) & SQLiteStore._PHASE7_TABLES)

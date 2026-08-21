# Windows Builder Commands

Use PowerShell with Python 3.12 and uv after builder authorization.

1. Run uv lock after reviewing pyproject.
2. Run uv sync --group dev.
3. Run uv run ruff check .
4. Run uv run ruff format --check .
5. Run uv run pytest.
6. Launch only on localhost with uv run uvicorn liltweak.api:create_app --factory --host 127.0.0.1 --port 8000.

The production command transport requires Linux isolation and must remain disconnected on an ordinary Windows workstation.


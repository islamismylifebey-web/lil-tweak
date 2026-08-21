# Linux Builder Commands

Run from a clean package directory after builder authorization:

- Confirm Python 3.12 and uv versions.
- Run uv lock to update the lock only after reviewing pyproject.
- Run uv sync --group dev.
- Run uv run ruff check .
- Run uv run ruff format --check .
- Run uv run pytest.
- Launch privately with uv run uvicorn liltweak.api:create_app --factory --host 127.0.0.1 --port 8000.

Do not set workbench model enabled or inject a qualified command transport during ordinary local verification.


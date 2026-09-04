from __future__ import annotations

import hashlib
from pathlib import Path


def write_files(root: Path, files: dict[str, str | bytes]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")


def source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def make_repository(root: Path) -> dict[str, str]:
    files: dict[str, str] = {
        "pyproject.toml": """[project]\nname = \"fixture-core\"\nversion = \"1.0.0\"\ndependencies = [\"fastapi>=0.100\", \"pydantic>=2\"]\n\n[tool.hatch.build.targets.wheel]\npackages = [\"src/app\"]\n""",
        "package.json": """{\n  \"name\": \"fixture-web\",\n  \"private\": true,\n  \"scripts\": {\"build\": \"vite build\", \"test\": \"node --test\"},\n  \"dependencies\": {\"react\": \"19.0.0\"},\n  \"devDependencies\": {\"typescript\": \"5.9.0\"}\n}\n""",
        "tsconfig.json": """{\"compilerOptions\": {\"baseUrl\": \".\", \"paths\": {\"@/*\": [\"./*\"]}}}\n""",
        "src/app/__init__.py": "from .service import build_user\n__all__ = [\"build_user\"]\n",
        "src/app/models.py": """from pydantic import BaseModel\n\nclass UserModel(BaseModel):\n    name: str\n\nclass Mode:\n    SAFE = \"safe\"\n""",
        "src/app/service.py": """from .models import UserModel\nimport missing_vendor\n\ndef build_user(name: str) -> UserModel:\n    return UserModel(name=name)\n""",
        "src/app/main.py": """from fastapi import APIRouter\nfrom .service import build_user\n\nrouter = APIRouter()\n\n@router.get(\"/users/{user_id}\")\ndef get_user(user_id: str):\n    return build_user(user_id)\n""",
        "src/app/cycle_a.py": "from . import cycle_b\n\ndef alpha():\n    return cycle_b.beta()\n",
        "src/app/cycle_b.py": "from . import cycle_a\n\ndef beta():\n    return cycle_a.alpha()\n",
        "src/app/broken.py": "def broken(:\n    pass\n",
        "tests/test_service.py": """from app.service import build_user\n\ndef test_build_user():\n    assert build_user(\"Bey\").name == \"Bey\"\n""",
        "tests/test_models.py": "def test_placeholder():\n    assert True\n",
        "web/package.json": """{\"name\": \"fixture-client\", \"dependencies\": {\"zod\": \"4.0.0\"}}\n""",
        "web/src/contracts.ts": """export interface UserContract {\n  name: string;\n}\nexport type UserSchema = { id: string };\n""",
        "web/src/api.ts": """import type { UserContract } from \"./contracts\";\nexport function fetchUser(): UserContract { return { name: \"Bey\" }; }\n""",
        "web/src/client.ts": """import { fetchUser } from \"./api\";\nexport const client = () => fetchUser();\n""",
        "web/app/api/items/route.ts": """import { fetchUser } from \"../../../src/api\";\nexport async function GET() { return Response.json(fetchUser()); }\nexport async function POST() { return Response.json(fetchUser()); }\n""",
        "deploy/Containerfile": "FROM python:3.12-slim\nCOPY . /app\n",
        "wrangler.toml": "name = \"fixture\"\nmain = \"worker/index.ts\"\n",
        "worker/index.ts": "export default { fetch() { return new Response(\"ok\"); } };\n",
        "notes/legacy.rb": "puts 'unsupported but visible'\n",
    }
    write_files(root, files)
    return files

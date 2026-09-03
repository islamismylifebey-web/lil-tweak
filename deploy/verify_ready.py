"""Send a signed readiness probe without disclosing its signing key."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sys
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def load_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("invalid environment file")
        name, value = line.split("=", 1)
        if not name or name in values:
            raise ValueError("invalid environment file")
        values[name] = value
    return values


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        print("signed readiness probe check: ok")
        return 0
    if len(argv) != 1:
        print("usage: verify_ready.py CORE_ENV", file=sys.stderr)
        return 2

    try:
        environment = load_environment(Path(argv[0]))
        signing_keys = json.loads(environment["LIL_TWEAK_SIGNING_KEYS_JSON"])
        if not isinstance(signing_keys, dict) or not signing_keys:
            raise ValueError("missing signing keys")
        key_id = sorted(signing_keys)[0]
        key = signing_keys[key_id]
        if not isinstance(key, str) or not key:
            raise ValueError("invalid signing key")
        owner = environment["LIL_TWEAK_CANONICAL_OWNER_ID"]
        if not re.fullmatch(r"[a-f0-9]{32}", owner):
            raise ValueError("invalid canonical owner")

        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        request_id = str(uuid.uuid4())
        body_digest = hashlib.sha256(b"").hexdigest()
        canonical = "\n".join(
            [
                "v2",
                key_id,
                "GET",
                "/readyz",
                timestamp,
                nonce,
                body_digest,
                request_id,
                "",
                owner,
            ]
        )
        signature = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        request = Request(
            "http://127.0.0.1:8017/readyz",
            headers={
                "X-Lil-Tweak-Key-Id": key_id,
                "X-Lil-Tweak-Timestamp": timestamp,
                "X-Lil-Tweak-Nonce": nonce,
                "X-Lil-Tweak-Request-Id": request_id,
                "X-Lil-Tweak-Body-SHA256": body_digest,
                "X-Lil-Tweak-Signature": signature,
                "X-Lil-Tweak-Owner": owner,
            },
        )
        with urlopen(request, timeout=5) as response:
            payload = json.load(response)
        checks = payload.get("checks", {})
        if response.status != 200 or payload.get("status") != "ready":
            raise ValueError("core is not ready")
        if not isinstance(checks, dict) or not checks or not all(checks.values()):
            raise ValueError("a readiness dependency failed")
    except (KeyError, OSError, ValueError, json.JSONDecodeError, HTTPError, URLError):
        print("signed readiness probe failed", file=sys.stderr)
        return 1

    print("signed readiness probe: ready")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

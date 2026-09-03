"""Dependency-free liveness probe used by the core container."""

from __future__ import annotations

import json
import sys
from urllib.error import URLError
from urllib.request import urlopen


def main() -> int:
    try:
        with urlopen("http://127.0.0.1:8080/healthz", timeout=2) as response:
            payload = json.load(response)
            return 0 if response.status == 200 and payload == {"status": "ok"} else 1
    except (OSError, URLError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main())

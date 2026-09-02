from __future__ import annotations

import time

from .candidates import CandidateStore
from .client import ControlPlaneClient
from .config import load_credentials
from .execution import HostJobExecutor
from .service import RunnerService


def main() -> int:
    credentials = load_credentials()
    CandidateStore().cleanup_expired(
        now_seconds=int(time.time()),
        retention_seconds=86_400,
    )
    with ControlPlaneClient(credentials) as client:
        service = RunnerService(
            client=client,
            executor=HostJobExecutor(),
            controller_key_id=credentials.controller_key_id,
            controller_public_key=credentials.controller_public_key,
        )
        while True:
            try:
                worked = service.run_once()
            except Exception:
                worked = False
            if not worked:
                time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import re
import socket
import sys
from typing import Any, Callable, Final
import urllib.request


GENERIC_FAILURE: Final = "DigitalOcean target verification failed"
METADATA_URL: Final = "http://169.254.169.254/metadata/v1/id"
METADATA_TIMEOUT_SECONDS: Final = 2
MAX_METADATA_BYTES: Final = 32


@dataclass(frozen=True)
class TargetConfiguration:
    provider: str
    droplet_id: str
    hostname: str
    region: str
    operating_system: str
    size: str
    role: str


TARGET: Final = TargetConfiguration(
    provider="DigitalOcean",
    droplet_id="597343619",
    hostname="galor-tweak-runner-01",
    region="nyc1",
    operating_system="Ubuntu 24.04 LTS x64",
    size="s-4vcpu-8gb",
    role="role-tweak-runner",
)


@dataclass(frozen=True)
class TargetIdentity:
    provider: str
    droplet_id: str
    hostname: str
    role: str

    def as_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "droplet_id": self.droplet_id,
            "hostname": self.hostname,
            "role": self.role,
        }


class TargetVerificationError(RuntimeError):
    pass


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Any,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _failure() -> TargetVerificationError:
    return TargetVerificationError(GENERIC_FAILURE)


def _parse_metadata_id(payload: bytes) -> str:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_METADATA_BYTES:
        raise _failure()
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise _failure() from None
    if value.endswith("\n"):
        value = value[:-1]
    if re.fullmatch(r"[0-9]+", value) is None or value != TARGET.droplet_id:
        raise _failure()
    return value


def read_metadata(opener: Any, url: str) -> bytes:
    try:
        request = urllib.request.Request(url, method="GET")
        with opener.open(request, timeout=METADATA_TIMEOUT_SECONDS) as response:
            if response.getcode() != 200:
                raise _failure()
            if hasattr(response, "geturl") and response.geturl() != url:
                raise _failure()
            payload = response.read(MAX_METADATA_BYTES + 1)
    except TargetVerificationError:
        raise
    except Exception:
        raise _failure() from None
    if len(payload) > MAX_METADATA_BYTES:
        raise _failure()
    return payload


def read_live_metadata(
    *,
    opener_factory: Callable[[], Any] = lambda: urllib.request.build_opener(
        urllib.request.ProxyHandler({}), RejectRedirects()
    ),
) -> bytes:
    return read_metadata(opener_factory(), METADATA_URL)


def verify_target(
    hostname_getter: Callable[[], str] = lambda: socket.gethostname().split(".", 1)[0],
    metadata_reader: Callable[[], bytes] = read_live_metadata,
) -> TargetIdentity:
    try:
        hostname = hostname_getter()
        if hostname != TARGET.hostname:
            raise _failure()
        droplet_id = _parse_metadata_id(metadata_reader())
    except TargetVerificationError:
        raise _failure() from None
    except Exception:
        raise _failure() from None
    return TargetIdentity(
        provider=TARGET.provider,
        droplet_id=droplet_id,
        hostname=hostname,
        role=TARGET.role,
    )


def offline_check() -> None:
    expected = TargetConfiguration(
        provider="DigitalOcean",
        droplet_id="597343619",
        hostname="galor-tweak-runner-01",
        region="nyc1",
        operating_system="Ubuntu 24.04 LTS x64",
        size="s-4vcpu-8gb",
        role="role-tweak-runner",
    )
    if TARGET != expected:
        raise _failure()
    if (
        METADATA_URL != "http://169.254.169.254/metadata/v1/id"
        or METADATA_TIMEOUT_SECONDS != 2
        or MAX_METADATA_BYTES != 32
        or _parse_metadata_id(b"597343619\n") != "597343619"
    ):
        raise _failure()
    for invalid in (b"", b"\n", b"+597343619\n", b"597343619\nextra", b"1" * 33):
        try:
            _parse_metadata_id(invalid)
        except TargetVerificationError:
            continue
        raise _failure()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lil-tweak-digitalocean-target.py")
    parser.add_argument("--check", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    hostname_getter: Callable[[], str] = lambda: socket.gethostname().split(".", 1)[0],
    metadata_reader: Callable[[], bytes] | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.check:
            offline_check()
            print("DigitalOcean target check: ok")
            return 0
        identity = verify_target(
            hostname_getter,
            metadata_reader if metadata_reader is not None else read_live_metadata,
        )
    except TargetVerificationError:
        print(GENERIC_FAILURE, file=sys.stderr)
        return 1
    print(
        "DigitalOcean target verified: "
        f"droplet {identity.droplet_id} / {identity.hostname}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

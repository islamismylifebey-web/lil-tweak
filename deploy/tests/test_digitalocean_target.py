from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
import http.server
import importlib.util
import io
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest.mock import patch
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-digitalocean-target.py"
GOOD_IDENTITY = {
    "provider": "DigitalOcean",
    "droplet_id": "597343619",
    "hostname": "galor-tweak-runner-01",
    "role": "role-tweak-runner",
}


def load_target_module():
    spec = importlib.util.spec_from_file_location("lil_tweak_digitalocean_target", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("DigitalOcean target helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class MetadataHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/id":
            body = b"597343619\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/id")
            self.end_headers()
            return
        if self.path == "/oversize":
            body = b"1" * 33
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


class HostileProxyHandler(http.server.BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:
        type(self).requests.append(self.path)
        body = b"597343619\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


class RecordingResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_sizes: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.payload[:size]

    def getcode(self) -> int:
        return 200


class RecordingOpener:
    def __init__(self, payload: bytes) -> None:
        self.response = RecordingResponse(payload)
        self.calls: list[tuple[str, float]] = []

    def open(self, request, *, timeout: float):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        self.calls.append((url, timeout))
        return self.response


class DigitalOceanTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = load_target_module()
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MetadataHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.proxy = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), HostileProxyHandler
        )
        cls.proxy_thread = threading.Thread(target=cls.proxy.serve_forever, daemon=True)
        cls.proxy_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.proxy.shutdown()
        cls.proxy.server_close()
        cls.proxy_thread.join(timeout=2)

    def test_accepts_only_exact_hostname_and_metadata_id(self) -> None:
        identity = self.target.verify_target(
            hostname_getter=lambda: "galor-tweak-runner-01",
            metadata_reader=lambda: b"597343619\n",
        )
        self.assertEqual(identity.as_dict(), GOOD_IDENTITY)

    def test_rejects_every_non_exact_identity_without_echoing_it(self) -> None:
        cases = (
            ("different-hostname", lambda: "other-host", lambda: b"597343619\n"),
            ("different-id", lambda: "galor-tweak-runner-01", lambda: b"597343618\n"),
            ("blank-id", lambda: "galor-tweak-runner-01", lambda: b"\n"),
            ("signed-id", lambda: "galor-tweak-runner-01", lambda: b"+597343619\n"),
            ("negative-id", lambda: "galor-tweak-runner-01", lambda: b"-597343619\n"),
            ("non-decimal-id", lambda: "galor-tweak-runner-01", lambda: b"59734361x\n"),
            ("overlong-id", lambda: "galor-tweak-runner-01", lambda: b"1" * 33),
            ("trailing-data", lambda: "galor-tweak-runner-01", lambda: b"597343619\nextra"),
            ("invalid-utf8", lambda: "galor-tweak-runner-01", lambda: b"597343619\xff"),
            (
                "metadata-exception",
                lambda: "galor-tweak-runner-01",
                lambda: (_ for _ in ()).throw(OSError("hostile-metadata")),
            ),
            (
                "hostname-exception",
                lambda: (_ for _ in ()).throw(OSError("hostile-hostname")),
                lambda: b"597343619\n",
            ),
        )
        for label, hostname_getter, metadata_reader in cases:
            with self.subTest(label=label):
                with self.assertRaises(self.target.TargetVerificationError) as raised:
                    self.target.verify_target(hostname_getter, metadata_reader)
                self.assertEqual(str(raised.exception), "DigitalOcean target verification failed")
                self.assertNotIn("hostile", str(raised.exception))

    def test_read_metadata_uses_exact_url_timeout_and_one_bounded_read(self) -> None:
        opener = RecordingOpener(b"597343619\n")
        observed = self.target.read_metadata(opener, self.target.METADATA_URL)

        self.assertEqual(observed, b"597343619\n")
        self.assertEqual(
            opener.calls,
            [("http://169.254.169.254/metadata/v1/id", 2)],
        )
        self.assertEqual(opener.response.read_sizes, [33])

    def test_read_metadata_accepts_id_and_rejects_redirect_and_oversize(self) -> None:
        origin = f"http://127.0.0.1:{self.server.server_port}"
        opener = urllib.request.build_opener(self.target.RejectRedirects())
        self.assertEqual(
            self.target.read_metadata(opener, origin + "/id"),
            b"597343619\n",
        )
        with self.assertRaises(self.target.TargetVerificationError):
            self.target.read_metadata(opener, origin + "/redirect")
        with self.assertRaises(self.target.TargetVerificationError):
            self.target.read_metadata(opener, origin + "/oversize")

    def test_production_metadata_reader_uses_the_immutable_endpoint(self) -> None:
        opener = RecordingOpener(b"597343619\n")
        observed = self.target.read_live_metadata(opener_factory=lambda: opener)
        self.assertEqual(observed, b"597343619\n")
        self.assertEqual(
            opener.calls,
            [("http://169.254.169.254/metadata/v1/id", 2)],
        )

    def test_live_metadata_bypasses_every_hostile_proxy_environment(self) -> None:
        proxy_url = f"http://127.0.0.1:{self.proxy.server_port}"
        proxy_environment = {
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
        }
        original_create_connection = socket.create_connection

        def block_direct_metadata(address, *args, **kwargs):
            if address[0] == "169.254.169.254":
                raise OSError("direct metadata unavailable in test")
            return original_create_connection(address, *args, **kwargs)

        HostileProxyHandler.requests.clear()
        accepted_proxy_identity = False
        with patch.dict(os.environ, proxy_environment, clear=True), patch(
            "socket.create_connection", side_effect=block_direct_metadata
        ):
            try:
                self.target.verify_target(
                    hostname_getter=lambda: "galor-tweak-runner-01"
                )
            except self.target.TargetVerificationError:
                pass
            else:
                accepted_proxy_identity = True

        self.assertEqual(
            (accepted_proxy_identity, HostileProxyHandler.requests),
            (False, []),
        )

    def test_check_is_offline_and_live_failure_is_one_generic_message(self) -> None:
        metadata_calls = 0

        def forbidden_metadata() -> bytes:
            nonlocal metadata_calls
            metadata_calls += 1
            raise AssertionError("offline check contacted metadata")

        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = self.target.main(
                ["--check"],
                hostname_getter=lambda: "other-host",
                metadata_reader=forbidden_metadata,
            )
        self.assertEqual(status, 0)
        self.assertEqual(metadata_calls, 0)
        self.assertEqual(output.getvalue(), "DigitalOcean target check: ok\n")
        self.assertEqual(errors.getvalue(), "")

        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = self.target.main(
                [],
                hostname_getter=lambda: "galor-tweak-runner-01",
                metadata_reader=lambda: b"hostile-received-metadata\n",
            )
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "DigitalOcean target verification failed\n")
        self.assertNotIn("hostile", errors.getvalue())

    def test_target_configuration_is_frozen_and_has_all_immutable_facts(self) -> None:
        self.assertEqual(
            (
                self.target.TARGET.provider,
                self.target.TARGET.droplet_id,
                self.target.TARGET.hostname,
                self.target.TARGET.region,
                self.target.TARGET.operating_system,
                self.target.TARGET.size,
                self.target.TARGET.role,
            ),
            (
                "DigitalOcean",
                "597343619",
                "galor-tweak-runner-01",
                "nyc1",
                "Ubuntu 24.04 LTS x64",
                "s-4vcpu-8gb",
                "role-tweak-runner",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            self.target.TARGET.droplet_id = "1"


if __name__ == "__main__":
    unittest.main()

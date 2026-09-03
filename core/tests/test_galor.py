import io
import json
import unittest
from urllib.request import HTTPRedirectHandler, ProxyHandler

from core.lil_tweak.galor import GalorClient


class _Response:
    def __init__(self, body):
        self._body = body

    def read(self, size=-1):
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class GalorClientTests(unittest.TestCase):
    def test_bounded_read_only_context_is_sanitized(self):
        calls = []

        def open_request(request, timeout):
            calls.append((request, timeout))
            return _Response(
                io.BytesIO(
                    json.dumps(
                        {"project": "Alpha", "notes": "x" * 10_000}
                    ).encode()
                )
            )

        result = GalorClient(
            "https://galor.internal/context", opener=open_request
        ).fetch({"projectId": "project-1"})
        self.assertIsNone(result.error)
        self.assertEqual(result.context["project"], "Alpha")
        self.assertLessEqual(len(result.context["notes"]), 2048)
        request, timeout = calls[0]
        self.assertEqual(request.method, "GET")
        self.assertNotIn("authorization", dict(request.header_items()))
        self.assertLessEqual(timeout, 2.0)

    def test_failure_is_reported_without_raising(self):
        def fail(*args, **kwargs):
            raise TimeoutError("private detail")

        result = GalorClient("https://galor.internal", opener=fail).fetch(
            {"projectId": "p"}
        )
        self.assertIsNone(result.context)
        self.assertEqual(result.error, "galor_unavailable")

    def test_default_transport_uses_no_proxy_and_refuses_redirects(self):
        client = GalorClient("https://galor-readonly.internal/context")
        proxy_handlers = [
            handler for handler in client.opener.handlers if isinstance(handler, ProxyHandler)
        ]
        redirect_handlers = [
            handler
            for handler in client.opener.handlers
            if isinstance(handler, HTTPRedirectHandler)
        ]
        # Passing an empty ProxyHandler suppresses urllib's environment-derived
        # default; CPython omits the inert handler from the final chain.
        self.assertTrue(all(handler.proxies == {} for handler in proxy_handlers))
        self.assertEqual(len(redirect_handlers), 1)
        self.assertIsNone(
            redirect_handlers[0].redirect_request(
                None, None, 302, "redirect", {},
                "https://other.internal/context"
            )
        )

    def test_endpoint_is_an_exact_credential_free_origin_and_path(self):
        for url in (
            "http://galor.internal/context",
            "https://user:pass@galor.internal/context",
            "https://galor.internal/context?target=other",
            "https://galor.internal/context#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                GalorClient(url)
        GalorClient("https://galor-readonly.internal/context")


if __name__ == "__main__":
    unittest.main()

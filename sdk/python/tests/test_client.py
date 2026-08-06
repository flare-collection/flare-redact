"""The gateway client, exercised against a stub that speaks the real wire format."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from flare_redact.client import GatewayClient, GatewayError
from flare_redact.wire import UnserializableOptionError, options_from_wire, options_to_wire

_REQUESTS: list = []


class _StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:  # keep the test output readable
        pass

    def _read(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length)) if length else None

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        _REQUESTS.append(("GET", self.path, None, dict(self.headers)))
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "version": "1.5.0"})
        elif self.path == "/v1/detectors":
            self._send(200, {"detectors": [{"id": "email", "default": True}]})
        else:
            self._send(404, {"code": "ERR_NOT_FOUND", "message": "no route"})

    def do_POST(self) -> None:
        payload = self._read()
        _REQUESTS.append(("POST", self.path, payload, dict(self.headers)))
        if self.path == "/v1/redact":
            self._send(200, {"output": "redacted", "findings": []})
        elif self.path == "/v1/scan":
            self._send(200, {"findings": [
                {"detector": "email", "label": "Email address", "why": "why.", "risk": "high",
                 "confidence": 0.92, "start": 0, "end": 15}
            ]})
        elif self.path == "/v1/sessions":
            self._send(201, {"id": "abc123"})
        elif self.path.endswith("/redact"):
            self._send(200, {"output": "[EMAIL_1]"})
        elif self.path.endswith("/restore"):
            self._send(200, {"output": "ada@example.com"})
        else:
            self._send(400, {"code": "ERR_BAD_REQUEST", "message": "unsupported"})

    def do_DELETE(self) -> None:
        _REQUESTS.append(("DELETE", self.path, None, dict(self.headers)))
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


class GatewayClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address[:2]
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _REQUESTS.clear()
        self.client = GatewayClient(self.base_url, token="s3cret")

    def test_redact_sends_input_and_options(self) -> None:
        self.assertEqual(self.client.redact("x", enable=["pii"]), "redacted")
        method, path, payload, headers = _REQUESTS[-1]
        self.assertEqual((method, path), ("POST", "/v1/redact"))
        self.assertEqual(payload["input"], "x")
        self.assertEqual(payload["options"], {"enable": ["pii"]})
        self.assertEqual(headers["Authorization"], "Bearer s3cret")

    def test_scan_returns_findings(self) -> None:
        findings = self.client.scan("ada@example.com")
        self.assertEqual(findings[0].detector, "email")
        self.assertEqual(findings[0].end, 15)
        self.assertFalse(self.client.is_clean("ada@example.com"))

    def test_detectors_and_health(self) -> None:
        self.assertEqual(self.client.detectors()[0]["id"], "email")
        self.assertEqual(self.client.health()["status"], "ok")

    def test_session_round_trip_and_close(self) -> None:
        with self.client.session(enable=["pii"]) as session:
            self.assertEqual(session.id, "abc123")
            self.assertEqual(session.redact("ada@example.com"), "[EMAIL_1]")
            self.assertEqual(session.restore("[EMAIL_1]"), "ada@example.com")
        self.assertEqual(_REQUESTS[-1][0], "DELETE")

    def test_http_errors_carry_the_gateway_code(self) -> None:
        with self.assertRaises(GatewayError) as caught:
            self.client._request("GET", "/v1/nope")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.code, "ERR_NOT_FOUND")

    def test_unreachable_gateway_is_reported_clearly(self) -> None:
        offline = GatewayClient("http://127.0.0.1:1", timeout=1.0)
        with self.assertRaises(GatewayError):
            offline.health()


class WireTest(unittest.TestCase):
    def test_defaults_are_omitted(self) -> None:
        self.assertEqual(options_to_wire(None), {})

    def test_round_trip(self) -> None:
        wire = {"enable": ["pii"], "mode": "label", "minConfidence": 0.5, "includeValues": True}
        options = options_from_wire(wire)
        self.assertEqual(options_to_wire(options), wire)

    def test_secret_is_never_sent(self) -> None:
        self.assertNotIn("transformSecret", options_to_wire({"transform_secret": "k", "mode": "hash"}))

    def test_callable_mask_is_rejected(self) -> None:
        with self.assertRaises(UnserializableOptionError):
            options_to_wire({"mask": lambda value, detector: "x"})

    def test_unknown_wire_option_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            options_from_wire({"nonsense": True})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

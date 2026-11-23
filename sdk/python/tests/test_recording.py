"""Recorded HTTP traffic (vcrpy cassettes, HAR files) must not keep credentials."""

from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

from flare_redact.recording import RecordingRedactor, is_credential_name, redact_har, vcr_config

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
SESSION = "f3a9c1d2e8b7a6f5"
SRC = str(Path(__file__).resolve().parents[1] / "src")


def har():
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1"},
            "entries": [
                {
                    "startedDateTime": "2026-11-23T10:00:00.000Z",
                    "time": 12,
                    "request": {
                        "method": "POST",
                        "url": f"https://api.example.com/v1/users?access_token={SESSION}&page=2",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Authorization", "value": f"Bearer {TOKEN}"},
                            {"name": "X-Api-Key", "value": "k-7c1e0f2a9b"},
                            {"name": "Cookie", "value": f"sid={SESSION}"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                        "cookies": [{"name": "sid", "value": SESSION}],
                        "queryString": [{"name": "access_token", "value": SESSION}, {"name": "page", "value": "2"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"email": "ada@example.com", "password": "hunter2hunter2", "plan": "pro"}),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": f"sid={SESSION}; HttpOnly"},
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Content-Length", "value": "64"},
                        ],
                        "cookies": [{"name": "sid", "value": SESSION, "httpOnly": True}],
                        "content": {
                            "size": 64,
                            "mimeType": "application/json",
                            "text": json.dumps({"id": 7, "token": TOKEN, "owner": "ada@example.com"}),
                        },
                        "redirectURL": "",
                    },
                    "timings": {"send": 0, "wait": 10, "receive": 2},
                }
            ],
        }
    }


def header(message, name):
    return next(h["value"] for h in message["headers"] if h["name"].lower() == name.lower())


class CredentialNameTests(unittest.TestCase):
    def test_names_with_and_without_x_prefix(self):
        for name in ("Authorization", "X-Api-Key", "Proxy-Authorization", "Set-Cookie", "Cookie",
                     "access_token", "X-Auth-Token", "X-Amz-Security-Token", "Private-Token", "X-CSRF-Token"):
            self.assertTrue(is_credential_name(name), name)
        for name in ("Accept", "Content-Type", "User-Agent", "page", "X-Request-Id"):
            self.assertFalse(is_credential_name(name), name)


class HarTests(unittest.TestCase):
    def test_redact_har_masks_and_keeps_the_rest(self):
        source = har()
        out = redact_har(source)
        text = json.dumps(out)
        for secret in (TOKEN, SESSION, "k-7c1e0f2a9b", "hunter2hunter2", "ada@example.com"):
            self.assertNotIn(secret, text)
        entry = out["log"]["entries"][0]
        request, response = entry["request"], entry["response"]
        self.assertEqual(header(request, "Accept"), "application/json")
        self.assertEqual(header(request, "X-Api-Key"), "***")
        self.assertEqual(request["url"], "https://api.example.com/v1/users?access_token=***&page=2")
        self.assertEqual(request["queryString"][1], {"name": "page", "value": "2"})
        self.assertEqual(json.loads(request["postData"]["text"])["plan"], "pro")
        self.assertTrue(response["cookies"][0]["httpOnly"])
        self.assertEqual(json.loads(response["content"]["text"])["id"], 7)
        size = len(response["content"]["text"].encode("utf-8"))
        self.assertEqual(response["content"]["size"], size)
        self.assertEqual(header(response, "Content-Length"), str(size))
        self.assertEqual(entry["timings"]["wait"], 10)
        self.assertIn(TOKEN, json.dumps(source), "the input is not mutated")

    def test_same_output_as_the_node_engine(self):
        try:
            node = subprocess.run(
                ["node", str(Path(__file__).resolve().parents[3] / "bin" / "flare-redact.mjs"), "--har"],
                input=json.dumps(har()), capture_output=True, text=True,
            )
        except OSError:
            self.skipTest("node is not installed")
        if node.returncode != 0:
            self.skipTest("the Node CLI is not built")
        self.assertEqual(json.loads(node.stdout), redact_har(har()))

    def test_exact_body_kept_and_forms_by_field(self):
        redactor = RecordingRedactor()
        pretty = '{\n  "ok": true\n}'
        self.assertEqual(redactor.body(pretty, "application/json"), pretty)
        self.assertEqual(
            redactor.body("user=ada%40home&password=hunter2hunter2", "application/x-www-form-urlencoded"),
            "user=ada%40home&password=***",
        )

    def test_base64_text_body_and_binary_untouched(self):
        redactor = RecordingRedactor()
        encoded = base64.b64encode(json.dumps({"token": TOKEN}).encode()).decode()
        entry = redactor.entry({"response": {"headers": [], "content": {
            "mimeType": "application/json; charset=utf-8", "encoding": "base64", "text": encoded}}})
        self.assertNotIn(TOKEN, base64.b64decode(entry["response"]["content"]["text"]).decode())
        image = {"mimeType": "image/png", "encoding": "base64", "text": "iVBORw0KGgo="}
        self.assertIs(redactor.entry({"response": {"content": image}})["response"]["content"], image)

    def test_cli_har(self):
        run = lambda data: subprocess.run(
            [sys.executable, "-m", "flare_redact", "--har"], input=data, capture_output=True, text=True,
            env={"PYTHONPATH": SRC, "PATH": ""},
        )
        good = run(json.dumps(har()))
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertNotIn(TOKEN, good.stdout)
        self.assertEqual(json.loads(good.stdout)["log"]["entries"][0]["response"]["status"], 200)
        self.assertEqual(run('{"not":"har"}').returncode, 2)


class FakeRequest:
    """The parts of vcr.request.Request the hook touches."""

    def __init__(self, uri, body, headers):
        self.uri, self.body, self.headers = uri, body, headers


class VcrHookTests(unittest.TestCase):
    def test_request_hook(self):
        config = vcr_config()
        request = FakeRequest(
            f"https://api.example.com/x?api_key={SESSION}&q=books",
            json.dumps({"password": "hunter2hunter2", "q": "books"}).encode(),
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", "Accept": "*/*"},
        )
        out = config["before_record_request"](request)
        self.assertEqual(out.uri, "https://api.example.com/x?api_key=***&q=books")
        self.assertEqual(out.headers["Authorization"], "***")
        self.assertEqual(out.headers["Accept"], "*/*")
        self.assertIsInstance(out.body, bytes)
        self.assertNotIn(b"hunter2hunter2", out.body)
        self.assertTrue(config["decode_compressed_response"])

    def test_request_hook_is_deterministic_for_playback_matching(self):
        hook = vcr_config()["before_record_request"]
        make = lambda: FakeRequest(f"https://h/x?token={SESSION}", None, {})
        self.assertEqual(hook(make()).uri, hook(make()).uri)

    def test_response_hook_masks_and_fixes_length(self):
        hook = vcr_config()["before_record_response"]
        body = json.dumps({"token": TOKEN, "n": 1}).encode()
        response = {
            "status": {"code": 200, "message": "OK"},
            "headers": {"Set-Cookie": [f"sid={SESSION}"], "Content-Type": ["application/json"],
                        "Content-Length": [str(len(body))]},
            "body": {"string": body},
        }
        out = hook(copy.deepcopy(response))
        self.assertEqual(out["headers"]["Set-Cookie"], ["***"])
        self.assertNotIn(TOKEN.encode(), out["body"]["string"])
        self.assertEqual(json.loads(out["body"]["string"])["n"], 1)
        self.assertEqual(out["headers"]["Content-Length"], [str(len(out["body"]["string"]))])

    def test_response_hook_reads_gzip_bodies(self):
        hook = vcr_config()["before_record_response"]
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
            handle.write(json.dumps({"token": TOKEN}).encode())
        out = hook({"headers": {"Content-Encoding": ["gzip"], "Content-Type": ["application/json"]},
                    "body": {"string": buffer.getvalue()}})
        self.assertNotIn("Content-Encoding", out["headers"])
        self.assertNotIn(TOKEN.encode(), out["body"]["string"])

    def test_binary_body_untouched(self):
        hook = vcr_config()["before_record_response"]
        png = b"\x89PNG\r\n\x1a\n\x00\x00"
        out = hook({"headers": {"Content-Type": ["image/png"]}, "body": {"string": png}})
        self.assertIs(out["body"]["string"], png)


if __name__ == "__main__":
    unittest.main()

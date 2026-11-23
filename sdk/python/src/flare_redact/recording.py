"""Redaction for recorded HTTP traffic: vcrpy cassettes and HAR files.

Test suites record real HTTP traffic and commit it: vcrpy and pytest-recording
cassettes, HAR files from browser devtools and Playwright. A recording leaks in
places a log line does not: credential headers whose names carry an ``x-``
prefix, cookies whose values are opaque session ids, and bodies stored as JSON
text, form text or base64. Each is handled here.

With pytest-recording::

    import pytest
    from flare_redact.recording import vcr_config as flare_vcr_config

    @pytest.fixture(scope="module")
    def vcr_config():
        return flare_vcr_config()

With vcrpy directly::

    import vcr
    from flare_redact.recording import vcr_config

    my_vcr = vcr.VCR(**vcr_config())

Requests are masked the same way when they are recorded and when they are
matched, so playback keeps working with a token in the query string.
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from typing import Any, Dict, List, Mapping, Optional, Union
from urllib.parse import quote_plus, unquote_plus

from .engine import _SENSITIVE_KEY_RE, Options, compile_policy

__all__ = [
    "RecordingRedactor",
    "is_credential_name",
    "redact_har",
    "redact_har_entry",
    "vcr_config",
]

MASK = "***"

#: Header and parameter names that always carry a credential, after dropping ``x-``.
CREDENTIAL_NAMES = frozenset(
    {
        "access_token",
        "api_token",
        "apikey",
        "auth_token",
        "csrf_token",
        "id_token",
        "private_token",
        "proxy_authorization",
        "set_cookie",
        "vault_token",
        "xsrf_token",
        "amz_security_token",
        "amz_credential",
        "amz_signature",
        "goog_api_key",
        "signature",
    }
)

_TEXTUAL = re.compile(
    r"^(?:text/|application/(?:[\w.+-]*\+)?(?:json|xml|javascript|x-www-form-urlencoded|graphql))",
    re.IGNORECASE,
)


def is_credential_name(name: str) -> bool:
    """Whether a header, query parameter or form field name carries a credential.

    ``X-Api-Key``, ``Proxy-Authorization``, ``Set-Cookie`` and ``access_token``
    all do; the plain sensitive-key list matches whole names only and would miss
    them.
    """
    normal = re.sub(r"^x-", "", name.strip().lower()).replace("-", "_")
    return bool(_SENSITIVE_KEY_RE.fullmatch(normal)) or normal in CREDENTIAL_NAMES


def _header(headers: Mapping[str, Any], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            if isinstance(value, (list, tuple)):
                return str(value[0]) if value else ""
            return str(value)
    return ""


class RecordingRedactor:
    """A redactor for recordings, built from the usual options.

    Bodies are redacted as JSON when they parse as JSON (so field names count),
    as form fields when they are form-encoded, and as text otherwise; a body
    that needs no change keeps its exact bytes.
    """

    def __init__(self, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> None:
        self.policy = compile_policy(options, **overrides)

    # -- values ------------------------------------------------------------- #

    def header(self, name: str, raw: str) -> str:
        """Redact a header or parameter value, masking it whole when the name carries a credential."""
        if is_credential_name(name):
            return MASK
        return self.policy.redact({name: raw})[name]

    def form(self, text: str) -> str:
        """Redact form-encoded text one field at a time; untouched fields keep their bytes."""
        parts = text.split("&")
        changed = False
        for index, part in enumerate(parts):
            if not part:
                continue
            raw_name, sep, raw_value = part.partition("=")
            name, value = unquote_plus(raw_name), unquote_plus(raw_value)
            masked = self.header(name, value)
            if masked != value:
                parts[index] = raw_name + (sep or "=") + quote_plus(masked, safe="*")
                changed = True
        return "&".join(parts) if changed else text

    def body(self, text: str, mime_type: str = "") -> str:
        """Redact a body held as text; JSON and form bodies keep their field names."""
        if re.search(r"x-www-form-urlencoded", mime_type or "", re.IGNORECASE):
            return self.form(text)
        if text.lstrip()[:1] in ("{", "["):
            try:
                parsed = json.loads(text)
            except ValueError:
                pass
            else:
                if self.policy.is_clean(parsed):
                    return text
                return json.dumps(self.policy.redact(parsed), ensure_ascii=False, separators=(",", ":"))
        return self.policy.redact_str(text)

    def url(self, raw: str) -> str:
        """Redact a URL; credential query parameters are masked by name.

        The query string is redacted one parameter at a time: run over the whole
        URL, an assignment detector would read ``token=x&page=2`` as one value
        and swallow the parameters after it.
        """
        before_hash, hash_mark, fragment = raw.partition("#")
        tail = self.policy.redact_str(hash_mark + fragment) if hash_mark else ""
        base, question, query = before_hash.partition("?")
        if not question:
            return self.policy.redact_str(base) + tail
        return f"{self.policy.redact_str(base)}?{self.form(query)}{tail}"

    def _bytes(self, data: Any, mime_type: str) -> Any:
        """Redact a body given as bytes or text, returning the same type."""
        if isinstance(data, str):
            return self.body(data, mime_type)
        if not isinstance(data, (bytes, bytearray)) or not data:
            return data
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            return data  # binary: images, archives, protobuf
        masked = self.body(text, mime_type)
        return data if masked == text else masked.encode("utf-8")

    # -- vcrpy -------------------------------------------------------------- #

    def request(self, request: Any) -> Any:
        """A vcrpy ``before_record_request`` hook. vcrpy passes a copy, so it is changed in place."""
        request.uri = self.url(request.uri)
        for name in list(request.headers.keys()):
            request.headers[name] = self.header(name, str(request.headers[name]))
        content_type = _header(request.headers, "content-type")
        body = self._bytes(request.body, content_type)
        if body is not request.body:
            request.body = body
            size = len(body.encode("utf-8") if isinstance(body, str) else body)
            for name in list(request.headers.keys()):
                if name.lower() == "content-length":
                    request.headers[name] = str(size)
        return request

    def response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """A vcrpy ``before_record_response`` hook for the response dict vcrpy records."""
        headers: Dict[str, List[Any]] = response.get("headers") or {}
        for name in list(headers):
            values = headers[name]
            listed = values if isinstance(values, list) else [values]
            headers[name] = [self.header(name, str(value)) for value in listed]
        body = response.get("body")
        if not isinstance(body, dict) or "string" not in body:
            return response
        data = body["string"]
        encoding = _header(headers, "content-encoding").lower()
        if encoding in ("gzip", "deflate") and isinstance(data, (bytes, bytearray)) and data:
            # A compressed body cannot be read; store it decompressed, as
            # vcrpy's own decode_compressed_response does.
            try:
                data = zlib.decompress(bytes(data), zlib.MAX_WBITS | 16 if encoding == "gzip" else zlib.MAX_WBITS)
            except zlib.error:
                return response
            for name in [key for key in headers if key.lower() == "content-encoding"]:
                del headers[name]
        elif encoding not in ("", "identity"):
            return response  # br, zstd: left as recorded
        masked = self._bytes(data, _header(headers, "content-type"))
        body["string"] = masked
        size = len(masked.encode("utf-8") if isinstance(masked, str) else masked)
        for name in headers:
            if name.lower() == "content-length":
                headers[name] = [str(size)]
        return response

    # -- HAR ---------------------------------------------------------------- #

    def _pairs(self, pairs: Optional[List[Dict[str, Any]]], always: bool = False) -> Optional[List[Dict[str, Any]]]:
        if pairs is None:
            return None
        return [
            {**pair, "value": MASK if always else self.header(str(pair.get("name", "")), str(pair.get("value", "")))}
            for pair in pairs
        ]

    def _content(self, content: Dict[str, Any]) -> Dict[str, Any]:
        text = content.get("text")
        if not isinstance(text, str):
            return content
        mime_type = content.get("mimeType") or ""
        if content.get("encoding") == "base64":
            if not _TEXTUAL.match(mime_type):
                return content
            decoded = base64.b64decode(text).decode("utf-8", errors="replace")
            masked = self.body(decoded, mime_type)
            if masked == decoded:
                return content
            data = masked.encode("utf-8")
            return {**content, "text": base64.b64encode(data).decode("ascii"), "size": len(data)}
        masked = self.body(text, mime_type)
        if masked == text:
            return content
        return {**content, "text": masked, "size": len(masked.encode("utf-8"))}

    def _message(self, message: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not message:
            return message
        out = dict(message)
        if isinstance(message.get("url"), str):
            out["url"] = self.url(message["url"])
        if message.get("headers") is not None:
            out["headers"] = self._pairs(message["headers"])
        if message.get("cookies") is not None:
            out["cookies"] = self._pairs(message["cookies"], always=True)
        if message.get("queryString") is not None:
            out["queryString"] = self._pairs(message["queryString"])
        post = message.get("postData")
        if isinstance(post, dict):
            post = dict(post)
            if isinstance(post.get("text"), str):
                post["text"] = self.body(post["text"], post.get("mimeType") or "")
            if post.get("params") is not None:
                post["params"] = self._pairs(post["params"])
            out["postData"] = post
        content = message.get("content")
        if isinstance(content, dict):
            out["content"] = self._content(content)
            size = out["content"].get("size")
            if out["content"] is not content and isinstance(size, int) and out.get("headers"):
                out["headers"] = [
                    {**h, "value": str(size)} if str(h.get("name", "")).lower() == "content-length" else h
                    for h in out["headers"]
                ]
        if isinstance(message.get("redirectURL"), str) and message["redirectURL"]:
            out["redirectURL"] = self.url(message["redirectURL"])
        return out

    def entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """A redacted copy of one HAR entry."""
        out = dict(entry)
        for side in ("request", "response"):
            if side in entry:
                out[side] = self._message(entry[side])
        return out

    def har(self, har: Dict[str, Any]) -> Dict[str, Any]:
        """A redacted copy of a whole HAR document."""
        log = dict(har.get("log") or {})
        if isinstance(log.get("entries"), list):
            log["entries"] = [self.entry(entry) for entry in log["entries"]]
        return {**har, "log": log}


def redact_har(har: Dict[str, Any], options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Dict[str, Any]:
    """A redacted copy of a HAR document."""
    return RecordingRedactor(options, **overrides).har(har)


def redact_har_entry(entry: Dict[str, Any], options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Dict[str, Any]:
    """A redacted copy of one HAR entry."""
    return RecordingRedactor(options, **overrides).entry(entry)


def vcr_config(options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> Dict[str, Any]:
    """Keyword arguments for ``vcr.VCR(...)`` or a pytest-recording ``vcr_config`` fixture."""
    redactor = RecordingRedactor(options, **overrides)
    return {
        "before_record_request": redactor.request,
        "before_record_response": redactor.response,
        "decode_compressed_response": True,
    }

"""A client for the flare-redact gateway.

The local engine implements the portable FRS-1 profile. The gateway runs the
full JavaScript detector set and holds server-side sessions, so point this client
at your sidecar when you want one policy enforced for every language in the
estate, and want it configured in one place rather than in every service.

    from flare_redact.client import GatewayClient

    gateway = GatewayClient("http://127.0.0.1:8080")
    gateway.redact({"email": "ada@example.com"})

    with gateway.session(enable=["pii"]) as session:
        safe = session.redact(user_message)
        reply = session.restore(model_reply)

Only the standard library is used, so adding this SDK to a service adds nothing
to its dependency tree.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Union

from .engine import Finding, Options
from .wire import finding_from_wire, options_to_wire

__all__ = ["GatewayClient", "GatewayError", "RemoteAgentFlow", "RemoteSession"]

DEFAULT_TIMEOUT = 10.0


class GatewayError(RuntimeError):
    """The gateway returned an error, or could not be reached."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


class GatewayClient:
    """Synchronous client for the gateway's ``/v1`` API."""

    __slots__ = ("base_url", "_token", "_timeout", "_default_options", "_opener")

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        *,
        token: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        options: Union[Options, Mapping[str, Any], None] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._default_options = options
        # No proxy handler: a redaction sidecar is reached directly, and routing
        # request bodies through an ambient HTTP proxy would defeat the point.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # -- transport ---------------------------------------------------------- #

    def _request(self, method: str, path: str, payload: Optional[Mapping[str, Any]] = None) -> Any:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method)
        request.add_header("Accept", "application/json")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if self._token:
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            code = None
            parsed_error = None
            try:
                parsed = json.loads(detail)
                detail = parsed.get("message", detail)
                code = parsed.get("code")
                parsed_error = parsed
            except (ValueError, AttributeError):
                pass
            raise GatewayError(
                f"gateway responded {exc.code}: {detail}",
                status=exc.code,
                code=code,
                details=parsed_error,
            ) from exc
        except urllib.error.URLError as exc:
            raise GatewayError(f"gateway at {self.base_url} is unreachable: {exc.reason}") from exc
        return json.loads(raw.decode("utf-8")) if raw else None

    def _merge(self, options: Union[Options, Mapping[str, Any], None], overrides: Mapping[str, Any]) -> Dict[str, Any]:
        chosen = options if options is not None else self._default_options
        return options_to_wire(Options.coerce(chosen, **dict(overrides)))

    # -- API ---------------------------------------------------------------- #

    def redact(
        self,
        value: Any,
        options: Union[Options, Mapping[str, Any], None] = None,
        **overrides: Any,
    ) -> Any:
        """Redact any JSON-serialisable value using the gateway's policy."""
        response = self._request("POST", "/v1/redact", {
            "input": value,
            "options": self._merge(options, overrides),
        })
        return response["output"]

    def scan(
        self,
        value: Any,
        options: Union[Options, Mapping[str, Any], None] = None,
        **overrides: Any,
    ) -> List[Finding]:
        """List what the gateway would redact, and why."""
        response = self._request("POST", "/v1/scan", {
            "input": value,
            "options": self._merge(options, overrides),
        })
        return [finding_from_wire(item) for item in response.get("findings", [])]

    def is_clean(self, value: Any, options: Union[Options, Mapping[str, Any], None] = None, **overrides: Any) -> bool:
        """True when the gateway finds nothing to redact."""
        return not self.scan(value, options, **overrides)

    def detectors(self) -> List[Dict[str, Any]]:
        """Every detector the gateway knows about."""
        return self._request("GET", "/v1/detectors")["detectors"]

    def health(self) -> Dict[str, Any]:
        """Liveness and version information."""
        return self._request("GET", "/healthz")

    def session(
        self,
        options: Union[Options, Mapping[str, Any], None] = None,
        **overrides: Any,
    ) -> "RemoteSession":
        """Open a server-side session whose placeholders survive across calls."""
        response = self._request("POST", "/v1/sessions", {"options": self._merge(options, overrides)})
        return RemoteSession(self, str(response["id"]))

    def agent_flow(self) -> "RemoteAgentFlow":
        """Open an operator-policy-controlled FlareFlow session."""
        response = self._request("POST", "/v1/flows", {})
        return RemoteAgentFlow(self, str(response["id"]))


class RemoteSession:
    """A gateway-held vault. Use it as a context manager so it is always closed."""

    __slots__ = ("_client", "id", "_closed")

    def __init__(self, client: GatewayClient, session_id: str) -> None:
        self._client = client
        self.id = session_id
        self._closed = False

    def redact(self, value: Any) -> Any:
        """Mask a message before it reaches the model."""
        return self._client._request("POST", f"/v1/sessions/{self.id}/redact", {"input": value})["output"]

    def restore(self, value: Any) -> Any:
        """Restore the model's reply before showing it to the user."""
        return self._client._request("POST", f"/v1/sessions/{self.id}/restore", {"input": value})["output"]

    def close(self) -> None:
        """Discard the server-side mapping. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._client._request("DELETE", f"/v1/sessions/{self.id}")

    def __enter__(self) -> "RemoteSession":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class RemoteAgentFlow:
    """A gateway-held source-to-sink capability boundary."""

    __slots__ = ("_client", "id", "_closed")

    def __init__(self, client: GatewayClient, flow_id: str) -> None:
        self._client = client
        self.id = flow_id
        self._closed = False

    def protect_for_model(self, source: str, value: Any) -> Any:
        """Protect a trusted source before its data enters model context."""
        response = self._client._request(
            "POST", f"/v1/flows/{self.id}/protect", {"source": source, "input": value}
        )
        return response["output"]

    def inspect_for_sink(self, sink: str, value: Any) -> Dict[str, Any]:
        """Preflight a model-produced call without restoring or consuming budget."""
        response = self._client._request(
            "POST", f"/v1/flows/{self.id}/inspect", {"sink": sink, "input": value}
        )
        return response["decision"]

    def authorize_for_sink(self, sink: str, value: Any) -> Any:
        """Restore an allowed sink call, or raise ``GatewayError`` on denial."""
        response = self._client._request(
            "POST", f"/v1/flows/{self.id}/authorize", {"sink": sink, "input": value}
        )
        return response["output"]

    def restore_for_app(self, value: Any) -> Any:
        """Restore live mappings only at the trusted final application boundary."""
        response = self._client._request(
            "POST", f"/v1/flows/{self.id}/restore", {"input": value}
        )
        return response["output"]

    def snapshot(self) -> Dict[str, Any]:
        """Return the value-free audit and budget snapshot."""
        return self._client._request("GET", f"/v1/flows/{self.id}/snapshot")

    def close(self) -> None:
        """Discard every protected mapping and budget counter. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._client._request("DELETE", f"/v1/flows/{self.id}")

    def __enter__(self) -> "RemoteAgentFlow":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

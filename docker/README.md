# The flare-redact gateway

A redaction sidecar. Point a vendor SDK's base URL at it and the request body is
scrubbed on the way out and the originals are put back on the way in — streaming
included. Your application keeps sending and receiving real data; the vendor
never sees it.

```bash
docker build -f docker/Dockerfile -t flare-redact-gateway .

docker run --rm -p 127.0.0.1:8787:8787 \
  -e FLARE_REDACT_ENABLE=pii \
  flare-redact-gateway --upstream https://api.openai.com
```

```diff
- OPENAI_BASE_URL=https://api.openai.com/v1
+ OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

That diff is the whole integration. No middleware, no wrapper, no import — which
is the point: the teams that most need this are the ones whose Python service,
PHP monolith and Node worker all call the same vendor and cannot each grow a new
dependency.

Without Docker: `npx flare-redact gateway --upstream https://api.openai.com`.

## Contents

- [What it does to a request](#what-it-does-to-a-request)
- [Routes](#routes)
- [Which parts of the body](#which-parts-of-the-body)
- [Restoring the answer](#restoring-the-answer)
- [The redaction API](#the-redaction-api)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Security model](#security-model)
- [What it deliberately does not do](#what-it-deliberately-does-not-do)

## What it does to a request

```
your app ──▶ gateway ──▶ vendor
   real data    │            placeholders
                │
   real data ◀──┘◀──────────  placeholders
```

1. Read the body, up to `maxBodyBytes`.
2. Redact it — the whole body by default, or only the JSON paths you name.
3. Forward it with your headers untouched, including `Authorization`.
4. Restore the originals in the response, buffered for JSON and incrementally
   for `text/event-stream`.

## Routes

One upstream:

```bash
flare-redact gateway --upstream https://api.openai.com
```

Several, by prefix:

```bash
flare-redact gateway \
  --route /openai=https://api.openai.com \
  --route /anthropic=https://api.anthropic.com
```

```
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic
```

The longest matching prefix wins, so `/openai/v1` can be routed differently from
`/openai`. A route may not claim `/healthz`, `/readyz`, `/metrics` or `/v1/` —
the gateway answers those itself, and a config that would shadow one is rejected
at startup rather than mysteriously at runtime.

## Which parts of the body

Redacting the entire body is the safe default and the one you get. For a chat
completion it also rewrites the model name and the tool schema, which is usually
harmless and occasionally not — so name the paths that hold what a human typed:

```bash
--paths 'messages[*].content,input,prompt,system'
```

`a.b`, `a[0]`, `a[*]` and `*` are supported. A path that does not exist in a
given request is a no-op, so one configuration covers several endpoint shapes.

Non-JSON bodies pass through untouched unless you add `--redact-text`, which
extends handling to `application/x-www-form-urlencoded` and `text/*`. A body that
claims to be JSON but does not parse is redacted as text rather than forwarded:
its framing is already broken, and the failure mode that matters is leaking.

## Restoring the answer

Redaction uses a per-request vault, so `ada@example.com` becomes
`[FR_EMAIL_9f2c…]` on the way out and comes back on the way in. The model's reply
reads correctly to your user, and the vendor never held the address.

For a streamed response the restorer holds back the longest suffix that could
still be the start of a placeholder, so a token split across two SSE frames is
still restored exactly once. Substituted values are escaped for the JSON string
context those frames use, so a name containing a quote cannot break the client's
parser.

Turn it off with `--no-restore` when the upstream never echoes the prompt back
and you would rather save the work.

## The redaction API

The gateway is also a service the [Python](../sdk/python/README.md) and
[Go](../sdk/go/README.md) clients talk to, for the cases where a native engine is
not what you want:

| | |
|---|---|
| `POST /v1/redact` | `{"input": …, "options": {…}}` → `{"output": …, "summary": {…}}` |
| `POST /v1/scan` | → `{"findings": [...], "summary": {…}}` |
| `GET /v1/detectors` | the catalogue, plus this gateway's selectors |
| `POST /v1/sessions` | open a server-side vault → `{"id", "expiresAt"}` |
| `POST /v1/sessions/:id/redact` | mask, remembering the mapping |
| `POST /v1/sessions/:id/restore` | put the originals back |
| `DELETE /v1/sessions/:id` | discard the mapping |
| `GET /healthz`, `GET /readyz` | liveness |
| `GET /metrics` | Prometheus text |

Set `FLARE_GATEWAY_TOKEN` and every `/v1` call needs
`Authorization: Bearer <token>`. Health and metrics stay open so a probe does not
need a credential.

Those eight paths are the only ones the gateway answers itself, and they are the
only ones that shadow your upstream. Everything else under `/v1` — `/v1/chat/
completions`, `/v1/models`, `/v1/messages` — is proxied like any other path, which
is the whole point of putting the sidecar in front of a vendor that owns that
namespace.

Sessions are held in memory, expire after `sessions.ttlMs` and are capped at
`sessions.max`. An unbounded map of secrets is a memory leak with a disclosure
attached. Because they are per-process, a replicated gateway needs sticky routing
for session traffic — the stateless `/v1/redact` path does not.

## Configuration

Three layers, later winning: a config file, the environment, the command line.

```bash
flare-redact gateway --config docker/flare-gateway.example.json --print-config
```

| Environment variable | |
|---|---|
| `FLARE_UPSTREAM` | single-upstream shorthand |
| `FLARE_GATEWAY_HOST` / `FLARE_GATEWAY_PORT` | bind address (default `127.0.0.1:8787`) |
| `FLARE_GATEWAY_TOKEN` | bearer token for `/v1` |
| `FLARE_REDACT_ONLY` / `_ENABLE` / `_DISABLE` | detector selection |
| `FLARE_REDACT_MODE` | `mask`, `label`, `hash`, `pseudonym`, `surrogate` |
| `FLARE_REDACT_SECRET` | key for the keyed modes |
| `FLARE_GATEWAY_MAX_BODY_BYTES` | default 8 MiB |
| `FLARE_GATEWAY_TIMEOUT_MS` | default 120 s |
| `FLARE_GATEWAY_SESSION_TTL_MS` | default 30 min |
| `FLARE_GATEWAY_LOG` | `silent`, `info`, `debug` |

See [`flare-gateway.example.json`](./flare-gateway.example.json) for the full
shape, including per-route policies.

## Operating it

The audit log is JSON lines and contains counts, never content:

```json
{"time":"2026-08-05T09:12:44.031Z","level":"info","name":"flare-gateway","msg":"proxied",
 "route":"openai","method":"POST","path":"/openai/v1/chat/completions","status":200,
 "durationMs":412,"findings":{"email":2,"phone":1},"placeholders":3}
```

`/metrics` exposes `flare_gateway_requests_total{route,status}`,
`flare_gateway_findings_total{detector}`, request and response byte counters,
error counters and an active-session gauge. Counting findings costs one extra
scan per request; set `auditFindings: false` if you would rather have the
throughput than the numbers.

Every response carries `X-Flare-Redact: route=…; findings=N; restored=on|off`,
which makes "is the proxy actually in the path?" answerable from a single curl.

## Security model

- **Your credential is forwarded, never redacted.** The `Authorization` header
  that authenticates you *to* the vendor is not the secret being hidden *from*
  it. Header values pass through untouched.
- **Bodies, headers and matched values are never logged.**
- **The gateway's policy wins.** A client may pass options, but the configured
  policy is layered over them, so no caller can send `{"disable":["email"]}` and
  opt out. `transformSecret` from a client is rejected outright.
- **It binds to loopback by default.** In a container that has to be `0.0.0.0`;
  publish it as `127.0.0.1:8787:8787` or keep it on an internal network. A
  redaction proxy reachable from the internet is a proxy anyone can send data
  through.
- **Failures are refusals.** An oversized body is a 413, an unreachable upstream
  is a 502. Neither is a partially redacted request that quietly reaches the
  vendor.
- **Hop-by-hop headers are stripped** in both directions, and redirects are not
  followed — an upstream cannot bounce your data somewhere the config never
  named.

## What it deliberately does not do

- **No TLS interception.** This is a reverse proxy you point at, not a MITM that
  forges certificates. Changing one base URL is a smaller, more auditable change
  than installing a root CA on every host.
- **No shared session store.** Sessions are per-process. Distributing them would
  mean replicating a map of plaintext secrets across your cluster.
- **No response redaction.** The gateway restores what it masked; it does not
  scan what the vendor sent back. If the *upstream* is the untrusted party, redact
  its response in your application with the library.

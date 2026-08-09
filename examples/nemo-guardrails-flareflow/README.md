# NeMo Guardrails IORails + FlareFlow

A deterministic, no-network integration example for the application-owned tool
execution boundary.

NeMo Guardrails IORails can validate an OpenAI-shaped model tool call against a
tool allowlist and JSON Schema. It does not execute the tool. This example takes
that validated call, resolves the tool through a trusted local registry, and
uses FlareFlow immediately before execution to enforce the protected value's
source, detector, sink, exact JSON path, and cumulative budget.

```bash
npm install
npm start
```

The program proves two paths with assertions:

- copying a protected database value into a valid HTTP tool is denied;
- the same value is restored at the approved database argument only.

No model, API key, NeMo installation, network call, or external service is
required. In a live application, pass NeMo's validated `tool_calls` item into
`executeValidatedToolCall` and return the executed tool result to the next
guardrails request.

NVIDIA and the NVIDIA logo are trademarks and/or registered trademarks of
NVIDIA Corporation. NeMo Guardrails is referenced only for interoperability.
Flare Redact is an independent project and is not affiliated with, sponsored
by, or endorsed by NVIDIA.

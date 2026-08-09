# FlareFlow 1 — Source-to-sink declassification for tool-using agents

Status: experimental specification, August 2026

FlareFlow is a deterministic information-flow boundary for reversible redaction
in tool-using language-model applications. It prevents a model-produced call
from turning a protected placeholder back into its original value unless a
runtime-owned capability authorizes the value's source, detector class,
destination sink, and JSON location. It also limits cumulative restoration
across turns.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## 1. Scope

FlareFlow protects one narrow but important boundary:

```text
trusted source ──protect──▶ model context ──authorize──▶ trusted sink
  original                  opaque token                  original or refusal
```

It controls exact restoration of values that Flare Redact detected and replaced.
It is model-independent: enforcement does not depend on a system prompt, model
classification, tool description, or the model following an instruction.

FlareFlow is not:

- a general prompt-injection detector or prevention system;
- semantic taint tracking for information the model has already observed;
- an authorization system for deciding whether a tool itself may run;
- protection against a compromised host runtime, policy owner, detector, or
  trusted sink;
- a guarantee that detection found every sensitive value.

## 2. Trust model

The following components are trusted:

- the host runtime that calls FlareFlow;
- source identifiers assigned by that runtime;
- sink identifiers resolved through the runtime's tool registry;
- the sink capability policy and resource limits;
- detectors used before a value enters model context;
- a final application boundary that deliberately calls `restoreForApp`.

The following inputs are untrusted:

- model text and structured tool-call arguments;
- tool names or source labels emitted by a model;
- placeholders copied from another session or constructed by an attacker;
- any object location chosen by a model.

A conforming integration MUST NOT derive the selected sink, source identity, or
capability policy from model output without first resolving it to runtime-owned
metadata. In the gateway profile, clients cannot submit a policy when creating a
flow; the gateway operator owns it.

## 3. Terms and state

- **Source**: a stable runtime identifier for data entering model context, such
  as `postgres.result`, `user.message`, or `config`.
- **Detector**: the Flare Redact detector identifier that classified a value,
  such as `url_credentials` or `email`.
- **Sink**: a stable runtime identifier for an operation that may receive a
  restored value, such as `postgres.execute` or `http.fetch`.
- **Path**: the JSON Pointer location of a placeholder in the complete
  model-produced call.
- **Capability**: an operator rule that authorizes a set of source and detector
  labels at a set of paths for one sink.
- **Declassification**: replacement of an opaque token with its original value.
- **Flow**: one isolated in-memory mapping, budget state, and value-free audit
  history.

For each protected value, a flow stores a record:

```text
token → (original, source, detector, created_at, expires_at, use_count)
```

For each sink and capability it stores cumulative use counters. Mappings MUST be
isolated between flows, bounded in count, and removed when expired or revoked.

## 4. Tokens

The reference profile uses:

```text
[FR_FLOW_<32 lowercase hexadecimal characters>]
```

The hexadecimal component carries 128 bits sampled with Web Crypto. Tokens MUST
be unpredictable, MUST NOT encode the original, source, detector, or sequence
number, and MUST be unique among live mappings in the flow.

A well-formed token with no live record in the current flow is an unknown token.
Unknown tokens MUST NOT be restored. This includes forged tokens, expired or
revoked tokens, and tokens copied from another flow.

## 5. Capability policy

Each sink contains an ordered array of capabilities and an optional cumulative
budget:

```json
{
  "postgres.execute": {
    "capabilities": [
      {
        "id": "database-connection",
        "sources": ["postgres.result"],
        "detectors": ["url_credentials"],
        "paths": ["/args/connectionString"],
        "maxUses": 1
      }
    ],
    "budget": {
      "maxUses": 4,
      "maxUniqueValues": 2,
      "maxBytes": 512
    }
  }
}
```

`sources` and `detectors` are either `"*"` or a non-empty list of identifiers.
Omitted `detectors` means `"*"`. Paths are RFC 6901 JSON Pointers with two
extensions:

- `*` matches exactly one segment;
- `**`, only as the final segment, matches zero or more remaining segments.

The first capability whose source selector, detector selector, and path all
match an occurrence is selected. Capability order is therefore observable and
MUST be preserved. A placeholder in an object or map key is never eligible for
declassification, regardless of path policy.

All budgets are cumulative for the lifetime of a flow:

- `maxUses`: number of restored token occurrences;
- `maxUniqueValues`: number of distinct token records restored to a sink;
- `maxBytes`: sum of UTF-8 byte lengths of every restored occurrence.

Missing budgets are unbounded. Counters do not reset between model turns.

## 6. Operations

### 6.1 Protect

`protectForModel(source, input)` MUST:

1. validate the runtime-owned source identifier;
2. remove expired mappings;
3. detect sensitive spans under the configured Flare Redact policy;
4. replace each span with a token bound to `(source, detector)`;
5. return a graph-safe copy without mutating the input;
6. record only value-free audit metadata.

The same `(source, detector, original)` SHOULD reuse one live token. Protection
is transactional: a resource-limit or audit failure MUST roll back every mapping
minted by that call.

### 6.2 Inspect

`inspectForSink(sink, input)` MUST evaluate the complete call without restoring a
value or consuming a budget. Its decision reports occurrence counts, projected
budget use, and value-free violations.

### 6.3 Authorize

`authorizeForSink(sink, input)` MUST perform a complete preflight before any
declassification. For every token occurrence it MUST verify:

1. a live record exists in the same flow;
2. the token is in a value position;
3. one capability for this sink matches its source, detector, and path;
4. the capability's projected use remains within its limit;
5. the sink's projected use, unique-value count, and byte count remain within
   their limits.

If any occurrence violates any check, the complete operation MUST fail: no token
is restored and no capability or sink counter is consumed. Passing through a
partially restored call is forbidden.

If all occurrences pass, the implementation MUST first construct the restored
copy, then emit its value-free audit event, then commit counters, and finally
return the copy. This ordering ensures cloning or audit failures do not consume
authorization state or return unaudited plaintext.

Audit callbacks MUST NOT re-enter the same flow while an operation is in
progress. The reference implementation rejects every such call so a callback
cannot invalidate the preflight snapshot or race a budget commit.

A call with no FlareFlow token MAY pass through by identity, including at an
unconfigured sink. FlareFlow does not authorize the tool call itself; it
authorizes declassification.

### 6.4 Trusted restoration and revocation

`restoreForApp(input)` restores live mappings without sink policy and MUST be
used only at a trusted final application boundary. `revokeSource(source)` removes
all mappings minted by that source. `reset()` removes every mapping and counter;
the reference implementation replaces retained history with one value-free reset
event. Audit delivery for revocation and reset occurs before mutation; failure
leaves their mapping, counter, and retained-event state unchanged.

## 7. Security invariant

Let `R(t) = (v, s, d, …)` be the live record for token `t`. Let an occurrence of
`t` appear at path `p` in a call resolved by the runtime to sink `k`.

FlareFlow releases `v` at that occurrence only if there exists a configured
capability `c` for `k` such that:

```text
source(c, s) ∧ detector(c, d) ∧ path(c, p)
∧ within_capability_budget(c)
∧ within_sink_budget(k)
```

and every other token occurrence in the same call also satisfies its checks.

Under the trust model in section 2, this gives the reference implementation an
exact-token noninterference property: changing model-controlled text, sink
arguments, key positions, or token placement cannot cause an original value to
appear in the authorized output unless the runtime's policy already grants that
specific declassification. A denial leaves the flow's authorization counters
unchanged.

This property says nothing about paraphrases, encoded information, or values the
model saw before protection.

## 8. Violations and audit

The reference profile reports these value-free reasons:

| Reason | Meaning |
|---|---|
| `unknown_token` | No live mapping exists in this flow |
| `key_position` | A token appears in an object or map key |
| `capability_denied` | Source, detector, sink, or path is not authorized |
| `capability_budget_exceeded` | The selected capability lacks remaining uses |
| `sink_budget_exceeded` | A sink-wide use, unique-value, or byte limit would be exceeded |

Audit records MAY contain time, source or sink identifiers, detector ids,
capability ids, JSON paths, counts, limits, and aggregate budget use. They MUST
NOT contain originals or token strings. Token-bearing object keys MUST be
represented by a positional label rather than copied into an audit path. Audit
retention MUST be bounded.

## 9. Resource and graph behavior

Implementations MUST bound live mappings and SHOULD bound retained events and
flow count. A gateway flow SHOULD have both a mapping TTL and an idle-flow TTL.
When a hard mapping limit is reached, protection MUST fail closed and roll back
the incomplete transaction.

The JavaScript reference preserves cycles, sparse arrays, shared references,
maps, sets, errors, URLs, enumerable symbol properties, and property descriptors
to the same extent as the core graph transformer. Accessor properties are not
invoked. Atomic host objects are not traversed.

## 10. Reference APIs

JavaScript and TypeScript:

```js
import { createAgentFlow } from 'flare-redact/agent';

const flow = createAgentFlow({ policy, sinks, limits });
const safe = flow.protectForModel('postgres.result', toolResult);
const decision = flow.inspectForSink('postgres.execute', modelCall);
const localCall = flow.authorizeForSink('postgres.execute', modelCall);
```

Gateway control plane:

```text
POST   /v1/flows
POST   /v1/flows/:id/protect
POST   /v1/flows/:id/inspect
POST   /v1/flows/:id/authorize
POST   /v1/flows/:id/restore
GET    /v1/flows/:id/snapshot
DELETE /v1/flows/:id
```

The sidecar makes the same operator policy available to any JSON/HTTP client.
The repository ships standard-library clients for Python and Go.

## 11. Reproducibility profile

`bench/agent-flow-cases.json` defines deterministic attack and utility families.
`npm run benchmark:agent -- --json` evaluates the legacy shared vault, the
tool-scoped vault, and FlareFlow. The corpus measures exact-token restoration
only. Results MUST be reported with the corpus scope statement and MUST NOT be
presented as a general prompt-injection benchmark.

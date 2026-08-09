# FlareFlow: Capability-Bounded Declassification for Tool-Using Language Model Agents

**Umud Hasanli**
Flare Collection
https://github.com/flare-collection/flare-redact

Technical report / preprint — August 2026. Not peer reviewed.

## Abstract

Reversible prompt redaction hides a sensitive value from a language model while
leaving an opaque reference that can be restored locally. In a tool-using agent,
however, a model can copy that reference into a different tool call. A shared
vault then restores the value immediately before execution, creating a
declassification channel even though the model never observed the plaintext.
Tool-scoped vaults close cross-tool movement but cannot express different
authority among argument paths of one tool, value origins, detector classes, or
repeated releases across turns.

We present FlareFlow, a small, model-independent information-flow boundary for
exact protected-value restoration. Each opaque 128-bit token is bound to a
runtime-assigned source and detector. A token is declassified only when an
operator-owned capability additionally matches the runtime-resolved sink and
JSON Pointer destination and when per-capability and cumulative sink budgets
remain. Authorization uses an atomic whole-call preflight; a single violation
returns no restored output and consumes no budget. Audit records contain labels,
paths, counts, and budgets but neither originals nor token strings.

The JavaScript reference implementation is dependency-free and graph-safe, and
the same policy is exposed through a bounded in-memory sidecar with Python and
Go clients. In a deterministic synthetic evaluation of 700 exact-token attack
trials and 300 utility trials, FlareFlow produced zero plaintext exposures and
preserved all utility trials. It denied 680 attacks; 20 percent-encoded-token
trials passed without declassification and therefore without exposure. Shared
and tool-scoped vault baselines exposed plaintext in 480 and 300 trials,
respectively. On one Apple A18 Pro / Node.js 22 run, authorization sustained
220,964 operations/s versus 858,002 operations/s for shared-vault restoration.
These results establish only the specified exact-token property: FlareFlow is
not a general prompt-injection defense and does not track information already
visible to a model.

## 1. Introduction

Tool-integrated language-model agents mix two kinds of authority. The model
chooses or constructs text, while the host runtime holds credentials, invokes
tools, and decides which operation actually executes. Indirect prompt injection
is dangerous precisely because untrusted content is processed inside this mixed
control plane. InjecAgent and AgentDojo demonstrate the breadth of harmful and
privacy-impacting tool behavior under injected instructions [1, 2].

Prompt redaction reduces what a remote model observes. A local vault replaces a
credential such as a database URL with an opaque reference and can restore the
reference after the model responds. Yet reversible redaction silently creates a
new authority: possession of the token can become authority to obtain its
plaintext. If the runtime restores every known token before every tool call, an
injected model can transplant a database token into an outbound URL. The model
does not learn the secret, but the network sink does.

This report studies that narrower problem. We ask: can a deployable redaction
layer preserve useful exact references while making declassification depend on
runtime policy rather than model behavior?

FlareFlow contributes:

1. a provenance record connecting every opaque token to a trusted source and
   detector class;
2. source–detector–sink–path capabilities with cumulative occurrence,
   unique-value, and byte budgets;
3. atomic whole-call authorization and bounded value-free audit state;
4. a dependency-free reference engine plus an operator-policy-controlled HTTP
   sidecar and Python/Go clients;
5. a public specification, deterministic evaluation corpus, runnable attack
   example, and claim-to-test mapping.

The central design decision is intentionally modest: do not ask the language
model whether declassification is safe. Enforce an exact, auditable predicate in
the host runtime.

## 2. Motivating failure

Assume a database tool returns a value that policy classifies in full as a
custom secret:

```text
postgres://admin:secret@db.internal/prod
```

A reversible redactor gives the model:

```text
[FR_FLOW_8c20…]
```

An injected instruction proposes:

```json
{
  "tool": "http.fetch",
  "args": { "url": "https://attacker.invalid/?x=[FR_FLOW_8c20…]" }
}
```

With one conversation-wide vault, generic restoration converts the URL to
plaintext before `http.fetch` executes. A vault per tool blocks that example,
but not a same-tool move from `args.connectionString` to `args.callbackUrl`, nor
can it distinguish a credential loaded from trusted configuration from a token
found in user input. It also has no cumulative release budget.

FlareFlow treats restoration as explicit declassification. The host resolves
`http.fetch` through its trusted registry, walks the complete argument graph,
and refuses the call because no capability grants that token at `/args/url`.

## 3. Threat model and goals

### 3.1 Trusted components

We trust the host runtime, its source labels, its tool registry and resolved sink
identifiers, the configured detector set, the capability policy, and downstream
sinks explicitly granted plaintext. We also trust a final application boundary
that deliberately requests unrestricted local restoration.

### 3.2 Adversary

The adversary controls model text and structured tool arguments. It may copy,
repeat, relocate, concatenate, construct, or replay well-formed token strings;
choose object value locations and keys; and attempt releases over multiple
turns. It may cause the model to emit arbitrary tool names, but the runtime—not
the model—resolves a name to the sink identifier passed to FlareFlow.

### 3.3 Goals

G1. An original is released at a model-produced occurrence only if runtime
policy authorizes its provenance and destination.
G2. A denied call returns no partially restored graph.
G3. A denial does not consume a valid future release budget.
G4. Repeated releases remain within lifetime budgets across turns.
G5. Audit output contains no original value or usable token string.
G6. Mappings, events, and server-side flows are bounded and expire.

### 3.4 Non-goals

FlareFlow does not detect malicious instructions, authorize whether a tool may
execute, sandbox tools, validate ordinary non-token arguments, or prevent a
trusted sink from mishandling plaintext. It is not semantic taint tracking. If a
model received plaintext before protection, it may paraphrase or encode that
information beyond FlareFlow's exact-token boundary. Detector false negatives
are also outside the invariant.

## 4. Design

### 4.1 Provenance-bearing opaque references

Protection runs before data enters model context. For a detected original `v`,
trusted source `s`, and detector `d`, the flow samples an opaque token `t` and
stores:

```text
R(t) = (v, s, d, created_at, expires_at, use_count)
```

The reference profile uses 128 random bits represented as 32 lowercase
hexadecimal characters. Tokens do not encode labels, values, or sequence
numbers. The same `(source, detector, original)` reuses one live token inside a
flow. Flow isolation makes foreign-session replay an unknown token.

### 4.2 Capabilities

Each sink `k` owns an ordered capability set. A capability `c` specifies source
selector `S_c`, detector selector `D_c`, path-pattern set `P_c`, and optional
cumulative use limit `U_c`:

```json
{
  "id": "database-credential",
  "sources": ["config"],
  "detectors": ["url_credentials"],
  "paths": ["/args/connectionString"],
  "maxUses": 1
}
```

Paths are RFC 6901 JSON Pointers extended with `*` for one segment and terminal
`**` for descendants. The first fully matching capability wins. Tokens in map
or object keys are never eligible for declassification.

### 4.3 Cumulative leakage budgets

A sink may bound total restored occurrences, distinct token records, and UTF-8
bytes. A capability may independently bound occurrences. These counters persist
across turns for the flow lifetime. Budgets control exact release volume; they
do not estimate semantic sensitivity.

### 4.4 Atomic authorization

Authorization performs five checks for every token occurrence: live same-flow
record, value position, matching capability, capability budget, and sink budget.
Only after the complete graph passes does the implementation construct a
restored copy, emit the audit event, commit counters, and return the copy.

The ordering matters. A graph-cloning failure consumes nothing. An audit-sink
failure returns no plaintext. A mixed call with one authorized token and one
forbidden token cannot expose the authorized token and cannot exhaust its
single-use grant.

The implementation also rejects re-entrant calls on the same flow while an
operation is active. An audit callback therefore cannot change mapping or
budget state between preflight and commit. Revocation and reset deliver their
audit event before mutation and leave state unchanged if delivery fails.

### 4.5 Value-free observability

Events report trusted identifiers, detectors, capability ids, sanitized JSON
paths, counts, and projected budgets. They omit originals and token strings.
Token-bearing object keys are replaced by positional labels before audit. Event
retention is bounded.

## 5. Security argument

Let occurrence `o = (t, p)` be token `t` at JSON path `p` in a call resolved to
sink `k`. Let `R(t) = (v, s, d, …)` be its live same-flow record. Define:

```text
Permit(o, k) := exists c in C_k:
  source_match(c, s) AND detector_match(c, d) AND path_match(c, p)
  AND capability_budget_ok(c) AND sink_budget_ok(k)
```

For a call graph `x` with occurrence set `O(x)`:

```text
Authorize(k, x) succeeds iff every o in O(x) satisfies Permit(o, k)
```

and succeeds only after constructing `restore(x)`. Otherwise it throws and does
not return a transformed graph.

**Exact-token declassification invariant.** Under the trusted components in
Section 3.1, an original `v` associated with token `t` appears through token
restoration in a successful model-produced sink call only if `Permit((t,p),k)`
held for its occurrence and every other occurrence in the call also passed.

**Argument sketch.** The only model-facing representation minted for `v` is
`t`. The authorization walk enumerates every exact token occurrence, and the
restoration map contains entries only for occurrences assigned a passing
capability. The map is not applied until the universal preflight predicate holds.
Unknown, expired, revoked, and foreign tokens have no record; key positions are
unconditionally rejected. Runtime-owned sink resolution prevents the model from
changing `k` by relabeling its output. Therefore token placement alone cannot
produce `v` outside the configured predicate. Transaction ordering leaves
budgets unchanged on refusal.

This is an implementation-level safety argument, not a machine-checked proof.
The public normative specification defines the behaviors on which it depends.

## 6. Implementation

The reference implementation is an opt-in `flare-redact/agent` ESM subpath for
Node.js 20+, browsers, and edge runtimes. It has zero runtime dependencies and
uses Web Crypto for tokens. It preserves cycles and shared references and
supports arrays, maps, sets, errors, URLs, enumerable symbols, sparse arrays,
and value descriptors without invoking accessors. Protection, live mappings,
events, and policy size have hard bounds; tokens and gateway flows have TTLs.

The sidecar exposes protect, inspect, authorize, trusted restore, snapshot, and
delete operations. It owns the policy and accepts no client policy at flow
creation. Flows are in-memory, idle-TTL-bound, and count-bounded. Python and Go
clients use only their standard libraries and preserve structured 403 denial
details. Local JavaScript and remote sidecar APIs implement the same policy
model; Python and Go do not claim separate local FlareFlow engines.

## 7. Evaluation

### 7.1 Questions

- RQ1: Do baseline vault designs expose originals under exact-token transplant,
  provenance mismatch, replay, key-position, and cumulative-release trials?
- RQ2: Does FlareFlow prevent plaintext exposure under its stated threat model?
- RQ3: Does the boundary preserve approved and token-free utility cases?
- RQ4: What is the microbenchmark cost of authorization relative to restoration?

### 7.2 Method

The checked-in `flareflow-benchmark-v1` corpus is deterministic and uses public
synthetic strings only. It runs 100 trials in each of seven attack families:
cross-sink movement, same-sink wrong path, source mismatch, detector mismatch,
foreign-flow replay, cumulative budget exhaustion, and object-key placement.
The cross-sink family varies raw URL placement and percent-encoded placement.

Three utility families contain 100 trials each: exact approved paths, approved
recursive paths at depths zero through four, and token-free calls. No language
model or network service is invoked. This isolates enforcement behavior from
model variance but does not measure end-to-end agent task success.

We compare:

- **Shared vault:** one reversible mapping for every tool;
- **Scoped vault:** independent mappings per tool/trust domain;
- **FlareFlow:** provenance, destination path, and cumulative capabilities.

An exposure is counted only when a synthetic plaintext secret appears in the
returned call. A denial is counted separately. A non-denied call that retains an
opaque transformed token is a harmless pass, not a plaintext exposure.

### 7.3 Security and utility results

| System | Attack trials | Denied | Harmless pass | Plaintext exposures | Utility passed |
|---|---:|---:|---:|---:|---:|
| Shared vault | 700 | 0 | 220 | 480 | 300/300 |
| Scoped vault | 700 | 0 | 400 | 300 | 300/300 |
| FlareFlow | 700 | 680 | 20 | 0 | 300/300 |

The 20 FlareFlow harmless passes are percent-encoded tokens. Because exact token
syntax is absent before the HTTP tool runs, FlareFlow neither restores nor
blocks them; the attacker receives only the opaque token. Raw tokens at the same
sink are denied. This distinction is important: the goal is controlled
declassification, not classifying every suspicious string.

Shared-vault exposure occurs under cross-sink raw placement, same-sink wrong
path, source mismatch, detector mismatch, and repeated release. Scoping removes
cross-sink and source-mismatch exposure in this corpus but cannot express
detector, same-tool path, or cumulative limits. Unknown foreign tokens and key
positions do not expose plaintext in the baselines, but they also produce no
explicit policy decision.

### 7.4 Runtime microbenchmark

One local run used Node.js v22.23.1 on Darwin arm64, Apple A18 Pro, 8 GB memory,
with the median of nine 100,000-iteration samples after 1,000 warmups:

| Operation | Operations/s | Median time/op |
|---|---:|---:|
| Shared-vault restore | 858,002 | 1.17 μs |
| Scoped-vault restore | 858,948 | 1.16 μs |
| FlareFlow authorize | 220,964 | 4.53 μs |

FlareFlow is about 3.9× slower than unvalidated restoration in this narrow
microbenchmark, adding roughly 3.4 μs per one-token call on this machine while
still exceeding 220k operations/s. The result includes graph traversal, policy
matching, budget projection, graph restoration, and bounded audit maintenance.
It is a single-machine directional measurement without confidence intervals;
users should rerun the script on their deployment runtime.

## 8. Claim-to-evidence map

| Claim | Executable evidence |
|---|---|
| Exact source/detector/sink/path match restores | `test/agent.test.mjs` authorized-path test |
| Cross-sink and wrong-path transplant deny | dedicated unit tests + benchmark families |
| Whole-call denial consumes no budget | mixed valid/invalid single-use test |
| Budgets persist across turns | use/unique-value/UTF-8 byte test |
| Replay, expiry, revocation, and key positions fail closed | dedicated unit tests |
| Cycles/shared references survive | graph preservation test |
| Audit state omits originals and token strings | bounded snapshot test |
| Audit failure/re-entrancy cannot consume or alter state | authorization and revocation rollback tests |
| Gateway policy is operator-owned | gateway client-policy rejection test |
| Python and Go wire clients complete the flow | SDK stub-server tests |

## 9. Related work

Information-flow control has a long systems lineage. Denning's lattice model
formalized constraints on flows among security classes [3], and Sabelfeld and
Myers survey language-based confidentiality and noninterference techniques [4].
FlareFlow is not a new general IFC calculus; it applies a small runtime
declassification predicate to reversible redaction references in agent calls.

NeMo Guardrails provides model-independent programmable rails around LLM
applications [5]. Current NVIDIA documentation separates input, retrieval,
dialog, execution, and output rails and identifies PII masking before the model
and argument/result validation at execution time [6]. FlareFlow is naturally a
small execution-rail primitive: detectors protect values before model context,
while capabilities govern their exact restoration at a tool boundary.

InjecAgent and AgentDojo establish indirect prompt injection and privacy
exfiltration as concrete evaluation problems for tool-integrated agents [1, 2].
RTBAS uses a separate model and task alignment to prevent prompt injection and
privacy leakage [7]. CaMeL instead extracts control and data flows from trusted
queries and uses capabilities to restrict unauthorized flows [8]. FlareFlow
shares the systems principle that enforcement should sit outside the vulnerable
model, but it is narrower and easier to integrate: it does not synthesize an
agent program, infer task intent, or provide general prompt-injection security.
It controls only declassification of exact values already hidden by the
redaction layer. These approaches are complementary rather than direct baseline
equivalents.

The Model Context Protocol security guidance recommends splitting access by
tool or capability and verifying scopes at the resource server [9]. FlareFlow's
host-owned sink identity follows the same least-authority direction while adding
value provenance and destination-path constraints for local restoration.

## 10. Limitations and threats to validity

**Detection coverage.** A value that is not detected is not tokenized and falls
outside the guarantee. Detector selection and false negatives remain deployment
responsibilities.

**Exact syntax only.** Encoding, hashing, paraphrase, inference, and covert
channels are not semantic taint. Percent-encoded tokens remain opaque but are not
blocked in the reference syntax.

**Trusted runtime.** A compromised host can read in-memory mappings, call
`restoreForApp`, alter policy, or bypass FlareFlow. A malicious authorized sink
receives plaintext by definition.

**Policy correctness.** Wildcards and broad selectors may grant more than the
operator intended. First-match capability ordering is observable and should be
reviewed like firewall rules.

**Synthetic evaluation.** The seven families exercise the formal boundary but
are not a substitute for adaptive attacks, public end-to-end agent benchmarks,
model diversity, or production traces. Repeated trials vary synthetic values
and selected structures; they are not 700 independent semantic tasks.

**Performance.** One machine, runtime, graph shape, and token count cannot
predict a complete agent's latency. Network and model latency are intentionally
excluded.

**Proof status.** The security argument is by construction and tests, not a
machine-checked proof or independent audit. The code should be reviewed and
fuzzed before use as a high-assurance security boundary.

## 11. Operational guidance

Deploy FlareFlow with ordinary defense in depth:

1. keep source and sink identifiers in trusted runtime registries;
2. grant exact paths and detector classes instead of broad wildcards;
3. give network egress sinks empty capabilities unless declassification is
   explicitly required;
4. use short mapping and flow TTLs and low cumulative budgets;
5. close flows when tenant, conversation, or authorization context ends;
6. keep snapshots value-free and alert on denials or budget pressure;
7. validate schemas, authorize tools, sandbox execution, and use content and
   prompt-injection defenses independently.

For NVIDIA-style deployments, FlareFlow can sit between a tool-call execution
rail and the actual action: PII/secret detection protects tool results before
context; the execution rail resolves the action; FlareFlow authorizes exact
declassification; ordinary schema and action policy then run before execution.
No NVIDIA component or endorsement is implied.

## 12. Reproducibility and ethics

All evaluation secrets use the public form `FRBENCH_SECRET_NNN`. The benchmark
makes no external calls, uses no personal data, and requires no model or API
key. Corpus definitions, implementation, tests, and the exact result snapshot
are versioned with the source. Reproduce with:

```bash
npm ci
npm run benchmark:agent -- --json --iterations=100000 --samples=9
```

The benchmark prints runtime version, platform, architecture, family-level
outcomes, durations, and a checksum that prevents dead-code elimination. Future
reports should retain the scope statement and must not relabel these results as
general prompt-injection performance.

## 13. Conclusion

Reversible redaction changes the security question from “did the model see the
secret?” to “who may turn the model's reference back into the secret?” FlareFlow
makes that answer an external, deterministic capability over provenance,
destination, and cumulative exposure. The implementation is small enough to
audit, deployable through a zero-dependency library or polyglot sidecar, and
explicit about the boundary it does not solve. The next research step is an
independent evaluation inside adaptive, end-to-end agent benchmarks and a
machine-checked model of the atomic declassification invariant.

## References

[1] Q. Zhan, Z. Liang, Z. Ying, and D. Kang. “InjecAgent: Benchmarking Indirect
Prompt Injections in Tool-Integrated Large Language Model Agents.” arXiv:2403.02691,
2024. https://arxiv.org/abs/2403.02691

[2] E. Debenedetti et al. “AgentDojo: A Dynamic Environment to Evaluate Prompt
Injection Attacks and Defenses for LLM Agents.” arXiv:2406.13352, 2024.
https://arxiv.org/abs/2406.13352

[3] D. E. Denning. “A Lattice Model of Secure Information Flow.” Communications
of the ACM 19(5), 236–243, 1976. https://doi.org/10.1145/360051.360056

[4] A. Sabelfeld and A. C. Myers. “Language-Based Information-Flow Security.”
IEEE Journal on Selected Areas in Communications 21(1), 5–19, 2003.
https://doi.org/10.1109/JSAC.2002.806121

[5] T. Rebedea, R. Dinu, M. N. Sreedhar, C. Parisien, and J. Cohen. “NeMo
Guardrails: A Toolkit for Controllable and Safe LLM Applications with
Programmable Rails.” EMNLP System Demonstrations, 431–445, 2023.
https://doi.org/10.18653/v1/2023.emnlp-demo.40

[6] NVIDIA. “Guardrail Types — NeMo Guardrails Library Developer Guide.”
Accessed August 9, 2026.
https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/rail-types

[7] P. Y. Zhong et al. “RTBAS: Defending LLM Agents Against Prompt Injection and
Privacy Leakage.” arXiv:2502.08966, 2025. https://arxiv.org/abs/2502.08966

[8] E. Debenedetti et al. “Defeating Prompt Injections by Design.”
arXiv:2503.18813, 2025. https://arxiv.org/abs/2503.18813

[9] Model Context Protocol. “Security Best Practices.” Accessed August 9, 2026.
https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

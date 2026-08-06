# Security

If you've found a detector bypass, a built-in pattern that can be made to
backtrack, a vault confidentiality/authentication issue, a placeholder collision,
or another security impact, report it privately instead of opening a public
issue. Use synthetic or revoked values in the reproduction.

Use GitHub's private advisory form:
**[Report a vulnerability](https://github.com/flare-collection/flare-redact/security/advisories/new)**

I'll acknowledge within a few days and keep you in the loop on a fix. Once it's
patched and released, I'm glad to credit you — unless you'd rather stay
anonymous, which is completely fine.

Supported versions: the latest released version on npm. Please make sure you can
reproduce on that before reporting.

## Security scope

Detection is best-effort and cannot prove that input is free of PII. Built-in
patterns are reviewed and adversarially benchmarked, but custom regular
expressions are trusted code because JavaScript RegExp has no general linear-time
guarantee. Encrypted vaults protect persisted maps, not a compromised host,
untrusted code running in the same process, or keys already present in process
memory. Restoring a placeholder intentionally reveals its original value, and
deterministic transforms intentionally reveal equality between matching inputs.

`scan()` omits matched values by default. Enabling `includeValues` is an explicit
confidentiality tradeoff: those findings must not be logged or exported. HTTP
redaction covers only the returned snapshot, never the live request. Tool and LLM
vaults protect data before it crosses the configured model boundary; restoring a
model-produced tool call intentionally exposes the original locally to that tool.

## The gateway

The gateway is the only network-facing component, so its boundaries are worth
stating explicitly.

It binds to loopback by default, and in a container it should be published to
loopback: a redaction proxy reachable from the network is a proxy anyone can send
data through. `/v1` accepts a bearer token compared in constant time; health and
metrics stay open so probes need no credential. A caller may pass options, but the
configured policy is layered over them, so no client can widen what the operator
chose to protect, and a client-supplied `transformSecret` is rejected outright.

Request headers — including the `Authorization` that authenticates you to the
upstream — are forwarded untouched. That header is the credential, not the secret
being hidden, and redacting it would break every request. Hop-by-hop headers are
stripped in both directions and redirects are not followed, so an upstream cannot
bounce a request somewhere the configuration never named.

Sessions hold placeholder→original maps in memory only. They expire, they are
capped, and they are per-process; there is no shared store, because distributing
one would mean replicating plaintext secrets across a cluster. The audit log and
metrics carry detector ids and counts — never bodies, headers, matched values or
placeholder mappings.

Out of scope by design: TLS interception, response scanning (the gateway restores
what it masked; it does not inspect what the upstream sent), and any guarantee
about an upstream you did not configure.

## Other language engines

The Python, Go and Rust engines implement the FRS-1 subset, which is deliberately
narrower than the Node detector set — `spec/SPEC.md` §14 lists every difference.
A pack that uses a construct an engine cannot execute exactly fails to load
rather than loading with the check skipped. Report a divergence between engines
the same way you would report a bypass: it is one.

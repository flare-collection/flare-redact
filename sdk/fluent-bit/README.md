# flare-redact for Fluent Bit

A Fluent Bit [WASM filter](https://docs.fluentbit.io/manual/pipeline/filters/wasm)
that redacts secrets and personal data from every record before it leaves the
node. It is the flare-redact Rust engine compiled to WebAssembly, so it catches
exactly what the JavaScript, Python, Go and Rust engines catch.

## Use it

Download `flare-redact-fluent-bit.wasm` from a
[GitHub Release](https://github.com/flare-collection/flare-redact/releases),
or build it:

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
# target/wasm32-wasip1/release/flare_redact_fluent_bit.wasm
```

```text
[FILTER]
    Name             wasm
    Match            *
    WASM_Path        /etc/fluent-bit/flare-redact-fluent-bit.wasm
    Function_Name    flare_redact
    Accessible_Paths /etc/flare-redact
```

```text
{"log":"login ada@example.com key ghp_A1b2...","password":"hunter2hunter2","level":"info"}
{"log":"login a***@*** key ghp_***","password":"***","level":"info"}
```

## Choose a policy

Pick one with `Function_Name`, no file needed:

| Function | What it does |
| --- | --- |
| `flare_redact` | the default detectors: keys and tokens, emails, cards, IBANs, and more |
| `flare_redact_pii` | the defaults plus the `pii` group, phone numbers included |
| `flare_redact_label` | the defaults, written as `[REDACTED:email]` |

For anything else, put a `flare-redact.json` in the working directory or in
`/etc/flare-redact`, and list that directory in `Accessible_Paths`:

```json
{
  "enable": ["pii"],
  "disable": ["ipv4"],
  "allow": ["ops@example.com"],
  "terms": ["Project Falcon"],
  "mode": "mask"
}
```

The fields are `only`, `enable`, `disable`, `mode` (`mask`, `label`, `hash`,
`pseudonym`, `surrogate`), `mask`, `allow`, `terms`, `transform_secret` (the
key for `hash`, `pseudonym` and `surrogate`) and `min_confidence`.

## Fails closed

If `flare-redact.json` is invalid, or a record cannot be redacted (for example
because it is over the size limit), the record is replaced by
`{"flare_redact_error": "..."}` and the reason is printed on Fluent Bit's
standard error. A redactor that passed records through when it was
misconfigured would leak exactly when nobody is looking.

The filter uses Fluent Bit's default `Event_Format json`. CI runs it in the
official `fluent/fluent-bit:5.2.0` image on every change.

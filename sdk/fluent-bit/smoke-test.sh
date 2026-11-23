#!/usr/bin/env bash
# Run the filter in the official Fluent Bit image and check what it writes.
# Needs Docker and a built filter:
#   cargo build --release --target wasm32-wasip1
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
image="${FLUENT_BIT_IMAGE:-fluent/fluent-bit:5.2.0}"
work="$(mktemp -d)"
chmod 777 "$work"
cp "$here/target/wasm32-wasip1/release/flare_redact_fluent_bit.wasm" "$work/flare-redact.wasm"

token="ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
record="{\"log\":\"login ada@example.com key $token\",\"password\":\"hunter2hunter2\",\"level\":\"info\"}"

run() {
  local function_name="$1" out="$2"
  cat > "$work/fluent-bit.conf" <<CONF
[SERVICE]
    Flush     1
    Log_Level info

[INPUT]
    Name    dummy
    Tag     app
    Dummy   $record
    Samples 3

[FILTER]
    Name             wasm
    Match            *
    WASM_Path        /work/flare-redact.wasm
    Function_Name    $function_name
    Accessible_Paths /work
    WASM_Stack_Size  2M
    WASM_Heap_Size   8M

[OUTPUT]
    Name   file
    Match  *
    Path   /work
    File   $out
    Format plain
CONF
  docker run -d --name flare-redact-fb -v "$work:/work" "$image" /fluent-bit/bin/fluent-bit -c /work/fluent-bit.conf >/dev/null
  sleep 8
  docker logs flare-redact-fb 2>&1 | tail -n 20
  docker rm -f flare-redact-fb >/dev/null
}

fail() { echo "FAIL: $*" >&2; exit 1; }

run flare_redact out.log
echo "--- flare_redact"
cat "$work/out.log"
[ "$(wc -l < "$work/out.log")" -eq 3 ] || fail "expected 3 records"
grep -q 'ada@example.com' "$work/out.log" && fail "an email got through"
grep -q "$token" "$work/out.log" && fail "a token got through"
grep -q 'hunter2hunter2' "$work/out.log" && fail "a password got through"
grep -q 'a\*\*\*@\*\*\*' "$work/out.log" || fail "the email mask is missing"
grep -q '"level":"info"' "$work/out.log" || fail "a clean field was changed"

run flare_redact_label label.log
echo "--- flare_redact_label"
cat "$work/label.log"
grep -q 'REDACTED:email' "$work/label.log" || fail "the label function did not label"

# A broken config fails closed: records are replaced, not passed through.
echo '{"mode":"shout"}' > "$work/flare-redact.json"
run flare_redact closed.log
echo "--- invalid flare-redact.json"
cat "$work/closed.log"
grep -q 'ada@example.com' "$work/closed.log" && fail "a broken config let an email through"
grep -q 'flare_redact_error' "$work/closed.log" || fail "a broken config was not reported"

echo "Fluent Bit redacted every record."

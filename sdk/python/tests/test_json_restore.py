"""Restoring into JSON text: tool-call arguments, partial JSON and JSON-mode
output stay valid JSON with the same structure, whatever the restored value
contains."""

from __future__ import annotations

import json
import re
import unittest
from types import SimpleNamespace

import flare_redact as fr
from flare_redact.integrations import wrap_anthropic, wrap_openai
from flare_redact.vault import (
    StreamRestorer,
    _decode_json_string_content,
    is_json_document,
    requests_json_output,
)

# A quote, a backslash and control characters.
AWKWARD = 'Q"uo\\te\nline\ttab\x01end'
TERMS = {"terms": [AWKWARD]}
# URL credentials holding a quoted fragment: a default detector captures it whole.
QUOTED_URL = 'https://user:pa","extra":true,"note":"x@example.com/pay'
PLACEHOLDER = re.compile(r"\[FR_[A-Z_]+_[0-9a-f]{24}\]")


def placeholder_in(value: object) -> str:
    match = PLACEHOLDER.search(json.dumps(value))
    assert match, "no placeholder reached the model"
    return match.group(0)


def split(text: str, at: int) -> list:
    return [text[:at], text[at:]]


class RestoreRuleTest(unittest.TestCase):
    def test_a_json_document_gets_escaped_originals(self) -> None:
        vault = fr.create_vault(TERMS)
        placeholder = vault.redact(f"say {AWKWARD}")[4:]
        args = json.dumps({"text": placeholder, "n": 1})
        self.assertEqual(json.loads(vault.restore(args)), {"text": AWKWARD, "n": 1})
        self.assertEqual(json.loads(fr.restore(f'\n ["{placeholder}"]', vault)), [AWKWARD])
        self.assertEqual(json.loads(vault.restore({"args": args})["args"]), {"text": AWKWARD, "n": 1})

    def test_any_other_string_gets_the_original_verbatim(self) -> None:
        vault = fr.create_vault(TERMS)
        placeholder = vault.redact(f"say {AWKWARD}")[4:]
        self.assertEqual(vault.restore(f"say {placeholder}"), f"say {AWKWARD}")
        self.assertEqual(vault.restore(f"{{ not json {placeholder}"), f"{{ not json {AWKWARD}")
        self.assertEqual(vault.restore(f'"{placeholder}"'), f'"{AWKWARD}"')
        self.assertEqual(vault.restore({"input": {"text": placeholder}}), {"input": {"text": AWKWARD}})

    def test_a_restored_value_keeps_the_structure(self) -> None:
        vault = fr.create_vault()
        placeholder = placeholder_in(vault.redact(f"call back {QUOTED_URL}"))
        parsed = json.loads(vault.restore(json.dumps({"amount": 10, "callback": placeholder})))
        self.assertEqual(parsed["amount"], 10)
        self.assertEqual(list(parsed), ["amount", "callback"])
        self.assertTrue(QUOTED_URL.startswith(parsed["callback"]))

    def test_a_session_restores_by_the_same_rule(self) -> None:
        session = fr.create_session(TERMS)
        placeholder = session.redact(f"say {AWKWARD}")[4:]
        self.assertEqual(json.loads(session.restore(json.dumps([placeholder]))), [AWKWARD])

    def test_json_stream_mode_escapes_across_chunk_splits(self) -> None:
        vault = fr.create_vault(TERMS)
        placeholder = vault.redact(AWKWARD)
        text = json.dumps({"note": placeholder})
        at = text.index(placeholder) + 6
        for restorer in (vault.stream(json=True), StreamRestorer(vault.entries(), json=True)):
            out = "".join(restorer.push(piece) for piece in split(text, at)) + restorer.flush()
            self.assertEqual(json.loads(out), {"note": AWKWARD})
        plain = vault.stream()
        self.assertEqual(plain.push(f"<{placeholder}>") + plain.flush(), f"<{AWKWARD}>")

    def test_is_json_document(self) -> None:
        self.assertTrue(is_json_document(' \n{"a": [1]}\t'))
        self.assertTrue(is_json_document("[]"))
        for text in ('"text"', "42", "{ not json", "[NaN]", " {}", ""):
            self.assertFalse(is_json_document(text), text)

    def test_requests_json_output(self) -> None:
        self.assertTrue(requests_json_output({"response_format": {"type": "json_object"}}))
        self.assertTrue(requests_json_output({"response_format": {"type": "json_schema"}}))
        self.assertTrue(requests_json_output({"text": {"format": {"type": "json_schema"}}}))
        self.assertTrue(requests_json_output({"output_config": {"format": {"type": "json_schema"}}}))
        self.assertTrue(requests_json_output({"output_format": {"type": "json_schema"}}))
        self.assertFalse(requests_json_output({"response_format": {"type": "text"}}))
        self.assertFalse(requests_json_output({}))


def openai_client(reply):
    seen = {}

    class Completions:
        def create(self, **kwargs):
            seen.update(kwargs)
            return reply(placeholder_in(kwargs["messages"]))

    client = SimpleNamespace(chat=SimpleNamespace(completions=Completions()))
    return client, seen


def chunk(delta: dict, index: int = 0) -> dict:
    return {"choices": [{"index": index, "delta": delta, "finish_reason": None}]}


def args_chunk(args: str, call: int = 0) -> dict:
    return chunk({"tool_calls": [{"index": call, "function": {"arguments": args}}]})


def collect_openai(stream) -> tuple:
    content, args = "", {}
    for event in stream:
        delta = event["choices"][0]["delta"]
        content += delta.get("content") or ""
        for call in delta.get("tool_calls") or ():
            args[call["index"]] = args.get(call["index"], "") + call["function"]["arguments"]
    return content, args


class WrapOpenAITest(unittest.TestCase):
    def test_tool_call_arguments_stay_valid_json(self) -> None:
        def reply(placeholder):
            return {"choices": [{"message": {
                "role": "assistant",
                "content": f"Calling the tool for {placeholder}",
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "save", "arguments": json.dumps({"note": placeholder, "n": 1})}}],
                "function_call": {"name": "save", "arguments": json.dumps({"note": placeholder})},
            }}]}

        client, _ = openai_client(reply)
        message = wrap_openai(client, TERMS).chat.completions.create(model="x", messages=[{"role": "user", "content": f"Save {AWKWARD}"}])["choices"][0]["message"]
        self.assertEqual(json.loads(message["tool_calls"][0]["function"]["arguments"]), {"note": AWKWARD, "n": 1})
        self.assertEqual(json.loads(message["function_call"]["arguments"]), {"note": AWKWARD})
        self.assertEqual(message["content"], f"Calling the tool for {AWKWARD}")

    def test_a_captured_value_with_quotes_keeps_the_arguments_structure(self) -> None:
        client, seen = openai_client(lambda placeholder: {"choices": [{"message": {"tool_calls": [
            {"function": {"name": "pay", "arguments": json.dumps({"amount": 10, "callback": placeholder})}}]}}]})
        res = wrap_openai(client).chat.completions.create(model="x", messages=[{"role": "user", "content": f"Pay 10, call back {QUOTED_URL}"}])
        self.assertNotIn("extra", json.dumps(seen["messages"]))
        parsed = json.loads(res["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(parsed["amount"], 10)
        self.assertEqual(list(parsed), ["amount", "callback"])

    def test_json_mode_content(self) -> None:
        client, _ = openai_client(lambda placeholder: {"choices": [{"message": {"content": json.dumps({"note": placeholder})}}]})
        res = wrap_openai(client, TERMS).chat.completions.create(
            model="x", response_format={"type": "json_object"}, messages=[{"role": "user", "content": f"Save {AWKWARD}"}])
        self.assertEqual(json.loads(res["choices"][0]["message"]["content"]), {"note": AWKWARD})

    def test_streamed_arguments_split_mid_placeholder_are_valid_json(self) -> None:
        def reply(placeholder):
            args = json.dumps({"note": placeholder, "again": placeholder})
            at = args.index(placeholder) + 9
            return iter([
                chunk({"content": f"Saving {placeholder[:5]}"}),
                chunk({"content": placeholder[5:]}),
                *(args_chunk(piece) for piece in split(args, at)),
            ])

        client, _ = openai_client(reply)
        stream = wrap_openai(client, TERMS).chat.completions.create(stream=True, messages=[{"role": "user", "content": f"Save {AWKWARD}"}])
        content, args = collect_openai(stream)
        self.assertEqual(content, f"Saving {AWKWARD}")
        self.assertEqual(json.loads(args[0]), {"note": AWKWARD, "again": AWKWARD})

    def test_streamed_quoted_value_keeps_the_arguments_structure(self) -> None:
        def reply(placeholder):
            args = json.dumps({"amount": 10, "callback": placeholder})
            return iter([args_chunk(piece) for piece in split(args, args.index(placeholder))])

        client, _ = openai_client(reply)
        _, args = collect_openai(wrap_openai(client).chat.completions.create(stream=True, messages=[{"role": "user", "content": f"Pay {QUOTED_URL}"}]))
        parsed = json.loads(args[0])
        self.assertEqual(parsed["amount"], 10)
        self.assertEqual(list(parsed), ["amount", "callback"])
        self.assertTrue(parsed["callback"].startswith('https://user:pa","extra":true'), "restored, as a value")

    def test_streamed_json_mode_content_and_object_events(self) -> None:
        def reply(placeholder):
            text = json.dumps({"note": placeholder})
            at = text.index(placeholder) + 5
            return iter([SimpleNamespace(choices=[SimpleNamespace(index=0, delta=SimpleNamespace(content=piece, tool_calls=None))]) for piece in split(text, at)])

        client, _ = openai_client(reply)
        stream = wrap_openai(client, TERMS).chat.completions.create(
            stream=True, response_format={"type": "json_schema"}, messages=[{"role": "user", "content": f"Save {AWKWARD}"}])
        text = "".join(event.choices[0].delta.content for event in stream)
        self.assertEqual(json.loads(text), {"note": AWKWARD})

    def test_held_back_text_is_not_lost_and_events_keep_their_order(self) -> None:
        def reply(placeholder):
            return iter([
                chunk({"content": "a list: ["}),
                args_chunk('{"list":['),
                args_chunk(f'"{placeholder}"]}}'),
                chunk({}, 0),
            ])

        client, _ = openai_client(reply)
        events = list(wrap_openai(client, TERMS).chat.completions.create(stream=True, messages=[{"role": "user", "content": f"Save {AWKWARD}"}]))
        self.assertEqual(len(events), 4)
        content, args = collect_openai(events)
        self.assertEqual(content, "a list: [")
        self.assertEqual(json.loads(args[0]), {"list": [AWKWARD]})


def anthropic_client(reply):
    class Messages:
        def create(self, **kwargs):
            return reply(placeholder_in(kwargs["messages"]))

    return SimpleNamespace(messages=Messages())


def block_delta(index: int, kind: str, field: str, text: str) -> dict:
    return {"type": "content_block_delta", "index": index, "delta": {"type": kind, field: text}}


def collect_anthropic(stream) -> dict:
    blocks: dict = {}
    for event in stream:
        delta = event.get("delta") or {}
        piece = delta.get("text") or delta.get("partial_json") or ""
        if event["type"] == "content_block_delta":
            blocks[event["index"]] = blocks.get(event["index"], "") + piece
    return blocks


class WrapAnthropicTest(unittest.TestCase):
    def test_partial_json_split_mid_placeholder_is_valid_json(self) -> None:
        def reply(placeholder):
            text = json.dumps({"note": placeholder})
            at = text.index(placeholder) + 3
            return iter([
                block_delta(0, "text_delta", "text", f"About {placeholder}"),
                {"type": "content_block_stop", "index": 0},
                *(block_delta(1, "input_json_delta", "partial_json", piece) for piece in split(text, at)),
                {"type": "content_block_stop", "index": 1},
            ])

        blocks = collect_anthropic(wrap_anthropic(anthropic_client(reply), TERMS).messages.create(
            stream=True, messages=[{"role": "user", "content": f"Save {AWKWARD}"}]))
        self.assertEqual(blocks[0], f"About {AWKWARD}")
        self.assertEqual(json.loads(blocks[1]), {"note": AWKWARD})

    def test_a_captured_value_with_quotes_keeps_the_tool_input_structure(self) -> None:
        def reply(placeholder):
            text = json.dumps({"amount": 10, "callback": placeholder})
            return iter([block_delta(0, "input_json_delta", "partial_json", piece) for piece in split(text, 25)])

        blocks = collect_anthropic(wrap_anthropic(anthropic_client(reply)).messages.create(
            stream=True, messages=[{"role": "user", "content": f"Pay {QUOTED_URL}"}]))
        parsed = json.loads(blocks[0])
        self.assertEqual(parsed["amount"], 10)
        self.assertEqual(list(parsed), ["amount", "callback"])
        self.assertTrue(parsed["callback"].startswith('https://user:pa","extra":true'), "restored, as a value")

    def test_structured_output_text_is_escaped(self) -> None:
        def reply(placeholder):
            text = json.dumps({"note": placeholder})
            at = text.index(placeholder) + 7
            return iter([block_delta(0, "text_delta", "text", piece) for piece in split(text, at)])

        schema = {"type": "json_schema", "schema": {"type": "object"}}
        client = wrap_anthropic(anthropic_client(reply), TERMS)
        for request in ({"output_config": {"format": schema}}, {"output_format": schema}):
            blocks = collect_anthropic(client.messages.create(stream=True, messages=[{"role": "user", "content": f"Save {AWKWARD}"}], **request))
            self.assertEqual(json.loads(blocks[0]), {"note": AWKWARD}, list(request)[0])

    def test_a_tool_use_input_object_gets_the_value_as_is(self) -> None:
        client = anthropic_client(lambda placeholder: {"content": [
            {"type": "text", "text": f"Saving {placeholder}"},
            {"type": "tool_use", "id": "toolu_1", "name": "save", "input": {"note": placeholder, "list": [placeholder]}},
        ]})
        res = wrap_anthropic(client, TERMS).messages.create(messages=[{"role": "user", "content": f"Save {AWKWARD}"}])
        self.assertEqual(res["content"][0]["text"], f"Saving {AWKWARD}")
        self.assertEqual(res["content"][1]["input"], {"note": AWKWARD, "list": [AWKWARD]})



class CaptureFromJsonTextTest(unittest.TestCase):
    """A value captured from a string that is a JSON document is stored decoded,
    so a round trip through JSON is exact (issue #34)."""

    def test_round_trip_through_json_text_is_exact(self) -> None:
        vault = fr.create_vault(placeholder_style="readable")
        text = '{"url":"https://user:p\\"ss@db.example.com/x"}'
        self.assertEqual(vault.restore(vault.redact(text)), text)
        self.assertEqual(vault.entries(), [("[URL_CREDENTIALS_1]", 'https://user:p"ss@')])
        self.assertEqual(vault.restore("[URL_CREDENTIALS_1]"), 'https://user:p"ss@')

    def test_other_text_keeps_the_captured_form(self) -> None:
        vault = fr.create_vault(placeholder_style="readable")
        vault.redact('url https://user:p\\"ss@db.example.com/x')
        self.assertEqual(vault.entries()[0][1], 'https://user:p\\"ss@')

    def test_invalid_string_content_keeps_the_captured_form(self) -> None:
        vault = fr.create_vault({"terms": ["ab\\ud800cd", "x\\u0041y"]}, placeholder_style="readable")
        vault.redact('["ab\\ud800cd", "x\\u0041y"]')
        self.assertEqual({original for _, original in vault.entries()}, {"ab\\ud800cd", "xAy"})

    def test_decoder(self) -> None:
        decode = _decode_json_string_content
        self.assertEqual(decode("plain"), "plain")
        self.assertEqual(decode('q\\"b\\\\s\\/'), 'q"b\\s/')
        self.assertEqual(decode("\\b\\f\\n\\r\\t"), "\b\f\n\r\t")
        self.assertEqual(decode("\\u00e9\\uD83D\\uDE00"), "é\U0001F600")
        for text in ['a"b', "a\nb", "a\\", "\\x", "\\u12", "\\ud800", "\\udc00", "\\ud800\\u0041"]:
            self.assertIsNone(decode(text), text)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""A value under a sensitive key is masked whatever its type (FRS-1 §9)."""

from __future__ import annotations

import dataclasses
import datetime
import unittest
import uuid
from decimal import Decimal
from fractions import Fraction

import flare_redact as fr
from flare_redact.engine import _js_float


class SensitiveValuesTest(unittest.TestCase):
    def test_numbers_under_a_sensitive_key_are_masked(self) -> None:
        out = fr.redact({"cardNumber": "4242424242424242", "cvv": 123, "pin": Decimal("1234"), "amount": 1000})
        self.assertEqual(out, {"cardNumber": "***", "cvv": "***", "pin": "***", "amount": 1000})

    def test_containers_are_masked_at_every_depth(self) -> None:
        out = fr.redact({
            "cookie": {"name": "connect.sid", "value": "s%3A_SID_abc"},
            "password": ("hunter2", ["letmein", 7]),
            "credentials": {"tags": frozenset({"a"})},
        })
        self.assertEqual(out["cookie"], {"name": "***", "value": "***"})
        self.assertEqual(out["password"], ("***", ["***", "***"]))
        self.assertEqual(out["credentials"]["tags"], frozenset({"***"}))

    def test_booleans_and_none_are_kept(self) -> None:
        source = {"hasPassword": True, "password": None, "token": False, "max_tokens": 4096}
        self.assertEqual(fr.redact(source), source)

    def test_bytes_are_masked_as_hex_text(self) -> None:
        self.assertEqual(fr.redact({"private_key": b"\x01\x02\xff"}), {"private_key": "***"})
        hashed = fr.redact({"secret": bytearray(b"\x01\x02\xff")}, mode="hash", transform_secret="k")
        self.assertEqual(hashed["secret"], fr.redact({"secret": "0102ff"}, mode="hash", transform_secret="k")["secret"])
        data = b"\x09"
        self.assertIs(fr.redact({"data": data})["data"], data)

    def test_uuids_are_masked_as_their_text(self) -> None:
        key = uuid.UUID("0f8fad5b-d9cb-469f-a165-70867728950e")
        self.assertEqual(fr.redact({"api_key": key, "request_id": key}), {"api_key": "***", "request_id": key})
        hashed = fr.redact({"api_key": key}, mode="hash", transform_secret="k")
        self.assertEqual(hashed, fr.redact({"api_key": str(key)}, mode="hash", transform_secret="k"))
        self.assertEqual([f.path for f in fr.scan({"api_key": key})], ["api_key"])

    def test_numpy_scalars_and_opaque_objects_are_masked(self) -> None:
        @dataclasses.dataclass
        class Creds:
            user: str
            password: str

        when = datetime.datetime(2026, 1, 2)
        out = fr.redact({"credentials": Creds("ada", "hunter2"), "token": when, "secret": Fraction(1, 2)})
        self.assertEqual(out, {"credentials": "***", "token": when, "secret": "***"})
        findings = fr.scan({"credentials": Creds("ada", "hunter2")}, include_values=True)
        self.assertEqual([f.path for f in findings], ["credentials"])
        self.assertTrue(findings[0].value.endswith("Creds(user='ada', password='hunter2')"))
        try:
            import numpy as np
        except ImportError:
            return
        row = {"cvv": np.int64(123), "ratio": np.float64(1.5), "pin": np.float32(1.5), "flag": np.bool_(True)}
        self.assertEqual(fr.redact({"credentials": row}), {"credentials": {"cvv": "***", "ratio": "***", "pin": "***", "flag": True}})
        self.assertEqual(fr.redact(row)["cvv"], "***")

    def test_exceptions_under_a_sensitive_key_are_masked(self) -> None:
        out = fr.redact({"credentials": ValueError("bad hunter2")})
        self.assertEqual(out["credentials"].args, ("***",))

    def test_a_shared_object_keeps_its_copies_apart(self) -> None:
        shared = {"value": "abc"}
        out = fr.redact({"a": shared, "cookie": shared, "b": shared})
        self.assertEqual(out, {"a": {"value": "abc"}, "cookie": {"value": "***"}, "b": {"value": "abc"}})
        self.assertIs(out["a"], out["b"])

    def test_allowlisted_number_is_kept(self) -> None:
        self.assertEqual(fr.redact({"pin": 1234}, allow=["1234"]), {"pin": 1234})

    def test_scan_reports_every_value_inside(self) -> None:
        findings = fr.scan({"cvv": 123, "cookie": {"name": "sid", "value": "abc", "secure": True}})
        self.assertEqual([(f.detector, f.path) for f in findings],
                         [("sensitive_key", "cvv"), ("sensitive_key", "cookie.name"), ("sensitive_key", "cookie.value")])
        self.assertEqual(fr.scan({"pin": 1234}, include_values=True)[0].value, "1234")

    def test_vault_mints_and_restores_numbers_as_text(self) -> None:
        vault = fr.Vault()
        out = vault.redact({"otp": 482913, "cookie": {"value": "abc"}})
        self.assertNotIn("482913", repr(out))
        self.assertEqual(vault.restore(out), {"otp": "482913", "cookie": {"value": "abc"}})

    def test_float_text_matches_ecmascript(self) -> None:
        cases = {
            1.5: "1.5", 0.1: "0.1", 1e-7: "1e-7", 1.2e-5: "0.000012", 1e21: "1e+21", 1.5e21: "1.5e+21",
            1e16: "10000000000000000", -0.0: "0", 100.0: "100", 123456789012345680000.0: "123456789012345680000",
            0.1 + 0.2: "0.30000000000000004", 5e-324: "5e-324", float("nan"): "NaN", float("-inf"): "-Infinity",
        }
        for value, text in cases.items():
            self.assertEqual(_js_float(value), text, repr(value))


if __name__ == "__main__":
    unittest.main()

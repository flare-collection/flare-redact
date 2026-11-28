"""Data frames and SQL: pandas, Polars and DuckDB. Each test skips when its library is missing."""

from __future__ import annotations

import importlib.util
import unittest

import flare_redact.frames as frames

HAS = {name: importlib.util.find_spec(name) is not None for name in ("pandas", "polars", "duckdb")}
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

ROWS = {
    "id": [1, 2, 3, 4],
    "note": [f"call ada@example.com", "all good", None, f"key {TOKEN}"],
    "password": ["hunter2hunter2", "correct horse", "s3cret!", None],
    "city": ["Baku", "Ganja", "Baku", "Baku"],
}


class CommonTests(unittest.TestCase):
    def test_rejects_other_objects(self):
        with self.assertRaises(TypeError):
            frames.redact_frame({"a": [1]})


@unittest.skipUnless(HAS["pandas"], "pandas is not installed")
class PandasTests(unittest.TestCase):
    def setUp(self):
        import pandas as pd

        self.pd = pd
        self.df = pd.DataFrame(ROWS)

    def test_redact_frame(self):
        out = frames.redact_frame(self.df)
        self.assertEqual(out["note"].tolist()[:2], ["call a***@***", "all good"])
        self.assertTrue(self.pd.isna(out["note"][2]))
        self.assertEqual(out["note"][3], "key ghp_***")
        self.assertEqual(out["password"].tolist()[:3], ["***", "***", "***"])
        self.assertTrue(self.pd.isna(out["password"][3]))
        self.assertEqual(out["city"].tolist(), ROWS["city"])
        self.assertEqual(out["id"].tolist(), ROWS["id"])
        self.assertEqual(self.df["note"][0], "call ada@example.com", "the input is not changed")

    def test_columns_and_options(self):
        out = frames.redact_frame(self.df, columns=["note"], mode="label")
        self.assertEqual(out["note"][0], "call [REDACTED:email]")
        self.assertEqual(out["password"][0], "hunter2hunter2")

    def test_string_and_category_dtypes(self):
        df = self.pd.DataFrame({"note": self.pd.Series(["ada@example.com", None], dtype="string"),
                                "tag": self.pd.Series(["ada@example.com", "x"], dtype="category")})
        out = frames.redact_frame(df)
        self.assertEqual(str(out["note"].dtype), str(df["note"].dtype))
        self.assertEqual(out["note"][0], "a***@***")
        self.assertEqual(str(out["tag"].dtype), "category")
        self.assertEqual(out["tag"][0], "a***@***")

    def test_deterministic_mode_keeps_joins(self):
        df = self.pd.DataFrame({"email": ["ada@example.com", "bob@example.com", "ada@example.com"]})
        out = frames.redact_frame(df, mode="hash", transform_secret="k" * 32)
        self.assertEqual(out["email"][0], out["email"][2])
        self.assertNotEqual(out["email"][0], out["email"][1])

    def test_number_columns_with_a_sensitive_name(self):
        df = self.pd.DataFrame({"cvv": [123, None, 456], "pin": [1234, 1234, 99], "amount": [1, 2, 3],
                                "has_password": [True, False, True]})
        out = frames.redact_frame(df)
        self.assertEqual(out["cvv"][0], "***")
        self.assertTrue(self.pd.isna(out["cvv"][1]))
        self.assertEqual(out["pin"].tolist(), ["***", "***", "***"])
        self.assertEqual(out["amount"].tolist(), [1, 2, 3])
        self.assertEqual(out["has_password"].tolist(), [True, False, True])
        self.assertEqual(frames.redact_frame(df, allow=["99"])["pin"].tolist(), ["***", "***", 99])
        self.assertEqual(frames.scan_frame(df)["columns"]["cvv"], {"rows": 2, "by_detector": {"sensitive_key": 2}})

    def test_accessor_and_scan(self):
        frames.register()
        self.assertEqual(self.df.flare.redact()["note"][3], "key ghp_***")
        self.assertEqual(self.df["note"].flare.redact()[0], "call a***@***")
        report = self.df.flare.scan()
        self.assertEqual(report["columns"]["note"], {"rows": 2, "by_detector": {"email": 1, "github_token": 1}})
        self.assertEqual(report["columns"]["password"]["rows"], 3)
        self.assertNotIn("city", report["columns"])
        self.assertNotIn("ada@example.com", repr(report))


@unittest.skipUnless(HAS["polars"], "polars is not installed")
class PolarsTests(unittest.TestCase):
    def setUp(self):
        import polars as pl

        self.pl = pl
        self.df = pl.DataFrame(ROWS)

    def test_redact_frame_and_lazy(self):
        out = frames.redact_frame(self.df)
        self.assertEqual(out["note"].to_list(), ["call a***@***", "all good", None, "key ghp_***"])
        self.assertEqual(out["password"].to_list(), ["***", "***", "***", None])
        self.assertEqual(out["city"].to_list(), ROWS["city"])
        lazy = frames.redact_frame(self.df.lazy()).collect()
        self.assertTrue(lazy.equals(out))

    def test_namespaces(self):
        pl = self.pl
        frames.register()
        out = self.df.with_columns(pl.col("note").flare.redact(), pl.col("city").alias("c2"))
        self.assertEqual(out["note"][0], "call a***@***")
        self.assertEqual(self.df.select(pl.col("password").flare.redact())["password"][0], "***")
        self.assertEqual(self.df["note"].flare.redact()[3], "key ghp_***")
        self.assertEqual(self.df.flare.redact(columns=["note"])["password"][0], "hunter2hunter2")
        self.assertEqual(self.df.lazy().flare.redact().collect()["note"][0], "call a***@***")
        self.assertEqual(self.df.flare.scan()["columns"]["note"]["rows"], 2)

    def test_number_columns_with_a_sensitive_name(self):
        pl = self.pl
        df = pl.DataFrame({"cvv": [123, None, 456], "pin": [1.5, 2.0, None], "amount": [1, 2, 3]})
        out = frames.redact_frame(df)
        self.assertEqual(out["cvv"].to_list(), ["***", None, "***"])
        self.assertEqual(out["pin"].to_list(), ["***", "***", None])
        self.assertEqual(out["amount"].to_list(), [1, 2, 3])
        self.assertTrue(frames.redact_frame(df.lazy()).collect().equals(out))

    def test_categorical(self):
        pl = self.pl
        df = pl.DataFrame({"tag": pl.Series(["ada@example.com", "x"], dtype=pl.Categorical)})
        out = frames.redact_frame(df)
        self.assertEqual(out["tag"].dtype, pl.Categorical)
        self.assertEqual(out["tag"].to_list(), ["a***@***", "x"])


@unittest.skipUnless(HAS["duckdb"], "duckdb is not installed")
class DuckDBTests(unittest.TestCase):
    def test_sql_functions(self):
        import duckdb

        con = frames.register_duckdb(duckdb.connect())
        con.execute("CREATE TABLE t (note VARCHAR, pw VARCHAR)")
        con.execute("INSERT INTO t VALUES ('call ada@example.com', 'hunter2hunter2'), (NULL, NULL), ('ok', 'x')")
        rows = con.sql("SELECT redact(note), redact_field('password', pw), redact_is_clean(note) FROM t").fetchall()
        self.assertEqual(rows, [("call a***@***", "***", False), (None, None, None), ("ok", "***", True)])

    def test_options_and_name(self):
        import duckdb

        con = frames.register_duckdb(duckdb.connect(), mode="label", name="scrub")
        self.assertEqual(con.sql("SELECT scrub('mail ada@example.com')").fetchall()[0][0], "mail [REDACTED:email]")


if __name__ == "__main__":
    unittest.main()

"""Redaction for data frames and SQL: pandas, Polars and DuckDB.

Analytics and ML data passes through data frames on its way to a notebook, a
parquet file, a feature store or a model. These helpers clean string columns
where the data already is, with none of the libraries imported until you use
them, so this package stays dependency-free.

    import flare_redact.frames as frames

    safe = frames.redact_frame(df)                  # pandas or Polars
    frames.scan_frame(df)                           # what is in which column

    frames.register()                               # adds a .flare namespace
    df.flare.redact(columns=["note", "email"])      # pandas and Polars
    df.with_columns(pl.col("note").flare.redact())  # Polars expressions

    frames.register_duckdb(con)                     # SQL functions
    con.sql("SELECT redact(note), redact_field('email', email) FROM tickets")

A column is treated like a field: a column named ``password`` or ``api_key`` is
masked whole, as a dictionary key with that name would be, and so is a column of
numbers named ``pin`` or ``cvv`` (missing values stay missing). Each distinct value
is redacted once, so a column with many repeated values stays fast, and
deterministic modes (``hash``, ``pseudonym``, ``surrogate``) keep joins working.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Union

from .engine import Options, Policy, compile_policy, number_text

__all__ = ["redact_frame", "redact_series", "scan_frame", "register", "register_duckdb"]

OptionsArg = Union[Options, Mapping[str, Any], None]


def _policy(options: OptionsArg, overrides: Mapping[str, Any]) -> Policy:
    if isinstance(options, Policy):
        return options
    return compile_policy(options, **overrides)


def _value_redactor(policy: Policy, name: Optional[str]) -> Callable[[str], str]:
    """Redact one cell; the column name counts as the field name."""
    if name:
        key = str(name)
        return lambda value: policy.redact({key: value})[key]
    return policy.redact_str


def _changes(values: Iterable[Any], redact_one: Callable[[str], str]) -> Dict[str, str]:
    """The distinct string values that change, mapped to their redacted form."""
    out: Dict[str, str] = {}
    for value in values:
        if isinstance(value, str):
            masked = redact_one(value)
            if masked != value:
                out[value] = masked
    return out


def _kind(obj: Any) -> str:
    module = type(obj).__module__.split(".")[0]
    if module in ("pandas", "polars"):
        return module
    raise TypeError(f"expected a pandas or Polars data frame or series, got {type(obj).__name__}")


# --------------------------------------------------------------------------- #
# pandas
# --------------------------------------------------------------------------- #


def _pandas_is_text(series: Any) -> bool:
    dtype = str(series.dtype)
    return dtype == "object" or dtype.startswith("string") or dtype == "str" or dtype == "category"


def _pandas_is_number(series: Any) -> bool:
    from pandas.api import types

    return types.is_numeric_dtype(series) and not types.is_bool_dtype(series)


def _sensitive(policy: Policy, name: Any) -> bool:
    return name is not None and policy.is_sensitive_key(str(name))


def _number_changes(values: Iterable[Any], policy: Policy, key: str) -> Dict[Any, Any]:
    """Distinct numbers of a sensitive column mapped to what replaces them."""
    out: Dict[Any, Any] = {}
    for value in values:
        plain = value.item() if hasattr(value, "item") else value
        masked = policy.redact({key: plain})[key]
        if masked != plain:
            out[value] = masked
    return out


def _pandas_series(series: Any, policy: Policy, name: Optional[str]) -> Any:
    if not _pandas_is_text(series):
        if not (_sensitive(policy, name) and _pandas_is_number(series)):
            return series
        number_changes = _number_changes(series.dropna().unique(), policy, str(name))
        if not number_changes:
            return series
        masked = series.astype(object)
        hit = series.isin(list(number_changes))
        masked[hit] = series[hit].map(number_changes)
        return masked
    if str(series.dtype) == "category":
        return _pandas_series(series.astype(object), policy, name).astype("category")
    redact_one = _value_redactor(policy, name)
    try:
        changes = _changes(series.dropna().unique(), redact_one)
    except TypeError:  # unhashable cells (lists, dicts): redact each one
        return series.map(lambda cell: policy.redact({name: cell})[name] if name else policy.redact(cell))
    if not changes:
        return series
    out = series.copy()
    hit = series.isin(list(changes))
    out[hit] = series[hit].map(changes)
    return out


# --------------------------------------------------------------------------- #
# Polars
# --------------------------------------------------------------------------- #


def _polars_is_text(dtype: Any) -> bool:
    import polars as pl

    return dtype in (pl.String, pl.Categorical) or str(dtype) in ("String", "Utf8", "Categorical")


def _polars_series(series: Any, policy: Policy, name: Optional[str]) -> Any:
    import polars as pl

    if not _polars_is_text(series.dtype):
        if not (_sensitive(policy, name) and series.dtype.is_numeric()):
            return series
        number_changes = _number_changes(series.drop_nulls().unique().to_list(), policy, str(name))
        if not number_changes:
            return series
        return series.map_elements(lambda v: number_changes.get(v, number_text(v)), return_dtype=pl.String)
    categorical = series.dtype == pl.Categorical
    text = series.cast(pl.String) if categorical else series
    changes = _changes(text.drop_nulls().unique().to_list(), _value_redactor(policy, name))
    if not changes:
        return series
    out = text.replace(changes)
    return out.cast(pl.Categorical) if categorical else out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def redact_series(series: Any, options: OptionsArg = None, *, name: Optional[str] = None, **overrides: Any) -> Any:
    """A redacted copy of one pandas or Polars series of text.

    ``name`` is the field name for the key rule; it defaults to the series name.
    Series that do not hold text are returned unchanged, except numbers under a
    sensitive name, which are masked like a dictionary value with that key.
    """
    policy = _policy(options, overrides)
    field = name if name is not None else getattr(series, "name", None)
    if _kind(series) == "pandas":
        return _pandas_series(series, policy, field)
    return _polars_series(series, policy, field)


def _text_columns(frame: Any, policy: Policy) -> List[str]:
    """Text columns, plus number columns whose name is sensitive."""
    if _kind(frame) == "pandas":
        return [
            column for column in frame.columns
            if _pandas_is_text(frame[column]) or (_sensitive(policy, column) and _pandas_is_number(frame[column]))
        ]
    return [
        column for column, dtype in frame.collect_schema().items()
        if _polars_is_text(dtype) or (_sensitive(policy, column) and dtype.is_numeric())
    ]


def redact_frame(
    frame: Any,
    options: OptionsArg = None,
    *,
    columns: Optional[Iterable[str]] = None,
    **overrides: Any,
) -> Any:
    """A redacted copy of a pandas or Polars data frame (Polars lazy frames too).

    Every text column is cleaned unless ``columns`` names the ones to clean.
    Other columns, the index and the row order are left as they are.
    """
    policy = _policy(options, overrides)
    names = list(columns) if columns is not None else _text_columns(frame, policy)
    if _kind(frame) == "pandas":
        out = frame.copy()
        for column in names:
            out[column] = _pandas_series(frame[column], policy, str(column))
        return out
    import polars as pl

    return frame.with_columns(
        [pl.col(column).map_batches(lambda s, c=column: _polars_series(s, policy, c)) for column in names]
    )


def scan_frame(
    frame: Any,
    options: OptionsArg = None,
    *,
    columns: Optional[Iterable[str]] = None,
    **overrides: Any,
) -> Dict[str, Any]:
    """Counts of what is in which column, safe to log: no values are included.

    ``{"total": 3, "columns": {"note": {"rows": 2, "by_detector": {"email": 2}}}}``
    where ``rows`` is how many rows of the column hold at least one finding.
    """
    policy = _policy(options, overrides)
    if _kind(frame) == "polars" and hasattr(frame, "collect") and not hasattr(frame, "height"):
        frame = frame.collect()
    names = list(columns) if columns is not None else _text_columns(frame, policy)
    report: Dict[str, Any] = {"total": 0, "columns": {}}
    for column in names:
        if _kind(frame) == "pandas":
            counts = frame[column].dropna().astype(str).value_counts().items()
        else:
            import polars as pl

            series = frame[column].cast(pl.String).drop_nulls()
            counted = series.value_counts()
            counts = zip(counted[column].to_list(), counted["count"].to_list())
        rows = 0
        by_detector: Dict[str, int] = {}
        for value, count in counts:
            findings = policy.scan({str(column): value})
            if not findings:
                continue
            rows += int(count)
            for finding in findings:
                by_detector[finding.detector] = by_detector.get(finding.detector, 0) + int(count)
        if rows:
            report["columns"][str(column)] = {"rows": rows, "by_detector": by_detector}
            report["total"] += sum(by_detector.values())
    return report


# --------------------------------------------------------------------------- #
# The .flare namespace
# --------------------------------------------------------------------------- #


class _FrameNamespace:
    def __init__(self, frame: Any) -> None:
        self._frame = frame

    def redact(self, options: OptionsArg = None, *, columns: Optional[Iterable[str]] = None, **overrides: Any) -> Any:
        """A redacted copy; every text column unless ``columns`` is given."""
        return redact_frame(self._frame, options, columns=columns, **overrides)

    def scan(self, options: OptionsArg = None, *, columns: Optional[Iterable[str]] = None, **overrides: Any) -> Dict[str, Any]:
        """Counts of what is in which column; no values are included."""
        return scan_frame(self._frame, options, columns=columns, **overrides)


class _SeriesNamespace:
    def __init__(self, series: Any) -> None:
        self._series = series

    def redact(self, options: OptionsArg = None, *, name: Optional[str] = None, **overrides: Any) -> Any:
        """A redacted copy of this series."""
        return redact_series(self._series, options, name=name, **overrides)


class _ExprNamespace:
    def __init__(self, expr: Any) -> None:
        self._expr = expr

    def redact(self, options: OptionsArg = None, *, name: Optional[str] = None, **overrides: Any) -> Any:
        """A Polars expression that redacts this column; the column name is the field name."""
        policy = _policy(options, overrides)
        return self._expr.map_batches(lambda s: _polars_series(s, policy, name if name is not None else s.name))


def register(name: str = "flare") -> List[str]:
    """Add a ``.flare`` namespace to whichever of pandas and Polars is installed.

    pandas: ``DataFrame.flare`` and ``Series.flare``. Polars: ``DataFrame``,
    ``LazyFrame``, ``Series`` and ``Expr``. Returns the libraries registered.
    """
    done: List[str] = []
    try:
        import pandas as pd
    except ImportError:
        pass
    else:
        if not hasattr(pd.DataFrame, name):
            pd.api.extensions.register_dataframe_accessor(name)(_FrameNamespace)
            pd.api.extensions.register_series_accessor(name)(_SeriesNamespace)
        done.append("pandas")
    try:
        import polars as pl
    except ImportError:
        pass
    else:
        if not hasattr(pl.DataFrame, name):
            pl.api.register_dataframe_namespace(name)(_FrameNamespace)
            pl.api.register_lazyframe_namespace(name)(_FrameNamespace)
            pl.api.register_series_namespace(name)(_SeriesNamespace)
            pl.api.register_expr_namespace(name)(_ExprNamespace)
        done.append("polars")
    return done


# --------------------------------------------------------------------------- #
# DuckDB
# --------------------------------------------------------------------------- #


def register_duckdb(connection: Any, options: OptionsArg = None, *, name: str = "redact", **overrides: Any) -> Any:
    """Add SQL functions to a DuckDB connection and return the connection.

    - ``redact(text)``: the text with findings masked
    - ``redact_field(field_name, value)``: the key rule too, so
      ``redact_field('password', col)`` masks the whole value
    - ``redact_is_clean(text)``: true when nothing would be redacted

    ``NULL`` in gives ``NULL`` out. Repeated values are redacted once.
    """
    try:
        from duckdb.sqltypes import BOOLEAN, VARCHAR
    except ImportError:  # duckdb before 1.4
        from duckdb.typing import BOOLEAN, VARCHAR

    policy = _policy(options, overrides)

    @lru_cache(maxsize=65536)
    def redact_text(text: str) -> str:
        return policy.redact_str(text)

    @lru_cache(maxsize=65536)
    def redact_field(field: str, value: str) -> str:
        return policy.redact({field: value})[field]

    @lru_cache(maxsize=65536)
    def is_clean(text: str) -> bool:
        return policy.is_clean(text)

    connection.create_function(name, redact_text, [VARCHAR], VARCHAR)
    connection.create_function(f"{name}_field", redact_field, [VARCHAR, VARCHAR], VARCHAR)
    connection.create_function(f"{name}_is_clean", is_clean, [VARCHAR], BOOLEAN)
    return connection

"""
Reassemble sliced query results into one table.

Sliced aggregates cannot be naively concatenated. count/sum are additive,
min/max reduce, but estimate_distinct and percentiles are NOT additive. This
module implements the additive/reduce cases correctly and flags distinct/
percentile columns as approximate when they are combined by summation, so the
output never silently overstates a distinct count.

Each slice result is a dict: {"columns": [str, ...], "values": [[...], ...]}.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .catalog import MergeSpec


def _to_number(x: Any) -> float:
    """Defensive numeric cast. SDL columns can arrive string-typed even when the
    parser declares them numeric, so mirror the project's number() failsafe."""
    if x is None or x == "":
        return 0.0
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


def column_union(results: List[Dict[str, Any]]) -> List[str]:
    """Ordered union of columns across slices (parser drift can add columns)."""
    cols: List[str] = []
    seen: set = set()
    for r in results:
        for c in r.get("columns", []):
            if c not in seen:
                seen.add(c)
                cols.append(c)
    return cols


def concat_rows(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Union all rows, aligning to the column union. For LOG / row-level queries."""
    cols = column_union(results)
    idx = {c: i for i, c in enumerate(cols)}
    out_rows: List[List[Any]] = []
    for r in results:
        rcols = r.get("columns", [])
        for row in r.get("values", []):
            new = [None] * len(cols)
            for j, c in enumerate(rcols):
                if j < len(row):
                    new[idx[c]] = row[j]
            out_rows.append(new)
    return {"columns": cols, "values": out_rows}


def merge_aggregate(results: List[Dict[str, Any]], spec: MergeSpec) -> Tuple[Dict[str, Any], List[str]]:
    """Re-aggregate grouped slice results by key.

    Returns (merged_result, warnings). Warnings flag approximations (distinct
    columns summed across slices).
    """
    warnings: List[str] = []
    cols = column_union(results)
    key_cols = spec.key_cols or [c for c in cols
                                 if c not in spec.sum_cols + spec.min_cols
                                 + spec.max_cols + spec.distinct_cols]

    acc: Dict[Tuple, Dict[str, Any]] = {}
    for r in results:
        rcols = r.get("columns", [])
        cidx = {c: i for i, c in enumerate(rcols)}
        for row in r.get("values", []):
            def val(col: str) -> Any:
                i = cidx.get(col)
                return row[i] if i is not None and i < len(row) else None

            key = tuple(val(k) for k in key_cols)
            bucket = acc.get(key)
            if bucket is None:
                bucket = {k: val(k) for k in key_cols}
                for c in spec.sum_cols + spec.distinct_cols:
                    bucket[c] = 0.0
                for c in spec.min_cols:
                    bucket[c] = None
                for c in spec.max_cols:
                    bucket[c] = None
                acc[key] = bucket
            for c in spec.sum_cols + spec.distinct_cols:
                bucket[c] = bucket.get(c, 0.0) + _to_number(val(c))
            for c in spec.min_cols:
                v = _to_number(val(c))
                bucket[c] = v if bucket[c] is None else min(bucket[c], v)
            for c in spec.max_cols:
                v = _to_number(val(c))
                bucket[c] = v if bucket[c] is None else max(bucket[c], v)

    if spec.distinct_cols and len(results) > 1:
        warnings.append(
            "distinct columns " + ", ".join(spec.distinct_cols)
            + " were summed across slices and are an APPROXIMATE upper bound "
            "(estimate_distinct is not additive). Re-run a single unsliced query "
            "on the deduped set for an exact count."
        )

    out_cols = list(key_cols) + spec.sum_cols + spec.min_cols + spec.max_cols + spec.distinct_cols
    out_cols = [c for i, c in enumerate(out_cols) if c not in out_cols[:i]]  # de-dup, keep order
    out_values = [[bucket.get(c) for c in out_cols] for bucket in acc.values()]
    return {"columns": out_cols, "values": out_values}, warnings


def merge_query_results(results: List[Dict[str, Any]], spec: MergeSpec) -> Tuple[Dict[str, Any], List[str]]:
    """Dispatch on merge kind. Returns (merged, warnings)."""
    results = [r for r in results if r and r.get("columns")]
    if not results:
        return {"columns": [], "values": []}, []
    if spec.kind == "aggregate":
        return merge_aggregate(results, spec)
    return concat_rows(results), []

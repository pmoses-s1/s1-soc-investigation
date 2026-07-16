from s1engine.catalog import MergeSpec
from s1engine.merge import merge_query_results


def test_aggregate_sum_min_max_across_slices():
    spec = MergeSpec(kind="aggregate", key_cols=["k"], sum_cols=["hits"],
                     min_cols=["first"], max_cols=["last"])
    r1 = {"columns": ["k", "hits", "first", "last"], "values": [["a", 5, 10, 20]]}
    r2 = {"columns": ["k", "hits", "first", "last"], "values": [["a", 3, 8, 25], ["b", 1, 1, 2]]}
    merged, warns = merge_query_results([r1, r2], spec)
    rows = {row[0]: row for row in merged["values"]}
    ci = {c: i for i, c in enumerate(merged["columns"])}
    assert rows["a"][ci["hits"]] == 8      # 5 + 3
    assert rows["a"][ci["first"]] == 8     # min(10, 8)
    assert rows["a"][ci["last"]] == 25     # max(20, 25)
    assert not warns


def test_distinct_columns_flagged_approximate():
    spec = MergeSpec(kind="aggregate", key_cols=["k"], distinct_cols=["uniq"])
    r1 = {"columns": ["k", "uniq"], "values": [["a", 4]]}
    r2 = {"columns": ["k", "uniq"], "values": [["a", 6]]}
    merged, warns = merge_query_results([r1, r2], spec)
    assert warns and "approximate" in warns[0].lower()


def test_rows_concat_with_column_union():
    spec = MergeSpec(kind="rows")
    r1 = {"columns": ["a", "b"], "values": [[1, 2]]}
    r2 = {"columns": ["b", "c"], "values": [[3, 4]]}  # parser drift: new column
    merged, _ = merge_query_results([r1, r2], spec)
    assert merged["columns"] == ["a", "b", "c"]
    assert len(merged["values"]) == 2
    # first row has no 'c', second has no 'a'
    assert merged["values"][0][2] is None
    assert merged["values"][1][0] is None

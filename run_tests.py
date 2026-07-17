#!/usr/bin/env python3
"""
Zero-dependency test runner.

The tests are written in the pytest style (a `tmp_path` argument where needed),
so `pytest -q` works if you have it. This runner executes the same tests using
only the standard library, so the suite verifies in locked-down environments
without PyPI access. Run from the repo root:  python run_tests.py
"""

import importlib
import inspect
import sys
import tempfile
import traceback
from pathlib import Path

MODULES = [
    "tests.test_slicing",
    "tests.test_ledger",
    "tests.test_merge",
    "tests.test_rate_limiter",
    "tests.test_engine_e2e",
    "tests.test_catalog_defaults",
    "tests.test_catalog_lint",
]


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    passed = failed = 0
    failures = []
    for modname in MODULES:
        mod = importlib.import_module(modname)
        for name, fn in sorted(vars(mod).items()):
            if not name.startswith("test_") or not callable(fn):
                continue
            params = inspect.signature(fn).parameters
            try:
                if "tmp_path" in params:
                    with tempfile.TemporaryDirectory() as d:
                        fn(Path(d))
                else:
                    fn()
                passed += 1
                print(f"PASS  {modname}::{name}")
            except Exception:
                failed += 1
                failures.append((modname, name, traceback.format_exc()))
                print(f"FAIL  {modname}::{name}")
    print(f"\n{passed} passed, {failed} failed")
    for m, n, tb in failures:
        print(f"\n=== {m}::{n} ===\n{tb}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

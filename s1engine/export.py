"""
Zip export of a run's outputs, shared by the CLI and the web UI.

Kinds:
  logs     activity.jsonl + manifest.json + ledger.db (the audit trail)
  results  logs + merged results/ + the .xlsx workbook (default; the hand-off set)
  all      everything under the run dir, including the per-slice cache
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import List, Tuple

_LOG_FILES = ("activity.jsonl", "manifest.json", "ledger.db")


def _select(run_dir: Path, kind: str) -> List[Path]:
    files: List[Path] = []
    for name in _LOG_FILES:
        p = run_dir / name
        if p.is_file():
            files.append(p)
    if kind == "logs":
        return files
    if kind in ("results", "all"):
        rd = run_dir / "results"
        if rd.is_dir():
            files += [p for p in rd.rglob("*") if p.is_file()]
        files += [p for p in run_dir.glob("*.xlsx") if p.is_file()]
    if kind == "all":
        sd = run_dir / "slices"
        if sd.is_dir():
            files += [p for p in sd.rglob("*") if p.is_file()]
    # de-dup, keep order
    seen, out = set(), []
    for p in files:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def zip_run(run_dir: str | Path, kind: str = "results") -> Tuple[bytes, str]:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"run dir not found: {run_dir}")
    files = _select(run_dir, kind)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, arcname=str(p.relative_to(run_dir)))
    fname = f"{run_dir.name}_{kind}.zip"
    return buf.getvalue(), fname

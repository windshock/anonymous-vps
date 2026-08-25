"""Todo 5 contract: pipeline dry-run is side-effect free and wires the context stage.

The current pipeline forwards --dry-run only to the legacy-bridge and
provider-ranges stages, so incident/high-risk generators still write during a
dry-run. This suite fails (RED) on that defect and on the missing context stage.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPELINE = ROOT / "scripts" / "pipeline.py"

_SNAPSHOT_ROOTS = [ROOT / "generated", ROOT / "queries"]
_SNAPSHOT_FILES = [
    ROOT / "data" / "vps-providers.csv",
    ROOT / "data" / "ip-ranges" / "known-providers.csv",
]


def _snapshot() -> dict[str, tuple[int, str]]:
    snap: dict[str, tuple[int, str]] = {}
    files = list(_SNAPSHOT_FILES)
    for base in _SNAPSHOT_ROOTS:
        if base.exists():
            files.extend(base.rglob("*"))
    for path in files:
        if path.is_file():
            data = path.read_bytes()
            snap[str(path)] = (path.stat().st_mtime_ns, hashlib.sha256(data).hexdigest())
    return snap


def test_dry_run_changes_no_file():
    before = _snapshot()
    result = subprocess.run(
        [sys.executable, str(PIPELINE), "--skip-fetch", "--vendor", "BitLaunch", "--dry-run"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    after = _snapshot()
    assert before == after, "dry-run mutated a file — a write-capable stage is missing --dry-run"


def test_pipeline_includes_context_generator():
    source = PIPELINE.read_text(encoding="utf-8")
    assert "generate_location_context.py" in source


def test_query_and_sigma_generators_ignore_location_context():
    for name in ("generate_queries.py", "generate_sigma.py"):
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "location_context" not in source
        assert "kr-localized" not in source
        assert "generate_location_context" not in source
        assert "generated/context" not in source

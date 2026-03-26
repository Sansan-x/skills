#!/usr/bin/env python3
"""
Optional helper: merge structured findings JSON files into one.

Expected input shape per file (best-effort):
{
  "findings": [ { "id": "...", ... }, ... ]
}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def _read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--findings-dir", default=None, help="Directory containing per-task findings JSON")
    ap.add_argument("--output", default=None, help="Output merged findings json path")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).expanduser().resolve()
    findings_dir = Path(args.findings_dir).expanduser().resolve() if args.findings_dir else (project_dir / "findings")
    out_path = Path(args.output).expanduser().resolve() if args.output else (project_dir / "merged_findings.json")

    if not findings_dir.exists():
        print(f"[WARN] findings dir not found: {findings_dir}", file=sys.stderr)
        out_path.write_text(json.dumps({"findings": [], "source": str(findings_dir)}, indent=2, ensure_ascii=False), encoding="utf-8")
        return

    merged: List[Dict[str, Any]] = []
    seen_ids = set()

    for p in sorted(findings_dir.glob("*.json")):
        try:
            doc = _read_json(p)
        except Exception:
            continue
        items = doc.get("findings") or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            fid = item.get("id")
            if fid and fid in seen_ids:
                continue
            if fid:
                seen_ids.add(fid)
            merged.append(item)

    out_path.write_text(
        json.dumps({"findings": merged, "count": len(merged), "source": str(findings_dir)}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[OK] merged findings: {out_path} (count={len(merged)})", file=sys.stderr)
    print(json.dumps({"output": str(out_path), "count": len(merged)}, ensure_ascii=False))


if __name__ == "__main__":
    main()


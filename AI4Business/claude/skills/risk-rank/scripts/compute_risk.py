#!/usr/bin/env python3
"""Compute per-service security risk scores from services_summary.json.

Default formula:

    score = 8 * ext_write + 4 * ext_get + 2 * int_write + 1 * int_get

All four weights are overridable via CLI flags. Ties are broken by total
endpoint count (more endpoints -> higher risk).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


BUCKET_KEYS = ("ext_write", "ext_get", "int_write", "int_get")


def load_summary(path: Path) -> Dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(
            f"Summary not found: {path}. Run collect-information first."
        )
    with path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    if "services" not in payload:
        raise ValueError(f"Invalid summary file at {path}: missing 'services'")
    return payload


def compute_scores(
    services: List[Dict[str, object]],
    weights: Dict[str, float],
) -> List[Dict[str, object]]:
    scored: List[Dict[str, object]] = []
    for svc in services:
        counts = {key: int(svc.get(key, 0) or 0) for key in BUCKET_KEYS}
        total = int(svc.get("total", sum(counts.values())))
        score = sum(weights[key] * counts[key] for key in BUCKET_KEYS)
        scored.append(
            {
                "rank": 0,
                "name": svc.get("name", ""),
                "file": svc.get("file", ""),
                "risk_score": round(score, 4),
                **counts,
                "total": total,
            }
        )

    scored.sort(key=lambda x: (-x["risk_score"], -x["total"], x["name"]))
    for idx, item in enumerate(scored, start=1):
        item["rank"] = idx
    return scored


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        required=True,
        type=Path,
        help="Path to data/services_summary.json",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write risk_scores.json",
    )
    parser.add_argument("--w-ext-write", type=float, default=8.0)
    parser.add_argument("--w-ext-get", type=float, default=4.0)
    parser.add_argument("--w-int-write", type=float, default=2.0)
    parser.add_argument("--w-int-get", type=float, default=1.0)
    args = parser.parse_args(argv)

    weights = {
        "ext_write": args.w_ext_write,
        "ext_get": args.w_ext_get,
        "int_write": args.w_int_write,
        "int_get": args.w_int_get,
    }

    summary = load_summary(args.summary)
    services = summary.get("services", [])
    if not isinstance(services, list):
        raise ValueError("'services' must be a list")

    ranked = compute_scores(services, weights)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "weights": weights,
        "formula": (
            f"score = {weights['ext_write']}*ext_write + "
            f"{weights['ext_get']}*ext_get + "
            f"{weights['int_write']}*int_write + "
            f"{weights['int_get']}*int_get"
        ),
        "total_services": len(ranked),
        "total_endpoints": int(summary.get("total_endpoints", 0)),
        "services": ranked,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)

    top = ranked[:5]
    preview = ", ".join(f"{s['name']}({s['risk_score']:g})" for s in top)
    print(
        f"[compute_risk] ranked {len(ranked)} services -> {args.output}\n"
        f"  top 5: {preview}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

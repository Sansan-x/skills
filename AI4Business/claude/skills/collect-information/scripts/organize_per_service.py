#!/usr/bin/env python3
"""Group normalized endpoints by service and sort URLs by risk priority.

Reads ``all_endpoints.json`` produced by ``extract_excel.py`` and writes:

* ``data/services/<safe-name>.json`` — one file per microservice, with
  the four buckets pre-sorted in the required order:
    1. external POST/PUT/PATCH/DELETE
    2. external GET
    3. internal POST/PUT/PATCH/DELETE
    4. internal GET
* ``data/services_summary.json`` — small aggregate file (counts only),
  the only output an LLM should read in bulk.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional


BUCKET_ORDER = ["ext_write", "ext_get", "int_write", "int_get"]

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(service_name: str) -> str:
    safe = SAFE_NAME_RE.sub("_", service_name.strip())
    safe = safe.strip("._-") or "unnamed_service"
    return safe[:120]


def load_endpoints(input_path: Path) -> List[Dict[str, str]]:
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")
    with input_path.open("r", encoding="utf-8") as fp:
        payload = json.load(fp)
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        raise ValueError(
            f"Expected 'endpoints' list in {input_path}; got {type(endpoints).__name__}"
        )
    return endpoints


def group_by_service(
    endpoints: List[Dict[str, str]],
) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    grouped: Dict[str, Dict[str, List[Dict[str, str]]]] = defaultdict(
        lambda: {key: [] for key in BUCKET_ORDER}
    )
    for ep in endpoints:
        bucket = ep.get("bucket")
        if bucket not in BUCKET_ORDER:
            continue
        grouped[ep["service_name"]][bucket].append(
            {"method": ep["method"], "url": ep["url"]}
        )
    return grouped


def sort_bucket(items: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return sorted(items, key=lambda x: (x["method"], x["url"]))


def write_service_file(
    services_dir: Path,
    service_name: str,
    buckets: Dict[str, List[Dict[str, str]]],
) -> Path:
    safe = safe_filename(service_name)
    out_path = services_dir / f"{safe}.json"
    payload = {
        "service_name": service_name,
        "counts": {key: len(buckets[key]) for key in BUCKET_ORDER},
        "total": sum(len(buckets[key]) for key in BUCKET_ORDER),
        "ext_write": sort_bucket(buckets["ext_write"]),
        "ext_get": sort_bucket(buckets["ext_get"]),
        "int_write": sort_bucket(buckets["int_write"]),
        "int_get": sort_bucket(buckets["int_get"]),
    }
    with out_path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
    return out_path


def build_summary(
    grouped: Dict[str, Dict[str, List[Dict[str, str]]]],
    services_dir: Path,
) -> Dict[str, object]:
    services_summary: List[Dict[str, object]] = []
    total_endpoints = 0
    for service_name in sorted(grouped):
        buckets = grouped[service_name]
        counts = {key: len(buckets[key]) for key in BUCKET_ORDER}
        total = sum(counts.values())
        total_endpoints += total
        services_summary.append(
            {
                "name": service_name,
                "file": str(services_dir / f"{safe_filename(service_name)}.json"),
                "ext_write": counts["ext_write"],
                "ext_get": counts["ext_get"],
                "int_write": counts["int_write"],
                "int_get": counts["int_get"],
                "total": total,
            }
        )
    return {
        "total_services": len(services_summary),
        "total_endpoints": total_endpoints,
        "services": services_summary,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="all_endpoints.json")
    parser.add_argument(
        "--services-dir",
        required=True,
        type=Path,
        help="Directory to write per-service JSON files",
    )
    parser.add_argument(
        "--summary",
        required=True,
        type=Path,
        help="Path to write services_summary.json",
    )
    args = parser.parse_args(argv)

    endpoints = load_endpoints(args.input)
    grouped = group_by_service(endpoints)

    args.services_dir.mkdir(parents=True, exist_ok=True)
    for service_name, buckets in grouped.items():
        write_service_file(args.services_dir, service_name, buckets)

    summary = build_summary(grouped, args.services_dir)

    args.summary.parent.mkdir(parents=True, exist_ok=True)
    with args.summary.open("w", encoding="utf-8") as fp:
        json.dump(summary, fp, ensure_ascii=False, indent=2)

    print(
        f"[organize_per_service] {summary['total_services']} services, "
        f"{summary['total_endpoints']} endpoints "
        f"-> {args.services_dir} (per-service) + {args.summary} (summary)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

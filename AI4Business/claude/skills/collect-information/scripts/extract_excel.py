#!/usr/bin/env python3
"""Extract microservice endpoint rows from an Excel file into a normalized JSON.

Reads the Excel sheet once, normalizes the four required columns
(``url``, ``service_name``, ``method``, ``url_type``) and writes one
JSON record per endpoint into ``all_endpoints.json``.

The LLM should NOT read the output of this script in bulk; it is
intended to be consumed only by ``organize_per_service.py`` downstream.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import pandas as pd


DEFAULT_COLUMNS = {
    "url": "url",
    "service_name": "service_name",
    "method": "method",
    "url_type": "url_type",
}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READ_METHODS = {"GET"}

EXTERNAL_ALIASES = {"external", "ext", "外部", "公网", "public", "outer", "outside"}
INTERNAL_ALIASES = {"internal", "int", "内部", "内网", "private", "inner", "inside"}


def parse_columns_map(raw: Optional[str]) -> Dict[str, str]:
    mapping = dict(DEFAULT_COLUMNS)
    if not raw:
        return mapping
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(
                f"Invalid --columns-map entry '{pair}'; expected logical=actual"
            )
        logical, actual = (s.strip() for s in pair.split("=", 1))
        if logical not in DEFAULT_COLUMNS:
            raise ValueError(
                f"Unknown logical column '{logical}'. "
                f"Allowed: {sorted(DEFAULT_COLUMNS)}"
            )
        mapping[logical] = actual
    return mapping


def normalize_method(raw: object) -> str:
    if raw is None:
        return ""
    text = str(raw).strip().upper()
    return text


def normalize_url_type(raw: object) -> str:
    if raw is None:
        return ""
    text = str(raw).strip().lower()
    if text in EXTERNAL_ALIASES:
        return "external"
    if text in INTERNAL_ALIASES:
        return "internal"
    return text


def classify_bucket(url_type: str, method: str) -> Optional[str]:
    if url_type == "external" and method in WRITE_METHODS:
        return "ext_write"
    if url_type == "external" and method in READ_METHODS:
        return "ext_get"
    if url_type == "internal" and method in WRITE_METHODS:
        return "int_write"
    if url_type == "internal" and method in READ_METHODS:
        return "int_get"
    return None


def load_dataframe(input_path: Path, sheet: Optional[str]) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"Input Excel not found: {input_path}")

    read_kwargs = {"dtype": str}
    if sheet is not None:
        read_kwargs["sheet_name"] = sheet

    df = pd.read_excel(input_path, engine="openpyxl", **read_kwargs)
    if isinstance(df, dict):
        first_sheet = next(iter(df))
        df = df[first_sheet]
    return df


def iter_records(
    df: pd.DataFrame,
    columns: Dict[str, str],
) -> Iterable[Dict[str, str]]:
    missing = [actual for actual in columns.values() if actual not in df.columns]
    if missing:
        raise KeyError(
            "Missing required columns in Excel: "
            f"{missing}. Found columns: {list(df.columns)}"
        )

    url_col = columns["url"]
    svc_col = columns["service_name"]
    method_col = columns["method"]
    type_col = columns["url_type"]

    for _, row in df.iterrows():
        url = "" if pd.isna(row[url_col]) else str(row[url_col]).strip()
        service = "" if pd.isna(row[svc_col]) else str(row[svc_col]).strip()
        method = normalize_method(row[method_col])
        url_type = normalize_url_type(row[type_col])

        if not url or not service:
            continue

        yield {
            "url": url,
            "service_name": service,
            "method": method,
            "url_type": url_type,
            "bucket": classify_bucket(url_type, method),
        }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Path to .xlsx file")
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write all_endpoints.json",
    )
    parser.add_argument(
        "--sheet",
        default=None,
        help="Sheet name or index (default: first sheet)",
    )
    parser.add_argument(
        "--columns-map",
        default=None,
        help=(
            "Comma-separated logical=actual column overrides, e.g. "
            "'url=URL,service_name=Service,method=HTTP Method,url_type=Type'"
        ),
    )
    args = parser.parse_args(argv)

    columns = parse_columns_map(args.columns_map)
    df = load_dataframe(args.input, args.sheet)

    records: List[Dict[str, str]] = []
    skipped_unbucketed = 0
    for rec in iter_records(df, columns):
        if rec["bucket"] is None:
            skipped_unbucketed += 1
        records.append(rec)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fp:
        json.dump(
            {
                "source": str(args.input),
                "total_rows": len(records),
                "endpoints": records,
            },
            fp,
            ensure_ascii=False,
            indent=2,
        )

    print(
        f"[extract_excel] wrote {len(records)} endpoints to {args.output} "
        f"(unbucketed methods/types: {skipped_unbucketed})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

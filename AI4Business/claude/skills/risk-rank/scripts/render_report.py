#!/usr/bin/env python3
"""Render the unified microservice security risk Markdown report.

Reads ``risk_scores.json`` (small) for the ranking table and opens
per-service JSON files one at a time for the Top-N detail sections.
The LLM never needs to assemble the report from raw URL data.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


BUCKET_TITLES = {
    "ext_write": "外部 — POST/PUT/PATCH/DELETE",
    "ext_get": "外部 — GET",
    "int_write": "内部 — POST/PUT/PATCH/DELETE",
    "int_get": "内部 — GET",
}
BUCKET_ORDER = ["ext_write", "ext_get", "int_write", "int_get"]


def load_json(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def fmt_int(n: object) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def render_summary_table(services: List[Dict[str, object]]) -> List[str]:
    lines = [
        "| 排名 | 服务 | 风险分 | 外部写 | 外部 GET | 内部写 | 内部 GET | 总数 |",
        "|------|------|--------|--------|----------|--------|----------|------|",
    ]
    for svc in services:
        lines.append(
            "| {rank} | {name} | {score:g} | {ew} | {eg} | {iw} | {ig} | {total} |".format(
                rank=svc["rank"],
                name=str(svc["name"]).replace("|", "\\|"),
                score=svc["risk_score"],
                ew=svc["ext_write"],
                eg=svc["ext_get"],
                iw=svc["int_write"],
                ig=svc["int_get"],
                total=svc["total"],
            )
        )
    return lines


def render_detail_section(
    rank: int,
    score_record: Dict[str, object],
    service_payload: Dict[str, object],
    max_urls_per_bucket: int,
) -> List[str]:
    lines: List[str] = []
    lines.append(
        f"### {rank}. {score_record['name']} — 风险分 {score_record['risk_score']:g}"
    )
    lines.append("")
    counts = service_payload.get("counts", {})
    lines.append(
        "- 计数：外部写 {ew} ｜ 外部 GET {eg} ｜ 内部写 {iw} ｜ 内部 GET {ig} ｜ 总数 {total}".format(
            ew=counts.get("ext_write", 0),
            eg=counts.get("ext_get", 0),
            iw=counts.get("int_write", 0),
            ig=counts.get("int_get", 0),
            total=service_payload.get("total", 0),
        )
    )
    lines.append("")
    for bucket in BUCKET_ORDER:
        items = service_payload.get(bucket, []) or []
        title = BUCKET_TITLES[bucket]
        lines.append(f"**{title} ({len(items)})**")
        if not items:
            lines.append("")
            lines.append("- _(无)_")
            lines.append("")
            continue
        shown = items[:max_urls_per_bucket]
        for item in shown:
            method = item.get("method", "")
            url = item.get("url", "")
            lines.append(f"- `{method:<6}` {url}")
        if len(items) > max_urls_per_bucket:
            lines.append(
                f"- _… 省略 {len(items) - max_urls_per_bucket} 条，"
                f"完整列表见 `{service_payload.get('_source_file', '')}`_"
            )
        lines.append("")
    return lines


def render(
    scores: Dict[str, object],
    services_dir: Path,
    top_n_detail: int,
    max_urls_per_bucket: int,
) -> str:
    generated = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    services = scores.get("services", []) or []
    out: List[str] = []
    out.append("# 微服务安全风险排名")
    out.append("")
    out.append(f"- 生成时间：{generated}")
    out.append(f"- 微服务总数：{fmt_int(scores.get('total_services', len(services)))}")
    out.append(f"- 接口总数：{fmt_int(scores.get('total_endpoints', 0))}")
    out.append(f"- 评分公式：`{scores.get('formula', '')}`")
    out.append("")
    out.append("## 排名总表")
    out.append("")
    out.extend(render_summary_table(services))
    out.append("")
    out.append(f"## 详细分解（Top {top_n_detail}）")
    out.append("")

    for svc in services[:top_n_detail]:
        file_path = svc.get("file")
        if not file_path:
            continue
        path = Path(file_path)
        if not path.is_absolute():
            path = Path(file_path)
        if not path.exists():
            out.append(f"### {svc['rank']}. {svc['name']} — 风险分 {svc['risk_score']:g}")
            out.append("")
            out.append(f"_(per-service file missing: `{file_path}`)_")
            out.append("")
            continue
        service_payload = load_json(path)
        service_payload["_source_file"] = str(path)
        out.extend(
            render_detail_section(
                int(svc["rank"]),
                svc,
                service_payload,
                max_urls_per_bucket,
            )
        )

    if len(services) > top_n_detail:
        out.append("---")
        out.append("")
        out.append(
            f"_排名 {top_n_detail + 1}–{len(services)} 的服务仅出现在总表中。"
            f"完整 URL 列表见各自的 `{services_dir}/<name>.json`。_"
        )
        out.append("")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", required=True, type=Path)
    parser.add_argument("--services-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--top-n-detail", type=int, default=20)
    parser.add_argument(
        "--max-urls-per-bucket",
        type=int,
        default=100,
        help="Cap URLs shown per bucket in detail sections (rest are summarized).",
    )
    args = parser.parse_args(argv)

    if not args.scores.exists():
        raise FileNotFoundError(
            f"Scores not found: {args.scores}. Run compute_risk.py first."
        )
    scores = load_json(args.scores)

    markdown = render(
        scores=scores,
        services_dir=args.services_dir,
        top_n_detail=args.top_n_detail,
        max_urls_per_bucket=args.max_urls_per_bucket,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fp:
        fp.write(markdown)
        if not markdown.endswith("\n"):
            fp.write("\n")

    print(
        f"[render_report] wrote {args.output} "
        f"(top-{args.top_n_detail} detailed, "
        f"{scores.get('total_services', 0)} services total)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

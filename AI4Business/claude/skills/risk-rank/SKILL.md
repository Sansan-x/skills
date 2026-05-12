---
name: risk-rank
description: Ranks all microservices by security risk using the data prepared by collect-information, then generates a unified Markdown risk report. Use when the user asks to rank, score, or prioritize microservices by security risk, or asks for a microservice risk report.
---

# risk-rank

Computes a per-service risk score from the aggregate counts in `services_summary.json` and renders a unified Markdown report (`output/RISK_RANK_REPORT.md`). Scripts do all the heavy work; the LLM only reads the small ranked JSON.

## Prerequisites

- `data/services_summary.json` must exist (produced by `collect-information`).
- `data/services/<name>.json` files must exist (also produced by `collect-information`); they are read by `render_report.py` for the Top-N detail sections.

If either is missing, invoke the `collect-information` skill first.

## Risk Formula

Default weights (configurable via CLI flags):

```
score = 8 * ext_write + 4 * ext_get + 2 * int_write + 1 * int_get
```

- `ext_write`: external POST/PUT/PATCH/DELETE — highest risk (state-changing AND exposed)
- `ext_get`: external GET — data exposure risk
- `int_write`: internal POST/PUT/PATCH/DELETE — moderate risk
- `int_get`: internal GET — lowest risk

Tiebreaker: total endpoint count (more endpoints → higher risk).

## Workflow

1. **Verify prerequisites.** Check `data/services_summary.json` exists. If not, run `collect-information` first.
2. **Compute risk scores.**

```bash
python ./.claude/skills/risk-rank/scripts/compute_risk.py \
    --summary data/services_summary.json \
    --output data/risk_scores.json
```

   To use different weights:

```bash
python ./.claude/skills/risk-rank/scripts/compute_risk.py \
    --summary data/services_summary.json \
    --output data/risk_scores.json \
    --w-ext-write 10 --w-ext-get 5 --w-int-write 2 --w-int-get 1
```

3. **Render the report.**

```bash
python ./.claude/skills/risk-rank/scripts/render_report.py \
    --scores data/risk_scores.json \
    --services-dir data/services \
    --output output/RISK_RANK_REPORT.md \
    --top-n-detail 20
```

4. **Present results.** Read `data/risk_scores.json` (small — just the ranked summary). Report Top-10 to the user with risk scores and bucket counts, and point them to `output/RISK_RANK_REPORT.md` for the full report.

## Report Structure

`output/RISK_RANK_REPORT.md` contains:

- **Header**: generation time, service/endpoint totals, scoring formula.
- **排名总表 (Ranking Summary)**: Markdown table with every service — rank, name, risk score, four bucket counts, and total.
- **详细分解 Top-N (Detailed Breakdown)**: For each of the top N services (default 20), the URLs in the four required buckets in order:
  1. 外部 — POST/PUT/PATCH/DELETE
  2. 外部 — GET
  3. 内部 — POST/PUT/PATCH/DELETE
  4. 内部 — GET
- **Trailer**: For services beyond rank N, the report links to their `data/services/<name>.json` for full details.

Each bucket caps URLs at `--max-urls-per-bucket` (default 100) with a summarized remainder note, keeping the report readable even for huge services.

## Context Discipline

- Read `data/risk_scores.json` only (small).
- Do **not** read `data/services/<name>.json` files directly; the renderer handles them.
- Do **not** read the full `output/RISK_RANK_REPORT.md` in bulk. If the user wants a sample, read with line offset/limit and show the header + top of the summary table.

## Smoke Test

After running the `collect-information` smoke test, the full pipeline can be exercised with:

```bash
python ./.claude/skills/risk-rank/scripts/compute_risk.py \
    --summary data/services_summary.json --output data/risk_scores.json

python ./.claude/skills/risk-rank/scripts/render_report.py \
    --scores data/risk_scores.json \
    --services-dir data/services \
    --output output/RISK_RANK_REPORT.md \
    --top-n-detail 5
```

Expected on the 4-row sample data: `user-svc` ranks above `order-svc` because it has more endpoints, or the two tie on `ext_write` weight with `user-svc` winning on total count.

## Dependencies

- Python 3.9+ (no third-party packages required for this skill — only the standard library).

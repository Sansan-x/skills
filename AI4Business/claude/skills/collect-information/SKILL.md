---
name: collect-information
description: Extracts microservice endpoints from an Excel inventory and organizes each service's URLs in the order external POST/PUT/PATCH/DELETE, external GET, internal POST/PUT/PATCH/DELETE, internal GET. Use when the user wants to consolidate microservice URL inventories from an .xlsx file, organize endpoints per service, or as the first step of microservice security risk analysis.
---

# collect-information

Organizes a large microservice endpoint inventory (Excel, ~20k rows) into per-service JSON files pre-sorted by risk priority. Python scripts do all heavy work; the LLM only reads the small aggregate summary.

## Inputs and Outputs

- **Input**: An `.xlsx` file with one row per endpoint and at least these columns (defaults shown):
  - `url` — the endpoint path
  - `service_name` — owning microservice
  - `method` — HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`)
  - `url_type` — `external` or `internal` (Chinese aliases like `外部` / `内部` are auto-normalized)
- **Outputs** (under `data/`):
  - `all_endpoints.json` — full normalized records (DO NOT read in bulk)
  - `services/<safe-name>.json` — one file per microservice, pre-sorted in required order (DO NOT read in bulk; open at most one on demand)
  - `services_summary.json` — small aggregate; this is the **only** file the LLM should read fully

## Workflow

Follow these steps in order:

1. **Locate the Excel file.** Default path is `microservices.xlsx` at the workspace root. If absent, ask the user for the path.
2. **Run extraction.** Column names default to `url, service_name, method, url_type`; if they differ, pass `--columns-map`.

```bash
python ./.claude/skills/collect-information/scripts/extract_excel.py \
    --input microservices.xlsx \
    --output data/all_endpoints.json
```

3. **Run per-service organization.** This groups by `service_name` and sorts each group in the required priority order.

```bash
python ./.claude/skills/collect-information/scripts/organize_per_service.py \
    --input data/all_endpoints.json \
    --services-dir data/services \
    --summary data/services_summary.json
```

4. **Verify via summary only.** Read `data/services_summary.json` (small). Confirm `total_services` and `total_endpoints` look reasonable; spot-check a few service counts. Report a short summary to the user.

## Context Discipline

To keep large inventories from filling the context window:

- **Do not** open `data/all_endpoints.json` with the read tool.
- **Do not** open any `data/services/*.json` in bulk. If a specific service's URLs are needed, open exactly one file.
- The only file you should read fully is `data/services_summary.json`.

## Column Mapping (when defaults don't match)

If the Excel uses different headers, pass `--columns-map`:

```bash
python ./.claude/skills/collect-information/scripts/extract_excel.py \
    --input microservices.xlsx \
    --output data/all_endpoints.json \
    --columns-map "url=URL,service_name=Service,method=HTTP Method,url_type=Type"
```

Logical keys are fixed: `url`, `service_name`, `method`, `url_type`. Only the right-hand actual column names change.

## Smoke Test

For a quick end-to-end sanity check, create a tiny xlsx and run the pipeline:

```bash
python - <<'PY'
import pandas as pd
pd.DataFrame([
    {"url": "/api/users", "service_name": "user-svc", "method": "POST", "url_type": "external"},
    {"url": "/api/users/{id}", "service_name": "user-svc", "method": "GET", "url_type": "external"},
    {"url": "/internal/users", "service_name": "user-svc", "method": "GET", "url_type": "internal"},
    {"url": "/api/orders", "service_name": "order-svc", "method": "POST", "url_type": "external"},
]).to_excel("sample_microservices.xlsx", index=False)
PY

python ./.claude/skills/collect-information/scripts/extract_excel.py \
    --input sample_microservices.xlsx --output data/all_endpoints.json

python ./.claude/skills/collect-information/scripts/organize_per_service.py \
    --input data/all_endpoints.json \
    --services-dir data/services \
    --summary data/services_summary.json
```

Expected: `services_summary.json` lists 2 services with non-zero `ext_write`, `ext_get`, and `int_get` counts.

## Dependencies

- Python 3.9+
- `pandas`
- `openpyxl`

Install if missing: `pip install pandas openpyxl`

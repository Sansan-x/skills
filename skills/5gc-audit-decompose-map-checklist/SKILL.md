---
name: 5gc-audit-decompose-map-checklist
description: 面向 5GC/free5gc/open5gs 等“5G核心网 Go 代码审计”的首步技能。只要用户提到要对 5GC Go 项目做审计，并且需要“分解模块/提取函数/生成模块-检查项框架/准备后续 matrix 与 tasklist”，就必须使用本 skill 来生成 `audit_project_map.json` 与 `audit_checklists.json`。优先用 tree-sitter 做 Go AST 提取；若依赖缺失则自动降级为 regex/符号扫描，但仍保证输出结构完整。
---

# 5GC Decompose + Map + Checklist

## 触发条件（尽量覆盖）
- 用户要审计 5GC 核心网 Go 代码（例如 free5gc / open5gs / 自研 NF）
- 用户要求“项目地图/模块清单/函数清单/入口候选/检查清单”，或明确要继续生成 matrix / tasklist
- 用户要求“先 decompose/map，再规划、最后推理审计”

## 执行方式
1. 以 `workspace root = 目标项目目录` 作为输入。
2. 运行脚本生成：
   - `audit_project_map.json`
   - `audit_checklists.json`
3. 若 tree-sitter 不可用，脚本会在输出里写入 `extraction_method` 与 `warnings`，并继续生成（禁止失败中断）。

## 必要产物（在目标项目根目录）
- `audit_project_map.json`
- `audit_checklists.json`

## 关键字段约束（保证后续 skill 可直接消费）
- `audit_project_map.json`
  - 必含：`modules[]`、`functions[]`、`entry_candidates`、`extraction_method`
- `audit_checklists.json`
  - 必含：`checklist_categories[]`（每类包含 `category_id` 与 `check_items[]`）

## 参考脚本
运行命令（由你在执行时调用脚本）：
```bash
python scripts/ts_decompose_go.py <project_dir>
```

## 成功判定
- 控制台/对话输出中给出：
  - 提取模式（tree-sitter / fallback）
  - Go 文件扫描数量与函数数量摘要
  - `audit_project_map.json` / `audit_checklists.json` 路径与文件大小（或至少确认已生成）


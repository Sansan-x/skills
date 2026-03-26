---
name: 5gc-audit-end2end
description: 5GC Go 代码审计端到端总控编排技能：当用户只提供 workspace root（目标 5GC Go 项目目录）并要求“一键生成规划产物并输出最终审计报告”时，自动按严格顺序执行 Stage-1(分解/地图/检查清单) → Stage-2(matrix/tasklist/tasks) → Stage-3(任务排序+报告骨架) → 基于 ordered_tasks.json 填充最终中文安全审计报告（遵循 module -> business flow -> single function）。
---

# 5GC Audit End-to-End Orchestrator

本 skill 的目标是把 5GC Go 项目的审计流程“从零到报告”打通：在用户仅给出 `workspace root=目标项目目录` 的情况下，自动生成所有中间产物并输出最终报告到 `./reports/*-5gcoreaudit-*.md`。

## 触发条件
- 用户提供 `workspace root = 目标 5GC Go 项目目录`（free5gc/open5gs/自研 NF 等 Go 项目）
- 用户希望“一键跑完”：生成规划产物（map/checklists/matrix/tasklist/tasks/ordered_tasks）并输出最终审计报告
- 用户未明确要求只运行某一个 stage（若用户只想运行单 stage，应优先用对应的子 skill）

## 交付目标（用户最终交付物）
- **必须**：`./reports/*-5gcoreaudit-*.md`（最终中文安全审计报告；若无法完成推理至少输出 report skeleton）
- **必须**：`ordered_tasks.json`（用于证明推理顺序与审计覆盖）
- **可保留但不作为交付目标**：`audit_project_map.json`、`audit_checklists.json`、`audit_matrix.json`、`audit_tasklist.json`、`audit_tasks/*.md`

## 端到端严格流程（Stage-1 → Stage-2 → Stage-3 → Reasoning Fill）

### Stage-0：输入自检（必须）
在任何脚本/推理前，先做“不可臆想”的输入校验：
- 目标目录存在，且看起来像 Go 项目（例如存在 `go.mod` 或大量 `*.go`）
- 如果用户给的目录不是代码根目录，必须明确指出并要求补充：正确的 `workspace root`（不要猜测子目录）

### Stage-1：decompose + map + checklist（生成项目地图与检查清单）
目标产物（位于目标项目根目录）：
- `audit_project_map.json`
- `audit_checklists.json`

执行命令（在 `workspace root = 目标项目目录` 下）：
```bash
python skills/5gc-audit-decompose-map-checklist/scripts/ts_decompose_go.py <project_dir>
```

### Stage-2：matrix planner（生成 matrix/tasklist/tasks）
目标产物：
- `audit_matrix.json`
- `audit_tasklist.json`
- `audit_tasks/*.md`

执行命令：
```bash
python skills/5gc-audit-matrix-planner/scripts/build_matrix_and_tasks.py --project-dir <project_dir>
```

### Stage-3：order + report skeleton（生成 ordered_tasks.json 与报告骨架）
目标产物：
- `ordered_tasks.json`
- `./reports/<name>-5gcoreaudit-<timestamp>.md`（报告骨架）

执行命令：
```bash
python skills/5gc-audit-executor/scripts/order_tasks_and_skeleton.py --project-dir <project_dir>
```

### Reasoning Fill：基于 ordered_tasks.json 填充最终报告（严格顺序）
你必须把推理严格限制在以下顺序与粒度约束里（见下方“推理约束”），并把输出落到 Stage-3 的报告文件中（继续填充骨架内容，直到形成“最终报告”）。

## Smoke Guard（必须，自动回退 stage，缺失时明确报错）

### 自动回退规则（缺啥补啥，按最小必要回退）
当用户触发 end2end 时，按以下顺序检查目标项目根目录的中间产物；若缺失则自动回退执行对应 stage：

1. 若缺少 `audit_project_map.json` 或 `audit_checklists.json`：
   - **先执行 Stage-1**
2. 若缺少 `audit_tasklist.json` 或 `audit_tasks/` 或 `audit_matrix.json`：
   - **确保 Stage-1 已完成/存在**，再执行 Stage-2
3. 若缺少 `ordered_tasks.json` 或 `reports/` 下不存在 `*-5gcoreaudit-*.md`：
   - **确保 Stage-2 已完成/存在**，再执行 Stage-3

注意：
- 如果存在部分产物（例如只有 `audit_tasklist.json`，但 `audit_tasks/` 不全），仍应继续 Stage-3 并允许在 `ordered_tasks.json` 中跳过缺失的 task md（由 Stage-3 脚本行为决定）；同时在报告里明确标注“缺失任务 md 导致审计覆盖不完整”，不得臆想补齐。

### 明确错误（禁止臆想）
出现以下情况必须停止并给出“明确错误 + 需要用户补充的信息”，而不是编造：
- 脚本路径不存在/无法运行：输出缺失的脚本相对路径，并提示用户确认本 repo 的 skills 是否完整
- 目标目录不是 Go 项目或缺少可扫描源码：输出你观察到的关键证据（例如没有 `go.mod` / 没有 `*.go`），并要求用户提供正确的 `workspace root`
- Stage-3 脚本报错提示缺少 `audit_tasklist.json` 或 `audit_tasks/`：不要继续推理；回退 Stage-2 或提示用户补充缺失文件

## 推理约束（核心：module → business flow → single function）

### 1) module 粒度（只做总览，不做证据链）
- 只产出：模块级风险摘要、将覆盖的 checklist 类别、每个 business flow 的定位目标
- **禁止**：展开单函数级 source→sink 证据链、给出具体行号/代码片段（除非你确实在代码中读到并能引用）

### 2) business flow 粒度（中间粒度：show_quasi_trace）
business flow 阶段必须使用 **show_quasi_trace** 的表达方式：
- 只输出“准调用链/关键节点”结论：入口消息/数据从哪里来 → 关键校验/净化/鉴权/状态变更 → 关键 sink
- 只列关键节点（例如 3–8 个），每个节点说明：
  - 节点职责（校验/鉴权/状态变更/转发/存储等）
  - 关键信号（例如是否有鉴权、是否有输入净化、是否有错误分支）
  - 证据状态：确认 / 疑似 / 待补充证据
- **禁止**：把 business flow 写成逐函数完整证据链（避免与 single function 重复）

show_quasi_trace 输出格式（建议）：
- 入口：<入口函数/协议/消息>
- 关键节点：
  1. <func/handler> — <做了什么> — 证据：确认/疑似/待补充
  2. ...
- 关键 sink：<危险操作/状态写入/外部调用>
- 结论：<风险点>；<缺失证据列表>

### 3) single function 粒度（精审：逐 check_id 核对）
对 `audit_tasks/*.md` 中指定的 `主要函数/次要函数` 与 `check_id` 做逐项核对：
- 必须输出 **source→sink 证据表** 与可操作修复建议（可落地的 Go 代码级建议）
- 行号/代码片段必须来源于真实代码阅读；若无法确认上下文：
  - 只能写“待补充证据”，并列出你需要用户提供/你需要进一步读取的文件/函数
  - **禁止** 编造行号、编造文件路径、编造代码片段

## 报告填充规则（最终输出必须对齐章节顺序）
- 输出目录：`./reports/`
- 文件命名：由 Stage-3 脚本生成（`<name>-5gcoreaudit-<timestamp>.md`）
- 报告章节顺序：尽量对齐 `skills/go-audit/references/report-template.md` 的章序（执行摘要→项目概况→范围与方法→发现汇总→详细发现→攻击链→修复优先级→附录）
- 报告中必须出现明确的顺序证据（用于评估）：例如在“审计范围与方法”处写明
  - `审计模式： module -> business flow -> single function`
  - 并在“详细发现”填充时按 `ordered_tasks.json` 的顺序推进

## 输出完成标准（终止条件）
- `ordered_tasks.json` 已生成
- `./reports/*-5gcoreaudit-*.md` 至少存在一份，并已按 `ordered_tasks.json` 顺序填充到“详细发现”章节（若证据不足必须标注，不得臆想）

## 示例提示词
- “workspace root 是 free5gc 项目根目录。请用 5gc-audit-end2end 一键生成所有规划产物并输出最终审计报告。”
- “我已经有 audit_project_map.json 与 audit_checklists.json 了，请继续跑后续 stages 并输出最终报告。”

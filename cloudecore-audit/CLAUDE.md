# Claude Pipeline: (conditional project-analyzer) -> orchestrator -> go-audit-detector -> trace-resolver -> go-audit-judge

## Stage 1: project-analyzer（条件执行）
Step 1: 检查 `./reports/audit-strategy-plan.md` 是否存在且非空：
- 若存在且非空：**跳过** `Agent(project-analyzer)`，直接进入 Stage 2。
- 若不存在或为空：运行 `Agent(project-analyzer)` 生成策略文件后进入 Stage 2。

约束：
- `project-analyzer` 只负责阶段1-3。
- 必须将审计策略计划写入文件 `./reports/audit-strategy-plan.md`。

输出：
- `strategy_plan_file` = `./reports/audit-strategy-plan.md`（来源可能为“复用已有”或“本次新生成”）

## Stage 2: orchestrator（must-cover 并行调度）
Step 2: 运行 `Agent(orchestrator)`。

输入：
- `orchestrator` 从 `./reports/audit-strategy-plan.md` 读取策略并展开覆盖义务。
- 若策略包含并行编排字段，`orchestrator` 必须并行调度：
  - `Agent(file-audit)`
  - `Agent(sqli-audit)`
  - `Agent(go-runtime-audit)`

输出：
- `must_cover_results`（结构化聚合结果，供 go-audit-detector/go-audit-judge 汇总）
- `gate_status`（Gate-1..4）
- `must_cover_results_file` = `./reports/must-cover-results.json`（必须落盘，供 judge 稳定消费）

## Stage 3: go-audit-detector
Step 3: 运行 `Agent(go-audit-detector)`。

输入：
- `go-audit-detector` 将自动从 `./reports/audit-strategy-plan.md` 读取审计策略计划，不再需要上下文粘贴/注入。
- `go-audit-detector` 应优先按策略中的**审计覆盖粒度**（必审文件 / 必审目录全量 / 其余尽量全量）与模块/目录顺序执行，并执行 CoverageBackfill（覆盖补扫），输出 `detector_findings` 与 `sink_candidates`。
- 若存在 `must_cover_results`，`go-audit-detector` 必须进行统一去重与 backfill 收敛后输出检测结果。

## Stage 4: trace-resolver（父层MCP追踪）
Step 4: 父流程统一执行 `trace-resolver`（非子agent技能）。

输入：
- `sink_candidates`（来自 `file-audit` / `sqli-audit` / `go-runtime-audit` / `go-audit-detector`）
- 策略中的 sink/source/stop_conditions 约束

输出：
- `trace_results`
- `trace_metrics`
- `trace_results_file` = `./reports/trace-results.json`（必须落盘，供 judge 稳定消费）

规则：
- 必须通过 CodeBadger MCP 完成 source→sink 追踪（每条候选的追踪/查询不得绕过 MCP）。
- 当策略启用 CPG 复用（`codebadger_cpg_reuse` 为 `auto`/`on`）且 MCP 确认存在与当前代码范围匹配的 CPG 时，**允许跳过 CPG 生成/重建步骤**；未启用或不可复用时仍须按 MCP 流程确保 CPG 可用。
- `trace-results.json` 须包含 `cpg_context`（复用策略、结果、标识与中止/不匹配原因），供 judge 核对证据时效性。
- 仅当 `timeout/error/empty` 时允许 `LLMInferred` 降级，并显式写入降级原因。

## Stage 5: go-audit-judge
Step 5: 运行 `Agent(go-audit-judge)`。

输入：
- `go-audit-judge` 自动读取 `./reports/audit-strategy-plan.md`。
- `go-audit-judge` 必须读取 `./reports/must-cover-results.json` 与 `./reports/trace-results.json`。
- 消费 `detector_findings`、`trace_results`、`trace_metrics`、`must_cover_results`、`gate_status`。
- 执行净化/验证、漏洞判定、评级、攻击链分析并生成最终报告（含附录 A.1/A.2/A.3）。
- 最终报告必须遵循 `go-audit-judge` skill 与 `skills/go-audit-common/references/report-template.md` 的章节骨架与附录约定，并**仅**以符合命名正则的 Markdown 文件写入 `./reports/`（与 judge 契约一致，不得另存自拟路径）。

硬性约束：
- `go-audit-detector` 与 `go-audit-judge` 必须严格依赖 `./reports/audit-strategy-plan.md` 的文件内容，禁止自行生成阶段1-3内容。
- 如果文件不存在或为空，两个agent都必须中止并提示先运行 `project-analyzer`。
- 如果策略计划中缺失字段，必须标注"不确定"，而不是臆想补全。
- 并行编排模式下，`file-audit`/`sqli-audit`/`go-runtime-audit` 必须由各自独立 skill 执行；不得把三类逻辑硬编码回 `go-audit-detector` 或 `go-audit-judge`。
- `must-cover-results` 与 `trace-results` 仅允许 JSON 结构化证据文件；缺失必填字段时必须判定输入无效并中止，不得回退为自然语言推断解析。

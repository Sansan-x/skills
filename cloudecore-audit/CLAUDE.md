# Claude Pipeline: (conditional project-analyzer) -> orchestrator -> go-audit

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
- `must_cover_results`（结构化聚合结果，供 go-audit 汇总）
- `gate_status`（Gate-1..4）

## Stage 3: go-audit
Step 3: 运行 `Agent(go-audit)`。

输入：
- `go-audit` 将自动从 `./reports/audit-strategy-plan.md` 读取审计策略计划，不再需要上下文粘贴/注入。
- `go-audit` 应优先按策略中的**审计覆盖粒度**（必审文件 / 必审目录全量 / 其余尽量全量）与模块/目录顺序执行，并执行 CoverageBackfill（覆盖补扫）；最终在附录输出**文件级**、**模块/目录级**以及（并行模式下）**模式执行级**覆盖统计（见 `go-audit` skill 与报告模板附录 A）。
- 若存在 `must_cover_results`，`go-audit` 必须进行统一去重、冲突仲裁与 backfill 收敛后再生成最终报告。

硬性约束：
- `go-audit` 必须严格依赖 `./reports/audit-strategy-plan.md` 的文件内容，禁止自行生成阶段1-3内容。
- 如果文件不存在或为空，`go-audit` 必须中止并提示先运行 `project-analyzer`。
- 如果策略计划中缺失字段，必须标注"不确定"，而不是臆想补全。
- 并行编排模式下，`file-audit`/`sqli-audit`/`go-runtime-audit` 必须由各自独立 skill 执行；不得把三类逻辑硬编码回 go-audit。

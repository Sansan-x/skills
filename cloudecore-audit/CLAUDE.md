# Claude Pipeline: project-analyzer -> go-audit

## Stage 1: project-analyzer
Step 1: 运行 `Agent(project-analyzer)`。

约束：
- `project-analyzer` 只负责阶段1-3。
- 必须将审计策略计划写入文件 `./reports/audit-strategy-plan.md`。

输出：
- `strategy_plan_file` = `./reports/audit-strategy-plan.md`

## Stage 2: go-audit
Step 2: 运行 `Agent(go-audit)`。

输入：
- `go-audit` 将自动从 `./reports/audit-strategy-plan.md` 读取审计策略计划，不再需要上下文粘贴/注入。
- `go-audit` 应优先按模块/目录执行策略，并执行 CoverageBackfill（覆盖补扫），最终在附录输出模块级覆盖统计。

硬性约束：
- `go-audit` 必须严格依赖 `./reports/audit-strategy-plan.md` 的文件内容，禁止自行生成阶段1-3内容。
- 如果文件不存在或为空，`go-audit` 必须中止并提示先运行 `project-analyzer`。
- 如果策略计划中缺失字段，必须标注"不确定"，而不是臆想补全。

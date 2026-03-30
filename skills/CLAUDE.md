# Claude Pipeline: project-analyzer -> go-audit

## Stage 1: project-analyzer
Step 1: 运行 `Agent(project-analyzer)`。

约束：
- `project-analyzer` 只负责阶段1-3。
- 仅接收并保存其输出中的固定标题块：`# Auditing Strategy Plan`（整段原文，不要二次改写）。

输出：
- `strategy_plan` = `# Auditing Strategy Plan` 固定标题块原文

## Stage 2: go-audit
Step 2: 运行 `Agent(go-audit)`。

输入注入（粘贴/注入到本 step prompt 中）：
- `strategy_plan`（上一步的 `# Auditing Strategy Plan` 原文）

硬性约束：
- `go-audit` 必须严格依赖 `strategy_plan`，禁止自行生成阶段1-3内容。
- 如果 `strategy_plan` 中缺失字段，必须标注“不确定”，而不是臆想补全。


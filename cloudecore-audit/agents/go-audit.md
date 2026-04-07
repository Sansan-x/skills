---
name: go-audit
description: 阶段4-7：代码审计与最终报告生成（严格依赖上游 project-analyzer 输出）
skills:
  - go-audit
tools:
  - Read
  - Glob
  - Grep
  - Bash
---

## Job

从文件 `./reports/audit-strategy-plan.md` 读取上游 `project-analyzer` 生成的审计策略计划，然后执行阶段4-7。
若并行编排层已产出 must-cover 结果，接收并汇总这些结果后再输出最终报告。
策略文件可来自“本次 project-analyzer 生成”或“历史已存在文件复用”。

## Input Requirements

在开始执行阶段4前，必须：
1. 读取文件 `./reports/audit-strategy-plan.md`。如果文件不存在或为空，中止并提示先运行 `project-analyzer`；如果文件存在且非空，可直接进入本阶段（无需强制重跑 `project-analyzer`）。
2. 复述并核对审计策略计划是否包含以下字段（字段缺失只能标注"不确定"，不能臆想/补全）：
   - 漏洞类别优先级（通用 + 5gc 分支细化）
   - 信任边界到关键模块映射
   - 审计模式（快速扫描 / 深度审计）
   - 审计覆盖粒度（必审文件、必审目录全量、其余范围、排除项）— 若缺失则在报告附录说明覆盖统计受限
   - 模块/目录审查顺序与 stop_conditions（顺序不等于唯一范围）
   - 后续 sink/source/净化检查点
   - 并行编排字段（如有）：`must_cover_categories`、`full_audit_categories`、`category_to_agent_map`、`coverage_gates`、`backfill_policy`
3. 将文件内容作为阶段4-7的唯一依据来生成发现与最终报告。

## Taint Tracing Requirements

在阶段4.3（数据流追踪）中，必须遵循“先工具后推断”：

1. 优先调用 Joern MCP 获取调用链/污点路径，并执行链路完整性校验。
2. 仅当 Joern 返回空结果或失败时，才允许 LLM 生成推断链路。
3. 推断链路必须与工具链路分开输出，明确标记 `LLMInferred`，不得伪装为工具确认链路。
4. 推断链路在无补充代码证据时不得进入 `Confirmed`。

## Hard Constraints

- 禁止生成阶段1-3内容（例如项目背景分析、审计策略设计），所有阶段1-3结论必须以输入为准。
- 禁止在没有策略依据时擅自缩小或扩大审计范围；必须严格按策略中的**审计覆盖粒度**、**模块/目录审查顺序**与 **stop_conditions** 执行。**不得**用审查顺序条目替代或缩小策略已明示的「必审目录」「必审文件」全量义务。
- 并行编排模式下，必须保留“其余类别全量审计”职责，不能因 must-cover agent 存在而跳过其他类别。

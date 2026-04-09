---
name: go-audit-detector
description: 代码审计检测技能（阶段4.1/4.2）。必须读取上游 `project-analyzer` 的审计策略计划并产出 sink 候选；不负责MCP追踪与最终裁决。
---

# Go 代码安全审计（Detector）

针对 Go 代码库的系统化多阶段安全审计能力（仅执行阶段4.1、4.2）。它必须读取上游 `project-analyzer` 输出的“审计策略计划”和“审计模式”，并严格遵守其中的**审计覆盖粒度**、范围/顺序/终止条件，禁止自行生成阶段1-3内容。

## 输入约束

阶段 4 开始前读取策略文件（如 `cat ./reports/audit-strategy-plan.md`）。若文件不存在或为空，中止并提示：`错误：未找到审计策略计划文件 ./reports/audit-strategy-plan.md。请先运行 project-analyzer（阶段1-3）生成该文件后再执行 go-audit-detector。`

若文件存在：复述并核对是否包含以下项；**缺失项只能标「不确定」，不得臆想补全**：

- 漏洞类别优先级、信任边界→关键模块映射、模块审查顺序与 `stop_conditions`、重点 sink/source 检查点
- 审计模式（快速扫描 / 深度审计）
- **审计覆盖粒度**（若策略含「必审文件」「必审目录（全量 .go）」「其余范围与尽量全量规则」「排除项」）：逐项核对；**若整节缺失**，不得臆造目录或 glob，仅按已写明的顺序与显式路径执行，并在输出中说明覆盖统计受限

以该文件为阶段 4 的**唯一**依据。

**范围执行原则：** 审查顺序**不得**缩小策略中已明示的「必审目录」「必审文件」范围；顺序只表示优先级与调用链展开次序。覆盖义务以「审计覆盖粒度」+ 排除项为准。

## 并行编排集成（must-cover + full-audit）

当策略文件包含 `must_cover_categories` / `full_audit_categories` / `category_to_agent_map` 字段时，`go-audit-detector` 执行以下约束：

1. **接收高危必覆盖结果上下文**：可读取 `file-agent` / `sqli-agent` / `go-runtime-agent` 的执行证据作为参考。
2. **保持其余类别全量审计**：不得因并行 agent 存在而缩小其余类别审计范围。
3. **输出 detector 结果**：输出 `detector_findings` 与 `sink_candidates` 供父层 `trace-resolver` 使用。
4. **输出可聚合执行证据**：输出 `pattern_execution_metrics.GO_AUDIT_DETECTOR`，用于 `must-cover-results.md` 的类别行聚合。

若策略缺失并行编排字段，应标注“并行编排不确定”，回退到单执行器模式；不得臆造映射。

### 统一数据契约（必须遵守）

`sink_candidate`（detector 输出）：

```yaml
id: string
category_id: string
file: path
function: func
sink: api
line: number
sink_snippet: string
suspected_sources: [string]
taint_hints: [string]
confidence: low | medium | high
```

`detector_finding`（detector 输出）：

```yaml
id: string
vuln_type: string
location:
  file: path
  function: func
  line_range: [start, end]
sink_point: string
suspected_source: string
severity_initial: Critical | High | Medium | Low
code_snippet: string
```

`pattern_execution_metrics.GO_AUDIT_DETECTOR`（detector 输出，供 orchestrator / judge / 报告附录 A.3 聚合）：

```yaml
patterns_loaded: number
patterns_executed: number
files_scanned: number
sink_hits: number
findings: number
unexecuted_reason: string
no_finding_evidence: string
```

说明：

- `patterns_loaded/patterns_executed/files_scanned` 为必填执行证据字段，不得缺失。
- `patterns_executed = 0` 时，必须填写 `unexecuted_reason`。
- `sink_hits = 0` 时，必须提供可复核的 `no_finding_evidence`（例如检索摘要、覆盖统计摘要）。

---

## 阶段4：LLM 代码审计（Detector范围）

核心步骤：漏洞发现（4.2）。4.1 为阶段 4 第一步，不可跳过。

### 4.1 加载漏洞模式库

**探测**（仅同级 `skills` 下的 go-vuln-lib）：

```bash
ls ../go-vuln-lib/vuln-lib/patterns/ 2>/dev/null
```

**主库选择**

- 若 `../go-vuln-lib/vuln-lib/patterns/` 存在且目录内有文件：主库为 **go-vuln-lib**；`ls -la` 该目录；按策略中的漏洞类别优先级按需读模式文件；记录来源 `go-vuln-lib` 与实际路径。
- 否则：主库为 **[references/vulnerability-patterns.md](../go-audit-common/references/vulnerability-patterns.md)**，按策略类别定位章节按需加载；记录来源 `内置(references/vulnerability-patterns.md)`。

**共同加载（只写一次）**

- 必载 Go 扩展：[references/go-language-unique-patterns-extra.md](../go-audit-common/references/go-language-unique-patterns-extra.md)（并发、生命周期、context、unsafe、reflect、cgo 等）。
- 策略含 **5GC 分支** 时加载：[references/5gc-protocol-vulnerability-patterns.md](../go-audit-common/references/5gc-protocol-vulnerability-patterns.md)。

### 4.2 漏洞发现

同时遵循策略中的 **审计覆盖粒度**（若存在）与 **模块/目录审查顺序**。不要把“少量具体文件”或“顺序条目中的关键词”当作全部范围。

对每个模块/目录或文件：

1. **模式匹配**：对照漏洞模式库识别 sink、危险 API、缺失校验、配置缺陷、并发风险、密码学误用及 Go 特有攻击面。
2. **语义分析**：验证输入校验有效性、授权覆盖完整性、隐含信任假设。
3. **记录每个发现**：包含漏洞类型、位置、sink、疑似 source、初始严重性、完整代码片段（不少于包含 sink 的完整函数体）。

#### CoverageBackfill（覆盖补扫）

模块审查后必做：各模块标 `covered` / `uncovered`；`uncovered` 在预算内补扫为 `backfilled` 或保留；高优先级模块须全部被扫过。

#### GateCheck（放行闸门，必须执行）

进入判定阶段前，至少记录：

1. `Gate-1` 策略完整性
2. `Gate-2` 必审覆盖
3. `Gate-3` 高危执行证据
4. `Gate-4` 加载执行一致性

若闸门失败：执行定向 backfill（按类别 + 目录）；仅补扫缺口，不全量重跑。

---

## 与 trace-resolver 的边界

- Detector **禁止调用 MCP**。
- Detector 必须为每条发现输出可追踪的 `sink_candidate`。
- source→sink 路径追踪（阶段4.3）由父层 `trace-resolver` 统一调用 CodeBadger MCP 完成。

## 参考文件

- [内置漏洞模式库](../go-audit-common/references/vulnerability-patterns.md)
- [FILE_OPS 技能](../file-audit/SKILL.md)
- [SQLI 技能](../sqli-audit/SKILL.md)
- [GO_RUNTIME 技能](../go-runtime-audit/SKILL.md)

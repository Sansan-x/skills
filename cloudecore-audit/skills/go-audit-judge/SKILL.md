---
name: go-audit-judge
description: 审计裁决与报告技能（阶段4.4-7）。仅消费 detector 与 trace-resolver 输入，执行净化验证、漏洞判定、评级、攻击链与最终报告。
---

# Go 代码安全审计（Judge）

针对 Go 代码库的系统化安全裁决能力（执行阶段4.4、5、6、7）。必须读取上游 `project-analyzer` 输出的“审计策略计划”，并消费父层 `trace-resolver` 回填的 trace 证据；禁止自行生成阶段1-3内容。

## 输入约束

开始前必须确认以下输入可用：

1. `./reports/audit-strategy-plan.md` 存在且非空
2. `./reports/must-cover-results.json` 存在且非空
3. `./reports/trace-results.json` 存在且非空
4. `detector_findings`（来自 `file-audit` / `sqli-audit` / `go-runtime-audit` / `go-audit-detector`）
5. `trace_results`（来自父层 `trace-resolver`）
6. `trace_metrics` 与 `coverage_backfill_metrics`

若上述任一关键输入缺失，必须中止并明确缺失项；不得臆造补全。
对 `must-cover-results.json` 与 `trace-results.json` 必须进行必填字段校验；关键键缺失时按输入无效并中止。`trace-results.json` 顶层须含 `cpg_context`（含 `reuse_policy`、`reuse_outcome`、`cpg_identifier`、`mismatch_or_abort_reason`），用于核对 CPG 是否复用及证据时效性。

## 与 trace-resolver 的边界

- Judge **禁止调用 MCP**。
- Judge 只消费 `trace_results` 进行净化/验证和漏洞判定。
- 若 `tool_call_status in {timeout,error,empty}`，必须显式降级为 `LLMInferred` 并写明 `fallback_reason`。

---

## 阶段4.4：误报验证

对已做数据流追踪的漏洞，结合净化、可达性、可利用性做判定；逐项依据以下检查与识别规则执行。

### 必答验证检查清单

| # | 检查项 | 问题 | Yes = 可能误报 |
|---|--------|------|----------------|
| 1 | Source 可控性 | source 是否真的可被外部攻击者控制 | Source 不可被外部控制 → 排除 |
| 2 | 中间净化/校验 | source 到 sink 路径上是否存在有效净化 | 存在有效净化 → 排除 |
| 3 | 框架/ORM 自动防护 | 是否使用框架级自动防护 | 有框架防护 → 排除 |
| 4 | 路径可达性 | 该代码路径是否真的可达 | 路径不可达 → 排除 |
| 5 | 利用约束 | 数据格式/类型约束是否使利用不可行 | 格式约束阻断利用 → 排除 |

### 每个发现的判定

- **Confirmed**：路径清晰、无有效净化、未命中排除；且须 `ToolConfirmed` 或等效代码证据。
- **Likely**：路径存但依赖运行时条件。
- **Suspicious**：有显著缓解。
- **False Positive**：命中排除规则并写明原因。

**硬规则**：`LLMInferred` 且无补充代码证据 → 不得 `Confirmed`；`ChainCompleteness` 为部分/断裂 → 默认 `Suspicious` 或 `False Positive`。

---

## 阶段5：漏洞分类与评级

对 Confirmed / Likely 漏洞映射 CWE 并按 CVSS 维度评级（攻击向量、复杂度、权限、用户交互、机密性/完整性/可用性影响）。

---

## 阶段6：攻击链组合分析

多漏洞可组合放大影响；链须因果成立、端到端连续、有阶段4代码与数据流证据、现实可利用，禁止臆造关联。

输出每条有效攻击链的：

- 攻击链名称
- 组合严重性
- 分步能力升级
- 最终影响
- 前置条件

---

## 阶段7：审计报告生成
生成全面的中文安全审计报告。模板权威来源：[references/report-template.md](../go-audit-common/references/report-template.md)（与 `agents/go-audit-judge.md` 中 `skills/go-audit-common/references/report-template.md` 为同一文件）。

### 强制执行顺序（阶段7）

必须按以下顺序执行，**不得**先写自由结构再在事后「贴」章节名：

1. **`Read` 报告模板** — 使用 `Read` 读取 `../go-audit-common/references/report-template.md`（或工作区根下 `skills/go-audit-common/references/report-template.md`），确认目录与各级标题（含 `## 1.`…`## 7.` 与附录 `#### A.1` / `#### A.2` / `#### A.3` 约定）。
2. **复制章节骨架再填空** — 从模板复制**章节骨架**（主标题、`## 1.`…`## 7.` 及附录下 `#### A.1`… 等标题层级）到输出草稿，再逐项填入内容；**禁止**先写无编号或与模板不一致的 `##` 结构再改标题。
3. **落盘唯一规范路径** — `mkdir -p ./reports` 后，将定稿正文写入**唯一**路径：`./reports/<project>-goaudit-<YYYYMMDD-HHMM>.md`。
4. **交付自检** — 完成下方「交付自检清单」全部项后方可结束阶段7；若有任一项失败，须修正或中止并说明原因。

### 交付自检清单（必须通过后再结束阶段7）

| # | 检查项 | 通过标准 |
|---|--------|----------|
| 1 | 模板已读 | 本回合已对上述 `report-template.md` 执行 `Read`，且正文骨架来自该模板 |
| 2 | 文件名 | 唯一最终文件路径匹配 `^[A-Za-z0-9_-]+-goaudit-[0-9]{8}-[0-9]{4}\.md$` 且位于 `./reports/` |
| 3 | 单份规范交付 | `./reports/` 下**不得**存在多份互冲突的「最终报告」；若曾生成非规范草稿，应合并 |
| 4 | 第5章与汇总表一致 | `## 5. 详细发现` 中漏洞条数与第4章发现汇总表一致 |
| 5 | 附录齐全 | `#### A.1`、`#### A.2` 已写全；并行编排时 **`#### A.3`** 必须存在且内容非空 |

### 报告输出

报告输出到 `./reports/` 目录下，文件命名规则：

```
./reports/[项目名称]-goaudit-[YYYYMMDD-HHMM].md
```

例如：`./reports/myproject-goaudit-20260319-1430.md`

在生成报告前，先创建 `./reports/` 目录：

```bash
mkdir -p "$(pwd)/reports"
```

项目名称从 `go.mod` 的 module 声明中提取（取最后一个路径段），如果不可用则使用项目根目录名。时间使用审计执行时的当前时间。

### 报告结构

报告必须包含：

1. **执行摘要** — 高层发现、整体风险态势、关键数字（致命/严重/一般/提示计数）
2. **项目概况** — 来自 project-analyzer 输出的项目背景（类型、技术栈、架构）
3. **审计范围与方法** — 审计了什么、使用的模式和方式、运行的工具（如有）、覆盖的文件和模块
4. **发现汇总表** — 所有发现按严重性排序，含ID、标题、严重性、CWE、位置
5. **详细发现** — **发现汇总表中的所有漏洞必须全部输出在此章节中**，按等级排列（致命 → 严重 → 一般 → 提示），每个漏洞包含完整的6个必填子章节（漏洞描述、漏洞代码、数据流路径、利用场景含PoC、影响、修复建议含前后对比）
6. **攻击链分析** — 来自阶段6（如有链被识别）
7. **附录** — 须符合 [references/report-template.md](../go-audit-common/references/report-template.md)：**附录 A.1 文件级覆盖统计** 填入 `CoverageBackfill` 中的文件指标；**附录 A.2** 为模块/目录级覆盖表。若策略缺失「审计覆盖粒度」或排除项，在 A.1 中明确说明统计受限原因。
   - 若启用并行编排，必须额外输出 **附录 A.3 模式执行覆盖统计**（至少包含 `FILE_OPS`、`SQLI`、`GO_RUNTIME`、`GO_AUDIT_DETECTOR` 四类的 loaded/executed/files_scanned/hits/findings/unexecuted_reason）。

### 第3章显示约束

- 第3章“审计范围与方法”不得展示“模式库来源”相关信息（包括来源类型、模式库路径、已加载模式数、已加载模式类别）。
- 模式库来源信息仅允许出现在附录的方法论说明中。

### 详细发现全量输出要求

所有漏洞必须全部输出在主报告的第5章"详细发现"中，不使用分文件方式。这是确保审计人员能在一份报告中看到所有安全问题的核心要求。

**篇幅受限时的处理方式：** 如果漏洞数量较多，按以下策略分批输出，但最终所有漏洞都必须出现在同一份报告中：

1. **按等级分批生成** — 先输出致命级全部漏洞，再输出严重级全部漏洞，依次输出一般级和提示级。每批输出后继续下一批，直到所有漏洞输出完毕
2. **如果单次输出被截断** — 在后续的继续输出中接续上次中断的位置，将剩余漏洞追加到报告中，确保最终报告完整
3. **禁止省略或简化**  — 不得以任何理由跳过漏洞、合并漏洞或简化后续漏洞的子章节内容
4. **checklist** — 检查详细发现中的漏洞数量与发现汇总漏洞数量一致才算完成任务

### 报告质量要求

- **漏洞代码：** 每个发现必须包含完整的漏洞代码片段（不少于包含sink的完整函数体），包括文件路径和行号，使用 `// ↑ 漏洞:` 注释标注漏洞行
- **数据流路径：** 每个发现必须包含精简结构化字段，最少包含两组信息：
  - 证据来源：`ChainEvidenceType`、`ToolName`、`ToolCallStatus`、`ToolQuerySummary`、`ConfidenceCapReason`
  - 数据链信息：`漏洞ID`、`Source`、`Sink`、`关键传播路径`
- **利用PoC：** 每个发现的利用场景必须包含可直接复现的PoC代码或命令，而非仅文字描述
- **修复建议：** 每个发现应提供简明、可执行的修复步骤与修复说明；可给出关键实现要点
- 严重性评级必须有理由支撑，不能仅仅赋值
- 报告应可操作——开发者仅凭报告即可修复每个问题
- 并行编排模式下，必须在附录方法论中给出 `must-cover` 与 `full-audit` 的边界说明、闸门结果与 backfill 结果
- 附录指标至少包含：`trace_call_success_rate`、`trace_call_empty_rate`、`trace_call_timeout_rate`、`trace_downgrade_rate`。

---

## 参考文件

在审计过程中按需加载以下资源：

- **go-vuln-lib 漏洞模式库**（优先）— 由 `go-vuln-lib` skill 生成的漏洞模式库，各攻击模式独立存储在 `go-vuln-lib/vuln-lib/patterns/` 目录下。阶段4.1通过文件系统探测自动发现并优先加载。

- [内置漏洞模式库](../go-audit-common/references/vulnerability-patterns.md)（备选）— 当 `go-vuln-lib` skill 不可用时自动回退使用。按类别组织的Go专属漏洞模式，包含sink函数、危险API、漏洞代码特征、Go语言特有攻击方法和修复模式。


- [报告模板](../go-audit-common/references/report-template.md) — 最终审计报告的结构模板。在阶段7开始时加载。包含章节标题、格式指南和各章节示例内容。

- [并行编排技能](../orchestrator-audit/SKILL.md) — must-cover 并行调度与 gate/backfill 策略。仅在策略含并行编排字段时协同使用。

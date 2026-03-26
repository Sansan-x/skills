# audit_tasks/*.md 统一任务模板（示例字段说明）

以下模板由 `5gc-audit-matrix-planner` 自动生成，供 `5gc-audit-executor` 严格按模板推进 reasoning。

---

## 任务元信息（必填）
- `task_id`: 例如 `TASK-0001`
- `scope`: `module` | `business_flow` | `single_function`
- `module_id`: 当 scope != `module` 时必填
- `category_id`: 对应 `audit_checklists.json` 的 `check_id`/类别（例如 `SBI_AUTHORIZATION`）
- `business_flow_id`（可选）：当 scope 为 `single_function` 时可引用其上游 business flow

## 目标范围（必填）
- **主要文件（Primary）**：列出将被重点打开/推理的文件（`file[:line]`）
- **次要文件（Secondary）**：列出辅助上下文文件（允许更少）
- **主要函数（Primary）**：入口处理器/关键 sink 前的最后校验函数
- **次要函数（Secondary）**：中间传播器/净化器/状态机转换函数

## 使用的 Checklist（必填）
- `checks`: 从 `audit_checklists.json` 中选取的若干 `check_id`
- `evidence_hints`: 模式/证据提示（例如需要寻找的函数名片段、变量名、调用 API）
- `expected_sanitizers`: 期望出现的净化器/验证函数名称（如果没出现，要记录为不确定或发现）

## 扫描方法（必填）
1. **business flow（中间粒度）定位（仅当 scope 含 business flow）**
   - 先确认入口候选来自 `audit_project_map.json.entry_candidates`
   - 再沿调用图/调用名近似关系找到关键 sink/状态变更点（只需要“关键路径与关键节点”，不展开到单函数完整证据链）
2. **single function 精审**
   - 对选中的主要函数与次要函数：检查输入验证、净化、鉴权门控、错误处理、边界条件
   - 产出 source -> sink 结构化数据流证据

## 终止信号（Termination Conditions）（必填）
- `stop_conditions`: 逐条列出“达到某证据后立即停止继续向下扩展”
- 典型 stop condition：
  - “已证明 entry_candidate -> key sink 的准调用链存在，且关键字段已完成长度/mandatory 校验”
  - “已证明关键状态变更发生之前的鉴权/所有权校验存在且有效”
  - “继续扩展函数不会增加新的 sink/净化器候选”

## 输出（供 executor 消费）
- `findings_placeholder`: 发现列表占位（executor 填充）
- `uncertainties_placeholder`: 不确定点占位（executor 填充）

---

执行时请严格遵守模板字段，不要随意更改字段名称。


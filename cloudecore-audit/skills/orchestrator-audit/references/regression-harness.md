# Must-Cover Regression Harness

用于验证并行 must-cover 层不会出现召回退化。

## 基线数据

每次流水线执行后至少记录以下指标：

- `FILE_OPS.findings_total`
- `SQLI.findings_total`
- `GO_RUNTIME.findings_total`
- `must_audit_dir_coverage`
- `patterns_loaded_vs_executed_gap`
- `gate_fail_count`
- `trace_call_success_rate`
- `trace_call_empty_rate`
- `trace_call_timeout_rate`
- `trace_downgrade_rate`
- `judge_input_completeness`

## 回归样本要求

最少维护三类可复现样本（可来自内部测试仓库）：

1. `file_ops_sample`：包含路径穿越、Zip Slip、权限过宽至少各 1 个点。
2. `sqli_sample`：包含拼接 SQL、ORM Raw 注入至少各 1 个点。
3. `go_runtime_sample`：包含 panic DoS、资源耗尽、竞态至少各 1 个点。

## 判定规则

- 召回率不得低于上一次基线（允许 `0` 容忍退化）。
- 任一 must-cover 类别 `patterns_executed == 0` 直接失败。
- `must_audit_dir_coverage < 100%` 直接失败。
- `trace_call_success_rate == 0%` 且存在 `sink_candidates` 时直接失败。
- `judge_input_completeness < 100%` 直接失败。

## 失败处理

1. 触发 category + path scoped backfill。
2. 再次执行 Gate-1..5 与 trace 质量检查。
3. 若仍失败，标记本次流水线为 `failed`，禁止输出“完成审计”结论。

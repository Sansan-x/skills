# 审计报告模板与示例

## 1. 完整审计报告模板

```markdown
# Go代码安全审计报告

## 1. 报告信息

| 项目 | 内容 |
|------|------|
| 审计项目 | [项目名称] |
| 项目地址 | [仓库URL] |
| 审计版本 | [commit hash / tag] |
| 审计时间 | [开始日期] - [结束日期] |
| 审计范围 | [描述审计的代码范围] |
| 审计方法 | 自动化扫描 + 模式匹配 + 数据流分析 + 业务逻辑审计 |
| 审计工具 | govulncheck, gosec, staticcheck, go-vuln-lib |
| 审计人员 | [人员列表] |
| 报告版本 | v1.0 |
| 密级 | [公开/内部/机密] |

## 2. 执行摘要

### 2.1 整体评估

[项目名称]是一个[项目描述]。本次审计覆盖了[审计范围描述]，共审计Go代码[X]行。

**整体安全评估**: [优秀/良好/一般/需要改进/存在严重风险]

### 2.2 关键发现统计

| 严重程度 | 数量 | 已修复 | 待修复 |
|---------|------|--------|--------|
| 严重(Critical) | X | X | X |
| 高危(High) | X | X | X |
| 中危(Medium) | X | X | X |
| 低危(Low) | X | X | X |
| 信息(Info) | X | - | - |
| **总计** | **X** | **X** | **X** |

### 2.3 高优先级建议

1. **[最紧急的修复建议]**
2. **[第二紧急的建议]**
3. **[第三紧急的建议]**

## 3. 项目架构分析

### 3.1 项目概况
[项目架构描述，组件关系]

### 3.2 技术栈
[使用的框架、库、中间件]

### 3.3 攻击面分析
[外部接口、输入点、信任边界]

## 4. 漏洞详情

---

### VULN-001: [漏洞标题]

| 属性 | 值 |
|------|---|
| 严重性 | **CRITICAL** |
| CVSS | 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| 类型 | [漏洞类型] |
| CWE | CWE-XXX |
| 位置 | `pkg/file.go:42` |
| 函数 | `FunctionName()` |
| 攻击模式 | AP-GO-XXXX |
| 状态 | 待修复 |

**描述**:
[详细描述漏洞是什么，存在于哪里]

**根因分析**:
[分析漏洞产生的根本原因]

**数据流**:
```
[Source] → [传播路径] → [Sink]
具体的数据流追踪记录
```

**漏洞代码**:
```go
// file.go:40-48
func VulnerableFunction(input string) error {
    // 第42行: 漏洞所在位置
    query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", input) // ← 漏洞
    _, err := db.Query(query)
    return err
}
```

**影响**:
[成功利用此漏洞的安全影响]

**利用条件**:
[触发此漏洞需要的前提条件]

**修复建议**:
```go
func SecureFunction(input string) error {
    query := "SELECT * FROM users WHERE id = ?"
    _, err := db.Query(query, input) // 使用参数化查询
    return err
}
```

**修复优先级**: P0 - 立即修复
**修复工作量**: 低（约30分钟）

---

[更多漏洞使用相同格式]

## 5. 攻击链分析

### 攻击链1: [攻击链名称]

**涉及漏洞**: VULN-001 + VULN-003

**攻击路径**:
```
步骤1: 利用VULN-001获取[xxx]
  ↓
步骤2: 使用步骤1的结果利用VULN-003实现[xxx]
  ↓
最终影响: [xxx]
```

**组合严重性**: CRITICAL

**阻断建议**: 修复VULN-001即可阻断整条攻击链

## 6. 5GC安全评估（如适用）

### 6.1 3GPP合规性

| 规范 | 条款 | 合规状态 | 说明 |
|------|------|---------|------|
| TS 33.501 | 6.1 | 合规 | 认证机制正确实现 |
| TS 33.501 | 9.2 | 不合规 | NAS安全模式可被降级 |

### 6.2 NF安全评估

[按NF类型的安全评估结果]

### 6.3 5GC风险矩阵

| 风险场景 | 攻击复杂度 | 影响范围 | 风险等级 |
|---------|-----------|---------|---------|
| [场景1] | 低 | 全网 | 极高 |
| [场景2] | 高 | 单用户 | 中 |

## 7. 修复建议优先级总表

| 优先级 | 漏洞 | 修复时限 | 负责人 |
|--------|------|---------|--------|
| P0 | VULN-001, VULN-003 | 24小时内 | [待分配] |
| P1 | VULN-002, VULN-005 | 1周内 | [待分配] |
| P2 | VULN-004, VULN-006 | 1个月内 | [待分配] |
| P3 | VULN-007 | 下个版本 | [待分配] |

## 8. 审计方法与工具

### 8.1 自动化工具结果摘要
[各工具扫描结果统计]

### 8.2 攻击模式匹配统计
[从go-vuln-lib匹配到的模式统计]

### 8.3 手动审计覆盖
[手动审计的范围和深度]

## 附录

### A. 工具扫描原始结果
### B. 使用的攻击模式列表
### C. 数据流追踪完整记录
### D. 术语表
### E. 修订历史
```

## 2. 管理层摘要模板

```markdown
# [项目名称] 安全审计 — 管理层摘要

## 审计概况
对[项目名称]进行了全面的代码安全审计。审计范围覆盖[X]行Go代码。

## 核心发现
- 发现 **[X]** 个安全漏洞（严重[X]、高危[X]、中危[X]、低危[X]）
- 识别 **[X]** 条攻击链
- 最高风险：[简述最高风险]

## 整体安全评级: [评级]

## 需要立即行动的事项
1. [最紧急事项]
2. [次紧急事项]
3. [第三紧急事项]

## 修复工作量评估
[简要描述修复工作的整体规模]

## 建议的后续行动
1. 立即修复P0级漏洞
2. [其他建议]
```

## 3. vulnerabilities.json 格式

```json
{
  "report_version": "1.0",
  "project": "项目名称",
  "audit_date": "2024-01-01",
  "commit": "abc123",
  "summary": {
    "total": 7,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "attack_chains": 2
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "漏洞标题",
      "severity": "CRITICAL",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/...",
      "type": "SQL Injection",
      "cwe": "CWE-89",
      "attack_pattern": "AP-GO-0301",
      "location": {
        "file": "pkg/api/user.go",
        "line": 42,
        "function": "GetUser",
        "package": "github.com/example/pkg/api"
      },
      "description": "漏洞描述",
      "root_cause": "根因",
      "impact": "影响",
      "data_flow": "source → ... → sink",
      "remediation": "修复建议",
      "priority": "P0",
      "effort": "LOW",
      "status": "open",
      "5gc_context": {
        "applicable": true,
        "adjusted_severity": "CRITICAL",
        "nf_type": "AMF",
        "interface": "N1"
      }
    }
  ],
  "attack_chains": [
    {
      "id": "CHAIN-001",
      "name": "攻击链名称",
      "vulnerabilities": ["VULN-001", "VULN-003"],
      "combined_severity": "CRITICAL",
      "description": "攻击链描述",
      "mitigation": "阻断建议"
    }
  ]
}
```

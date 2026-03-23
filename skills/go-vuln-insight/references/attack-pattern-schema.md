# 攻击模式JSON Schema定义

本文档定义了 `attack-patterns.json` 的输出格式，供 go-vuln-lib 技能导入使用。

## 顶层结构

```json
{
  "schema_version": "1.0",
  "generated_at": "2024-01-01T00:00:00Z",
  "source": "go-vuln-insight",
  "analysis_scope": "分析范围描述",
  "patterns": [
    { "...攻击模式对象..." }
  ],
  "metadata": {
    "total_patterns": 0,
    "total_cves_analyzed": 0,
    "category_distribution": {}
  }
}
```

## 攻击模式对象

```json
{
  "id": "AP-GO-0001",
  "name": "未检查的类型断言导致panic",
  "version": "1.0",
  "category": "type_safety",
  "subcategory": "type_assertion",
  "severity": "HIGH",
  "cvss_range": "7.0-9.0",
  
  "description": "攻击模式的详细描述文本",
  
  "go_features": ["interface", "type_assertion"],
  
  "preconditions": [
    "函数接受interface{}类型参数",
    "攻击者可控制传入的具体类型"
  ],
  
  "vulnerable_pattern": {
    "code": "value := input.(TargetType) // 无ok检查",
    "ast_pattern": "TypeAssertExpr without comma-ok",
    "explanation": "单值类型断言在类型不匹配时触发panic，若输入可被外部控制则可导致DoS"
  },
  
  "secure_pattern": {
    "code": "value, ok := input.(TargetType)\nif !ok {\n    return fmt.Errorf(\"unexpected type: %T\", input)\n}",
    "explanation": "使用comma-ok模式进行类型断言，类型不匹配时通过error处理而非panic"
  },
  
  "detection": {
    "static_analysis": {
      "method": "AST遍历查找TypeAssertExpr节点，检查是否使用comma-ok形式",
      "tools": ["go/ast", "golang.org/x/tools/go/analysis"],
      "false_positive_rate": "low"
    },
    "grep_patterns": [
      "\\w+\\.\\(\\w+\\)\\s*$",
      "\\w+ := \\w+\\.\\(\\w+\\)\\s*$"
    ],
    "code_review_clues": [
      "函数参数中出现interface{}",
      "类型断言不在if语句的初始化部分"
    ]
  },
  
  "real_world_examples": [
    {
      "cve": "CVE-YYYY-XXXX",
      "ghsa": "GHSA-xxxx-xxxx-xxxx",
      "project": "github.com/example/project",
      "affected_versions": "<1.2.3",
      "fixed_version": "1.2.3",
      "description": "具体漏洞描述",
      "commit_url": "https://github.com/example/project/commit/abc123",
      "impact": "远程DoS"
    }
  ],
  
  "severity_context": {
    "base": "MEDIUM",
    "amplifiers": [
      {
        "context": "5GC控制面NF",
        "amplified_severity": "CRITICAL",
        "reason": "控制面NF崩溃可能导致大面积用户服务中断"
      },
      {
        "context": "处理外部网络输入的组件",
        "amplified_severity": "HIGH",
        "reason": "攻击者可从网络直接触发"
      }
    ]
  },
  
  "related_patterns": ["AP-GO-0002", "AP-GO-0015"],
  
  "tags": ["dos", "panic", "type-safety", "interface"],
  
  "references": [
    "https://go.dev/doc/effective_go#type_switch",
    "https://cwe.mitre.org/data/definitions/CWE-ID.html"
  ],
  
  "created_at": "2024-01-01",
  "updated_at": "2024-01-01",
  "source_reports": ["insight-report-001.md"]
}
```

## 类别枚举

| category值 | 描述 | 典型CWE |
|------------|------|---------|
| `input_validation` | 输入验证缺陷 | CWE-20, CWE-89, CWE-79 |
| `type_safety` | 类型安全问题 | CWE-843, CWE-704 |
| `concurrency` | 并发安全问题 | CWE-362, CWE-367 |
| `memory_safety` | 内存安全问题 | CWE-119, CWE-416 |
| `crypto_misuse` | 密码学误用 | CWE-327, CWE-330 |
| `auth_authz` | 认证授权缺陷 | CWE-287, CWE-862 |
| `resource_mgmt` | 资源管理问题 | CWE-400, CWE-770 |
| `error_handling` | 错误处理缺陷 | CWE-755, CWE-252 |
| `injection` | 注入类漏洞 | CWE-77, CWE-78, CWE-94 |
| `path_traversal` | 路径遍历 | CWE-22 |
| `ssrf` | 服务端请求伪造 | CWE-918 |
| `deserialization` | 反序列化问题 | CWE-502 |
| `protocol_parsing` | 协议解析缺陷 | CWE-20, CWE-125 |
| `config_exposure` | 配置与信息泄露 | CWE-200, CWE-532 |

## 严重性等级

| severity值 | 含义 | CVSS参考 |
|-----------|------|---------|
| `CRITICAL` | 远程代码执行或认证绕过 | 9.0-10.0 |
| `HIGH` | 远程DoS或敏感信息泄露 | 7.0-8.9 |
| `MEDIUM` | 需要特定条件触发的安全问题 | 4.0-6.9 |
| `LOW` | 信息泄露或需要本地权限 | 0.1-3.9 |

## vuln-summary.json 格式

```json
{
  "schema_version": "1.0",
  "generated_at": "2024-01-01T00:00:00Z",
  "scope": "分析范围",
  "summary": {
    "total_vulns": 0,
    "by_severity": { "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0 },
    "by_category": {},
    "by_year": {},
    "top_affected_packages": []
  },
  "vulnerabilities": [
    {
      "id": "CVE-YYYY-XXXX",
      "package": "github.com/example/module",
      "severity": "HIGH",
      "category": "concurrency",
      "summary": "简要描述",
      "affected_versions": "<1.0.0",
      "fixed_version": "1.0.0",
      "attack_patterns_extracted": ["AP-GO-0001"]
    }
  ]
}
```

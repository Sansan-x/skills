# 攻击模式完整Schema定义

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Go Attack Pattern",
  "type": "object",
  "required": ["id", "name", "category", "description", "vulnerable_patterns", "secure_patterns", "detection", "severity"],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^AP-GO-[0-9]{4}$",
      "description": "唯一标识符，格式为 AP-GO-XXXX"
    },
    "name": {
      "type": "string",
      "maxLength": 100,
      "description": "模式中文名称"
    },
    "name_en": {
      "type": "string",
      "maxLength": 100,
      "description": "模式英文名称"
    },
    "version": {
      "type": "string",
      "pattern": "^[0-9]+\\.[0-9]+$",
      "description": "模式版本号"
    },
    "status": {
      "type": "string",
      "enum": ["active", "deprecated", "draft"],
      "default": "draft"
    },
    "category": {
      "type": "string",
      "enum": [
        "input_validation", "type_safety", "concurrency", "memory_safety",
        "crypto_misuse", "auth_authz", "resource_mgmt", "error_handling",
        "injection", "path_traversal", "ssrf", "deserialization",
        "protocol_parsing", "config_exposure"
      ]
    },
    "subcategory": {
      "type": "string",
      "description": "二级分类，类别内自定义"
    },
    "cwe_ids": {
      "type": "array",
      "items": { "type": "string", "pattern": "^CWE-[0-9]+$" }
    },
    "capec_ids": {
      "type": "array",
      "items": { "type": "string", "pattern": "^CAPEC-[0-9]+$" }
    },
    "go_features": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": [
          "goroutine", "channel", "interface", "type_assertion",
          "defer", "panic_recover", "unsafe", "reflect",
          "cgo", "generics", "slice", "map",
          "error_handling", "http", "context", "io",
          "encoding_json", "encoding_xml", "crypto",
          "os_exec", "filepath", "net", "database_sql",
          "shared_variable", "sync", "atomic"
        ]
      }
    },
    "description": {
      "type": "string",
      "minLength": 50,
      "description": "详细的漏洞模式描述"
    },
    "preconditions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "impact": {
      "type": "object",
      "properties": {
        "confidentiality": { "enum": ["HIGH", "MEDIUM", "LOW", "NONE"] },
        "integrity": { "enum": ["HIGH", "MEDIUM", "LOW", "NONE"] },
        "availability": { "enum": ["HIGH", "MEDIUM", "LOW", "NONE"] }
      }
    },
    "vulnerable_patterns": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["code", "explanation"],
        "properties": {
          "code": { "type": "string" },
          "explanation": { "type": "string" },
          "context": { "type": "string" }
        }
      }
    },
    "secure_patterns": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["code", "explanation"],
        "properties": {
          "code": { "type": "string" },
          "explanation": { "type": "string" },
          "trade_offs": { "type": "string" }
        }
      }
    },
    "detection": {
      "type": "object",
      "properties": {
        "static_analysis": {
          "type": "object",
          "properties": {
            "ast_patterns": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "description": { "type": "string" },
                  "pattern": { "type": "string" }
                }
              }
            },
            "ssa_patterns": {
              "type": "array",
              "items": {
                "type": "object",
                "properties": {
                  "description": { "type": "string" },
                  "pattern": { "type": "string" }
                }
              }
            }
          }
        },
        "grep_patterns": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["pattern"],
            "properties": {
              "pattern": { "type": "string" },
              "description": { "type": "string" },
              "false_positive_rate": { "enum": ["HIGH", "MEDIUM", "LOW"] }
            }
          }
        },
        "taint_rules": {
          "type": "object",
          "properties": {
            "sources": { "type": "array", "items": { "type": "string" } },
            "sinks": { "type": "array", "items": { "type": "string" } },
            "sanitizers": { "type": "array", "items": { "type": "string" } }
          }
        },
        "review_clues": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "testing": {
      "type": "object",
      "properties": {
        "test_strategy": { "type": "string" },
        "poc_template": { "type": "string" },
        "fuzzing_hints": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "severity": {
      "type": "object",
      "required": ["base"],
      "properties": {
        "base": { "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
        "cvss_vector": { "type": "string" },
        "context_adjustments": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "context": { "type": "string" },
              "adjusted_severity": { "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
              "reason": { "type": "string" }
            }
          }
        }
      }
    },
    "evidence": {
      "type": "object",
      "properties": {
        "cves": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "id": { "type": "string" },
              "project": { "type": "string" },
              "description": { "type": "string" },
              "commit": { "type": "string" }
            }
          }
        },
        "research_refs": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "relationships": {
      "type": "object",
      "properties": {
        "related": { "type": "array", "items": { "type": "string" } },
        "prerequisite": { "type": "array", "items": { "type": "string" } },
        "chain_with": { "type": "array", "items": { "type": "string" } }
      }
    },
    "metadata": {
      "type": "object",
      "properties": {
        "created_at": { "type": "string", "format": "date" },
        "updated_at": { "type": "string", "format": "date" },
        "quality_score": { "type": "number", "minimum": 0, "maximum": 1 },
        "source": { "type": "string" },
        "tags": { "type": "array", "items": { "type": "string" } }
      }
    }
  }
}
```

## ID分配规则

| ID范围 | 分配给 |
|--------|-------|
| AP-GO-0001 ~ AP-GO-0099 | type_safety（类型安全） |
| AP-GO-0100 ~ AP-GO-0199 | concurrency（并发安全） |
| AP-GO-0200 ~ AP-GO-0299 | input_validation（输入验证） |
| AP-GO-0300 ~ AP-GO-0399 | injection（注入类） |
| AP-GO-0400 ~ AP-GO-0499 | auth_authz（认证授权） |
| AP-GO-0500 ~ AP-GO-0599 | crypto_misuse（密码学误用） |
| AP-GO-0600 ~ AP-GO-0699 | error_handling（错误处理） |
| AP-GO-0700 ~ AP-GO-0799 | resource_mgmt（资源管理） |
| AP-GO-0800 ~ AP-GO-0899 | memory_safety（内存安全） |
| AP-GO-0900 ~ AP-GO-0999 | protocol_parsing（协议解析） |
| AP-GO-1000 ~ AP-GO-1099 | path_traversal / ssrf / deserialization |
| AP-GO-1100 ~ AP-GO-1199 | config_exposure |
| AP-GO-2000 ~ AP-GO-2999 | 5gc_specific（5GC特定模式） |

## index.json 全局索引格式

```json
{
  "schema_version": "1.0",
  "updated_at": "2024-01-01T00:00:00Z",
  "total_patterns": 0,
  "patterns": [
    {
      "id": "AP-GO-0001",
      "name": "模式名称",
      "category": "type_safety",
      "severity": "HIGH",
      "status": "active",
      "quality_score": 0.85,
      "file_path": "type-safety/type-assertion-panic.yaml",
      "tags": ["dos", "panic"],
      "go_features": ["interface", "type_assertion"],
      "cwe_ids": ["CWE-843"]
    }
  ],
  "statistics": {
    "by_category": {},
    "by_severity": {},
    "by_status": {},
    "avg_quality_score": 0.0
  }
}
```

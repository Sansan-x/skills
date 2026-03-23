---
name: go-vuln-lib
description: Go语言攻击模式库的构建与管理技能。从多种来源（go-vuln-insight洞察报告、安全测试指导文档、专家漏洞案例、CVE数据库）收集并提取Go攻击模式，结构化存储为包含漏洞描述、测试方法、漏洞模式（典型脆弱代码案例）和安全模式的攻击模式库。当用户需要构建或维护Go攻击模式库、从漏洞报告中提取可复用模式、管理和查询安全审计规则库、或需要为go-audit提供攻击模式数据时使用此技能。
---

# Go攻击模式库构建与管理

系统化地从多种来源收集、提取、结构化存储和管理Go语言的攻击模式，形成可查询、可复用的攻击模式知识库，为go-audit代码审计提供模式匹配基础。

## 核心概念

**攻击模式（Attack Pattern）** 是对一类安全漏洞的抽象化描述，包含：
- 该类漏洞在Go代码中的典型表现形式（脆弱模式）
- 对应的安全编码方式（安全模式）
- 用于自动化检测的匹配策略
- 严重性评估与上下文调整因子

攻击模式库是这些模式的结构化集合，支持按类别、严重性、Go语言特性、适用场景等维度进行检索。

## 工作流程

```
数据源 → 模式提取 → 结构化 → 质量审核 → 入库 → 索引与检索
  │                                              │
  ├─ go-vuln-insight报告                          ├─ 供go-audit使用
  ├─ 安全测试指导文档                               ├─ 供安全培训使用
  ├─ 专家漏洞案例                                  └─ 供规则维护使用
  ├─ CVE/GHSA数据库
  └─ 代码审计实战经验
```

## 第一阶段：数据源接入与模式提取

### 1.1 从go-vuln-insight导入

读取go-vuln-insight生成的 `attack-patterns.json` 文件，执行以下处理：

1. **Schema验证**：检查输入是否符合 `references/pattern-schema.md` 定义的格式
2. **去重检查**：基于漏洞模式代码的语义相似度判断是否为已有模式的变体
3. **元数据补全**：补充缺失的CWE映射、CAPEC映射、5GC上下文评估
4. **质量评分**：根据完整度和证据强度评分

```
导入命令示例：
输入: attack-patterns.json（来自go-vuln-insight）
处理: 验证 → 去重 → 补全 → 评分
输出: 更新后的模式库
```

### 1.2 从安全测试指导文档提取

从安全编码标准和测试指导文档中提取模式：

**支持的文档类型**：
- OWASP Go安全编码指南
- CIS Go语言安全基准
- NIST安全开发框架（SSDF）Go实践
- 3GPP TS 33.501/33.117 安全测试规范（5GC相关）
- 企业内部安全编码规范

**提取策略**：
1. 识别文档中的安全规则和反模式描述
2. 将自然语言规则转化为Go代码级的脆弱模式和安全模式
3. 生成对应的检测策略（grep pattern / AST pattern / 数据流规则）
4. 标注规则来源和合规性映射

### 1.3 从专家漏洞案例提取

处理安全研究员提交的具体漏洞案例：

**输入格式**：
```yaml
expert_case:
  title: "案例标题"
  submitter: "提交者"
  project: "漏洞所在项目"
  vuln_code: |
    // 漏洞代码片段
  fix_code: |
    // 修复后的代码
  analysis: "漏洞分析说明"
  category: "漏洞类别"
  5gc_relevance: "与5GC的关联说明（可选）"
```

**处理流程**：
1. 从具体案例中抽象出通用攻击模式
2. 去除项目特定的上下文，保留可迁移的模式特征
3. 验证抽象后的模式仍能匹配原始案例
4. 生成对应的检测规则

### 1.4 从CVE/GHSA数据库批量提取

自动化处理大量CVE/GHSA条目：

1. 批量获取Go生态的新CVE/GHSA
2. 对每个条目尝试自动提取攻击模式
3. 对于无法自动提取的（如缺少代码patch），标记为"待人工分析"
4. 与已有模式库比对，识别新模式vs已有模式的新变体

## 第二阶段：模式结构化存储

### 2.1 攻击模式完整结构

每个攻击模式包含以下字段（详见 `references/pattern-schema.md`）：

```yaml
attack_pattern:
  # ===== 标识信息 =====
  id: "AP-GO-XXXX"           # 唯一标识符
  name: "模式名称"            # 简明的中文名称
  name_en: "Pattern Name"    # 英文名称（用于关联外部数据）
  version: "1.0"             # 模式版本
  status: "active"           # active/deprecated/draft
  
  # ===== 分类信息 =====
  category: "concurrency"    # 一级分类
  subcategory: "data_race"   # 二级分类
  cwe_ids: ["CWE-362"]       # CWE映射
  capec_ids: ["CAPEC-26"]    # CAPEC映射
  owasp_category: ""         # OWASP映射（如适用）
  
  # ===== Go语言特征 =====
  go_features:               # 涉及的Go语言特性
    - "goroutine"
    - "shared_variable"
  go_min_version: ""         # 受影响的最低Go版本（如适用）
  go_fixed_version: ""       # 已在Go新版本中修复（如适用）
  
  # ===== 漏洞描述 =====
  description: |
    详细的漏洞模式描述，包括：
    - 漏洞产生的根本原因
    - 攻击者如何利用此模式
    - 造成的安全影响
  
  preconditions:
    - "触发条件1"
    - "触发条件2"
  
  impact:
    confidentiality: "HIGH/MEDIUM/LOW/NONE"
    integrity: "HIGH/MEDIUM/LOW/NONE"
    availability: "HIGH/MEDIUM/LOW/NONE"
  
  # ===== 漏洞模式（脆弱代码） =====
  vulnerable_patterns:
    - code: |
        // 脆弱代码示例1
      explanation: "解释为何此代码不安全"
      context: "此模式出现的典型上下文"
    - code: |
        // 脆弱代码变体2
      explanation: "变体说明"
      context: "变体出现的上下文"
  
  # ===== 安全模式（修复代码） =====
  secure_patterns:
    - code: |
        // 安全代码示例
      explanation: "安全模式如何消除风险"
      trade_offs: "安全模式可能带来的性能或复杂度影响"
  
  # ===== 检测方法 =====
  detection:
    # 静态分析检测
    static_analysis:
      ast_patterns:
        - description: "AST匹配描述"
          pattern: "go/ast节点匹配规则"
      ssa_patterns:
        - description: "SSA分析规则"
          pattern: "SSA指令匹配描述"
    
    # 正则搜索（快速初筛）
    grep_patterns:
      - pattern: "正则表达式"
        description: "匹配说明"
        false_positive_rate: "HIGH/MEDIUM/LOW"
    
    # 污点分析规则
    taint_rules:
      sources:
        - "污点源描述（如：http.Request.Body）"
      sinks:
        - "汇聚点描述（如：exec.Command参数）"
      sanitizers:
        - "净化函数描述（如：strconv.Atoi转换）"
    
    # 代码审计线索
    review_clues:
      - "人工审计时的关键线索"
  
  # ===== 测试方法 =====
  testing:
    test_strategy: "如何编写测试验证此漏洞是否存在"
    poc_template: |
      // PoC代码模板
    fuzzing_hints:
      - "模糊测试的输入构造建议"
  
  # ===== 严重性评估 =====
  severity:
    base: "HIGH"
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    context_adjustments:
      - context: "5GC控制面"
        adjusted_severity: "CRITICAL"
        reason: "控制面NF崩溃影响全网用户"
      - context: "内部工具"
        adjusted_severity: "LOW"
        reason: "攻击面受限"
  
  # ===== 真实案例 =====
  evidence:
    cves:
      - id: "CVE-YYYY-XXXX"
        project: "项目名"
        description: "简述"
        commit: "修复commit URL"
    research_refs:
      - "安全研究论文或博客URL"
  
  # ===== 关联关系 =====
  relationships:
    related: ["AP-GO-XXXX"]      # 相关模式
    prerequisite: ["AP-GO-XXXX"] # 前置模式
    chain_with: ["AP-GO-XXXX"]   # 可组合攻击链
  
  # ===== 元信息 =====
  metadata:
    created_at: "2024-01-01"
    updated_at: "2024-01-01"
    quality_score: 0.85          # 0-1，基于完整度和证据强度
    source: "go-vuln-insight"    # 来源
    tags: ["5gc", "protocol", "dos"]
```

### 2.2 模式库文件组织

```
go-vuln-lib/
├── SKILL.md
├── references/
│   ├── pattern-schema.md        # 模式完整schema定义
│   ├── category-taxonomy.md     # 分类体系说明
│   └── 5gc-context.md           # 5GC上下文严重性调整规则
└── library/                     # 攻击模式库（按类别组织）
    ├── index.json               # 全局索引
    ├── input-validation/
    │   ├── sql-injection.yaml
    │   ├── command-injection.yaml
    │   ├── path-traversal.yaml
    │   └── ssrf.yaml
    ├── concurrency/
    │   ├── data-race.yaml
    │   ├── goroutine-leak.yaml
    │   └── channel-misuse.yaml
    ├── type-safety/
    │   ├── type-assertion-panic.yaml
    │   ├── integer-overflow.yaml
    │   └── unsafe-pointer.yaml
    ├── crypto-misuse/
    │   ├── weak-random.yaml
    │   ├── insecure-tls.yaml
    │   └── hardcoded-secret.yaml
    ├── auth-authz/
    │   ├── auth-bypass.yaml
    │   ├── privilege-escalation.yaml
    │   └── missing-authz.yaml
    ├── error-handling/
    │   ├── ignored-error.yaml
    │   ├── panic-recovery-bypass.yaml
    │   └── error-info-leak.yaml
    ├── resource-mgmt/
    │   ├── resource-exhaustion.yaml
    │   ├── connection-leak.yaml
    │   └── unbounded-allocation.yaml
    ├── protocol-parsing/
    │   ├── length-field-overflow.yaml
    │   ├── malformed-message.yaml
    │   └── state-machine-confusion.yaml
    └── 5gc-specific/
        ├── sbi-injection.yaml
        ├── nas-decode-overflow.yaml
        ├── gtp-tunnel-hijack.yaml
        ├── nrf-spoofing.yaml
        └── pfcp-session-manipulation.yaml
```

## 第三阶段：模式库管理操作

### 3.1 添加新模式

**流程**：
1. 接收新模式数据（来自go-vuln-insight、专家案例或手动创建）
2. 执行schema验证
3. 语义去重：与现有模式比对，判断是新模式还是已有模式的变体
4. 如果是变体，合并到已有模式（添加为vulnerable_patterns的新条目）
5. 如果是新模式，分配ID，确定分类，计算质量评分
6. 更新全局索引

**去重策略**：
- 比较vulnerability pattern的代码结构相似度
- 比较CWE/CAPEC映射
- 比较涉及的Go语言特性
- 相似度超过70%时视为同一模式的变体

### 3.2 更新已有模式

**触发条件**：
- 新CVE出现，属于已有模式的新实例
- 发现已有模式的新变体代码
- 检测规则需要优化（降低误报率或提升覆盖率）
- Go新版本修复了某类问题
- 严重性评估需要调整

**更新流程**：
1. 定位待更新的模式
2. 记录变更原因
3. 更新相应字段
4. 递增版本号
5. 更新updated_at时间戳
6. 重新计算质量评分

### 3.3 查询与检索

支持以下检索维度：

| 查询维度 | 示例 | 用途 |
|---------|------|-----|
| 按类别 | `category:concurrency` | 获取某类所有模式 |
| 按严重性 | `severity:CRITICAL` | 优先审计高危模式 |
| 按Go特性 | `go_features:goroutine` | 审计涉及特定特性的代码 |
| 按CWE | `cwe:CWE-362` | 合规检查 |
| 按标签 | `tags:5gc` | 5GC定向审计 |
| 按质量分 | `quality_score:>0.8` | 获取高质量模式 |
| 关键词搜索 | `search:"type assertion"` | 模糊搜索 |

### 3.4 模式库统计与健康度

定期生成模式库统计报告：

```
模式库健康度报告:
- 总模式数: XX
- 活跃模式: XX / 废弃模式: XX / 草稿模式: XX
- 分类覆盖: XX/14 类别已覆盖
- 平均质量评分: X.XX
- 无CVE证据的模式: XX（需补充）
- 超过6个月未更新的模式: XX（需审查）
- 5GC相关模式: XX
- 检测规则覆盖率: XX%（有grep_pattern）/ XX%（有ast_pattern）/ XX%（有taint_rule）
```

## 第四阶段：模式库质量保证

### 4.1 质量评分算法

```
质量评分 = 权重加权平均(
  完整度评分 × 0.30,     # 各必填字段的填充率
  证据强度评分 × 0.25,   # CVE数量和质量
  检测覆盖率评分 × 0.25, # 检测规则的完备度
  时效性评分 × 0.20      # 最近更新时间
)

完整度评分:
- vulnerable_patterns非空: +0.25
- secure_patterns非空: +0.25
- detection规则非空: +0.25
- testing信息非空: +0.25

证据强度评分:
- 有1+个CVE: +0.4
- 有3+个CVE: +0.7
- 有真实项目代码引用: +0.3

检测覆盖率评分:
- 有grep_pattern: +0.3
- 有ast_pattern: +0.3
- 有taint_rule: +0.4

时效性评分:
- 3个月内更新: 1.0
- 6个月内更新: 0.7
- 1年内更新: 0.4
- 超过1年: 0.2
```

### 4.2 模式验证

对每个模式执行以下验证：

1. **Schema合规性**：所有必填字段存在且格式正确
2. **代码可编译性**：vulnerable_pattern和secure_pattern中的代码片段可编译
3. **模式可区分性**：脆弱模式和安全模式之间存在明确差异
4. **检测规则有效性**：grep_pattern可匹配至少一个vulnerable_pattern
5. **分类一致性**：category/subcategory/CWE三者逻辑一致
6. **5GC标注准确性**：标记为5gc相关的模式确实与5GC场景有关

## 与go-audit的集成接口

go-audit技能通过以下方式消费攻击模式库：

### 按审计场景获取模式

```
请求: 获取适用于"HTTP API服务"审计的攻击模式
响应: 过滤出 category 为 input_validation, auth_authz, ssrf, 
      以及 tags 包含 "http", "api" 的所有模式
```

### 按代码特征获取模式

```
请求: 代码中使用了goroutine和channel，获取相关攻击模式
响应: 过滤出 go_features 包含 "goroutine" 或 "channel" 的所有模式
```

### 按5GC组件获取模式

```
请求: 获取适用于AMF审计的攻击模式
响应: 过滤出 tags 包含 "5gc", "nas", "ngap", "authentication" 
      的所有模式，并将severity按5GC控制面上下文调整
```

### 获取检测规则集

```
请求: 导出所有grep_patterns用于初步代码扫描
响应: 汇总所有模式的grep_patterns，按false_positive_rate排序
```

## 参考文件

- `references/pattern-schema.md` — 攻击模式完整schema定义（含JSON Schema）
- `references/category-taxonomy.md` — 分类体系详细说明
- `references/5gc-context.md` — 5GC上下文严重性评估规则

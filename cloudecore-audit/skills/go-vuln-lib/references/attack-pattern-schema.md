# 攻击模式结构化存储规范

本文档定义Go攻击模式库中每个条目的完整字段结构、数据类型约束和填充规则。

## 目录

1. [字段总览](#1-字段总览)
2. [标识字段](#2-标识字段)
3. [描述字段](#3-描述字段)
4. [测试方法字段](#4-测试方法字段)
5. [漏洞模式字段](#5-漏洞模式字段)
6. [安全模式字段](#6-安全模式字段)
7. [元数据字段](#7-元数据字段)
8. [完整条目示例](#8-完整条目示例)
9. [字段填充优先级](#9-字段填充优先级)

---

## 1. 字段总览

每个攻击模式条目由六个字段组构成：

| 字段组 | 用途 | 必填字段数 |
|--------|------|-----------|
| 标识字段 | 唯一标识和基本分类 | 5 |
| 描述字段 | 漏洞背景和影响说明 | 1（summary） |
| 测试方法字段 | 检测和验证方法 | 0（推荐填充） |
| 漏洞模式字段 | 典型漏洞代码和数据流 | 1（code_example） |
| 安全模式字段 | 修复代码和防御措施 | 1（code_example） |
| 元数据字段 | 管理和追溯信息 | 0（推荐填充） |

---

## 2. 标识字段

### pattern_id（必填）

**类型：** 字符串
**格式：** `GO-ATK-[类别缩写]-[三位序号]`
**示例：** `GO-ATK-SQLI-001`、`GO-ATK-GOLNG-012`

编码规则：
- `GO-ATK` 为固定前缀，表示Go攻击模式
- 类别缩写参见SKILL.md中的类别编码表
- 序号在每个类别内独立递增，从001开始
- 删除条目后序号不复用

### name（必填）

**类型：** 字符串
**长度：** 10-80个字符
**说明：** 简洁、具描述性的模式名称，应当仅看名称即可大致理解模式内容

命名规范：
- 包含漏洞类型关键词
- 包含攻击手段或触发条件
- 中文书写

**示例：**
- `"fmt.Sprintf构建SQL查询导致注入"`
- `"JWT未验证签名算法绕过认证"`
- `"goroutine无限创建导致拒绝服务"`
- `"unsafe.Pointer类型转换内存越界"`

### category（必填）

**类型：** 枚举字符串
**允许值：** `SQL注入` | `命令注入` | `跨站脚本` | `服务端请求伪造` | `路径穿越` | `认证缺陷` | `访问控制缺陷` | `密码学失败` | `反序列化漏洞` | `竞态条件` | `模板注入` | `拒绝服务` | `信息泄露` | `不安全文件操作` | `gRPC安全` | `Go语言特有` | `供应链攻击` | `开放重定向` | `日志注入` | `XML外部实体`

### severity（必填）

**类型：** 枚举字符串
**允许值：** `严重` | `高危` | `中危` | `低危`

评级参考标准（与CVSS对齐）：

| 严重性 | CVSS范围 | 判断标准 |
|--------|---------|---------|
| 严重 | 9.0-10.0 | 远程利用、无需认证、可导致RCE或完整数据泄露 |
| 高危 | 7.0-8.9 | 显著安全影响、中等利用难度 |
| 中危 | 4.0-6.9 | 有限影响或较高利用门槛 |
| 低危 | 0.1-3.9 | 最小影响、难以直接利用 |

### cwe_ids（必填）

**类型：** 字符串数组
**格式：** `["CWE-XXX", ...]`
**说明：** 关联的CWE（Common Weakness Enumeration）编号，至少提供一个

常用CWE编号速查：

| CWE | 漏洞类型 |
|-----|---------|
| CWE-89 | SQL注入 |
| CWE-78 | OS命令注入 |
| CWE-79 | 跨站脚本 |
| CWE-918 | 服务端请求伪造 |
| CWE-22 | 路径穿越 |
| CWE-287 | 认证失败 |
| CWE-862 | 缺失授权 |
| CWE-327 | 弱密码算法 |
| CWE-502 | 不安全反序列化 |
| CWE-362 | 竞态条件 |
| CWE-917 | 表达式语言注入 |
| CWE-400 | 资源耗尽 |
| CWE-200 | 信息暴露 |
| CWE-434 | 不安全文件上传 |
| CWE-843 | 类型混淆 |
| CWE-94 | 代码注入 |

### source_type（必填）

**类型：** 枚举字符串
**允许值：** `vuln-insight` | `codehub-issue` | `security-guide` | `expert-case` | `mixed`

当条目信息从多个来源合并时，使用 `mixed`。

### source_ref（推荐）

**类型：** 字符串
**说明：** 来源引用，指向来源注册表中的来源ID或直接描述

**示例：** `"SRC-001: myproject-vuln-insight-20260315.md"` 或 `"专家案例: CVE-2024-XXXX分析"`

---

## 3. 描述字段

### description.summary（必填）

**类型：** 字符串
**长度：** 20-200个字符
**说明：** 一句话概要，说明什么条件下产生什么安全问题

**示例：** `"当Go Web应用使用fmt.Sprintf拼接用户输入到SQL查询时，攻击者可注入恶意SQL语句读取或修改数据库"`

### description.background（推荐）

**类型：** 字符串（Markdown格式）
**说明：** 漏洞背景与原理的详细阐述，包括：
- 为什么这种模式是不安全的
- Go语言环境下的特殊性
- 与其他语言的差异（如有）
- 历史上的典型案例

### description.impact（推荐）

**类型：** 字符串
**说明：** 漏洞被成功利用后的安全影响，按CIA三要素描述：
- 机密性影响
- 完整性影响
- 可用性影响

### description.preconditions（推荐）

**类型：** 字符串数组
**说明：** 漏洞触发的前置条件列表

**示例：**
```yaml
preconditions:
  - "应用使用database/sql或GORM等ORM框架"
  - "用户输入直接或间接到达SQL查询构建"
  - "未使用参数化查询或预编译语句"
```

---

## 4. 测试方法字段

### test_method.strategy（推荐）

**类型：** 字符串
**说明：** 总体测试策略描述

**示例：** `"通过在所有用户输入点注入SQL特殊字符（单引号、双横线、UNION SELECT），观察应用响应差异来判断是否存在SQL注入"`

### test_method.detection_points（推荐）

**类型：** 字符串数组
**说明：** 代码审计中应关注的检测点

**示例：**
```yaml
detection_points:
  - "搜索fmt.Sprintf与SQL关键词的组合使用"
  - "搜索字符串拼接（+运算符）与db.Query/db.Exec的组合"
  - "检查GORM的Raw()和Where()方法参数来源"
  - "检查ORDER BY子句是否接受用户输入"
```

### test_method.test_steps（推荐）

**类型：** 字符串数组
**说明：** 具体测试步骤，按顺序执行

### test_method.tools（可选）

**类型：** 字符串数组
**说明：** 适用于此模式检测的工具

**示例：** `["gosec", "semgrep", "sqlmap", "govulncheck"]`

### test_method.automation_hint（可选）

**类型：** 字符串
**说明：** 自动化测试的提示信息，如正则表达式、semgrep规则ID、gosec规则编号

**示例：** `"gosec规则G201(SQL查询构造); semgrep规则 go.lang.security.audit.sqli.tainted-sql-string"`

---

## 5. 漏洞模式字段

### vuln_pattern.code_example（必填）

**类型：** 字符串（Go代码，Markdown代码块格式）
**说明：** 包含漏洞的典型Go代码示例

代码示例规范：
- 必须是语法上有效的Go代码（至少是函数级别的代码段）
- 包含必要的import语句
- 用注释标注漏洞行和漏洞原因
- 包含足够的上下文使读者无需其他代码即可理解
- 标注假设的文件路径

**示例：**
````markdown
```go
// 文件: pkg/handler/search.go
// 漏洞: 用户输入通过fmt.Sprintf直接拼接到SQL查询中
func SearchHandler(c *gin.Context) {
    keyword := c.Query("q")                    // SOURCE: 用户输入
    query := fmt.Sprintf(
        "SELECT * FROM products WHERE name LIKE '%%%s%%'",
        keyword,
    )
    rows, err := db.Query(query)               // SINK: 拼接的SQL执行
    if err != nil {
        c.JSON(500, gin.H{"error": "查询失败"})
        return
    }
    defer rows.Close()
    // ... 处理结果
}
```
````

### vuln_pattern.sink_functions（推荐）

**类型：** 字符串数组
**说明：** 此模式涉及的Sink函数（危险API）

**示例：** `["db.Query", "db.Exec", "db.QueryRow", "gorm.DB.Raw", "gorm.DB.Where"]`

### vuln_pattern.source_types（推荐）

**类型：** 字符串数组
**说明：** 可能的污点源类型

**示例：** `["HTTP查询参数", "HTTP请求体", "URL路径参数", "HTTP头", "Cookie"]`

### vuln_pattern.dataflow（推荐）

**类型：** 字符串
**说明：** Source → Sink 的数据流描述，使用箭头表示

**示例：** `"c.Query('q') → fmt.Sprintf(query, keyword) → db.Query(query)"`

### vuln_pattern.trigger_conditions（推荐）

**类型：** 字符串数组
**说明：** 漏洞实际触发的具体条件

**示例：**
```yaml
trigger_conditions:
  - "输入包含SQL特殊字符（', \", --, ;, UNION）"
  - "输入未经白名单校验或转义处理"
  - "数据库用户拥有足够的查询权限"
```

---

## 6. 安全模式字段

### safe_pattern.code_example（必填）

**类型：** 字符串（Go代码，Markdown代码块格式）
**说明：** 修复漏洞后的安全Go代码，与 `vuln_pattern.code_example` 形成对比

代码示例规范：
- 解决 `vuln_pattern.code_example` 中展示的安全问题
- 用注释说明修复点
- 展示具体的安全API使用方式

**示例：**
````markdown
```go
// 文件: pkg/handler/search.go
// 修复: 使用参数化查询替代字符串拼接
func SearchHandler(c *gin.Context) {
    keyword := c.Query("q")
    // 使用参数化查询，数据库驱动自动处理转义
    rows, err := db.Query(
        "SELECT * FROM products WHERE name LIKE $1",
        "%"+keyword+"%",                       // 安全: 作为参数传递
    )
    if err != nil {
        c.JSON(500, gin.H{"error": "查询失败"})
        return
    }
    defer rows.Close()
    // ... 处理结果
}
```
````

### safe_pattern.fix_strategy（推荐）

**类型：** 字符串
**说明：** 修复策略的文字描述

**示例：** `"使用参数化查询（$1占位符）替代fmt.Sprintf字符串拼接，使用户输入作为数据参数而非SQL代码的一部分"`

### safe_pattern.defense_layers（推荐）

**类型：** 字符串数组
**说明：** 纵深防御措施，超越直接修复的额外安全层

**示例：**
```yaml
defense_layers:
  - "使用ORM框架的安全查询方法（如GORM的Where占位符语法）"
  - "实施输入长度限制和字符白名单校验"
  - "配置数据库账户最小权限（只读账户用于查询接口）"
  - "部署WAF规则拦截常见SQL注入模式"
  - "启用数据库审计日志监控异常查询"
```

---

## 7. 元数据字段

### metadata.go_versions（可选）

**类型：** 字符串数组
**说明：** 此模式适用的Go版本范围

**示例：** `[">=1.13"]` 或 `["1.18-1.21"]`

### metadata.frameworks（可选）

**类型：** 字符串数组
**说明：** 相关的Go框架或库

**示例：** `["gin", "gorm", "database/sql"]`

### metadata.tags（可选）

**类型：** 字符串数组
**说明：** 自由标签，用于搜索和过滤

**示例：** `["注入", "Web", "数据库", "OWASP-Top10"]`

### metadata.created_at（推荐）

**类型：** 字符串（ISO日期格式）
**格式：** `YYYY-MM-DD`

### metadata.updated_at（推荐）

**类型：** 字符串（ISO日期格式）
**格式：** `YYYY-MM-DD`

### metadata.confidence（推荐）

**类型：** 枚举字符串
**允许值：** `高` | `中` | `低`

### metadata.related_patterns（可选）

**类型：** 字符串数组
**说明：** 相关联的模式ID列表

**示例：** `["GO-ATK-SQLI-002", "GO-ATK-SQLI-003"]`

---

## 8. 完整条目示例

以下为一个高置信度的完整攻击模式条目：

````yaml
pattern_id: "GO-ATK-SQLI-001"
name: "fmt.Sprintf构建SQL查询导致注入"
category: "SQL注入"
severity: "严重"
cwe_ids: ["CWE-89"]
source_type: "expert-case"
source_ref: "SRC-001: Go Web安全审计专家案例集"

description:
  summary: "当使用fmt.Sprintf将用户输入拼接到SQL查询字符串时，攻击者可注入恶意SQL语句，读取、修改或删除数据库数据"
  background: |
    Go标准库database/sql支持参数化查询，但许多开发者习惯使用fmt.Sprintf
    构建动态SQL查询。fmt.Sprintf的%s格式符不会对SQL特殊字符进行转义，
    导致用户输入中的单引号、双横线等字符被直接嵌入SQL语句中，
    形成经典的SQL注入漏洞。
    
    这一模式在Go Web应用中极为常见，尤其是在使用原生database/sql包
    或GORM的Raw()方法时。
  impact: |
    - 机密性：高 — 可通过UNION SELECT读取任意数据表
    - 完整性：高 — 可通过UPDATE/DELETE修改或删除数据
    - 可用性：高 — 可通过DROP TABLE破坏数据库
  preconditions:
    - "应用使用database/sql、GORM或sqlx等数据库访问库"
    - "用户输入（HTTP参数、请求体等）到达SQL查询构建点"
    - "使用fmt.Sprintf或字符串拼接（+）构建SQL查询"
    - "未使用参数化查询占位符（$1、?等）"

test_method:
  strategy: "静态分析定位所有SQL查询构建点，检查是否存在字符串拼接或fmt.Sprintf模式；动态测试通过注入SQL特殊字符验证"
  detection_points:
    - "搜索 fmt.Sprintf 与 SELECT/INSERT/UPDATE/DELETE/WHERE 关键词的组合"
    - "搜索字符串拼接运算符(+)与 db.Query/db.Exec/db.QueryRow 的组合"
    - "检查 GORM 的 Raw()、Where()、Having()、Order() 方法的参数构建方式"
    - "检查 ORDER BY、GROUP BY 子句是否接受用户输入"
  test_steps:
    - "1. 识别所有接受用户输入的HTTP/gRPC端点"
    - "2. 追踪用户输入到SQL查询构建点的数据流"
    - "3. 在输入中注入单引号(')，观察是否报错"
    - "4. 尝试 ' OR '1'='1 布尔型注入"
    - "5. 尝试 ' UNION SELECT null,null,null-- 联合查询注入"
    - "6. 验证参数化查询修复后注入是否被阻断"
  tools:
    - "gosec (G201, G202规则)"
    - "semgrep (go.lang.security.audit.sqli.*)"
    - "sqlmap (动态测试)"
  automation_hint: "gosec规则G201; semgrep规则ID: go.lang.security.audit.sqli.tainted-sql-string; grep模式: fmt.Sprintf.*SELECT|INSERT|UPDATE|DELETE"

vuln_pattern:
  code_example: |
    ```go
    // 文件: pkg/repository/product.go
    package repository
    
    import (
        "database/sql"
        "fmt"
    )
    
    type ProductRepo struct {
        db *sql.DB
    }
    
    func (r *ProductRepo) Search(keyword string) ([]Product, error) {
        // 漏洞: 用户输入直接通过fmt.Sprintf拼接到SQL查询
        query := fmt.Sprintf(
            "SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'",
            keyword,  // ← 未转义的用户输入
        )
        rows, err := r.db.Query(query) // SINK: 执行拼接的SQL
        if err != nil {
            return nil, err
        }
        defer rows.Close()
    
        var products []Product
        for rows.Next() {
            var p Product
            rows.Scan(&p.ID, &p.Name, &p.Price)
            products = append(products, p)
        }
        return products, nil
    }
    ```
  sink_functions:
    - "(*sql.DB).Query"
    - "(*sql.DB).QueryRow"
    - "(*sql.DB).Exec"
  source_types:
    - "HTTP查询参数"
    - "HTTP请求体(JSON)"
    - "URL路径参数"
  dataflow: "c.Query('keyword') → handler调用repo.Search(keyword) → fmt.Sprintf(query, keyword) → db.Query(query)"
  trigger_conditions:
    - "keyword包含单引号: ' OR '1'='1"
    - "keyword包含UNION注入: ' UNION SELECT username,password,null FROM users--"
    - "keyword包含时间盲注: ' AND SLEEP(5)--"

safe_pattern:
  code_example: |
    ```go
    // 文件: pkg/repository/product.go
    package repository
    
    import "database/sql"
    
    type ProductRepo struct {
        db *sql.DB
    }
    
    func (r *ProductRepo) Search(keyword string) ([]Product, error) {
        // 修复: 使用参数化查询，$1占位符由数据库驱动安全处理
        rows, err := r.db.Query(
            "SELECT id, name, price FROM products WHERE name LIKE $1",
            "%"+keyword+"%", // 安全: 作为参数值而非SQL代码
        )
        if err != nil {
            return nil, err
        }
        defer rows.Close()
    
        var products []Product
        for rows.Next() {
            var p Product
            rows.Scan(&p.ID, &p.Name, &p.Price)
            products = append(products, p)
        }
        return products, nil
    }
    ```
  fix_strategy: "使用参数化查询（$1占位符）替代fmt.Sprintf字符串拼接，将用户输入作为数据参数传递给数据库驱动，由驱动自动处理特殊字符转义"
  defense_layers:
    - "使用ORM框架的安全查询API（如GORM的Where('name LIKE ?', keyword)）"
    - "对输入实施长度限制和字符白名单校验"
    - "配置数据库连接使用最小权限账户"
    - "启用SQL查询日志监控异常模式"
    - "部署WAF拦截常见SQL注入载荷"

metadata:
  go_versions: [">=1.13"]
  frameworks: ["database/sql", "gin", "echo", "chi"]
  tags: ["注入", "Web", "数据库", "OWASP-Top10", "A03:2021"]
  created_at: "2026-03-19"
  updated_at: "2026-03-19"
  confidence: "高"
  related_patterns: ["GO-ATK-SQLI-002", "GO-ATK-SQLI-003"]
````

---

## 9. 字段填充优先级

### 必填字段（条目创建时必须提供）

| 字段 | 说明 |
|------|------|
| `pattern_id` | 唯一标识符 |
| `name` | 模式名称 |
| `category` | 漏洞类别 |
| `severity` | 严重性等级 |
| `cwe_ids` | CWE编号 |
| `source_type` | 来源类型 |
| `description.summary` | 一句话概要 |
| `vuln_pattern.code_example` | 漏洞代码示例 |
| `safe_pattern.code_example` | 安全代码示例 |

### 推荐填充字段（首次填充或后续补全）

| 字段 | 说明 |
|------|------|
| `source_ref` | 来源引用 |
| `description.background` | 漏洞背景 |
| `description.impact` | 安全影响 |
| `description.preconditions` | 前置条件 |
| `test_method.strategy` | 测试策略 |
| `test_method.detection_points` | 检测点 |
| `test_method.test_steps` | 测试步骤 |
| `vuln_pattern.sink_functions` | Sink函数 |
| `vuln_pattern.dataflow` | 数据流 |
| `vuln_pattern.trigger_conditions` | 触发条件 |
| `safe_pattern.fix_strategy` | 修复策略 |
| `safe_pattern.defense_layers` | 纵深防御 |
| `metadata.confidence` | 置信度 |
| `metadata.created_at` | 创建时间 |

### 可选字段（视信息可用性填充）

| 字段 | 说明 |
|------|------|
| `vuln_pattern.source_types` | 污点源类型 |
| `test_method.tools` | 适用工具 |
| `test_method.automation_hint` | 自动化提示 |
| `metadata.go_versions` | 适用Go版本 |
| `metadata.frameworks` | 相关框架 |
| `metadata.tags` | 标签 |
| `metadata.related_patterns` | 关联模式 |

# SQL注入攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-SQLI-001 | fmt.Sprintf构建SQL查询导致注入 | 严重 | 高 | expert-case |
| GO-ATK-SQLI-002 | GORM动态ORDER BY子句注入 | 高危 | 高 | vuln-insight |
| GO-ATK-SQLI-003 | 字符串拼接构建SQL查询 | 严重 | 高 | security-guide |

---

## GO-ATK-SQLI-001：fmt.Sprintf构建SQL查询导致注入

**严重性：** 严重
**CWE：** CWE-89
**置信度：** 高
**来源：** expert-case + security-guide

### 漏洞描述

Go标准库database/sql支持参数化查询，但开发者常习惯使用 `fmt.Sprintf` 拼接SQL。`%s` 格式符不进行SQL转义，用户输入中的特殊字符会被直接嵌入SQL语句。这是Go Web应用中极为常见的SQL注入模式。

**影响：** 攻击者可读取、修改或删除任意数据库数据，可能通过数据库特性实现远程代码执行。

**前置条件：**
- 应用使用 database/sql 或 GORM 等框架
- 用户输入通过 fmt.Sprintf 到达SQL查询构建
- 未使用参数化查询

### 测试方法

**策略：** 静态搜索 `fmt.Sprintf` 与SQL关键词的组合，动态注入单引号验证。

**检测点：**
- `fmt.Sprintf` 参数中包含 `SELECT`、`INSERT`、`UPDATE`、`DELETE`、`WHERE`
- 字符串拼接运算符(`+`)与 `db.Query`、`db.Exec`、`db.QueryRow` 的组合
- GORM的 `Raw()`、`Where()` 方法参数来源
- 检查 ORDER BY、GROUP BY 子句是否接受用户输入

**测试步骤：**
1. 定位所有SQL查询构建函数
2. 检查参数来源是否可被用户控制
3. 输入 `' OR '1'='1` 测试布尔型注入
4. 输入 `' UNION SELECT null--` 测试联合查询注入
5. 尝试时间盲注 `' AND SLEEP(5)--`

**适用工具：** gosec (G201, G202), semgrep, sqlmap

**自动化提示：** gosec规则G201; semgrep规则ID: go.lang.security.audit.sqli.tainted-sql-string

### 漏洞模式（典型代码）

```go
// 文件: pkg/repository/product.go
package repository

import (
    "database/sql"
    "fmt"
)

func SearchProducts(db *sql.DB, keyword string) ([]Product, error) {
    // 漏洞: fmt.Sprintf拼接用户输入到SQL
    query := fmt.Sprintf(
        "SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'",
        keyword, // ← 用户输入未转义
    )
    rows, err := db.Query(query) // SINK
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
// 攻击: keyword = "' UNION SELECT id,password,null FROM users--"
```

### 数据流

```
c.Query("keyword") → handler层传参 → SearchProducts(db, keyword)
    → fmt.Sprintf(query, keyword) → db.Query(query)
```

### 安全模式

```go
// 文件: pkg/repository/product.go
func SearchProducts(db *sql.DB, keyword string) ([]Product, error) {
    // 修复: 使用参数化查询
    rows, err := db.Query(
        "SELECT id, name, price FROM products WHERE name LIKE $1",
        "%"+keyword+"%", // 作为参数值传递
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

**修复策略：** 使用参数化查询占位符（$1、?）替代字符串拼接。

**纵深防御：**
- ORM框架安全API（GORM `Where("name LIKE ?", kw)`）
- 输入长度限制和字符校验
- 数据库最小权限账户
- SQL查询审计日志
- 部署WAF拦截常见SQL注入载荷

### 元数据

- Go版本：>=1.13
- 框架：database/sql, gin, echo, chi
- 标签：注入, Web, 数据库, OWASP-Top10, A03:2021

---

## GO-ATK-SQLI-002：GORM动态ORDER BY子句注入

**严重性：** 高危
**CWE：** CWE-89
**置信度：** 高
**来源：** vuln-insight

### 漏洞描述

ORDER BY子句不能使用参数化查询的占位符，开发者容易直接将用户输入传入GORM的 `Order()` 方法。攻击者可注入SQL语句篡改查询逻辑。

**前置条件：**
- 使用GORM框架
- 排序字段由用户请求参数控制
- 未对排序字段进行白名单校验

### 测试方法

**检测点：**
- GORM `Order()` 方法的参数来源
- 任何接受 `sort`、`order_by`、`sortBy` 等参数的端点

**测试步骤：**
1. 定位使用 `db.Order()` 的查询
2. 追踪Order参数来源
3. 尝试注入 `id; DROP TABLE users--`
4. 尝试基于时间的盲注 `(CASE WHEN 1=1 THEN id ELSE sleep(2) END)`

**适用工具：** gosec, semgrep

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/list.go
func ListItemsHandler(c *gin.Context) {
    sortField := c.Query("sort")   // SOURCE: 用户控制排序字段
    sortOrder := c.Query("order")  // SOURCE: 用户控制排序方向

    var items []Item
    // 漏洞: 用户输入直接作为ORDER BY子句
    db.Order(sortField + " " + sortOrder).Find(&items) // SINK
    c.JSON(200, items)
}
// 攻击: sort = "id; DROP TABLE users--"
```

### 数据流

```
c.Query("sort") → sortField → 字符串拼接 → db.Order(sortField+" "+sortOrder)
```

### 安全模式

```go
// 文件: pkg/handler/list.go
var allowedSortFields = map[string]bool{
    "id": true, "name": true, "created_at": true, "price": true,
}
var allowedSortOrders = map[string]bool{
    "asc": true, "desc": true,
}

func ListItemsHandler(c *gin.Context) {
    sortField := c.DefaultQuery("sort", "id")
    sortOrder := c.DefaultQuery("order", "asc")

    // 修复: 白名单校验
    if !allowedSortFields[sortField] {
        sortField = "id"
    }
    if !allowedSortOrders[strings.ToLower(sortOrder)] {
        sortOrder = "asc"
    }

    var items []Item
    db.Order(sortField + " " + sortOrder).Find(&items)
    c.JSON(200, items)
}
```

**修复策略：** 使用白名单限制允许的排序字段和排序方向。

**纵深防御：**
- 严格的字段名格式校验（仅允许字母数字下划线）
- 限制排序字段长度

### 元数据

- Go版本：>=1.13
- 框架：gorm, gin, echo
- 标签：注入, Web, 数据库, GORM

---

## GO-ATK-SQLI-003：字符串拼接构建SQL查询

**严重性：** 严重
**CWE：** CWE-89
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

使用字符串拼接（+运算符）构建SQL查询，用户输入直接嵌入SQL语句。与fmt.Sprintf类似，但更隐蔽。

**前置条件：**
- 应用使用 database/sql 或 ORM Raw() 方法
- 用户输入参与SQL字符串拼接
- 未使用参数化查询

### 测试方法

**检测点：**
- 字符串拼接运算符(+)与SQL关键词的组合
- `"SELECT" + userInput` 模式
- `"WHERE" + condition` 模式

**测试步骤：**
1. 搜索包含SQL关键词的字符串拼接表达式
2. 追踪拼接变量的来源
3. 构造注入测试用例

### 漏洞模式（典型代码）

```go
// 文件: pkg/dao/query.go
func QueryByField(db *sql.DB, field, value string) (*sql.Rows, error) {
    // 漏洞: 字符串拼接构建SQL
    query := "SELECT * FROM users WHERE " + field + " = '" + value + "'"
    return db.Query(query)
}
// 攻击: value = "' OR '1'='1'--"
```

### 数据流

```
外部输入 → 字符串拼接 → db.Query(拼接后的SQL)
```

### 安全模式

```go
// 文件: pkg/dao/query.go
var allowedFields = map[string]bool{"id": true, "name": true, "email": true}

func QueryByField(db *sql.DB, field, value string) (*sql.Rows, error) {
    // 修复: 字段白名单校验
    if !allowedFields[field] {
        return nil, errors.New("invalid field")
    }
    // 修复: 使用参数化查询
    query := "SELECT * FROM users WHERE " + field + " = $1"
    return db.Query(query, value)
}
```

**修复策略：** 字段名使用白名单校验，值使用参数化查询。

### 元数据

- Go版本：>=1.13
- 框架：database/sql
- 标签：注入, Web, 数据库

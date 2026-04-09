# Go攻击模式示例库

本文档包含预构建的Go攻击模式示例，覆盖主要漏洞类别。可作为首次构建模式库时的种子数据，也可作为格式参考。

## 目录

1. [SQL注入模式](#1-sql注入模式)
2. [命令注入模式](#2-命令注入模式)
3. [SSRF模式](#3-ssrf模式)
4. [认证缺陷模式](#4-认证缺陷模式)
5. [竞态条件模式](#5-竞态条件模式)
6. [Go语言特有模式](#6-go语言特有模式)
7. [供应链攻击模式](#7-供应链攻击模式)
8. [反序列化模式](#8-反序列化模式)
9. [路径穿越模式](#9-路径穿越模式)
10. [密码学失败模式](#10-密码学失败模式)

---

## 1. SQL注入模式

### GO-ATK-SQLI-001：fmt.Sprintf构建SQL查询导致注入

**严重性：** 严重
**CWE：** CWE-89
**置信度：** 高
**来源：** expert-case

#### 漏洞描述

Go标准库database/sql支持参数化查询，但开发者常习惯使用 `fmt.Sprintf` 拼接SQL。`%s` 格式符不进行SQL转义，用户输入中的特殊字符会被直接嵌入SQL语句。

**影响：** 攻击者可读取、修改或删除任意数据库数据，可能通过数据库特性实现远程代码执行。

**前置条件：**
- 应用使用 database/sql 或 GORM 等框架
- 用户输入通过 fmt.Sprintf 到达SQL查询构建
- 未使用参数化查询

#### 测试方法

**策略：** 静态搜索 `fmt.Sprintf` 与SQL关键词的组合，动态注入单引号验证。

**检测点：**
- `fmt.Sprintf` 参数中包含 `SELECT`、`INSERT`、`UPDATE`、`DELETE`
- 字符串拼接运算符(`+`)与 `db.Query`、`db.Exec` 的组合
- GORM的 `Raw()`、`Where()` 方法参数

**测试步骤：**
1. 定位所有SQL查询构建函数
2. 检查参数来源是否可被用户控制
3. 输入 `' OR '1'='1` 测试布尔型注入
4. 输入 `' UNION SELECT null--` 测试联合查询注入

**适用工具：** gosec (G201, G202), semgrep, sqlmap

#### 漏洞模式（典型代码）

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
```

#### 数据流

```
c.Query("keyword") → handler层传参 → SearchProducts(db, keyword)
    → fmt.Sprintf(query, keyword) → db.Query(query)
```

#### 安全模式

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

**修复策略：** 使用参数化查询占位符（$1）替代字符串拼接。

**纵深防御：**
- ORM框架安全API（GORM `Where("name LIKE ?", kw)`）
- 输入长度限制和字符校验
- 数据库最小权限账户
- SQL查询审计日志

---

### GO-ATK-SQLI-002：GORM动态ORDER BY子句注入

**严重性：** 高危
**CWE：** CWE-89
**置信度：** 高
**来源：** vuln-insight

#### 漏洞描述

ORDER BY子句不能使用参数化查询的占位符，开发者容易直接将用户输入传入GORM的 `Order()` 方法。攻击者可注入SQL语句篡改查询逻辑。

**前置条件：**
- 使用GORM框架
- 排序字段由用户请求参数控制
- 未对排序字段进行白名单校验

#### 测试方法

**检测点：**
- GORM `Order()` 方法的参数来源
- 任何接受 `sort`、`order_by`、`sortBy` 等参数的端点

**测试步骤：**
1. 定位使用 `db.Order()` 的查询
2. 追踪Order参数来源
3. 尝试注入 `id; DROP TABLE users--`
4. 尝试基于时间的盲注 `(CASE WHEN 1=1 THEN id ELSE sleep(2) END)`

#### 漏洞模式（典型代码）

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
```

#### 数据流

```
c.Query("sort") → sortField → 字符串拼接 → db.Order(sortField+" "+sortOrder)
```

#### 安全模式

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

---

## 2. 命令注入模式

### GO-ATK-CMDI-001：shell -c执行用户拼接命令

**严重性：** 严重
**CWE：** CWE-78
**置信度：** 高
**来源：** expert-case

#### 漏洞描述

通过 `exec.Command("sh", "-c", userInput)` 执行命令时，用户输入中的 shell 元字符（`;`、`&&`、`|`、`` ` ``、`$()`）会被 shell 解释执行。

**影响：** 攻击者可在服务器上执行任意系统命令，实现远程代码执行（RCE）。

**前置条件：**
- 应用调用 exec.Command 并通过 shell（sh -c）执行
- 用户输入被拼接到命令字符串中
- 无输入净化或命令白名单

#### 测试方法

**检测点：**
- `exec.Command("sh", "-c", ...)` 或 `exec.Command("bash", "-c", ...)`
- `fmt.Sprintf` 构建的命令字符串传入 exec.Command
- 用户输入到达 exec.Command 的任何参数

**测试步骤：**
1. 搜索所有 `exec.Command` 调用
2. 检查是否通过 shell 执行（`sh -c`、`bash -c`）
3. 追踪命令字符串中是否包含用户输入
4. 尝试注入 `; id`、`$(whoami)`、`` `whoami` ``

**适用工具：** gosec (G204), semgrep

#### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/tool.go
package handler

import (
    "fmt"
    "os/exec"

    "github.com/gin-gonic/gin"
)

func PingHandler(c *gin.Context) {
    host := c.Query("host") // SOURCE
    // 漏洞: 用户输入拼接到shell命令中
    cmdStr := fmt.Sprintf("ping -c 3 %s", host)
    cmd := exec.Command("sh", "-c", cmdStr) // SINK
    output, err := cmd.CombinedOutput()
    if err != nil {
        c.String(500, "执行失败: %v", err)
        return
    }
    c.String(200, string(output))
}
// 攻击: host = "127.0.0.1; cat /etc/passwd"
```

#### 数据流

```
c.Query("host") → fmt.Sprintf("ping -c 3 %s", host) → exec.Command("sh", "-c", cmdStr)
```

#### 安全模式

```go
// 文件: pkg/handler/tool.go
import (
    "net"
    "os/exec"

    "github.com/gin-gonic/gin"
)

func PingHandler(c *gin.Context) {
    host := c.Query("host")

    // 修复1: 输入校验——仅允许合法IP或域名
    if net.ParseIP(host) == nil {
        if _, err := net.LookupHost(host); err != nil {
            c.String(400, "无效的主机地址")
            return
        }
    }

    // 修复2: 参数作为独立参数传递，不经过shell
    cmd := exec.Command("ping", "-c", "3", host)
    output, err := cmd.CombinedOutput()
    if err != nil {
        c.String(500, "执行失败")
        return
    }
    c.String(200, string(output))
}
```

**修复策略：** 避免使用 `sh -c`，将参数作为独立参数传递给 `exec.Command`；同时校验用户输入格式。

**纵深防御：**
- 输入白名单校验（IP格式、域名格式）
- 命令白名单（仅允许执行特定程序）
- 最小权限运行（非root用户）
- 禁用shell元字符

---

## 3. SSRF模式

### GO-ATK-SSRF-001：用户控制URL的HTTP请求无校验

**严重性：** 高危
**CWE：** CWE-918
**置信度：** 高
**来源：** vuln-insight

#### 漏洞描述

应用接受用户提供的URL并发起HTTP请求，未校验目标地址是否为内部网络或敏感端点。攻击者可探测内部服务、访问云元数据API。

**前置条件：**
- 应用有代理、Webhook或URL获取功能
- 用户可控制请求的目标URL
- 未实施URL白名单或内网地址过滤

#### 测试方法

**检测点：**
- `http.Get(userURL)`、`http.Post(userURL, ...)`
- `http.NewRequest` 中URL参数来源
- Webhook回调URL配置

**测试步骤：**
1. 定位所有发起出站HTTP请求的代码
2. 检查URL参数是否可被用户控制
3. 尝试请求 `http://169.254.169.254/latest/meta-data/`
4. 尝试请求 `http://127.0.0.1:8080/admin`
5. 检查HTTP客户端是否跟随重定向

#### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/proxy.go
func FetchURLHandler(c *gin.Context) {
    targetURL := c.Query("url") // SOURCE
    // 漏洞: 用户URL未经校验直接请求
    resp, err := http.Get(targetURL) // SINK
    if err != nil {
        c.String(500, "获取失败")
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    c.Data(200, resp.Header.Get("Content-Type"), body)
}
// 攻击: url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

#### 安全模式

```go
// 文件: pkg/handler/proxy.go
import (
    "errors"
    "net"
    "net/http"
    "net/url"
    "strings"
)

var allowedHosts = map[string]bool{
    "api.example.com": true,
    "cdn.example.com": true,
}

func isInternalIP(host string) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        addrs, err := net.LookupIP(host)
        if err != nil || len(addrs) == 0 {
            return true // 无法解析视为不安全
        }
        ip = addrs[0]
    }
    privateRanges := []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128",
    }
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return false
}

func FetchURLHandler(c *gin.Context) {
    targetURL := c.Query("url")

    // 修复: 解析并校验URL
    u, err := url.Parse(targetURL)
    if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
        c.String(400, "无效的URL")
        return
    }
    if isInternalIP(u.Hostname()) {
        c.String(403, "禁止访问内部地址")
        return
    }

    // 修复: 禁止重定向到内部地址
    client := &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if isInternalIP(req.URL.Hostname()) {
                return errors.New("重定向到内部地址被阻止")
            }
            if len(via) >= 3 {
                return errors.New("重定向次数过多")
            }
            return nil
        },
    }
    resp, err := client.Get(targetURL)
    if err != nil {
        c.String(500, "获取失败")
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 限制1MB
    c.Data(200, resp.Header.Get("Content-Type"), body)
}
```

**修复策略：** 校验URL scheme和目标地址，过滤私有IP段，限制重定向目标。

---

## 4. 认证缺陷模式

### GO-ATK-AUTH-001：JWT未验证签名算法（alg:none攻击）

**严重性：** 严重
**CWE：** CWE-287
**置信度：** 高
**来源：** expert-case

#### 漏洞描述

JWT解析时未验证token的 `alg` 字段，攻击者可将算法设为 `none`，构造无签名的token绕过认证。

**前置条件：**
- 使用JWT进行认证
- JWT解析未强制指定或验证签名算法
- JWT库支持 `none` 算法（部分库默认支持）

#### 测试方法

**检测点：**
- `jwt.Parse()` 的 keyFunc 回调中是否检查 `token.Method`
- 是否使用 `jwt.ParseWithClaims` 并验证 Claims
- JWT密钥是否硬编码

**测试步骤：**
1. 获取正常的JWT token
2. 解码JWT，将header中的 `alg` 改为 `none`
3. 移除签名部分（第三段置空）
4. 使用修改后的token访问受保护端点

#### 漏洞模式（典型代码）

```go
// 文件: pkg/auth/jwt.go
import "github.com/golang-jwt/jwt/v5"

var secretKey = []byte("my-secret-key")

func ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // 漏洞: 未检查token.Method，接受任意算法包括"none"
        return secretKey, nil // SINK
    })
    if err != nil {
        return nil, err
    }
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        return nil, errors.New("无效token")
    }
    return parseClaims(claims), nil
}
```

#### 安全模式

```go
// 文件: pkg/auth/jwt.go
func ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // 修复: 强制验证签名算法为HMAC
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("非预期的签名算法: %v", token.Header["alg"])
        }
        return secretKey, nil
    })
    if err != nil {
        return nil, err
    }
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid {
        return nil, errors.New("无效token")
    }
    // 修复: 验证关键Claims
    if !claims.VerifyExpirationTime(time.Now(), true) {
        return nil, errors.New("token已过期")
    }
    return parseClaims(claims), nil
}
```

**修复策略：** 在keyFunc中显式验证 `token.Method` 类型，拒绝非预期算法。

---

## 5. 竞态条件模式

### GO-ATK-RACE-001：TOCTOU竞态导致双重支付

**严重性：** 高危
**CWE：** CWE-362
**置信度：** 高
**来源：** expert-case

#### 漏洞描述

检查余额和扣减余额之间存在时间窗口，并发请求可利用此窗口多次扣减，实现双重支付（double-spending）。

**前置条件：**
- 业务逻辑包含"先检查后使用"模式
- 检查和使用未在同一事务或锁保护下执行
- 端点可被并发调用

#### 测试方法

**检测点：**
- 先读取值、判断条件、再修改值的代码模式
- 余额检查、库存检查、限额检查的实现
- 数据库操作是否在事务中

**测试步骤：**
1. 识别所有"先检查后使用"的代码模式
2. 分析检查和使用之间是否有并发保护
3. 使用工具并发发送多个相同请求
4. 检查最终状态是否一致

**适用工具：** go test -race, curl并发脚本

#### 漏洞模式（典型代码）

```go
// 文件: pkg/service/wallet.go
func Withdraw(db *sql.DB, userID string, amount float64) error {
    // 检查: 读取当前余额
    var balance float64
    db.QueryRow("SELECT balance FROM wallets WHERE user_id = $1", userID).Scan(&balance)

    // 漏洞: 检查和使用之间存在时间窗口
    if balance < amount {
        return errors.New("余额不足")
    }

    // 使用: 扣减余额
    // 另一个并发请求可能在此时也通过了余额检查
    _, err := db.Exec(
        "UPDATE wallets SET balance = balance - $1 WHERE user_id = $2",
        amount, userID,
    )
    return err
}
// 攻击: 并发发送10个提现请求，余额仅被检查一次但被扣减多次
```

#### 安全模式

```go
// 文件: pkg/service/wallet.go
func Withdraw(db *sql.DB, userID string, amount float64) error {
    // 修复: 使用数据库事务+行级锁（SELECT FOR UPDATE）
    tx, err := db.BeginTx(context.Background(), &sql.TxOptions{
        Isolation: sql.LevelSerializable,
    })
    if err != nil {
        return err
    }
    defer tx.Rollback()

    var balance float64
    // FOR UPDATE 锁定行，阻止并发读取
    err = tx.QueryRow(
        "SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE",
        userID,
    ).Scan(&balance)
    if err != nil {
        return err
    }

    if balance < amount {
        return errors.New("余额不足")
    }

    _, err = tx.Exec(
        "UPDATE wallets SET balance = balance - $1 WHERE user_id = $2",
        amount, userID,
    )
    if err != nil {
        return err
    }

    return tx.Commit()
}
```

**修复策略：** 使用数据库事务配合 `SELECT FOR UPDATE` 行级锁，或使用 `Serializable` 隔离级别。

---

## 6. Go语言特有模式

### GO-ATK-GOLNG-001：unsafe.Pointer类型转换绕过类型安全

**严重性：** 严重
**CWE：** CWE-843
**置信度：** 中
**来源：** security-guide

#### 漏洞描述

`unsafe.Pointer` 可将任意类型指针相互转换，绕过Go的类型系统。如果攻击者能控制被转换的字节数据，可覆盖结构体字段值（如权限标志位），甚至实现任意内存读写。

**前置条件：**
- 代码使用 `unsafe.Pointer` 进行类型转换
- 被转换的数据来源可被外部影响
- 目标类型包含安全敏感字段

#### 测试方法

**检测点：**
- 所有 `import "unsafe"` 的文件
- `unsafe.Pointer` 的类型转换表达式
- `uintptr` 算术运算

**测试步骤：**
1. 搜索所有使用 `unsafe` 包的代码
2. 分析 `unsafe.Pointer` 转换的源数据是否可被外部控制
3. 检查目标类型结构体中是否有安全敏感字段
4. 验证是否有边界检查

#### 漏洞模式（典型代码）

```go
// 文件: pkg/protocol/decoder.go
import "unsafe"

type Header struct {
    Version  uint8
    Type     uint8
    IsAdmin  bool    // 安全敏感字段
    Reserved uint8
    Length   uint32
}

func DecodeHeader(data []byte) *Header {
    if len(data) < int(unsafe.Sizeof(Header{})) {
        return nil
    }
    // 漏洞: 网络数据直接转换为结构体，攻击者可控制所有字段
    return (*Header)(unsafe.Pointer(&data[0])) // SINK
}
// 攻击: 构造data使IsAdmin字段为true，绕过后续权限检查
```

#### 安全模式

```go
// 文件: pkg/protocol/decoder.go
import "encoding/binary"

type Header struct {
    Version  uint8
    Type     uint8
    IsAdmin  bool
    Reserved uint8
    Length   uint32
}

func DecodeHeader(data []byte) (*Header, error) {
    if len(data) < 8 {
        return nil, errors.New("数据不足")
    }
    h := &Header{
        Version:  data[0],
        Type:     data[1],
        // 修复: IsAdmin不从外部数据解析，由服务端认证决定
        IsAdmin:  false,
        Reserved: data[3],
        Length:   binary.BigEndian.Uint32(data[4:8]),
    }
    // 修复: 添加字段值校验
    if h.Version > 3 {
        return nil, errors.New("不支持的版本")
    }
    return h, nil
}
```

**修复策略：** 使用 `encoding/binary` 安全解码，逐字段赋值并校验；安全敏感字段不从外部数据填充。

---

### GO-ATK-GOLNG-002：reflect包动态方法调用导致任意方法执行

**严重性：** 高危
**CWE：** CWE-470
**置信度：** 高
**来源：** vuln-insight

#### 漏洞描述

使用 `reflect.ValueOf(obj).MethodByName(userInput)` 允许基于用户输入动态调用对象的任意导出方法，攻击者可调用 `Delete`、`Reset`、`Destroy` 等危险方法。

**前置条件：**
- 代码使用 reflect 包进行动态方法调用
- 方法名来源于用户输入
- 目标对象拥有安全敏感的导出方法

#### 漏洞模式（典型代码）

```go
// 文件: pkg/api/dispatcher.go
import "reflect"

type AdminService struct {
    db *sql.DB
}

func (s *AdminService) GetStats() interface{} { /* ... */ return nil }
func (s *AdminService) DeleteAll() error { /* 删除全部数据 */ return nil }
func (s *AdminService) ResetPassword(uid string) error { /* ... */ return nil }

func DispatchAction(svc *AdminService, action string, args ...interface{}) (interface{}, error) {
    v := reflect.ValueOf(svc)
    method := v.MethodByName(action) // SOURCE→SINK: action来自用户输入
    if !method.IsValid() {
        return nil, errors.New("方法不存在")
    }
    in := make([]reflect.Value, len(args))
    for i, arg := range args {
        in[i] = reflect.ValueOf(arg)
    }
    results := method.Call(in)
    return results[0].Interface(), nil
}
// 攻击: action = "DeleteAll" → 调用AdminService.DeleteAll()
```

#### 安全模式

```go
// 文件: pkg/api/dispatcher.go
var allowedActions = map[string]bool{
    "GetStats":      true,
    "GetUserCount":  true,
}

func DispatchAction(svc *AdminService, action string, args ...interface{}) (interface{}, error) {
    // 修复: 白名单校验允许调用的方法
    if !allowedActions[action] {
        return nil, fmt.Errorf("不允许的操作: %s", action)
    }
    v := reflect.ValueOf(svc)
    method := v.MethodByName(action)
    if !method.IsValid() {
        return nil, errors.New("方法不存在")
    }
    in := make([]reflect.Value, len(args))
    for i, arg := range args {
        in[i] = reflect.ValueOf(arg)
    }
    results := method.Call(in)
    return results[0].Interface(), nil
}
```

**修复策略：** 使用白名单限制可被动态调用的方法名称。

---

## 7. 供应链攻击模式

### GO-ATK-SUPPLY-001：go.mod依赖拼写劫持

**严重性：** 高危
**CWE：** CWE-829
**置信度：** 中
**来源：** security-guide

#### 漏洞描述

攻击者在Go模块注册中心注册与知名包名称相近的包（拼写变体），当开发者误输入依赖名时引入恶意代码。恶意包通过 `init()` 函数在导入时自动执行。

**前置条件：**
- 开发者手动编辑go.mod或使用go get添加依赖
- 拼写错误或混淆相似包名
- 未仔细审查go.mod变更

#### 测试方法

**检测点：**
- go.mod中的所有require条目
- 检查包名是否与知名包存在拼写差异
- go.mod中的replace指令
- 非标准的module路径

**测试步骤：**
1. 导出go.mod中所有依赖列表
2. 对每个依赖，比较与知名Go包的名称相似度
3. 检查是否存在typosquatting嫌疑的包
4. 审查所有replace指令的指向
5. 检查依赖的init()函数

#### 漏洞模式（典型代码）

```go
// go.mod
module myapp

go 1.21

require (
    github.com/gorilla/mux v1.8.0     // 正确包名
    github.com/gorila/mux v1.8.0      // 漏洞: 拼写劫持（少一个l）
    github.com/sirupsen/logrus v1.9.0  // 正确包名
    github.com/sirpusen/logrus v1.9.0  // 漏洞: 拼写劫持（字母换位）
)

// 漏洞: replace指令将可信包重定向到攻击者包
replace github.com/trusted/lib => github.com/attacker/lib v1.0.0
```

#### 安全模式

```go
// 防御措施（非代码级别）:
// 1. 使用 go mod verify 验证依赖哈希
// 2. 使用 GONOSUMCHECK 和 GONOSUMDB 控制校验行为
// 3. 启用 GOFLAGS=-mod=readonly 防止意外修改go.mod
// 4. CI/CD中添加go.mod变更审查步骤
// 5. 使用 govulncheck 扫描已知漏洞
// 6. 审查所有replace指令
```

```bash
# 验证依赖完整性
go mod verify

# 检查已知漏洞
govulncheck ./...

# 锁定依赖，防止意外修改
export GOFLAGS=-mod=readonly
```

**修复策略：** 建立依赖审查流程，CI中自动校验go.mod变更，使用 `go mod verify` 和 `govulncheck`。

---

## 8. 反序列化模式

### GO-ATK-DESER-001：JSON解码无请求体大小限制

**严重性：** 中危
**CWE：** CWE-400, CWE-502
**置信度：** 高
**来源：** codehub-issue

#### 漏洞描述

使用 `json.NewDecoder(r.Body).Decode()` 或 `io.ReadAll(r.Body)` 时未限制请求体大小，攻击者可发送超大JSON载荷耗尽服务器内存。

**前置条件：**
- HTTP处理函数读取请求体
- 未设置 `http.MaxBytesReader` 限制
- 未在反向代理层限制请求大小

#### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/api.go
func CreateItemHandler(w http.ResponseWriter, r *http.Request) {
    // 漏洞: 无大小限制，攻击者可发送GB级JSON
    var item Item
    err := json.NewDecoder(r.Body).Decode(&item) // SINK
    if err != nil {
        http.Error(w, "无效JSON", 400)
        return
    }
    // ... 处理item
}
```

#### 安全模式

```go
// 文件: pkg/handler/api.go
const maxBodySize = 1 << 20 // 1MB

func CreateItemHandler(w http.ResponseWriter, r *http.Request) {
    // 修复: 限制请求体大小
    r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
    var item Item
    err := json.NewDecoder(r.Body).Decode(&item)
    if err != nil {
        if err.Error() == "http: request body too large" {
            http.Error(w, "请求体过大", 413)
            return
        }
        http.Error(w, "无效JSON", 400)
        return
    }
    // ... 处理item
}
```

**修复策略：** 使用 `http.MaxBytesReader` 限制请求体大小。

---

## 9. 路径穿越模式

### GO-ATK-PTR-001：Zip Slip任意文件写入

**严重性：** 高危
**CWE：** CWE-22
**置信度：** 高
**来源：** expert-case

#### 漏洞描述

解压ZIP文件时，压缩包中的文件名可包含 `../` 路径穿越序列。如果提取逻辑未校验文件名，攻击者构造的ZIP文件可在目标目录之外写入任意文件。

**前置条件：**
- 应用接受ZIP/TAR文件上传并解压
- 解压时使用 `filepath.Join(destDir, entry.Name)` 构建路径
- 未校验结果路径是否仍在目标目录内

#### 漏洞模式（典型代码）

```go
// 文件: pkg/util/archive.go
import (
    "archive/zip"
    "io"
    "os"
    "path/filepath"
)

func ExtractZip(zipPath, destDir string) error {
    r, err := zip.OpenReader(zipPath)
    if err != nil {
        return err
    }
    defer r.Close()

    for _, f := range r.File {
        // 漏洞: f.Name可能包含"../../../etc/cron.d/backdoor"
        path := filepath.Join(destDir, f.Name) // SINK
        if f.FileInfo().IsDir() {
            os.MkdirAll(path, 0755)
            continue
        }
        outFile, err := os.Create(path)
        if err != nil {
            return err
        }
        rc, _ := f.Open()
        io.Copy(outFile, rc)
        outFile.Close()
        rc.Close()
    }
    return nil
}
```

#### 安全模式

```go
// 文件: pkg/util/archive.go
func ExtractZip(zipPath, destDir string) error {
    r, err := zip.OpenReader(zipPath)
    if err != nil {
        return err
    }
    defer r.Close()

    destDir, err = filepath.Abs(destDir)
    if err != nil {
        return err
    }

    for _, f := range r.File {
        // 修复: 清理路径并检查是否仍在目标目录内
        path := filepath.Join(destDir, f.Name)
        path = filepath.Clean(path)

        if !strings.HasPrefix(path, destDir+string(os.PathSeparator)) {
            return fmt.Errorf("非法路径: %s", f.Name)
        }

        if f.FileInfo().IsDir() {
            os.MkdirAll(path, 0755)
            continue
        }

        // 确保父目录存在
        os.MkdirAll(filepath.Dir(path), 0755)

        outFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil {
            return err
        }
        rc, _ := f.Open()
        // 限制单文件大小防止解压炸弹
        _, err = io.Copy(outFile, io.LimitReader(rc, 100<<20))
        outFile.Close()
        rc.Close()
        if err != nil {
            return err
        }
    }
    return nil
}
```

**修复策略：** 清理路径后验证是否仍以目标目录为前缀；限制单文件解压大小。

---

## 10. 密码学失败模式

### GO-ATK-CRYPTO-001：math/rand生成安全令牌

**严重性：** 高危
**CWE：** CWE-330
**置信度：** 高
**来源：** codehub-issue

#### 漏洞描述

使用 `math/rand` 而非 `crypto/rand` 生成安全相关的令牌（密码重置token、API Key、会话ID等）。`math/rand` 是伪随机数生成器，种子可预测，生成的序列可被重现。

**前置条件：**
- 安全令牌使用 `math/rand` 生成
- 令牌用于认证、授权或密码重置
- 攻击者可以观察或推断生成时间（作为种子）

#### 漏洞模式（典型代码）

```go
// 文件: pkg/auth/token.go
import (
    "fmt"
    "math/rand"
    "time"
)

func init() {
    rand.Seed(time.Now().UnixNano()) // 种子可基于时间推测
}

func GenerateResetToken() string {
    // 漏洞: math/rand不是密码学安全的PRNG
    return fmt.Sprintf("%06d", rand.Intn(999999)) // SINK
}

func GenerateAPIKey() string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, 32)
    for i := range b {
        b[i] = chars[rand.Intn(len(chars))] // SINK
    }
    return string(b)
}
```

#### 安全模式

```go
// 文件: pkg/auth/token.go
import (
    "crypto/rand"
    "encoding/hex"
)

func GenerateResetToken() (string, error) {
    // 修复: 使用crypto/rand生成密码学安全随机数
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

func GenerateAPIKey() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```

**修复策略：** 所有安全相关的随机数生成使用 `crypto/rand`，而非 `math/rand`。

**纵深防御：**
- 令牌设置合理的有效期
- 使用后即失效（一次性令牌）
- 令牌绑定用户身份，防止横向使用
- 限制令牌验证尝试次数

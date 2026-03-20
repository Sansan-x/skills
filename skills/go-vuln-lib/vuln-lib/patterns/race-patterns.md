# 竞态条件攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-RACE-001 | TOCTOU竞态导致双重支付 | 高危 | 高 | expert-case |
| GO-ATK-RACE-002 | map并发读写导致panic | 中危 | 高 | security-guide |

---

## GO-ATK-RACE-001：TOCTOU竞态导致双重支付

**严重性：** 高危
**CWE：** CWE-362
**置信度：** 高
**来源：** expert-case

### 漏洞描述

检查余额和扣减余额之间存在时间窗口（Time-Of-Check to Time-Of-Use），并发请求可利用此窗口多次扣减，实现双重支付（double-spending）。

**前置条件：**
- 业务逻辑包含"先检查后使用"模式
- 检查和使用未在同一事务或锁保护下执行
- 端点可被并发调用

### 测试方法

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

### 漏洞模式（典型代码）

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

### 数据流

```
并发请求A: 检查余额=100 → 通过 → 扣减
并发请求B: 检查余额=100 → 通过 → 扣减 (余额已变但检查时未感知)
```

### 安全模式

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

**纵深防御：**
- 业务层使用互斥锁（sync.Mutex）
- 幂等性设计（请求ID去重）
- 添加审计日志监控异常操作

### 元数据

- Go版本：>=1.13
- 框架：database/sql
- 标签：竞态条件, 并发, 逻辑漏洞

---

## GO-ATK-RACE-002：map并发读写导致panic

**严重性：** 中危
**CWE：** CWE-362
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

Go的map不是并发安全的，多个goroutine同时读写同一个map会导致panic: concurrent map writes。

**前置条件：**
- map被多个goroutine共享
- 未使用互斥锁保护
- 存在并发写操作

### 测试方法

**检测点：**
- 全局map变量
- goroutine中访问共享map
- 未使用sync.RWMutex或sync.Map

**测试步骤：**
1. 搜索全局map变量
2. 分析是否有多个goroutine访问
3. 使用 `go test -race` 检测

### 漏洞模式（典型代码）

```go
// 文件: pkg/cache/cache.go
var cache = make(map[string]string)

func Set(key, value string) {
    // 漏洞: 并发写入map
    cache[key] = value
}

func Get(key string) string {
    return cache[key]
}
// 并发调用Set会导致: fatal error: concurrent map writes
```

### 安全模式

```go
// 文件: pkg/cache/cache.go
import "sync"

var (
    cache = make(map[string]string)
    mu    sync.RWMutex
)

func Set(key, value string) {
    // 修复: 使用互斥锁保护
    mu.Lock()
    cache[key] = value
    mu.Unlock()
}

func Get(key string) string {
    mu.RLock()
    defer mu.RUnlock()
    return cache[key]
}

// 或使用sync.Map
var safeCache sync.Map

func SetSafe(key, value string) {
    safeCache.Store(key, value)
}

func GetSafe(key string) (string, bool) {
    v, ok := safeCache.Load(key)
    if !ok {
        return "", false
    }
    return v.(string), true
}
```

**修复策略：** 使用 `sync.RWMutex` 保护map访问，或使用并发安全的 `sync.Map`。

### 元数据

- Go版本：>=1.9 (sync.Map)
- 框架：sync
- 标签：竞态条件, map, 并发, Go特有

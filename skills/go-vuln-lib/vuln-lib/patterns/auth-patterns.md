# 认证缺陷攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-AUTH-001 | JWT未验证签名算法（alg:none攻击） | 严重 | 高 | expert-case |
| GO-ATK-AUTH-002 | 硬编码凭证 | 严重 | 高 | security-guide |

---

## GO-ATK-AUTH-001：JWT未验证签名算法（alg:none攻击）

**严重性：** 严重
**CWE：** CWE-287
**置信度：** 高
**来源：** expert-case

### 漏洞描述

JWT解析时未验证token的 `alg` 字段，攻击者可将算法设为 `none`，构造无签名的token绕过认证。这是JWT实现中最常见的漏洞。

**前置条件：**
- 使用JWT进行认证
- JWT解析未强制指定或验证签名算法
- JWT库支持 `none` 算法（部分库默认支持）

### 测试方法

**检测点：**
- `jwt.Parse()` 的 keyFunc 回调中是否检查 `token.Method`
- 是否使用 `jwt.ParseWithClaims` 并验证 Claims
- JWT密钥是否硬编码

**测试步骤：**
1. 获取正常的JWT token
2. 解码JWT，将header中的 `alg` 改为 `none`
3. 移除签名部分（第三段置空）
4. 使用修改后的token访问受保护端点
5. 尝试 `alg: HS256` 但使用空密钥

**适用工具：** jwt_tool, burp suite

### 漏洞模式（典型代码）

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
// 攻击: 构造 {alg: "none", typ: "JWT"} header + payload + 空签名
```

### 数据流

```
外部token → jwt.Parse → 未验证alg → 返回任意claims
```

### 安全模式

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
    if !claims.VerifyExpiresAt(time.Now(), true) {
        return nil, errors.New("token已过期")
    }
    return parseClaims(claims), nil
}
```

**修复策略：** 在keyFunc中显式验证 `token.Method` 类型，拒绝非预期算法。

**纵深防御：**
- JWT密钥从配置或密钥管理服务获取
- 设置合理的token过期时间
- 验证issuer和audience
- 使用JTI防止重放

### 元数据

- Go版本：>=1.13
- 框架：golang-jwt/jwt, gin
- 标签：认证, JWT, 绕过

---

## GO-ATK-AUTH-002：硬编码凭证

**严重性：** 严重
**CWE：** CWE-798
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

代码中硬编码密码、API密钥、私钥等认证凭据。

**前置条件：**
- 代码中存在硬编码的敏感凭证
- 代码可被获取（开源或源码泄露）

### 测试方法

**检测点：**
- 搜索敏感关键词: `password`, `passwd`, `secret`, `key`, `token`, `credential`
- 搜索正则: `\d{2,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` (硬编码IP)
- 搜索邮箱: `\w+@\w+\.\w+`

**测试步骤：**
1. 使用PowerGrep/Seninfo扫描敏感关键词
2. 人工确认是否为硬编码凭证
3. 检查全局变量是否存储明文敏感信息

**适用工具：** gosec (G101, G102), PowerGrep, Seninfo

### 漏洞模式（典型代码）

```go
// 文件: pkg/config/config.go
// 漏洞: 硬编码密码
const DBPassword = "admin123"
var APIKey = "sk-xxxxxxxxxxxxx"
var SecretKey = []byte("my-secret-key")

func ConnectDB() *sql.DB {
    db, _ := sql.Open("mysql", "user:"+DBPassword+"@tcp(localhost:3306)/db")
    return db
}
```

### 安全模式

```go
// 文件: pkg/config/config.go
import (
    "os"
    "github.com/joho/godotenv"
)

func ConnectDB() *sql.DB {
    // 修复: 从环境变量读取凭证
    dbPassword := os.Getenv("DB_PASSWORD")
    if dbPassword == "" {
        panic("DB_PASSWORD not set")
    }
    db, _ := sql.Open("mysql", "user:"+dbPassword+"@tcp(localhost:3306)/db")
    return db
}

// 或从配置文件读取
func LoadConfig() *Config {
    godotenv.Load()
    return &Config{
        APIKey: os.Getenv("API_KEY"),
        Secret: os.Getenv("SECRET_KEY"),
    }
}
```

**修复策略：** 凭证存储在配置文件、环境变量或密钥管理服务中，不硬编码在代码中。

**纵深防御：**
- 配置文件权限控制
- 密钥轮换机制
- 使用密钥管理服务（KMS/Vault）

### 元数据

- Go版本：>=1.13
- 框架：通用
- 标签：认证, 凭证, 敏感信息

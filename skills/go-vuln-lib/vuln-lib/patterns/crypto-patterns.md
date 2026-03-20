# 密码学失败攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-CRYPTO-001 | math/rand生成安全令牌 | 高危 | 高 | security-guide |
| GO-ATK-CRYPTO-002 | 弱加密算法使用 | 高危 | 高 | security-guide |
| GO-ATK-CRYPTO-003 | 硬编码加密密钥 | 严重 | 高 | security-guide |

---

## GO-ATK-CRYPTO-001：math/rand生成安全令牌

**严重性：** 高危
**CWE：** CWE-330
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

使用 `math/rand` 而非 `crypto/rand` 生成安全相关的令牌（密码重置token、API Key、会话ID等）。`math/rand` 是伪随机数生成器，种子可预测，生成的序列可被重现。

**前置条件：**
- 安全令牌使用 `math/rand` 生成
- 令牌用于认证、授权或密码重置
- 攻击者可以观察或推断生成时间（作为种子）

### 测试方法

**检测点：**
- `import "math/rand"` 且用于生成安全相关数据
- `rand.Seed(time.Now().UnixNano())` 时间作为种子
- UUID库使用非加密安全版本

**测试步骤：**
1. 搜索代码中使用math/rand库的.go文件
2. 在找到的文件中搜索 `rand.` 调用点
3. 判断生成的随机数的用途是否为密码学用途

**适用工具：** gosec (G404), semgrep

### 漏洞模式（典型代码）

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
// 攻击: 推断种子时间，重现随机序列，预测token
```

### 数据流

```
time.Now().UnixNano() → rand.Seed → rand.Intn → 可预测的token
```

### 安全模式

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

### 元数据

- Go版本：>=1.13
- 框架：crypto/rand
- 标签：密码学, 随机数, 认证

---

## GO-ATK-CRYPTO-002：弱加密算法使用

**严重性：** 高危
**CWE：** CWE-327
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

使用已不安全的加密算法，如MD5、SHA-1（数字签名）、DES、RC4、ECB模式等。

### 测试方法

**检测点：**
- `crypto/md5`、`crypto/sha1`、`crypto/des`、`crypto/rc4`
- ECB模式使用
- 短密钥的RSA/DSA

**测试步骤：**
1. 检查代码引用的库文件是否为不安全加密算法库文件
2. 使用PowerGrep搜索加密算法关键字

### 漏洞模式（典型代码）

```go
// 文件: pkg/auth/hash.go
import (
    "crypto/md5"
    "crypto/des"
)

func HashPassword(password string) string {
    // 漏洞: MD5不应用于密码存储
    h := md5.Sum([]byte(password))
    return hex.EncodeToString(h[:])
}

func EncryptData(data, key []byte) []byte {
    // 漏洞: DES不安全，密钥过短
    block, _ := des.NewCipher(key)
    // ...
}
```

### 安全模式

```go
// 文件: pkg/auth/hash.go
import (
    "golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
    // 修复: 使用bcrypt进行密码哈希
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

func VerifyPassword(hash, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
```

**修复策略：** 使用业界推荐的算法：密码用bcrypt/argon2，对称加密用AES-GCM，签名用RSA-2048+或ECDSA。

### 元数据

- Go版本：>=1.13
- 框架：crypto, golang.org/x/crypto
- 标签：密码学, 弱算法

---

## GO-ATK-CRYPTO-003：硬编码加密密钥

**严重性：** 严重
**CWE：** CWE-321
**置信度：** 高
**来源：** security-guide

### 漏洞描述

加密密钥硬编码在代码中，一旦代码泄露，加密形同虚设。

### 测试方法

**检测点：**
- 密钥字符串常量
- `[]byte("secret-key")` 模式

### 漏洞模式（典型代码）

```go
// 文件: pkg/crypto/aes.go
var SecretKey = []byte("my-secret-key-123") // 漏洞: 硬编码密钥

func Encrypt(plaintext []byte) []byte {
    block, _ := aes.NewCipher(SecretKey)
    // ...
}
```

### 安全模式

```go
// 文件: pkg/crypto/aes.go
import "os"

func GetSecretKey() []byte {
    // 修复: 从环境变量或密钥管理服务获取
    key := os.Getenv("ENCRYPTION_KEY")
    if key == "" {
        panic("ENCRYPTION_KEY not set")
    }
    return []byte(key)
}
```

**修复策略：** 密钥存储在配置文件、环境变量或密钥管理服务中。

### 元数据

- Go版本：>=1.13
- 框架：通用
- 标签：密码学, 密钥管理

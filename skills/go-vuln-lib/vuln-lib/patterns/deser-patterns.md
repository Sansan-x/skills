# 反序列化攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-DESER-001 | JSON解码无请求体大小限制 | 中危 | 高 | security-guide |
| GO-ATK-DESER-002 | gob解码不可信数据 | 严重 | 高 | expert-case |

---

## GO-ATK-DESER-001：JSON解码无请求体大小限制

**严重性：** 中危
**CWE：** CWE-400, CWE-502
**置信度：** 高
**来源：** security-guide

### 漏洞描述

使用 `json.NewDecoder(r.Body).Decode()` 或 `io.ReadAll(r.Body)` 时未限制请求体大小，攻击者可发送超大JSON载荷耗尽服务器内存。

**前置条件：**
- HTTP处理函数读取请求体
- 未设置 `http.MaxBytesReader` 限制
- 未在反向代理层限制请求大小

### 测试方法

**检测点：**
- `json.NewDecoder(r.Body).Decode()`
- `io.ReadAll(r.Body)`
- `ioutil.ReadAll(r.Body)`
- 无 `http.MaxBytesReader` 包装

**测试步骤：**
1. 定位所有读取HTTP请求体的代码
2. 检查是否限制请求体大小
3. 发送超大请求体测试

**适用工具：** gosec (G104), 人工审计

### 漏洞模式（典型代码）

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

### 数据流

```
HTTP请求体 → json.NewDecoder().Decode() → 无大小限制 → 内存耗尽
```

### 安全模式

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

**纵深防御：**
- 在反向代理层限制请求大小
- 限制JSON字段数量和嵌套深度

### 元数据

- Go版本：>=1.13
- 框架：net/http, encoding/json
- 标签：反序列化, DoS, 资源耗尽

---

## GO-ATK-DESER-002：gob解码不可信数据

**严重性：** 严重
**CWE：** CWE-502
**置信度：** 高
**来源：** expert-case

### 漏洞描述

Go的gob包在解码时会创建新类型，攻击者可构造恶意gob数据导致任意类型实例化，潜在RCE风险。

### 测试方法

**检测点：**
- `gob.NewDecoder(r.Body).Decode()`
- 解码来自不可信源的gob数据

### 漏洞模式（典型代码）

```go
// 文件: pkg/protocol/gob.go
func DecodeMessage(r io.Reader) (interface{}, error) {
    dec := gob.NewDecoder(r)
    var msg interface{}
    // 漏洞: 解码不可信数据
    err := dec.Decode(&msg)
    return msg, err
}
```

### 安全模式

```go
// 文件: pkg/protocol/gob.go
func DecodeMessage(r io.Reader) (*SafeMessage, error) {
    // 修复: 解码到具体类型，而非interface{}
    dec := gob.NewDecoder(r)
    var msg SafeMessage
    err := dec.Decode(&msg)
    if err != nil {
        return nil, err
    }
    // 校验消息内容
    if err := validateMessage(&msg); err != nil {
        return nil, err
    }
    return &msg, nil
}
```

**修复策略：** 避免解码不可信gob数据，或解码到具体类型而非interface{}。

### 元数据

- Go版本：>=1.13
- 框架：encoding/gob
- 标签：反序列化, RCE, Go特有

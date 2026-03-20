# SSRF攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-SSRF-001 | 用户控制URL的HTTP请求无校验 | 高危 | 高 | vuln-insight |
| GO-ATK-SSRF-002 | 重定向绕过内网访问限制 | 高危 | 高 | security-guide |

---

## GO-ATK-SSRF-001：用户控制URL的HTTP请求无校验

**严重性：** 高危
**CWE：** CWE-918
**置信度：** 高
**来源：** vuln-insight

### 漏洞描述

应用接受用户提供的URL并发起HTTP请求，未校验目标地址是否为内部网络或敏感端点。攻击者可探测内部服务、访问云元数据API（如AWS 169.254.169.254）。

**前置条件：**
- 应用有代理、Webhook或URL获取功能
- 用户可控制请求的目标URL
- 未实施URL白名单或内网地址过滤

### 测试方法

**检测点：**
- `http.Get(userURL)`、`http.Post(userURL, ...)`
- `http.NewRequest` 中URL参数来源
- Webhook回调URL配置
- beego框架的 `httplib.Get/Post`

**测试步骤：**
1. 定位所有发起出站HTTP请求的代码
2. 检查URL参数是否可被用户控制
3. 尝试请求 `http://169.254.169.254/latest/meta-data/`
4. 尝试请求 `http://127.0.0.1:8080/admin`
5. 检查HTTP客户端是否跟随重定向

**适用工具：** gosec (G107), semgrep

### 漏洞模式（典型代码）

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
// 攻击: url = "http://127.0.0.1:6379/"  ← 访问内网Redis
```

### 数据流

```
c.Query("url") → http.Get(targetURL)
```

### 安全模式

```go
// 文件: pkg/handler/proxy.go
import (
    "errors"
    "net"
    "net/http"
    "net/url"
    "strings"
)

func isInternalIP(host string) bool {
    ip := net.ParseIP(host)
    if ip == nil {
        addrs, err := net.LookupIP(host)
        if err != nil || len(addrs) == 0 {
            return true
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

**纵深防御：**
- URL白名单（仅允许特定域名）
- 请求超时限制
- 响应大小限制
- 网络层隔离（运行在无外网容器中）

### 元数据

- Go版本：>=1.13
- 框架：net/http, gin, beego
- 标签：SSRF, Web, 云安全, OWASP-Top10

---

## GO-ATK-SSRF-002：重定向绕过内网访问限制

**严重性：** 高危
**CWE：** CWE-918
**置信度：** 高
**来源：** security-guide

### 漏洞描述

即使校验了初始URL，HTTP重定向可能将请求导向内部地址。需要检查重定向目标。

### 测试方法

**检测点：**
- `http.Client.CheckRedirect` 是否设置
- 自定义重定向逻辑

**测试步骤：**
1. 检查HTTP客户端配置
2. 尝试通过外部重定向服务跳转到内网

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/fetch.go
func FetchHandler(c *gin.Context) {
    targetURL := c.Query("url")
    // 初始URL校验
    u, _ := url.Parse(targetURL)
    if isInternalIP(u.Hostname()) {
        c.String(403, "禁止")
        return
    }
    // 漏洞: 默认客户端会跟随重定向到内部地址
    resp, _ := http.Get(targetURL)
    // ...
}
// 攻击: 设置外部重定向服务，跳转到 http://127.0.0.1/admin
```

### 安全模式

```go
// 文件: pkg/handler/fetch.go
func FetchHandler(c *gin.Context) {
    targetURL := c.Query("url")
    u, _ := url.Parse(targetURL)
    if isInternalIP(u.Hostname()) {
        c.String(403, "禁止")
        return
    }
    
    // 修复: 自定义CheckRedirect校验每个重定向目标
    client := &http.Client{
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if isInternalIP(req.URL.Hostname()) {
                return errors.New("重定向到内部地址")
            }
            return nil
        },
    }
    resp, _ := client.Get(targetURL)
    // ...
}
```

**修复策略：** 为HTTP客户端设置 `CheckRedirect` 回调，校验每个重定向目标。

### 元数据

- Go版本：>=1.13
- 框架：net/http
- 标签：SSRF, 重定向, 绕过

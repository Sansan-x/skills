# 跨站脚本(XSS)攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-XSS-001 | 模板输出未转义用户输入 | 高危 | 高 | security-guide |
| GO-ATK-XSS-002 | fmt.Fprintf直接输出到响应 | 高危 | 高 | security-guide |

---

## GO-ATK-XSS-001：模板输出未转义用户输入

**严重性：** 高危
**CWE：** CWE-79
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

Go后端渲染HTML模板时，直接输出用户输入未进行HTML转义，可注入恶意JavaScript脚本。

**前置条件：**
- 使用 `html/template` 或 `text/template` 渲染HTML
- 用户输入直接输出到模板
- 未使用模板自动转义机制

### 测试方法

**检测点：**
- `template.Execute(w, data)` 中data包含用户输入
- `text/template` 使用（无自动转义）
- 模板中使用 `{{.Field | safe}}` 绕过转义

**测试步骤：**
1. 搜索 `text/template` 和 `html/template` 使用
2. 检查模板渲染的数据来源
3. 注入 `<script>alert(1)</script>` 测试

**适用工具：** semgrep, gosec

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/page.go
import (
    "fmt"
    "net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
    user_pro := r.FormValue("name")
    // 漏洞: 直接输出用户输入到响应
    fmt.Fprintf(w, "%s", user_pro)
}
// 攻击: name = "<script>alert(document.cookie)</script>"
```

### 数据流

```
r.FormValue("name") → fmt.Fprintf(w, "%s", userInput) → XSS
```

### 安全模式

```go
// 文件: pkg/handler/page.go
import (
    "html/template"
    "net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
    user_pro := r.FormValue("name")
    // 修复: 使用html/template自动转义
    tmpl := template.Must(template.New("page").Parse(`<html><body>{{.}}</body></html>`))
    tmpl.Execute(w, user_pro)
}

// 或使用HTMLEscapeString
func xss_handler(s string) string {
    return template.HTMLEscapeString(s)
}
```

**修复策略：** 使用 `html/template` 渲染HTML，自动转义；或使用 `HTMLEscapeString` 手动转义。

**纵深防御：**
- 前后端分离，API返回JSON
- Content-Security-Policy头
- HttpOnly Cookie

### 元数据

- Go版本：>=1.13
- 框架：html/template, net/http
- 标签：XSS, Web, OWASP-Top10

---

## GO-ATK-XSS-002：fmt.Fprintf直接输出到响应

**严重性：** 高危
**CWE：** CWE-79
**置信度：** 高
**来源：** security-guide

### 漏洞描述

使用 `fmt.Fprintf` 或 `fmt.Fprint` 直接将用户输入写入HTTP响应，无任何转义。

### 测试方法

**检测点：**
- `fmt.Fprintf(w, ...)` 包含用户输入
- `w.Write()` 写入未转义的用户数据

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/response.go
func EchoHandler(w http.ResponseWriter, r *http.Request) {
    msg := r.URL.Query().Get("msg")
    // 漏洞: 直接输出
    fmt.Fprintf(w, "You said: %s", msg)
}
```

### 安全模式

```go
// 文件: pkg/handler/response.go
import "html/template"

func EchoHandler(w http.ResponseWriter, r *http.Request) {
    msg := r.URL.Query().Get("msg")
    // 修复: HTML转义
    safeMsg := template.HTMLEscapeString(msg)
    fmt.Fprintf(w, "You said: %s", safeMsg)
}
```

**修复策略：** 输出前使用 `template.HTMLEscapeString` 转义。

### 元数据

- Go版本：>=1.13
- 框架：net/http
- 标签：XSS, Web

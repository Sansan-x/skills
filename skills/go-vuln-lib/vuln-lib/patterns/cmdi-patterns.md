# 命令注入攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-CMDI-001 | shell -c执行用户拼接命令 | 严重 | 高 | expert-case |
| GO-ATK-CMDI-002 | exec.Command参数注入 | 高危 | 高 | security-guide |
| GO-ATK-CMDI-003 | 白名单校验不严格绕过 | 高危 | 高 | security-guide |

---

## GO-ATK-CMDI-001：shell -c执行用户拼接命令

**严重性：** 严重
**CWE：** CWE-78
**置信度：** 高
**来源：** expert-case

### 漏洞描述

通过 `exec.Command("sh", "-c", userInput)` 执行命令时，用户输入中的 shell 元字符（`;`、`&&`、`|`、`` ` ``、`$()`）会被 shell 解释执行。这是最危险的命令注入形式。

**影响：** 攻击者可在服务器上执行任意系统命令，实现远程代码执行（RCE）。

**前置条件：**
- 应用调用 exec.Command 并通过 shell（sh -c）执行
- 用户输入被拼接到命令字符串中
- 无输入净化或命令白名单

### 测试方法

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

**自动化提示：** gosec规则G204; semgrep规则: go.lang.security.audit.command.tainted-exec-call

### 漏洞模式（典型代码）

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
// 攻击: host = "127.0.0.1$(whoami)"
```

### 数据流

```
c.Query("host") → fmt.Sprintf("ping -c 3 %s", host) → exec.Command("sh", "-c", cmdStr)
```

### 安全模式

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
- 使用seccomp限制系统调用

### 元数据

- Go版本：>=1.13
- 框架：os/exec, gin, echo
- 标签：命令注入, RCE, Web, OWASP-Top10

---

## GO-ATK-CMDI-002：exec.Command参数注入

**严重性：** 高危
**CWE：** CWE-78
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

即使不使用 `sh -c`，如果用户输入作为命令参数传递，且该参数被目标命令以特殊方式解释，仍可能存在命令注入。例如，`tar` 命令的 `--checkpoint-action` 参数可执行任意命令。

**前置条件：**
- 用户输入作为 exec.Command 的参数
- 目标命令具有危险参数选项

### 测试方法

**检测点：**
- `exec.Command(cmdName, args...)` 中 args 来源
- 用户输入到达命令参数位置

**测试步骤：**
1. 识别所有 exec.Command 调用
2. 分析每个参数的来源
3. 查阅目标命令的危险参数选项

### 漏洞模式（典型代码）

```go
// 文件: pkg/util/archive.go
func ExtractTarGz(tarPath, destDir string) error {
    // 漏洞: tarPath用户可控，可注入--checkpoint-action
    cmd := exec.Command("tar", "-xzf", tarPath, "-C", destDir)
    return cmd.Run()
}
// 攻击: tarPath = "archive.tar.gz --checkpoint-action=exec=sh shell.sh"
```

### 安全模式

```go
// 文件: pkg/util/archive.go
import (
    "archive/tar"
    "compress/gzip"
    "io"
    "os"
    "path/filepath"
    "strings"
)

func ExtractTarGz(tarPath, destDir string) error {
    // 修复: 使用Go原生库解压，避免调用外部命令
    f, err := os.Open(tarPath)
    if err != nil {
        return err
    }
    defer f.Close()

    gzr, err := gzip.NewReader(f)
    if err != nil {
        return err
    }
    defer gzr.Close()

    tr := tar.NewReader(gzr)
    destDir, _ = filepath.Abs(destDir)

    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }

        // 安全校验路径
        target := filepath.Join(destDir, hdr.Name)
        target = filepath.Clean(target)
        if !strings.HasPrefix(target, destDir+string(os.PathSeparator)) {
            return errors.New("非法路径")
        }
        // ... 安全写入文件
    }
    return nil
}
```

**修复策略：** 优先使用Go原生库实现功能，避免调用外部命令；如必须调用，严格校验参数。

### 元数据

- Go版本：>=1.13
- 框架：os/exec
- 标签：命令注入, RCE

---

## GO-ATK-CMDI-003：白名单校验不严格绕过

**严重性：** 高危
**CWE：** CWE-78
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

使用正则白名单校验但规则不严格，允许危险字符通过。

### 测试方法

**检测点：**
- 正则白名单中包含危险字符（`;`、`&`、`$`、`|`）
- 仅使用黑名单而非白名单

**测试步骤：**
1. 检查白名单正则表达式
2. 尝试用危险字符绕过

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/exec.go
var whiteRegex = regexp.MustCompile(`[^0-9a-zA-Z/.;]+`) // 漏洞: 允许分号

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
    param := r.URL.Query().Get("param")
    if whiteRegex.MatchString(param) {
        return
    }
    cmd := "ls " + param
    out, _ := exec.Command("bash", "-c", cmd).Output()
    w.Write(out)
}
// 攻击: param = ";whoami"  ← 分号绕过白名单
```

### 安全模式

```go
// 文件: pkg/handler/exec.go
// 修复: 更严格的白名单，仅允许必要字符
var safeRegex = regexp.MustCompile(`^[0-9a-zA-Z/_-]+$`)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
    param := r.URL.Query().Get("param")
    if !safeRegex.MatchString(param) {
        http.Error(w, "invalid param", 400)
        return
    }
    // 或者更好的方式: 完全避免shell执行
    out, _ := exec.Command("ls", param).Output()
    w.Write(out)
}
```

**修复策略：** 使用最严格的白名单，仅允许业务必需的字符集。

### 元数据

- Go版本：>=1.13
- 框架：os/exec
- 标签：命令注入, 绕过

# 路径穿越攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-PTR-001 | Zip Slip任意文件写入 | 高危 | 高 | expert-case |
| GO-ATK-PTR-002 | 用户输入直接拼接文件路径 | 高危 | 高 | security-guide |

---

## GO-ATK-PTR-001：Zip Slip任意文件写入

**严重性：** 高危
**CWE：** CWE-22
**置信度：** 高
**来源：** expert-case

### 漏洞描述

解压ZIP文件时，压缩包中的文件名可包含 `../` 路径穿越序列。如果提取逻辑未校验文件名，攻击者构造的ZIP文件可在目标目录之外写入任意文件，可能覆盖系统关键文件或写入webshell。

**前置条件：**
- 应用接受ZIP/TAR文件上传并解压
- 解压时使用 `filepath.Join(destDir, entry.Name)` 构建路径
- 未校验结果路径是否仍在目标目录内

### 测试方法

**检测点：**
- `archive/zip.OpenReader` 或 `archive/tar.NewReader` 使用
- `filepath.Join` 与解压文件名组合
- 未调用 `filepath.Clean` 或未检查路径前缀

**测试步骤：**
1. 定位所有ZIP/TAR解压代码
2. 检查是否校验解压文件名中的 `../`
3. 构造包含 `../../../etc/cron.d/backdoor` 的恶意ZIP测试

**适用工具：** semgrep, gosec

### 漏洞模式（典型代码）

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
// 攻击: 构造ZIP，包含文件名 "../../../var/www/html/shell.php"
```

### 数据流

```
恶意ZIP → f.Name="../../../etc/passwd" → filepath.Join(destDir, f.Name) → 路径穿越
```

### 安全模式

```go
// 文件: pkg/util/archive.go
import (
    "archive/zip"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
)

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

**纵深防御：**
- 限制解压文件总数量
- 限制解压后总大小
- 使用沙箱目录解压
- 禁止解压可执行文件

### 元数据

- Go版本：>=1.13
- 框架：archive/zip, archive/tar
- 标签：路径穿越, 文件操作, Zip Slip

---

## GO-ATK-PTR-002：用户输入直接拼接文件路径

**严重性：** 高危
**CWE：** CWE-22
**置信度：** 高
**来源：** security-guide

### 漏洞描述

用户输入直接拼接到文件路径中，未进行校验，可导致读取或写入任意文件。

### 测试方法

**检测点：**
- `os.Open(userPath)`
- `filepath.Join(baseDir, userInput)`
- `ioutil.ReadFile(userInput)`

**测试步骤：**
1. 搜索文件操作函数调用
2. 检查路径参数是否来自用户输入
3. 构造 `../etc/passwd` 测试

### 漏洞模式（典型代码）

```go
// 文件: pkg/handler/file.go
func DownloadHandler(c *gin.Context) {
    filename := c.Query("file") // SOURCE
    // 漏洞: 用户输入直接拼接到路径
    filepath := "/var/data/" + filename
    data, err := os.ReadFile(filepath) // SINK
    if err != nil {
        c.String(404, "文件不存在")
        return
    }
    c.Data(200, "application/octet-stream", data)
}
// 攻击: file = "../../../etc/passwd"
```

### 安全模式

```go
// 文件: pkg/handler/file.go
import (
    "path/filepath"
    "strings"
)

var allowedDir = "/var/data"

func DownloadHandler(c *gin.Context) {
    filename := c.Query("file")
    
    // 修复: 清理并校验路径
    fullPath := filepath.Join(allowedDir, filename)
    fullPath = filepath.Clean(fullPath)
    
    if !strings.HasPrefix(fullPath, allowedDir+string(os.PathSeparator)) {
        c.String(403, "非法路径")
        return
    }
    
    data, err := os.ReadFile(fullPath)
    if err != nil {
        c.String(404, "文件不存在")
        return
    }
    c.Data(200, "application/octet-stream", data)
}
```

**修复策略：** 使用 `filepath.Clean` 清理路径，校验结果路径是否在允许的目录内。

### 元数据

- Go版本：>=1.13
- 框架：os, path/filepath
- 标签：路径穿越, 文件操作

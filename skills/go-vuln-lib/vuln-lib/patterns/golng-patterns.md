# Go语言特有攻击模式集

## 模式列表

| ID | 名称 | 严重性 | 置信度 | 来源 |
|----|------|--------|--------|------|
| GO-ATK-GOLNG-001 | unsafe.Pointer类型转换绕过类型安全 | 严重 | 中 | security-guide |
| GO-ATK-GOLNG-002 | reflect包动态方法调用导致任意方法执行 | 高危 | 高 | vuln-insight |
| GO-ATK-GOLNG-003 | 数组/切片越界导致panic | 中危 | 高 | security-guide |
| GO-ATK-GOLNG-004 | 空指针解引用导致panic | 中危 | 高 | security-guide |
| GO-ATK-GOLNG-005 | goroutine泄漏导致资源耗尽 | 中危 | 高 | security-guide |

---

## GO-ATK-GOLNG-001：unsafe.Pointer类型转换绕过类型安全

**严重性：** 严重
**CWE：** CWE-843
**置信度：** 中
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

`unsafe.Pointer` 可将任意类型指针相互转换，绕过Go的类型系统。如果攻击者能控制被转换的字节数据，可覆盖结构体字段值（如权限标志位），甚至实现任意内存读写。Go无C语言的安全函数概念，一旦出现内存问题风险更严重。

**前置条件：**
- 代码使用 `unsafe.Pointer` 进行类型转换
- 被转换的数据来源可被外部影响
- 目标类型包含安全敏感字段

### 测试方法

**检测点：**
- 所有 `import "unsafe"` 的文件
- `unsafe.Pointer` 的类型转换表达式
- `uintptr` 算术运算

**测试步骤：**
1. 搜索所有使用 `unsafe` 包的代码
2. 分析 `unsafe.Pointer` 转换的源数据是否可被外部控制
3. 检查目标类型结构体中是否有安全敏感字段
4. 验证是否有边界检查

**适用工具：** gosec (G103), 人工审计

### 漏洞模式（典型代码）

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

### 数据流

```
网络数据 → []byte → unsafe.Pointer转换 → Header结构体 → 权限检查绕过
```

### 安全模式

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

**纵深防御：**
- 避免使用unsafe，除非符合安全规范例外场景
- 对unsafe使用进行代码审查和标注

### 元数据

- Go版本：>=1.13
- 框架：unsafe
- 标签：内存安全, 类型混淆, Go特有

---

## GO-ATK-GOLNG-002：reflect包动态方法调用导致任意方法执行

**严重性：** 高危
**CWE：** CWE-470
**置信度：** 高
**来源：** vuln-insight

### 漏洞描述

使用 `reflect.ValueOf(obj).MethodByName(userInput)` 允许基于用户输入动态调用对象的任意导出方法，攻击者可调用 `Delete`、`Reset`、`Destroy` 等危险方法。

**前置条件：**
- 代码使用 reflect 包进行动态方法调用
- 方法名来源于用户输入
- 目标对象拥有安全敏感的导出方法

### 测试方法

**检测点：**
- `reflect.ValueOf().MethodByName()`
- `reflect.Value.Call()`

**测试步骤：**
1. 搜索reflect包的使用
2. 检查MethodByName参数是否用户可控
3. 枚举目标对象的所有导出方法

### 漏洞模式（典型代码）

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

### 安全模式

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

### 元数据

- Go版本：>=1.13
- 框架：reflect
- 标签：反射, 任意方法调用, Go特有

---

## GO-ATK-GOLNG-003：数组/切片越界导致panic

**严重性：** 中危
**CWE：** CWE-129
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

数组或切片下标不在合法索引范围内，会导致panic异常。Go在运行时检查越界，越界会直接panic导致程序崩溃。

**前置条件：**
- 索引值来自外部输入或计算结果
- 未对索引进行边界检查

### 测试方法

**检测点：**
- 外部数据直接用于数组索引
- `data[i]` 无边界检查
- 切片操作 `data[start:end]` 无边界检查
- GoSDK函数如 `binary.BigEndian.Uint32` 调用前无长度检查

**测试步骤：**
1. 搜索所有数组/切片访问 `data[i]`
2. 检查索引i是否有边界检查
3. 使用go test -race检测

### 漏洞模式（典型代码）

```go
// 文件: pkg/protocol/decoder.go
func (g *Guti5G) DecodeIE(data []byte) error {
    // 漏洞: data长度未校验
    g.Plmn = data[:3]
    g.AmfRegionId = uint32(data[3])
    g.AmfSetId = uint32(((uint16(data[4]) << 2) & 0x3FC) | uint16(data[5]>>6)&0x3)
    // 如果len(data) < 7, 访问data[6]会panic
    g.AmfPointer = uint32(data[5] & 0x03F)
    g.Tmsi5G = binary.BigEndian.Uint32(data[6:])
    return nil
}
```

### 安全模式

```go
// 文件: pkg/protocol/decoder.go
func (g *Guti5G) DecodeIE(data []byte) error {
    // 修复: 边界检查
    if len(data) < 10 {
        return errors.New("数据长度不足")
    }
    g.Plmn = data[:3]
    g.AmfRegionId = uint32(data[3])
    g.AmfSetId = uint32(((uint16(data[4]) << 2) & 0x3FC) | uint16(data[5]>>6)&0x3)
    g.AmfPointer = uint32(data[5] & 0x03F)
    g.Tmsi5G = binary.BigEndian.Uint32(data[6:])
    return nil
}
```

**修复策略：** 访问数组/切片前检查长度。

### 元数据

- Go版本：>=1.13
- 框架：通用
- 标签：panic, 越界, Go特有

---

## GO-ATK-GOLNG-004：空指针解引用导致panic

**严重性：** 中危
**CWE：** CWE-476
**置信度：** 高
**来源：** security-guide (华为白盒测试指导)

### 漏洞描述

对值为nil的指针执行解引用操作，会抛出panic。

### 测试方法

**检测点：**
- `*ptr` 无nil检查
- `ptr.Field` 无nil检查
- 链式调用 `a.b.c` 无中间nil检查

**测试步骤：**
1. 搜索指针解引用操作
2. 检查是否有nil判断

### 漏洞模式（典型代码）

```go
// 文件: pkg/validator/validate.go
type NFComposition struct {
    NFBasicAttr *NFBasicAttribute `json:"NFBasicAttr"`
}

func (x *CreateSlice) Valid(d models.InVNFSliceDeployment) error {
    for _, nf := range d.NFList {
        // 漏洞: 未检查nf.NFBasicAttr是否为nil
        if _, ok := v.NfSet[*nf.NFBasicAttr.NFType]; !ok {
            break
        }
    }
    return nil
}
// 如果nf.NFBasicAttr为nil，对nil指针解引用导致panic
```

### 安全模式

```go
// 文件: pkg/validator/validate.go
func (x *CreateSlice) Valid(d models.InVNFSliceDeployment) error {
    for _, nf := range d.NFList {
        // 修复: nil检查
        if nf.NFBasicAttr == nil {
            return errors.New("NFBasicAttr不能为空")
        }
        if _, ok := v.NfSet[*nf.NFBasicAttr.NFType]; !ok {
            break
        }
    }
    return nil
}
```

**修复策略：** 解引用前检查指针是否为nil。

### 元数据

- Go版本：>=1.13
- 框架：通用
- 标签：panic, 空指针, Go特有

---

## GO-ATK-GOLNG-005：goroutine泄漏导致资源耗尽

**严重性：** 中危
**CWE：** CWE-400
**置信度：** 高
**来源：** security-guide

### 漏洞描述

goroutine被创建后永不退出，持续消耗内存和CPU资源。常见于缺少退出机制、channel阻塞、无限循环等场景。

### 测试方法

**检测点：**
- `go func()` 无退出条件
- goroutine中无限 `for {}` 循环
- 向无缓冲channel发送但无接收者
- 从channel接收但无发送者

**测试步骤：**
1. 搜索所有 `go` 关键字启动的goroutine
2. 分析每个goroutine的退出条件
3. 使用 `runtime.NumGoroutine()` 监控

### 漏洞模式（典型代码）

```go
// 文件: pkg/worker/worker.go
func StartWorker(jobs <-chan Job) {
    for {
        go func(j Job) {
            // 漏洞: 无退出机制，每个任务创建一个永不退出的goroutine
            for {
                process(j)
                time.Sleep(time.Second)
            }
        }(<-jobs)
    }
}
```

### 安全模式

```go
// 文件: pkg/worker/worker.go
func StartWorker(ctx context.Context, jobs <-chan Job) {
    for {
        select {
        case <-ctx.Done():
            return // 修复: 提供退出机制
        case j := <-jobs:
            go func(j Job) {
                process(j)
                // 处理完成后退出
            }(j)
        }
    }
}
```

**修复策略：** 为goroutine提供退出机制（context、done channel、退出标志）。

### 元数据

- Go版本：>=1.13
- 框架：goroutine
- 标签：资源泄漏, goroutine, Go特有

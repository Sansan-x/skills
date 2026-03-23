# Go污点分析技术指南

## 概述

污点分析（Taint Analysis）追踪不可信数据在程序中的传播路径，检测是否有未经净化的数据到达安全敏感操作。本指南专注于Go语言的污点分析技术。

## 1. 污点源（Source）分类

### 1.1 网络输入（最高优先级）

```go
// HTTP请求 — Go标准库
r.Body                           // 请求体
r.URL.Query()                    // URL查询参数
r.URL.Path                       // URL路径
r.Header.Get("X-Custom")        // 请求头
r.FormValue("key")              // 表单值
r.PostFormValue("key")          // POST表单值
r.MultipartForm                  // 多部分表单
r.Cookie("name")                // Cookie值
r.Host                          // Host头
r.RemoteAddr                    // 客户端地址（通常不可作为安全依据）

// HTTP请求 — Gin框架
c.Param("id")                   // 路径参数
c.Query("key")                  // 查询参数
c.PostForm("key")               // POST表单
c.ShouldBind(&obj)              // 请求绑定
c.GetRawData()                  // 原始请求体

// HTTP请求 — Echo框架
c.Param("id")
c.QueryParam("key")
c.FormValue("key")
c.Bind(&obj)

// gRPC请求
// 所有gRPC方法的request参数
func (s *server) Method(ctx context.Context, req *pb.Request) (*pb.Response, error)

// 原始网络连接
conn.Read(buf)                  // TCP读取
udpConn.ReadFromUDP(buf)       // UDP读取
```

### 1.2 文件和环境输入

```go
// 文件读取
os.ReadFile(path)
os.Open(path) → file.Read()
bufio.NewReader(file).ReadLine()

// 环境变量
os.Getenv("KEY")
os.LookupEnv("KEY")

// 命令行参数
os.Args[1:]
flag.String("key", "", "desc")

// 标准输入
bufio.NewReader(os.Stdin).ReadLine()
```

### 1.3 数据存储输入

```go
// 数据库查询结果
rows.Scan(&var1, &var2)
row.Scan(&var1)

// Redis/缓存
client.Get(ctx, "key").Result()

// 消息队列
msg := <-consumer.Messages()
```

### 1.4 5GC协议输入

```go
// NAS消息（来自UE，不可信）
nasMsg.Decode(rawBytes)
registrationRequest.MobileIdentity5GS

// NGAP消息（来自gNB，部分可信）
ngapMsg.Decode(rawBytes)
initiatingMessage.Value

// GTP-U数据包（来自UE/gNB）
gtpMsg.Decode(rawBytes)
gtpMsg.TEID

// PFCP消息（来自UPF/SMF，内部可信但需验证）
pfcpMsg.Decode(rawBytes)
sessionEstablishmentRequest.CreatePDR

// SBI请求（来自其他NF，需要mTLS验证）
sbiRequest.Body
sbiRequest.Header.Get("3gpp-Sbi-Target-apiRoot")
```

## 2. 污点汇聚点（Sink）分类

### 2.1 命令执行 — CRITICAL

```go
exec.Command(name, args...)      // 参数不经shell解释
exec.Command("sh", "-c", cmd)    // 经过shell，高危
syscall.Exec(path, args, env)
```

**安全判断**：
- `exec.Command(固定命令, 污点参数)` — 通常安全（参数不经过shell解释）
- `exec.Command("sh", "-c", 包含污点的字符串)` — 危险
- 使用 `strings.Contains(tainted, ";")` 等检查不够——需要正确转义或避免shell

### 2.2 SQL查询 — CRITICAL

```go
db.Query(query)                  // query中包含污点
db.Exec(query)                   
tx.Query(query)
```

**安全判断**：
- `db.Query("SELECT ... WHERE id = ?", taintedID)` — 安全（参数化）
- `db.Query("SELECT ... WHERE id = '" + taintedID + "'")` — 危险
- `db.Query(fmt.Sprintf("SELECT ... WHERE id = '%s'", taintedID))` — 危险

### 2.3 文件操作 — HIGH

```go
os.Open(path)                    // path包含污点
os.Create(path)
os.ReadFile(path)
os.WriteFile(path, data, perm)
filepath.Join(base, tainted)     // 可能路径遍历
```

### 2.4 网络请求 — HIGH

```go
http.Get(url)                    // url包含污点 — SSRF
http.Post(url, ct, body)
client.Do(req)                   // req.URL包含污点
net.Dial(network, address)       // address包含污点
```

### 2.5 响应输出 — MEDIUM

```go
fmt.Fprintf(w, tainted)          // 如果是HTML，XSS
w.Write(taintedBytes)
template.Execute(w, tainted)     // text/template不自动转义
json.NewEncoder(w).Encode(obj)   // obj含敏感字段可能信息泄露
```

### 2.6 日志输出 — LOW

```go
log.Printf("user: %s", tainted) // 日志注入 / 信息泄露
slog.Info("event", "data", tainted)
```

### 2.7 密码学操作 — HIGH

```go
cipher.NewCBCEncrypter(block, iv) // iv不应来自用户
hmac.New(hash, key)               // key不应来自不可信源
```

## 3. 污点传播规则

### 3.1 直接传播

```go
// 赋值传播
y := x              // x污点 → y污点

// 字符串操作传播
s := "prefix" + x   // x污点 → s污点
s := fmt.Sprintf("%s", x)  // x污点 → s污点
s := strings.Join([]string{x, "suffix"}, "/")  // 传播

// 切片操作传播
slice = append(slice, x)   // x污点 → slice最后一个元素污点
sub := slice[i:j]          // 如果slice中有污点元素，sub也是

// Map操作传播
m[key] = x          // x污点 → m[key]污点
v := m[taintedKey]  // 如果key是污点，v可能不受信任

// 结构体字段传播
obj.Field = x       // x污点 → obj.Field污点
```

### 3.2 函数调用传播

```go
// 参数到返回值的传播
func process(input string) string {
    return strings.ToUpper(input) // input污点 → 返回值污点
}

// 方法调用传播
builder.WriteString(tainted) // tainted → builder内部状态
result := builder.String()    // builder状态 → result污点

// 接口方法传播
var w io.Writer = &buf
w.Write(taintedBytes) // taintedBytes → buf内部状态
```

### 3.3 Go特有传播

```go
// Channel传播
ch <- tainted        // 发送端
received := <-ch     // received 继承 tainted 的污点

// Goroutine闭包传播
go func() {
    use(tainted)     // tainted通过闭包捕获传播到新goroutine
}()

// Defer传播
defer cleanup(tainted) // tainted在函数返回后仍被使用

// Context Value传播
ctx = context.WithValue(ctx, key, tainted)
val := ctx.Value(key) // val 继承 tainted 的污点

// 类型断言传播
concrete := iface.(ConcreteType) // iface污点 → concrete污点

// Reflect传播
v := reflect.ValueOf(tainted)
result := v.Interface() // 污点通过reflect传播
```

## 4. 净化函数识别

### 4.1 有效的净化

```go
// 类型转换净化（字符串→数值消除注入）
n, err := strconv.Atoi(tainted)
if err != nil { return err }
// n 不再携带字符串注入的污点

// 白名单验证
if tainted != "allowed_value_1" && tainted != "allowed_value_2" {
    return errors.New("invalid value")
}
// 通过白名单后的值是安全的

// 正则匹配验证
if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(tainted) {
    return errors.New("invalid format")
}
// 通过严格正则后的值对于注入是安全的

// HTML转义
safe := html.EscapeString(tainted)
// safe 对于HTML上下文是安全的

// URL编码
safe := url.QueryEscape(tainted)
// safe 对于URL参数上下文是安全的

// 参数化查询
db.Query("SELECT * FROM t WHERE id = ?", tainted)
// 参数化查询的占位符消除了SQL注入

// 路径净化
cleaned := filepath.Clean(filepath.Join(baseDir, tainted))
if !strings.HasPrefix(cleaned, filepath.Clean(baseDir) + string(os.PathSeparator)) {
    return errors.New("path traversal")
}
// 前缀检查后的路径是安全的
```

### 4.2 无效的"净化"（常见误区）

```go
// 不完整的黑名单过滤
safe := strings.ReplaceAll(tainted, "'", "")
// 可以用其他字符绕过，如 " 或 \

// 长度截断
safe := tainted[:10]
// 截断不改变内容性质，仍可能包含恶意payload

// Base64编解码
encoded := base64.StdEncoding.EncodeToString([]byte(tainted))
decoded, _ := base64.StdEncoding.DecodeString(encoded)
// 往返编码不消除污点

// strings.Contains检查后继续使用原值
if strings.Contains(tainted, "..") {
    return errors.New("invalid")
}
// 只检查了一种攻击向量，可能遗漏其他
```

## 5. 跨过程分析

### 5.1 函数摘要

对于频繁调用的函数，建立污点传播摘要：

```
函数签名 → 污点传播关系
func foo(a, b string) (string, error)
  摘要: {
    返回值[0] = taint(a) | taint(b)  // 返回值受a和b的污点影响
    返回值[1] = clean                 // error不携带输入污点
  }
```

### 5.2 接口多态分析

```go
type Handler interface {
    Handle(input string) string
}

// 需要分析所有实现了Handler接口的类型
// type A struct{} func (a A) Handle(input string) string { ... }
// type B struct{} func (b B) Handle(input string) string { ... }
// 对每个实现分别进行污点分析
```

### 5.3 回调和高阶函数

```go
// 高阶函数中的污点传播
func Map(items []string, fn func(string) string) []string {
    result := make([]string, len(items))
    for i, item := range items {
        result[i] = fn(item) // fn的行为决定污点传播
    }
    return result
}
```

## 6. Go特定污点分析挑战

### 6.1 接口断言后的类型信息丢失

当通过 `interface{}` 传递数据时，类型信息丢失，污点分析需要追踪具体类型：

```go
func store(ctx context.Context, data interface{}) {
    // data的具体类型和污点信息需要从调用者推导
}
```

### 6.2 反射调用

反射使得静态分析困难：

```go
method := reflect.ValueOf(obj).MethodByName(taintedName)
result := method.Call(args)
// taintedName控制了调用哪个方法，增加了攻击面
```

### 6.3 goroutine生命周期

```go
func process(input string) {
    ch := make(chan string)
    go func() {
        result := transform(input) // 污点通过闭包传播
        ch <- result               // 污点通过channel传播
    }()
    output := <-ch                  // output 携带污点
    sink(output)                    // 污点到达sink
}
// 需要跨goroutine追踪污点
```

### 6.4 错误路径中的污点

```go
data, err := parseInput(tainted)
if err != nil {
    // 错误路径：tainted可能部分解析
    log.Printf("parse error for input: %s", tainted) // 日志注入/信息泄露
    return err
}
// 正常路径：data携带tainted的污点
```

## 7. 实战污点分析流程

### Step 1: 枚举Source和Sink

使用Phase 2中的grep命令枚举所有Source和Sink位置。

### Step 2: 构建调用图

```
Source函数 → 调用的函数列表 → ... → Sink函数
```

对每个Source，追踪包含该Source的函数的所有调用者，建立调用链。

### Step 3: 逐路径分析

对每条Source→Sink路径：
1. 从Source开始，标记污点变量
2. 沿代码执行路径追踪污点传播
3. 在每个函数调用边界，分析参数传播
4. 检查路径上是否有有效净化
5. 如果污点到达Sink且无净化，报告漏洞

### Step 4: 记录数据流

为每个发现的漏洞记录完整数据流：

```
[Source] r.URL.Query().Get("id") at api/handler.go:15
  → [Propagate] 赋值 id := ... at api/handler.go:15
  → [Call] service.GetUser(id) at api/handler.go:20
  → [Propagate] 参数传入 func GetUser(userID string) at service/user.go:8
  → [Propagate] 字符串拼接 query := "SELECT ... " + userID at service/user.go:12
  → [Sink] db.Query(query) at service/user.go:13
  → [Result] SQL注入漏洞
```

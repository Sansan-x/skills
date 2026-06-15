# Go 语言特有漏洞模式库（增强版）

本参考文件为 `go-audit` 阶段4的漏洞模式匹配提供 Go 语言特有攻击面补充，重点覆盖：
并发与 goroutine/Channel 生命周期、`context.Context` 传递/超时/取消、slice header/cap 底层暴露、`sync.Map`/map 并发竞态、`unsafe`/`reflect` 类型混淆、`cgo` 指针传递与回调 use-after-free 等。

---

## 1. Goroutine 泄漏与 goroutine 永久阻塞（Channel 未被消费）

**CWE:** CWE-400（不受控制的资源消耗）
**风险等级:** 高危

### 危险特征
- 在函数内启动 goroutine，但在调用方退出/超时/取消时没有可靠的退出与排空（drain）
- 使用无缓冲/小缓冲 channel，接收端可能永远不执行（或条件分支导致不消费）
- 只对业务流程做 `return`，未对 goroutine 的退出条件做统一管理

### Sink API/行为
- `go func() { ch <- ... }()`：向 channel 发送但下游不消费
- `select { case ch <- ...: ... }`：没有在 `ctx.Done()` 触发时停止
- 从不关闭 channel：导致 `for v := range ch` 端永不结束

### 漏洞模式（示例）
```go
// 文件: pkg/worker/worker.go
// 风险: 调用方超时退出但未消费结果 channel，goroutine 永久阻塞
func RunJob(ctx context.Context, in <-chan int) <-chan string {
	out := make(chan string) // SINK: 无缓冲，可能导致发送阻塞
	go func() {
		for v := range in {
			// 未监听 ctx.Done()，当调用方不再读取 out 时发送会阻塞
			out <- doWork(v) // SINK
		}
		// 永远不关闭 out 也会导致接收端 range 卡住
	}()
	return out
}
```

### 修复要点
- 所有 goroutine 必须具备统一退出路径：优先使用 `ctx.Done()` + 取消后停止生产并关闭/退出消费通道
- 如果必须返回结果 channel：在 goroutine 退出时 `close(out)`，并确保发送方在取消后不再发送
- 对发送端使用 `select` 同时保护 `ctx.Done()`：
  - `select { case out <- x: case <-ctx.Done(): return }`

---

## 2. Channel 退出条件缺失导致死锁/逻辑绕过

**CWE:** CWE-362（竞态条件）/ CWE-400（资源消耗）
**风险等级:** 高危

### 危险特征
- `for range ch` 的结束依赖关闭，但关闭条件不满足或在异常分支缺失
- 采用多个 goroutine 互相等待（例如 A 等 B 的结果、B 等 A 继续）
- 对输入/输出 channel 的 close/reopen 时序缺少严格约束

### Sink API/行为
- `for v := range ch { ... }`：若 ch 未关闭则永不返回
- 两侧都使用阻塞发送：`ch1 <- ...` 与 `ch2 <- ...` 互相等待

### 漏洞模式（示例）
```go
// 文件: pkg/pipeline/pipeline.go
// 风险: 输入 channel 未关闭，导致 for range 永不结束
func Pipeline(in <-chan Request) <-chan Response {
	out := make(chan Response)
	go func() {
		for req := range in { // SINK: 依赖 in 被关闭
			out <- handle(req) // 若 out 不被消费会阻塞
		}
		close(out)
	}()
	return out
}
```

### 修复要点
- 明确 channel 生命周期：谁负责 close、何时 close、close 是否在所有异常分支都执行
- 在 pipeline 的入口/边界接入 `ctx.Done()`，保证取消时停止等待并关闭输出
- 对阻塞发送/接收使用 `select` 保护取消与超时

---

## 3. `context.Context` 不正确传递、无超时/无 cancel

**CWE:** CWE-400（资源消耗）/ CWE-362（并发竞态）
**风险等级:** 高危

### 危险特征
- 上层传入的 `ctx` 被忽略，内部继续使用 `context.Background()` / `context.TODO()`
- 网络请求没有设置 deadline/timeout，导致 goroutine 与连接泄漏
- 取消信号未贯穿：`ctx.Done()` 不参与 select/请求取消

### Sink API/行为
- `context.Background()` / `context.TODO()`（在非初始化场景使用）
- `http.NewRequest(...)` 后未使用 `req.WithContext(ctx)` 或未使用 `client.Do(req)`
- `exec.Command`/`net.Dial` 未使用 `CommandContext` 或未设置超时

### 漏洞模式（示例）
```go
// 文件: pkg/client/http_client.go
// 风险: 忽略入参 ctx，导致请求无法取消/超时
func FetchSomething(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	// SINK: 未把 ctx 绑定到 req；也未设置 deadline
	resp, err := http.DefaultClient.Do(req) // SINK
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
```

### 修复要点
- 使用入参 ctx 并确保绑定到请求：
  - `req = req.WithContext(ctx)`
  - 或创建时就使用 `http.NewRequestWithContext`
- 关键 I/O 必须可取消：DNS/HTTP/gRPC/DB/exec 均需要 ctx 贯穿

---

## 4. slice header/cap 底层共享导致敏感数据暴露或越界视图

**CWE:** CWE-200（信息泄露）/ CWE-125（缓冲区越界）
**风险等级:** 高危

### 危险特征
- 返回 subslice 或结构体持有 subslice，但保留了 `cap`，使得调用方可通过 `[:cap(sub)]` 访问原底层数组
- 在拷贝时只拷贝长度，不处理 cap/底层共享
- slice 重新切片（re-slice）用于构造更大视图，未进行边界校验

### Sink API/行为
- `s2 := s1[a:b]`：若外部可获得 `s2` 且保留原 cap，就可能暴露
- `append(dst, src...)`：若 dst 容量复用原底层，也可能造成越界视图或数据残留暴露

### 漏洞模式（示例）
```go
// 文件: pkg/security/redaction.go
// 风险: 返回 subslice 共享底层数组，cap 泄露导致潜在信息恢复
func Redact(secret []byte) []byte {
	sub := secret[:4] // SINK: 共享底层；若调用方拿到 cap(sub)，可恢复更多内容
	for i := range sub {
		sub[i] = 0
	}
	return sub
}
```

### 修复要点
- 返回前进行安全拷贝，确保新的底层数组不共享：
  - `out := append([]byte(nil), sub...)`
- 若确需返回子切片，确保外部无法利用 cap 访问更多数据（通常通过复制解决）
- 对敏感数据清理使用明确的 zeroize 语义，并避免把敏感底层数组暴露出去

---

## 5. `sync.Map` / map 并发访问错误与竞态窗口

**CWE:** CWE-362（竞态条件）
**风险等级:** 中危到高危

### 危险特征
- 对普通 `map` 进行并发读写但未使用锁，或错误使用锁粒度导致竞态
- 使用 `sync.Map` 时仍在复合操作上缺少原子性（Load -> modify -> Store 不是原子）
- 在热路径上对同一对象做读写但没保护其内部字段（字段竞态）

### Sink API/行为
- 普通 `map`：
  - `m[k] = v` / `v := m[k]`（并发场景无锁）
- sync.Map 复合操作：
  - `v, _ := sm.Load(k)` 后再修改 `v` 再 `sm.Store(k, v)`（非原子复合）

### 漏洞模式（示例）
```go
// 文件: pkg/cache/cache.go
// 风险: 普通 map 并发写导致 fatal error 或数据损坏
var m = make(map[string]string)

func Set(k, v string) {
	m[k] = v // SINK
}
```

### 修复要点
- 对普通 map：使用 `sync.Mutex/RWMutex` 保护所有读写
- 对 sync.Map 复合更新：
  - 优先使用 `LoadOrStore`/`CompareAndSwap`（若值类型支持）
  - 或把 value 设计为不可变结构 + 原子替换
  - 或对 value 的可变部分加锁

---

## 6. `unsafe` 指针类型混淆与任意内存访问（类型混淆/越界视图）

**CWE:** CWE-843（类型混淆）/ CWE-125（越界）
**风险等级:** 严重

### 危险特征
- 把 `[]byte`/切片底层地址重解释为结构体指针，未验证长度/对齐/大小
- `unsafe.Pointer` 算术构造越界视图
- 从不可信数据构造指针或偏移（导致攻击者可控越界读写）

### Sink API/行为
- `unsafe.Pointer(&x)` / `(*T)(unsafe.Pointer(p))`
- `uintptr(base)+offset` 再转回指针并解引用

### 漏洞模式（示例）
```go
// 文件: pkg/native/decoder.go
// 风险: 从 bytes 构造结构体指针，未检查长度与字段布局
type Header struct{ IsAdmin bool }

func ParseHeader(b []byte) *Header {
	// SINK: 若 b 长度不够或攻击者可控布局，会导致越界/类型混淆
	return (*Header)(unsafe.Pointer(&b[0]))
}
```

### 修复要点
- 避免把不可信字节直接重解释为结构体指针；改为显式解析与边界校验
- 如必须使用 unsafe：严格检查 `len`/`offset`/对齐与结构大小，并限制可控性

---

## 7. `reflect` 动态调用导致任意方法/类型实例化（可控 methodName/type）

**CWE:** CWE-470（不安全反射）
**风险等级:** 高危

### 危险特征
- 由外部输入控制 `methodName`、`typeName`、参数结构
- 反射调用缺少白名单、缺少类型断言或缺少结果约束

### Sink API/行为
- `reflect.ValueOf(obj).MethodByName(name)` + `.Call(...)`
- `reflect.TypeOf(...)`/`reflect.New(type)` 结合外部可控字符串

### 漏洞模式（示例）
```go
// 文件: pkg/plugin/dispatch.go
// 风险: methodName 来自外部输入，允许调用任意导出方法
func Dispatch(obj any, methodName string, args ...any) any {
	v := reflect.ValueOf(obj)
	m := v.MethodByName(methodName) // SINK: 可控 methodName
	if !m.IsValid() {
		return nil
	}
	in := make([]reflect.Value, len(args))
	for i, a := range args {
		in[i] = reflect.ValueOf(a)
	}
	return m.Call(in)[0].Interface() // SINK
}
```

### 修复要点
- 对 methodName/typeName 做严格白名单映射（而不是直接用字符串反射）
- 对输入参数类型做强校验，不允许任意 `interface{}` 进入
- 对调用结果进行约束，避免返回敏感对象引用

---

## 8. `cgo` 指针传递与回调生命周期错误（use-after-free）

**CWE:** CWE-416（释放后使用）
**风险等级:** 严重

### 危险特征
- 把 Go 指针/对象地址传给 C 后，C 持有指针但 Go 侧对象可能被 GC 回收或在生命周期结束后被复用
- 回调函数中把 Go 指针暴露给 C，且缺少 `runtime.KeepAlive` 或缺少引用管理
- 在 C 回调里使用已失效的 Go 对象

### Sink API/行为
- `C.register_handler(unsafe.Pointer(goPtr))` 后没有确保 Go 对象在回调期间保持存活
- 没有 `runtime.KeepAlive(goObj)` 或没有等价的引用生命周期管理

### 漏洞模式（示例）
```go
// 文件: pkg/native/callback.go
// 风险: 将 Go 指针交给 C 保存，但 Go 对象可能被 GC 回收后仍被使用
func RegisterCallback(cb *MyStruct) {
	C.register_handler(unsafe.Pointer(cb)) // SINK
	// SINK: 若此处 cb 生命周期结束，C 内部可能后续使用悬挂指针
}
```

### 修复要点
- 必须确保 Go 对象在 C 使用期间保持可达（引用管理/句柄表）
- 在合适时机使用 `runtime.KeepAlive(cb)`，并把对象存放在能保证存活的结构中
- 对回调注册/注销建立对称的生命周期（确保注销前 Go 对象仍存活）

---

## 9. `go:generate` / `init()` 触发的危险初始化与动态执行（审计时特别关注）

**CWE:** CWE-94（代码注入）/ CWE-912（隐藏功能）
**风险等级:** 中危

### 危险特征
- `go:generate` 注释或 `init()` 中包含下载/拼接命令/执行外部脚本
- 下划线导入触发 init()，导致执行点难以从表面逻辑推断
- 动态加载/反射执行被隐藏在 init 的副作用中

### Sink API/行为
- `exec.Command` / `os/exec` 被用于 init/go:generate
- shell 管道拼接（`sh -c`, `bash -lc`）或把用户输入拼到命令行
- `plugin.Open` / 动态注册（如果出现在 init 或 go:generate 场景）

### 漏洞模式（示例）
```go
// 文件: pkg/internal/side_effects.go
// 风险: init 启动 goroutine 发起外联或动态加载
func init() {
	go func() {
		sendTelemetry("http://collector.internal/data") // SINK
	}()
}
```

### 修复要点
- 明确禁止将外部网络/命令执行放进 init/go:generate（或做强隔离与审计）
- 若必须存在：限制来源、固定命令参数、增加可审计日志与开关


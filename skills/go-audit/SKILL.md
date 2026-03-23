---
name: go-audit
description: 全面的Go代码安全审计技能，对Go项目进行深度漏洞分析，包括项目背景分析、审计策略设计、漏洞模式匹配、污点分析与数据流追踪、误报验证、漏洞分类评级、攻击链组合分析以及详细的中文审计报告生成。当用户需要对Go项目进行安全审计、查找Go代码中的安全漏洞、分析Go项目的安全风险、或者进行5G核心网Go组件的安全评估时使用此技能。适用于任何Go代码的安全审查请求，即使用户没有明确提到"审计"二字。
---

# Go代码安全审计

对Go项目进行系统化的深度安全审计，从项目理解到漏洞发现再到报告生成，形成完整的审计闭环。审计过程利用go-vuln-lib提供的攻击模式库进行模式匹配，并结合污点分析、数据流追踪等技术发现深层安全问题。

## 审计总流程

```
接收审计目标
    │
    ▼
Phase 1: 项目背景分析（理解项目）
    │
    ▼
Phase 2: 攻击面识别与审计策略设计
    │
    ▼
Phase 3: 自动化扫描（初筛）
    │
    ▼
Phase 4: 模式匹配审计（go-vuln-lib）
    │
    ▼
Phase 5: 污点分析与数据流追踪（深度分析）
    │
    ▼
Phase 6: 业务逻辑安全审计
    │
    ▼
Phase 7: 误报验证与漏洞确认
    │
    ▼
Phase 8: 漏洞分类评级
    │
    ▼
Phase 9: 攻击链组合分析
    │
    ▼
Phase 10: 审计报告生成
```

## Phase 1: 项目背景分析

深入理解目标项目是有效审计的前提。跳过这一步直接找漏洞往往事倍功半。

### 1.1 项目概况收集

```bash
# 项目结构分析
find . -type f -name "*.go" | head -100
tree -d -L 3

# 统计项目规模
find . -name "*.go" -not -path "./vendor/*" | xargs wc -l | tail -1

# 理解模块依赖
cat go.mod
go mod graph | head -50

# 查看主要入口点
grep -r "func main()" --include="*.go" -l

# 查看对外暴露的API/服务
grep -rn "http.Handle\|http.ListenAndServe\|grpc.NewServer\|net.Listen" --include="*.go"
```

### 1.2 架构理解

需要回答以下问题：

1. **项目类型**：Web服务 / CLI工具 / 库 / 微服务 / 5GC NF？
2. **网络接口**：HTTP/gRPC/原始TCP/UDP，哪些端口对外暴露？
3. **认证机制**：OAuth2/JWT/mTLS/自定义认证？
4. **数据存储**：数据库类型？是否使用ORM？如何处理敏感数据？
5. **外部依赖**：依赖的第三方库，是否有已知漏洞？
6. **部署环境**：容器化？Kubernetes？云原生？
7. **5GC相关**（如适用）：是哪个NF？实现了哪些3GPP接口？处理哪些协议消息？

### 1.3 5GC项目特别分析

如果目标是5GC组件，额外分析：

```bash
# 识别实现的NF类型
grep -rn "amf\|smf\|upf\|ausf\|udm\|udr\|nrf\|nssf\|pcf\|sepp\|scp" --include="*.go" -l | head -20

# 查找协议处理代码
grep -rn "nas\.\|ngap\.\|pfcp\.\|gtp\.\|diameter\.\|sbi\." --include="*.go" -l | head -20

# 查找SBI路由定义
grep -rn "router\.\|Route{\|AddRoute\|HandleFunc" --include="*.go" | head -30

# 查找认证相关代码
grep -rn "OAuth\|Bearer\|mTLS\|certificate\|token\|authenticate" --include="*.go" -i | head -20
```

### 1.4 威胁建模简化版

基于项目理解，快速建立威胁模型：

```
资产清单:
  - [列出需要保护的关键资产：用户数据、认证凭证、API密钥等]

攻击面:
  - [列出所有外部输入点：HTTP端点、gRPC方法、消息队列消费者等]

信任边界:
  - [标识不同信任级别之间的边界]

主要威胁（按STRIDE分类）:
  - Spoofing（仿冒）: [具体威胁]
  - Tampering（篡改）: [具体威胁]
  - Repudiation（抵赖）: [具体威胁]
  - Information Disclosure（信息泄露）: [具体威胁]
  - Denial of Service（拒绝服务）: [具体威胁]
  - Elevation of Privilege（权限提升）: [具体威胁]
```

## Phase 2: 攻击面识别与审计策略设计

### 2.1 攻击面枚举

**输入点清单**（Source）：

```bash
# HTTP请求参数
grep -rn "r\.URL\.Query\|r\.FormValue\|r\.PostForm\|r\.Body\|r\.Header\|mux\.Vars\|c\.Param\|c\.Query\|c\.Bind" --include="*.go"

# gRPC请求
grep -rn "func.*context\.Context.*Request\)" --include="*.go"

# 文件读取
grep -rn "os\.Open\|ioutil\.ReadFile\|os\.ReadFile\|bufio\.NewReader" --include="*.go"

# 环境变量
grep -rn "os\.Getenv\|os\.LookupEnv\|viper\.\|envconfig\." --include="*.go"

# 网络数据
grep -rn "net\.Conn\|conn\.Read\|udpConn\.ReadFrom" --include="*.go"

# 数据库查询结果
grep -rn "rows\.Scan\|row\.Scan\|db\.Query" --include="*.go"

# 消息队列
grep -rn "kafka\.\|amqp\.\|nats\.\|Subscribe\|Consume" --include="*.go"
```

**敏感操作清单**（Sink）：

```bash
# 命令执行
grep -rn "exec\.Command\|os/exec\|syscall\.Exec" --include="*.go"

# SQL查询
grep -rn "db\.Exec\|db\.Query\|db\.Prepare\|tx\.Exec" --include="*.go"

# 文件写入
grep -rn "os\.Create\|os\.WriteFile\|ioutil\.WriteFile\|os\.OpenFile" --include="*.go"

# 网络请求
grep -rn "http\.Get\|http\.Post\|http\.NewRequest\|client\.Do" --include="*.go"

# 日志输出
grep -rn "log\.Print\|log\.Info\|zap\.\|logrus\.\|slog\." --include="*.go"

# 响应输出
grep -rn "w\.Write\|json\.NewEncoder\|c\.JSON\|c\.String" --include="*.go"

# 密码学操作
grep -rn "cipher\.\|hmac\.\|rsa\.\|ecdsa\.\|tls\.Config" --include="*.go"
```

### 2.2 审计策略制定

根据项目类型和攻击面，确定审计优先级：

**优先级P0（必须审计）**：
- 所有外部输入到敏感操作的数据流路径
- 认证和授权逻辑
- 密码学使用
- 已知存在高危漏洞的依赖

**优先级P1（应该审计）**：
- 并发安全（goroutine/channel使用）
- 错误处理完整性
- 资源管理（连接/文件/goroutine泄漏）
- 配置安全

**优先级P2（可选审计）**：
- 代码质量问题
- 日志安全
- 第三方库使用模式

### 2.3 Go语言特征快速扫描

识别代码中使用的Go语言特性，确定需要关注的攻击模式类型：

```bash
# unsafe包使用
grep -rn "\"unsafe\"\|unsafe\." --include="*.go"

# reflect包使用
grep -rn "\"reflect\"\|reflect\." --include="*.go"

# cgo使用
grep -rn "import \"C\"\|/\*.*#include\|//export" --include="*.go"

# goroutine创建
grep -rn "go func\|go .*(" --include="*.go" | wc -l

# channel使用
grep -rn "make(chan\|<-.*chan\|chan<-" --include="*.go" | wc -l

# 类型断言
grep -rn "\.\(.*\)" --include="*.go" | grep -v "test" | head -20

# interface{}使用
grep -rn "interface{}\|any " --include="*.go" | wc -l
```

## Phase 3: 自动化扫描（初筛）

### 3.1 工具链扫描

```bash
# Go官方漏洞检查
govulncheck ./...

# gosec安全扫描
gosec -fmt=json -out=gosec-results.json ./...

# staticcheck静态分析
staticcheck ./...

# Go vet
go vet ./...

# 竞态条件检测（需编译运行测试）
go test -race ./...

# 依赖审计
go list -m -json all | jq '.Path + "@" + .Version'
```

### 3.2 自定义grep扫描

基于go-vuln-lib中的grep_patterns进行快速初筛。

从攻击模式库中提取所有grep_patterns，按false_positive_rate排序，优先执行低误报率的规则：

```bash
# 示例：硬编码密钥检测（低误报）
grep -rn "password\s*=\s*\"[^\"]\+\"\|secret\s*=\s*\"[^\"]\+\"\|apikey\s*=\s*\"[^\"]\+\"" --include="*.go" -i

# 示例：命令注入初筛（中误报）
grep -rn "exec\.Command\s*(.*+" --include="*.go"

# 示例：SQL注入初筛（中误报）
grep -rn "fmt\.Sprintf.*SELECT\|fmt\.Sprintf.*INSERT\|fmt\.Sprintf.*UPDATE\|fmt\.Sprintf.*DELETE" --include="*.go" -i

# 示例：不安全TLS（低误报）
grep -rn "InsecureSkipVerify\s*:\s*true" --include="*.go"

# 示例：弱随机数（低误报）
grep -rn "math/rand\|rand\.Int\|rand\.Intn\|rand\.Read" --include="*.go" | grep -v "crypto/rand"
```

### 3.3 初筛结果整理

将所有工具和grep扫描的结果汇总为候选漏洞列表：

```
候选漏洞ID | 文件:行号 | 检测方法 | 漏洞类型 | 置信度 | 状态
F001       | pkg/api/handler.go:42 | gosec | SQL注入 | 中 | 待验证
F002       | internal/auth/jwt.go:15 | grep | 硬编码密钥 | 高 | 待验证
...
```

## Phase 4: 模式匹配审计

### 4.1 加载攻击模式

从go-vuln-lib攻击模式库中，根据Phase 2识别的项目特征加载相关模式：

1. 根据项目使用的Go语言特性（goroutine, unsafe, interface等）过滤模式
2. 根据项目类型（HTTP服务, gRPC服务, 5GC NF等）过滤模式
3. 按severity从高到低排序

### 4.2 代码模式匹配

对每个加载的攻击模式，在目标代码中搜索匹配：

**匹配策略分层**：

1. **精确匹配**：直接搜索与vulnerable_pattern高度相似的代码段
2. **结构匹配**：匹配代码结构（如：类型断言不在if初始化语句中）
3. **语义匹配**：理解代码意图后判断是否存在模式对应的安全缺陷

**匹配过程**：
```
对于每个攻击模式P:
  1. 使用P的grep_patterns在代码库中搜索
  2. 对于每个匹配位置:
     a. 读取上下文代码（前后20行）
     b. 与P的vulnerable_pattern进行比对
     c. 检查P的preconditions是否满足
     d. 如果匹配，记录为候选漏洞
     e. 标注匹配的置信度（高/中/低）
```

### 4.3 5GC专项模式匹配

如果目标是5GC组件，额外执行5GC特定模式匹配：

```
# NAS消息处理安全检查
- NAS消息解码前的完整性验证
- NAS IE长度字段的边界检查
- NAS安全模式是否可被降级

# NGAP消息处理安全检查
- ASN.1 PER解码的错误处理
- NGAP IE的optional字段nil检查
- 异常NGAP procedure的处理

# SBI接口安全检查
- 所有SBI端点是否有认证保护
- 请求参数是否经过验证
- 错误响应是否泄露内部信息

# GTP/PFCP处理安全检查
- 隧道ID（TEID）的来源验证
- PFCP IE的长度验证
- 状态机转换的合法性检查
```

## Phase 5: 污点分析与数据流追踪

这是发现深层漏洞的核心阶段。目标是追踪不可信数据从输入点（source）到敏感操作（sink）的完整路径。

### 5.1 污点源定义

```go
// 一级污点源（外部不可信输入）
http.Request.Body          // HTTP请求体
http.Request.URL.Query()   // URL查询参数
http.Request.Header        // HTTP头部
http.Request.Form          // 表单数据
grpc.Context              // gRPC请求上下文
net.Conn.Read()           // 原始网络数据
os.Stdin                  // 标准输入
os.Args                   // 命令行参数

// 二级污点源（间接不可信数据）
database.Query results    // 数据库查询结果（可能被注入）
os.Getenv()              // 环境变量（部署时可控）
file.Read()              // 文件读取（文件可能被篡改）
json.Unmarshal output    // 反序列化结果
```

### 5.2 污点传播规则

追踪污点如何在代码中传播：

```
传播规则:
1. 赋值传播: tainted_var := source → tainted_var是污点
2. 函数参数传播: func(tainted_var) → 函数内部参数是污点
3. 返回值传播: result := func(tainted_var) → result可能是污点
4. 字符串操作传播: str := "prefix" + tainted_var → str是污点
5. 结构体字段传播: obj.Field = tainted_var → obj.Field是污点
6. Slice/Map传播: slice[i] = tainted_var → slice[i]是污点
7. Channel传播: ch <- tainted_var → <-ch接收的值是污点
8. 闭包捕获传播: go func() { use(tainted_var) }()
```

### 5.3 净化函数识别

识别代码中的数据净化操作：

```
常见净化函数:
- strconv.Atoi/ParseInt/ParseFloat — 将字符串转为数值（消除注入）
- html.EscapeString — HTML转义
- url.QueryEscape — URL编码
- filepath.Clean + 路径前缀检查 — 路径净化
- 参数化查询 (db.Query("... ?", param)) — SQL注入净化
- regexp匹配验证 — 格式验证
- 白名单校验 — 值域限制

注意：以下不是有效的净化：
- strings.Replace 部分替换 — 可能被绕过
- 长度截断 — 不改变内容性质
- 类型转换后再转回string — 无效往返
```

### 5.4 数据流追踪执行

对每个identified source-to-sink路径：

```
1. 标记Source位置
2. 沿调用链跟踪污点传播
   - 进入函数调用：分析函数体中参数的使用
   - 跨goroutine：追踪channel传递
   - 跨包调用：追踪导出函数的参数流向
3. 检查路径上是否存在有效的净化操作
4. 如果污点到达Sink且无有效净化：记录为漏洞
5. 记录完整的数据流路径作为证据
```

### 5.5 Go特有数据流注意事项

- **接口多态**：`interface` 类型的方法调用需考虑所有可能的实现
- **goroutine边界**：通过channel传递的数据需要跨goroutine追踪
- **defer执行**：defer中的操作在函数返回后执行，需特殊处理
- **panic/recover**：panic可能中断正常的数据流，recover可能恢复不安全状态
- **context传递**：`context.Value` 可在调用链中携带污点数据

## Phase 6: 业务逻辑安全审计

自动化工具难以发现的逻辑漏洞，需要人工审计：

### 6.1 认证逻辑审计

```
检查点:
□ 所有需要认证的端点是否都经过认证中间件？
□ 认证token的生成是否使用了密码学安全的随机数？
□ token是否有过期机制？过期时间是否合理？
□ token刷新逻辑是否存在竞态条件？
□ 密码比较是否使用了常数时间比较（hmac.Equal/subtle.ConstantTimeCompare）？
□ 是否存在认证绕过的默认路径或后门？
```

### 6.2 授权逻辑审计

```
检查点:
□ 是否存在IDOR（不安全的直接对象引用）？
□ 角色/权限检查是否在所有需要的位置执行？
□ 批量操作是否对每个对象都做了权限检查？
□ API版本迁移中是否遗漏了授权检查？
□ 管理员接口是否有额外的访问控制？
```

### 6.3 5GC业务逻辑审计

```
检查点（AMF）:
□ UE注册流程中的安全模式协商是否可被降级？
□ NAS消息的安全头类型检查是否严格？
□ 切片准入控制是否正确？
□ 移动性管理中的源AMF验证

检查点（SMF）:
□ PDU会话建立中的QoS参数验证
□ UPF选择逻辑是否可被操纵？
□ N4会话修改的授权检查
□ DNN（数据网络名称）验证

检查点（UDM/AUSF）:
□ 认证向量的生成和存储安全
□ SUPI/SUCI转换的加密实现
□ 签约数据访问的授权控制
□ 认证确认（Auth Confirmation）逻辑

检查点（NRF）:
□ NF注册的身份验证
□ 服务发现的访问控制
□ NF心跳/去注册的验证
□ NF Profile中的敏感信息过滤

检查点（UPF）:
□ 数据包过滤规则（PDR）的完整性
□ GTP-U隧道端点的验证
□ 流量计量/计费的准确性
□ 转发策略（FAR）的正确性
```

## Phase 7: 误报验证与漏洞确认

### 7.1 验证策略

对Phase 3-6发现的每个候选漏洞执行验证：

**自动验证**：
- 确认漏洞代码确实可达（不是死代码）
- 确认输入确实来自外部（不是内部常量）
- 确认传播路径上没有遗漏的净化操作
- 确认sink操作确实产生安全影响

**上下文验证**：
- 代码所在函数的调用者是谁？是否所有调用者都提供了净化后的输入？
- 是否有上层中间件已经做了安全检查？
- 部署环境是否有额外的安全层（WAF, 网络隔离等）？

**代码构造验证**：
```go
// 这不是SQL注入（使用了参数化查询）
db.Query("SELECT * FROM users WHERE id = ?", userID)

// 这不是命令注入（参数作为单独argument）
exec.Command("git", "clone", userURL) // userURL不经过shell解释

// 这个类型断言在switch中是安全的
switch v := iface.(type) {
case string: // 每个case都是安全的
case int:
}
```

### 7.2 误报标记

对每个候选漏洞标记验证结果：

| 状态 | 含义 |
|------|------|
| CONFIRMED | 确认为真实漏洞 |
| FALSE_POSITIVE | 确认为误报，记录原因 |
| NEEDS_RUNTIME | 需要运行时验证（如竞态条件） |
| NEEDS_CONTEXT | 需要了解部署上下文才能判断 |
| POTENTIAL | 代码模式存在风险，但当前不可利用 |

## Phase 8: 漏洞分类评级

### 8.1 分类框架

对每个确认的漏洞进行分类：

```yaml
vulnerability:
  id: "VULN-001"
  title: "简明的漏洞标题"
  
  classification:
    type: "SQL Injection"          # 漏洞类型
    cwe: "CWE-89"                  # CWE分类
    owasp: "A03:2021-Injection"    # OWASP Top 10
    attack_pattern: "AP-GO-0301"   # go-vuln-lib中匹配的模式
  
  location:
    file: "pkg/api/user.go"
    line: 42
    function: "GetUser"
    package: "github.com/example/pkg/api"
  
  severity:
    cvss_v3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    cvss_score: 9.1
    rating: "CRITICAL"
    5gc_adjusted_rating: "CRITICAL"  # 5GC上下文调整后
  
  details:
    description: "漏洞详细描述"
    root_cause: "根因分析"
    data_flow: "source → ... → sink 数据流路径"
    impact: "安全影响"
    exploitability: "可利用性分析"
    
  evidence:
    vulnerable_code: |
      // 漏洞代码
    proof_of_concept: "如何触发此漏洞"
    
  remediation:
    recommendation: "修复建议"
    secure_code: |
      // 修复后的代码
    effort: "LOW/MEDIUM/HIGH"       # 修复工作量
```

### 8.2 严重性评估

使用CVSS v3.1进行基准评分，然后根据上下文调整：

**基准评分因子**：
- Attack Vector (AV): Network / Adjacent / Local / Physical
- Attack Complexity (AC): Low / High
- Privileges Required (PR): None / Low / High
- User Interaction (UI): None / Required
- Scope (S): Unchanged / Changed
- Confidentiality (C): High / Low / None
- Integrity (I): High / Low / None
- Availability (A): High / Low / None

**5GC上下文调整**：
参考go-vuln-lib的 `references/5gc-context.md` 进行调整。

## Phase 9: 攻击链组合分析

### 9.1 攻击链构建

检查多个漏洞是否可以组合形成攻击链：

```
攻击链模式:
1. 信息泄露 → 认证绕过 → 权限提升
2. SSRF → 内网访问 → 敏感数据获取
3. 路径遍历 → 配置读取 → 凭证窃取 → 远程访问
4. 类型断言panic → 服务重启 → 竞态条件利用
5. (5GC) NAS降级 → 明文通信 → 中间人攻击
6. (5GC) NRF伪造注册 → 流量劫持 → 用户数据窃取
```

### 9.2 组合分析方法

```
对于每对漏洞(V1, V2):
  1. V1的输出是否可以作为V2的输入？
  2. V1是否能降低V2的利用门槛（如获取权限、获取信息）？
  3. V1和V2的组合影响是否大于单个漏洞？
  
如果组合存在：
  - 描述完整的攻击链路径
  - 评估组合后的整体严重性
  - 攻击链中的每个步骤是否都可行？
  - 是否存在可以阻断攻击链的点？
```

### 9.3 5GC攻击场景建模

对5GC组件，构建端到端攻击场景：

```
场景模板:
  攻击者角色: [恶意UE / 已入侵的gNB / 内网攻击者 / 恶意NF]
  初始接入点: [N1 / N2 / N3 / SBI / N4 / N32]
  攻击步骤:
    1. [第一步：初始利用]
    2. [第二步：横向移动或权限提升]
    3. [第三步：达成最终目标]
  最终影响: [用户数据窃取 / 服务中断 / 网络操纵]
  前提条件: [需要的前置条件]
  检测可能性: [高/中/低]
  缓解措施: [如何阻断]
```

## Phase 10: 审计报告生成

### 10.1 报告结构

生成的审计报告必须为中文，使用以下结构：

```markdown
# Go代码安全审计报告

## 报告信息
- 审计项目：[项目名称]
- 审计版本：[代码版本/commit hash]
- 审计时间：[日期范围]
- 审计范围：[审计的代码/模块范围]
- 审计方法：[使用的方法和工具]
- 审计人员：AI辅助 + [审计人员]

## 执行摘要

### 整体安全评估
[一段话总结项目的整体安全状况]

### 关键数字
| 指标 | 数值 |
|------|------|
| 代码总行数 | X |
| 审计覆盖率 | X% |
| 发现漏洞总数 | X |
| 严重(Critical) | X |
| 高危(High) | X |
| 中危(Medium) | X |
| 低危(Low) | X |
| 攻击链 | X条 |

### 高优先级发现
[列出最需要立即关注的3-5个发现]

## 项目架构分析
[Phase 1的分析结果摘要]

## 攻击面分析
[Phase 2的攻击面识别结果]

## 漏洞详情

### VULN-001: [漏洞标题]

**严重性**: CRITICAL | CVSS: 9.1

**位置**: `pkg/api/user.go:42` - `GetUser()`

**描述**:
[漏洞的详细描述]

**根因分析**:
[漏洞产生的根本原因]

**数据流**:
```
http.Request.URL.Query().Get("id")  [Source: 用户输入]
  → handler.GetUser() 
  → fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)  [无净化]
  → db.Query(query)  [Sink: SQL执行]
```

**漏洞代码**:
```go
// 漏洞代码片段（标注关键行）
```

**影响**:
[安全影响分析]

**修复建议**:
```go
// 修复后的代码
```

**修复优先级**: 立即修复
**修复工作量**: 低

---

[重复以上结构，按严重性从高到低排列所有漏洞]

## 攻击链分析

### 攻击链1: [攻击链名称]

**涉及漏洞**: VULN-001 → VULN-003 → VULN-007

**攻击路径**:
[描述完整攻击路径]

**组合影响**:
[组合后的影响评估]

**阻断建议**:
[在哪个环节可以阻断攻击链]

## 5GC安全评估（如适用）

### 3GPP合规性分析
| 规范要求 | 合规状态 | 说明 |
|---------|---------|------|
| TS 33.501 XX条 | 合规/不合规/部分合规 | 详细说明 |

### 5GC风险矩阵
| 风险场景 | 可能性 | 影响 | 风险等级 |
|---------|--------|------|---------|
| 场景描述 | 高/中/低 | 高/中/低 | 高/中/低 |

## 审计工具与方法说明
[使用的工具版本和方法论]

## 修复建议优先级
| 优先级 | 漏洞列表 | 修复时限建议 |
|--------|---------|-------------|
| P0-立即 | VULN-XXX | 24小时内 |
| P1-紧急 | VULN-XXX | 1周内 |
| P2-重要 | VULN-XXX | 1个月内 |
| P3-一般 | VULN-XXX | 下个版本 |

## 附录

### A. 扫描工具原始报告
### B. 完整的数据流追踪记录
### C. 攻击模式匹配详情
### D. 术语表
```

### 10.2 报告输出

- `audit-report.md` — 完整审计报告（Markdown格式）
- `vulnerabilities.json` — 机器可读的漏洞数据
- `executive-summary.md` — 管理层摘要（1页）

## 审计质量保证

### 覆盖率检查

审计完成前确认以下覆盖率：

```
□ 所有外部输入点已分析
□ 所有认证/授权路径已审计
□ 所有密码学使用已检查
□ 所有并发代码已审查
□ 所有依赖漏洞已扫描
□ 所有Phase 3初筛发现已验证
□ 所有匹配的攻击模式已确认或排除
□ （5GC）所有3GPP安全要求已对标
```

### 误报率控制

目标误报率 < 20%。每个报告的漏洞必须有：
- 具体的代码位置
- 可复现的触发条件
- 明确的安全影响
- 与至少一个攻击模式或CWE的映射

## 参考文件

- `references/audit-methodology.md` — 审计方法论详述
- `references/taint-analysis-guide.md` — Go污点分析技术指南
- `references/5gc-audit-checklist.md` — 5GC安全审计检查清单
- `references/report-templates.md` — 报告模板与示例

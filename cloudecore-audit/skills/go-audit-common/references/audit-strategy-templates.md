# 审计策略模板

针对常见Go项目类型的预构建审计策略模板。在阶段3中以此为起点，根据阶段1识别的项目具体特征进行定制。

**写入 `# Auditing Strategy Plan` 的通用规则：** 本节「关键文件模式」仅用于**定位**高风险区域。输出策略时必须映射到 `project-analyzer` 定义的 **「审计覆盖粒度」**：`必审文件（glob/路径）`（单点高风险）、`必审目录（全量 .go）`（上述模式所在**目录整树**下每个 `.go` 均需审查，受排除项约束）、`其余范围与尽量全量规则`。禁止把模式列表或文件名示例仅粘贴进「审查顺序」当作唯一审计范围，否则下游会漏审同目录未列名文件。

**并行编排规则（must-cover + full-audit）：** 策略模板在落盘时还应补充 `must_cover_categories`、`full_audit_categories`、`category_to_agent_map`、`coverage_gates`、`backfill_policy` 五组字段，确保下游可以验证“模式已加载且已执行”，并在失败时按类别定向补扫。

**CodeBadger / CPG 复用（可选，供 trace-resolver）：** 非必填。若希望父层在 CodeBadger MCP 侧已有与当前代码范围匹配的 CPG 时跳过再次建图，可在 `# Auditing Strategy Plan` 中增加一段（Markdown 列表即可）：

- `codebadger_cpg_reuse`：`off`（默认；整节省略时等价 `off`）| `auto`（先探测可复用则跳过生成，否则建图）| `on`（强制复用；MCP 无匹配 CPG 时 trace 阶段须中止）
- `codebadger_cpg_id`：（可选）已知 MCP 侧 CPG 标识时填写，减少探测歧义

下游 `trace-resolver` 将把结果写入 `./reports/trace-results.json` 的 `cpg_context` 字段。

## 目录

1. [Web API / REST 服务](#1-web-api--rest-服务)
2. [gRPC 微服务](#2-grpc-微服务)
3. [Web应用（服务端渲染）](#3-web应用服务端渲染)
4. [命令行工具](#4-命令行工具)
5. [Kubernetes Operator / Controller](#5-kubernetes-operator--controller)
6. [库 / SDK](#7-库--sdk)
7. [文件处理服务](#8-文件处理服务)
8. [网关 / 代理服务](#9-网关--代理服务)

---

## 1. Web API / REST 服务

**典型技术栈：** gin / echo / chi / fiber + GORM / sqlx + JWT / OAuth2

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | SQL注入 | 用户输入直接与数据库交互 |
| P0 | 认证缺陷 | JWT/会话处理缺陷可导致完全访问 |
| P0 | 访问控制缺陷 / IDOR | API端点按ID暴露资源 |
| P1 | SSRF | API经常代理或获取外部资源 |
| P1 | 批量赋值 | JSON绑定到结构体可能暴露内部字段 |
| P1 | 信息泄露 | 错误响应可能泄露内部信息 |
| P2 | 限流 / DoS | API可公开访问 |
| P2 | CORS配置错误 | 跨域安全 |
| P2 | 日志注入 | 请求数据未净化直接记录日志 |

### 范围定义

**必须审计：**
- 所有路由定义和处理函数
- 认证中间件和token验证逻辑
- 每个处理器中的授权检查（IDOR重点）
- 所有数据访问函数中的数据库查询构建
- 请求体绑定和输入验证
- 错误处理和响应格式化
- CORS配置
- 限流配置

**需定位的关键文件模式：**
```
**/router.go, **/routes.go, **/handler*.go, **/controller*.go
**/middleware*.go, **/auth*.go
**/model*.go, **/repository*.go, **/dao*.go, **/store*.go
**/service*.go（业务逻辑层）
**/config*.go, **/main.go
```

**策略计划映射：** 为每个实际存在的父目录（如 `internal/api/`、`pkg/handler/`）写入 `必审目录（全量 .go）`；对孤立关键文件写入 `必审文件`；其余仓库写入 `其余范围与尽量全量规则`。

### 批量赋值 — Go特有检查

在Go REST API中，`c.BindJSON(&req)` 或 `json.Decode` 将JSON字段映射到结构体字段。如果结构体含有不应由用户设置的字段（如 `IsAdmin`、`Role`、`ID`），检查是否：
- 使用了单独的DTO结构体（不含敏感字段）
- 敏感字段设置了 `json:"-"` 标签
- 使用手动字段拷贝而非完整结构体绑定

**漏洞示例：**
```go
type User struct {
    ID      int    `json:"id"`
    Name    string `json:"name"`
    IsAdmin bool   `json:"is_admin"`  // 可通过JSON输入设置
}
func CreateUser(c *gin.Context) {
    var user User
    c.BindJSON(&user)  // 攻击者可设置 is_admin=true
    db.Create(&user)
}
```

---

## 2. gRPC 微服务

**典型技术栈：** gRPC + protobuf + gorm/ent + 内部服务网格

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | 认证拦截器绕过 | 拦截器中认证缺失或配置错误 |
| P0 | SQL注入 | 后端数据库查询 |
| P0 | 权限提升 | 服务间信任假设 |
| P1 | 元数据注入 | 客户端可控的gRPC元数据用于授权 |
| P1 | Protobuf消息验证 | 传入消息缺少字段验证 |
| P1 | 不安全的服务间通信 | 无mTLS的明文gRPC |
| P2 | 资源耗尽 | 大消息载荷、流式传输滥用 |
| P2 | 生产环境启用反射 | 服务发现暴露 |

### 范围定义

**必须审计：**
- gRPC服务器初始化和拦截器链
- 所有RPC方法实现
- Protobuf消息定义（检查缺失的验证）
- 元数据提取和在授权中的使用
- 服务间调用的TLS / mTLS配置
- RPC处理器中的数据库查询
- 错误状态码和消息（信息泄露）

**关键文件模式：**
```
**/*.proto（消息和服务定义）
**/server.go, **/grpc*.go
**/interceptor*.go, **/middleware*.go
**/service*.go, **/handler*.go
**/repository*.go, **/store*.go
```

**策略计划映射：** `*.proto` 与 gRPC 实现所在目录写入 `必审文件` / `必审目录（全量 .go）`；拦截器、服务实现目录整树全量。

### 服务间信任检查

微服务架构中，服务间往往存在隐式信任。验证：
- 服务A是否验证来自服务B的请求合法性（双向TLS、签名token）？
- 如果服务A以提升的权限调用服务B，被攻陷的服务B能否滥用这些权限？
- 仅限内部的端点是否真的无法从服务网格外部访问？

---

## 3. Web应用（服务端渲染）

**典型技术栈：** net/http / gin + html/template / text/template + sessions

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | XSS | 服务端渲染含用户数据的HTML |
| P0 | SQL注入 | 表单数据 → 数据库查询 |
| P0 | CSRF | 无CSRF token的状态变更表单 |
| P0 | 会话管理缺陷 | 基于Cookie的会话 |
| P1 | 路径穿越 | 文件服务、上传/下载 |
| P1 | 开放重定向 | 登录/登出重定向URL |
| P1 | SSTI | 如果用户输入到达模板解析 |
| P2 | 点击劫持 | 缺少X-Frame-Options |
| P2 | 信息泄露 | 错误页面、调试模式 |

### 范围定义

**必须审计：**
- 模板文件和渲染逻辑（html/template vs text/template）
- 所有 `template.HTML()`、`template.JS()`、`template.URL()` 类型转换
- 表单处理和CSRF token验证
- 会话创建、验证和销毁
- Cookie属性（Secure、HttpOnly、SameSite）
- 静态文件服务配置
- 登录/登出后的重定向逻辑

**关键文件模式：**
```
**/templates/**/*.html, **/views/**/*.html
**/handler*.go, **/controller*.go
**/session*.go, **/auth*.go
**/middleware*.go
```

**策略计划映射：** 模板与 handler 所在目录写入 `必审目录（全量 .go）`；会话与认证相关路径单独列出全量目录。

---

## 4. 命令行工具

**典型技术栈：** cobra / urfave/cli + os/exec + 文件I/O

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | 命令注入 | CLI工具常调用其他命令 |
| P0 | 参数注入 | 用户参数传递给子进程 |
| P1 | 路径穿越 | 用户提供路径的文件操作 |
| P1 | 凭证暴露 | 配置文件、环境变量、命令历史中的密钥 |
| P1 | 不安全临时文件 | 可预测的临时文件名 |
| P2 | 权限提升 | SUID/SGID行为、sudo交互 |
| P2 | 符号链接攻击 | 跟随符号链接到敏感文件 |

### 范围定义

**必须审计：**
- 所有 `exec.Command` 调用及参数构建方式
- 用户控制路径的文件I/O操作
- 配置文件解析（YAML、TOML、JSON）的注入点
- 密钥/凭证处理（读取、存储、传递给子进程）
- 临时文件创建模式
- 信号处理和清理例程
- 插件加载机制（如有）

**关键文件模式：**
```
**/cmd/**/*.go（cobra命令定义）
**/main.go
**/config*.go
**/exec*.go, **/run*.go, **/shell*.go
```

**策略计划映射：** `cmd/**` 与含 `exec`/shell 的目录写入 `必审目录（全量 .go）`；`main.go` 可单列 `必审文件`。

---

## 5. Kubernetes Operator / Controller

**典型技术栈：** controller-runtime / client-go / kubebuilder

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | RBAC配置错误 | Operator权限过宽 |
| P0 | 密钥暴露 | 读取/创建含敏感数据的Secret |
| P0 | 权限提升 | 创建具有提升权限的Pod |
| P1 | CRD输入验证 | 恶意自定义资源规格 |
| P1 | 控制器逻辑中的SSRF | 控制器基于CR规格获取外部资源 |
| P1 | 容器逃逸向量 | SecurityContext未设置或过于宽松 |
| P2 | 信息泄露 | CRD状态、事件或日志中的敏感数据 |
| P2 | 资源创建导致DoS | 从单个CR创建无限资源 |

### 范围定义

**必须审计：**
- RBAC清单（ClusterRole、Role定义）
- Reconcile循环逻辑（Operator创建/修改/删除了什么？）
- CRD验证（webhook验证器、schema约束）
- Secret读取和创建模式
- Pod规格生成（SecurityContext、capabilities、volumes）
- Reconcile循环中的外部资源获取
- Finalizer逻辑（删除时的清理）

**关键文件模式：**
```
**/controllers/**/*.go, **/reconciler*.go
**/api/**/*.go（CRD类型定义）
**/webhook*.go
config/rbac/*.yaml
config/manager/*.yaml
**/main.go
```

**策略计划映射：** `controllers/`、`api/`、`webhook` 所在目录写入 `必审目录（全量 .go）`；RBAC YAML 可列 `必审文件`；勿仅用「controllers/**/*.go」作为审查顺序中的唯一文件集合而不写目录全量。

---

## 6. 区块链 / DeFi 应用

**典型技术栈：** cosmos-sdk / go-ethereum / tendermint

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | 整数溢出/下溢 | 代币金额的金融计算 |
| P0 | 交易访问控制 | 未授权的交易执行 |
| P0 | 重入类模式 | 外部调用前的状态修改 |
| P0 | 密码学缺陷 | 密钥管理、签名验证 |
| P1 | 拒绝服务 | 交易处理资源耗尽 |
| P1 | 抢跑向量 | 交易排序依赖 |
| P1 | 预言机操纵 | 外部数据源信任假设 |
| P2 | 信息泄露 | 私钥泄露、交易元数据 |

### 范围定义

**必须审计：**
- 交易处理器/消息处理器
- 代币转账和余额修改逻辑
- 签名验证和密钥管理
- 状态机转换
- 金融值的数学运算（溢出检查）
- 共识相关逻辑
- 外部数据源（预言机）集成

**策略计划映射：** 按仓库实际路径将交易/消息处理、状态机所在**目录**写入 `必审目录（全量 .go）`；核心入口文件可列 `必审文件`。

---

## 7. 库 / SDK

**典型技术栈：** 纯Go库，提供公开API

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | 公开API输入验证 | 库使用者传入不可信数据 |
| P0 | 内存安全 | unsafe指针操作、缓冲区处理 |
| P1 | 资源耗尽 | 调用者输入导致无限分配 |
| P1 | 密码学误用 | 如果库提供加密操作 |
| P1 | 并发安全 | 并发使用中的竞态条件 |
| P2 | 错误处理 | 导致调用者程序崩溃的panic |
| P2 | 依赖链 | 传递性漏洞暴露 |

### 范围定义

**必须审计：**
- 所有导出函数和方法（公开API表面）
- 每个公开函数参数的输入验证
- `unsafe` 包的使用
- goroutine安全保证 vs 实际实现
- panic vs 错误返回行为
- 依赖及其漏洞状态

**策略计划映射：** 导出 API 所在包路径写入 `必审目录（全量 .go）`；使用 `unsafe` 的文件可额外列入 `必审文件`。

---

## 8. 文件处理服务

**典型技术栈：** net/http + archive/zip / archive/tar + 图像处理

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | 路径穿越 / Zip Slip | 带构造文件名的压缩包提取 |
| P0 | 命令注入 | 调用图像/文档处理器 |
| P1 | 解压炸弹 | 压缩文件展开为巨大尺寸 |
| P1 | 符号链接攻击 | Tar/zip条目为符号链接 |
| P1 | 资源耗尽 | 处理大型或畸形文件 |
| P2 | SSRF | 如果文件包含被获取的URL |
| P2 | 内容类型混淆 | 文件扩展名与实际内容不匹配 |

### 范围定义

**必须审计：**
- 文件上传处理器（大小限制、类型验证）
- 压缩包提取逻辑（zip、tar、gzip）
- 文件名净化
- 文件处理的外部工具调用
- 临时文件管理
- 输出文件路径构建

**策略计划映射：** 上传/解压/外部工具调用相关目录写入 `必审目录（全量 .go）`。

---

## 9. 网关 / 代理服务

**典型技术栈：** net/http / 反向代理 + 中间件链

### 优先级矩阵

| 优先级 | 漏洞类别 | 原因 |
|--------|---------|------|
| P0 | SSRF | 核心功能涉及发起出站请求 |
| P0 | 认证绕过 | 网关认证检查必须覆盖所有路由 |
| P0 | 头部注入 | 转发头部操纵 |
| P1 | 请求走私 | 代理与后端间的HTTP解析不一致 |
| P1 | 开放重定向 | 基于用户输入的路由 |
| P1 | 信息泄露 | 泄露后端拓扑、内部头部 |
| P2 | DoS | 慢速读取攻击、连接耗尽 |
| P2 | TLS配置 | 弱密码套件、证书验证 |

### 范围定义

**必须审计：**
- 路由逻辑和URL重写规则
- 头部转发和净化（X-Forwarded-For、Host等）
- 网关级别的认证和授权
- 后端连接配置（TLS、超时）
- 限流和熔断器实现
- WebSocket代理（如适用）
- 错误处理和上游超时行为

**策略计划映射：** 路由、中间件、转发逻辑所在目录写入 `必审目录（全量 .go）`；核心 `main` 或入口可列 `必审文件`。

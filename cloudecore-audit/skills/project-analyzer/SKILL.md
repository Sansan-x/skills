---
name: project-analyzer
description: 阶段1-3：项目威胁分析 & 审计策略制定（生成可被下游 go-audit 直接使用的审计策略计划）
---

# 项目威胁分析与审计策略制定

针对 Go 项目的系统化威胁建模与审计策略设计技能。输出内容会在下游 `go-audit` 阶段被直接引用，用于确定漏洞类别优先级、审计范围、文件/模块审查顺序以及终止条件。

审计按 3 个阶段顺序执行：

```
阶段1：项目背景分析
   ↓
阶段2：模式选择
   ↓
阶段3：审计策略设计（输出 # Auditing Strategy Plan）
```

---

## 阶段1：项目背景分析

在审计任何代码之前，先全面了解项目。这些上下文信息将直接影响阶段3的审计策略。

### 1.1 识别项目类型

判断项目属于哪种类型：

- **Web 应用 / API 服务**（gin、echo、fiber、chi、net/http、gRPC）
- **命令行工具**（cobra、urfave/cli）
- **微服务**（go-micro、go-kit、kratos）
- **区块链 / 智能合约**（cosmos-sdk、go-ethereum）
- **基础设施 / DevOps 工具**（Kubernetes operator、Terraform provider）
- **库 / SDK**
- **其他**（描述）

### 1.2 分析技术栈

扫描项目识别以下内容：

- **Go 版本** — 查看 `go.mod`
- **Web 框架** — gin、echo、fiber、chi、标准 net/http、gRPC 等
- **数据库层** — database/sql、gorm、ent、sqlx、sqlc、mongo-driver 等
- **认证方式** — JWT（golang-jwt）、OAuth2、基于会话、API Key
- **序列化** — encoding/json、encoding/xml、protobuf、msgpack
- **模板引擎** — html/template、text/template、第三方
- **外部集成** — 云SDK、消息队列、Redis 等
- **密码学** — crypto/*、x/crypto、第三方加密库
- **依赖管理** — go.mod 依赖项，特别关注已知漏洞版本

### 1.3 梳理关键模块与业务逻辑

识别架构边界和信任区域：

- **入口点** — HTTP 处理器、gRPC 方法、CLI 命令、消息消费者
- **认证与授权模块**
- **数据访问层** — 查询构建和执行的位置
- **文件处理** — 上传、下载、路径构造
- **外部通信** — 出站 HTTP、DNS、SMTP、命令执行
- **敏感数据处理** — PII、凭证、金融数据、健康数据
- **配置管理** — 环境变量、配置文件、密钥管理
- **中间件链** — CORS、限流、日志、认证中间件

### 1.4 识别 5GC 核心网领域并拆解信任边界（增强）

当识别到云核心网领域（free5gc/open5gs 等 5gc/5G 核心网相关项目）时，在阶段1必须额外输出以下内容（原文可直接用于审计策略计划）：

1. **信任边界拆解（必须输出）**
   - **UE/RAN -> AMF**：N1/NGAP 相关的协议边界与字段来源
   - **SBI（NF 之间）**：HTTP/2 + token/mTLS 的鉴权/授权边界
   - **SMF -> UPF**：PFCP 的会话建立/修改与消息来源关联边界
   - **用户面 GTP-U**：传输层隧道与 TEID/F-TEID 相关边界
   - **NF 内部上下文/会话生命周期边界**：会话状态写入、读取、清理与并发访问边界

2. **关键模块与攻击面清单（安全关联，必须输出）**
   - SBI 路由鉴权/授权门控
   - 协议解析与字段/长度校验（NAS/NGAP/PFCP）
   - PFCP session ownership 与规则编程
   - TEID/F-TEID 唯一性与合法范围校验
   - 密钥材料管理与零化/泄露控制
   - 敏感资产（SUPI/SUCI/IMSI/GUTI/TEID/上下文）日志/响应/错误信息泄露控制
   - 并发与生命周期清理（锁保护/释放路径）
   - 错误处理信息泄露（panic/recover/错误返回）
   - DoS 资源上限（解码大小/消息上限）
   - Go 语言特有陷阱（unsafe/reflect/go:generate）

阶段1末尾输出一份“结构化项目背景摘要”，用于阶段3生成审计策略计划。若为 5GC 项目，还要附带上述 5GC 信任边界拆解与关键模块清单。

---

## 阶段2：模式选择

两个维度的配置控制审计行为。除非用户明确指定，否则使用默认值。

### 审计模式

| 模式 | 说明 | 默认 |
|---|---|---|
| **快速扫描** | 聚焦高危模式（注入、认证绕过、RCE），跳过深度数据流追踪，适合快速反馈 | |
| **深度审计** | 完整多轮分析，包括污点追踪、误报验证和攻击链分析 | ✅ 默认 |

### 审计领域

| 领域 | 说明 | 默认 |
|---|---|---|
| **通用领域** | 覆盖 Web 应用、API 服务、CLI 工具、微服务等常见 Go 项目的安全审计，聚焦注入、认证、访问控制、密码学等通用安全问题 | ✅ 默认 |
| **云核领域** | 在通用领域基础上，额外聚焦云原生和基础设施安全：Kubernetes Operator/Controller 安全、容器逃逸、RBAC 配置、Service Mesh 安全、云 API 密钥管理、基础设施即代码安全等 | |

默认组合为 **深度审计 + 通用领域**。如果用户指定其他组合，按需调整。

---

## 阶段3：审计策略设计

基于阶段1（项目上下文）和阶段2（模式选择），设计针对性的审计策略，并在阶段3末尾输出下游可直接读取的 `# Auditing Strategy Plan`。

加载审计策略模板：[go-audit 的审计策略模板](../go-audit/references/audit-strategy-templates.md)

### 3.1 确定审计优先级

将项目特征映射到漏洞类别。策略必须反映实际的技术栈和业务领域，通用检查清单远远不够。

**优先级映射（通用示例）**：

| 项目特征 | 高优先级漏洞类别 |
|---|---|
| 带用户输入的 Web API | SQL 注入、XSS、SSRF、路径穿越、IDOR |
| gRPC 服务 | Protobuf 反序列化、认证拦截器绕过、元数据注入 |
| 文件处理服务 | 路径穿越、Zip Slip、符号链接攻击、资源耗尽 |
| 认证模块 | JWT 验证缺陷、计时攻击、权限提升、会话固定 |
| 加密使用 | 弱算法、硬编码密钥、IV 重用、不安全随机数 |
| K8s operator | RBAC 配置错误、权限提升、密钥泄露 |
| 带 exec 的 CLI 工具 | 命令注入、参数注入、环境变量注入 |

### 3.2 定义范围与覆盖

确定：

1. **关键路径** — 处理敏感操作的代码路径（认证、支付、数据访问等）
2. **信任边界** — 不可信输入的进入点及其到达敏感 sink 的路径
3. **排除项** — 生成代码、vendor 依赖（除非明确要求）、测试文件
4. **深度** — 快速扫描限于入口处理器和直接调用者；深度审计追踪完整调用链

### 3.3 设计文件审查顺序（通用）

优先审查位于信任边界上的文件：

1. HTTP/gRPC 处理器和路由定义
2. 中间件（认证、校验、过滤）
3. 数据库查询构建器和数据访问对象
4. 文件 I/O 和命令执行逻辑
5. 密码学操作
6. 配置和密钥管理
7. 上述模块使用的工具函数和辅助函数

### 3.4 5GC 核心网漏洞类别优先级细化（增强）

当识别到 5GC 核心网领域（free5gc/open5gs 等）时，审计策略的“漏洞类别优先级”必须依据 5G 核心网漏洞类别细化，并把类别名作为优先级输入。

5GC 漏洞类别 ID 已内嵌于下方列表（按需作为优先级向下游传递）：

- `SBI_AUTHORIZATION`
- `PROTOCOL_PARSING_VALIDATION`
- `PFCP_SESSION_OWNERSHIP`
- `TEID_FTEID_MANAGEMENT`
- `CRYPTO_KEY_MANAGEMENT`
- `SENSITIVE_ASSET_LEAKAGE`
- `CONCURRENCY_LIFECYCLE`
- `ERROR_HANDLING_INFOLEAK`
- `DOS_RESOURCE_LIMITS`
- `GENERAL_GO_SECURITY_TRAPS`

然后将这些类别映射到：

1. **审计范围**（应该检查哪些模块/目录/文件类型）
2. **文件/模块审查顺序**（从入口到敏感 sink 的顺序）
3. **stop_conditions（终止展开条件）**：在“校验/鉴权之后、状态写入（或规则编程）之前”停止向后展开

示例映射规则（必须根据项目实际调整文件关键词）：

- `SBI_AUTHORIZATION`
  - 范围：SBI 路由、NF 之间 HTTP/2 处理器、token/mTLS 鉴权与授权中间件、NF 级别访问控制
  - stop_conditions：通过鉴权/授权门控之后、进入任何会话创建/关键状态写入/协议转发之前停止展开
- `PROTOCOL_PARSING_VALIDATION`
  - 范围：NAS/NGAP/PFCP 的 decode/unmarshal/parse、mandatory IE/字段校验、长度/边界检查
  - stop_conditions：完成长度/mandatory IE/字段边界校验之后、在安全使用这些字段之前停止展开
- `PFCP_SESSION_OWNERSHIP`
  - 范围：PFCP Session Establishment/Modification 处理器、ownership/归属校验、会话上下文建立与修改点
  - stop_conditions：通过 ownership/归属校验之后、在执行 PDR/FAR/QER 等规则编程之前停止展开
- `TEID_FTEID_MANAGEMENT`
  - 范围：GTP-U/Outer Header 创建、TEID/F-TEID 的唯一性、合法范围、隧道端点校验
  - stop_conditions：完成唯一性与合法范围校验之后、在使用 TEID 构造/编程隧道与转发表之前停止展开
- `CRYPTO_KEY_MANAGEMENT`
  - 范围：密钥派生、密钥存储、生命周期结束清理/零化、密钥材料的日志/响应通道隔离
  - stop_conditions：密钥材料被正确存储/不会泄露之后、在用于加密/组包/响应之前停止展开
- `SENSITIVE_ASSET_LEAKAGE`
  - 范围：日志、错误返回、HTTP/PFCP 响应构造、异常/trace 处理
  - stop_conditions：确认所有输出路径对敏感资产（SUPI/SUCI/IMSI/GUTI/TEID/上下文等）已做红action/掩码/抑制之后停止展开
- `CONCURRENCY_LIFECYCLE`
  - 范围：包含会话/上下文的结构体、锁保护、释放路径、defer/clear/cleanup 调用链
  - stop_conditions：确认锁覆盖范围与清理时机正确之后、在释放之后的后续使用点再行展开（仅在后续阶段需要时）
- `ERROR_HANDLING_INFOLEAK`
  - 范围：panic/recover 中间件、错误对象构造、外部返回与内部日志写入
  - stop_conditions：确认对外返回错误为通用信息、内部日志已脱敏之后停止展开
- `DOS_RESOURCE_LIMITS`
  - 范围：消息读取、decode/unmarshal 之前的大小限制、最大消息长度/请求体上限
  - stop_conditions：确认任意不可信载荷均先做大小/资源上限约束之后停止展开
- `GENERAL_GO_SECURITY_TRAPS`
  - 范围：unsafe/reflect、go:generate/init 触发的副作用、动态加载/危险初始化路径（按项目实现调整）
  - stop_conditions：确认危险构造已被审查并有明确缓解/隔离逻辑后停止展开

### 3.5 输出固定格式并写入文件：# Auditing Strategy Plan

在阶段3末尾，必须生成下述固定标题块，并**写入文件**供下游 `go-audit` 直接读取。

#### 文件输出步骤

```bash
mkdir -p ./reports
```

将完整的审计策略计划写入固定路径：

```
./reports/audit-strategy-plan.md
```

文件内容必须从 `# Auditing Strategy Plan` 标题开始，包含下方所有字段，不得截断。下游 `go-audit` 将以此文件内容为准，不再依赖上下文粘贴。

#### 文件内容模板

# Auditing Strategy Plan

审计领域/模式：
- 审计模式：`快速扫描` 或 `深度审计`
- 审计领域：`通用领域` 或 `云核领域`（若识别 5GC，则在文本中标注 5GC 分支）

漏洞类别优先级（通用 + 5gc分支细化）：
- 通用优先级（简述高优先级漏洞类别）：注入/认证/访问控制/敏感泄露/密码学/DoS/Go 特有陷阱（按项目实际取舍）
- 5GC 核心网类别优先级（按优先级从高到低列出 category_id）：  
  1. `SBI_AUTHORIZATION`
  2. `PROTOCOL_PARSING_VALIDATION`
  3. `PFCP_SESSION_OWNERSHIP`
  4. `TEID_FTEID_MANAGEMENT`
  5. `CRYPTO_KEY_MANAGEMENT`
  6. `SENSITIVE_ASSET_LEAKAGE`
  7. `CONCURRENCY_LIFECYCLE`
  8. `ERROR_HANDLING_INFOLEAK`
  9. `DOS_RESOURCE_LIMITS`
  10. `GENERAL_GO_SECURITY_TRAPS`

信任边界到关键模块映射：
- UE/RAN -> AMF(N1/NGAP)：协议解析、字段校验、认证门控与错误处理
- SBI(NFs 间 HTTP/2 + token/mTLS)：鉴权/授权、路由到关键 handler 的状态写入点
- SMF -> UPF(PFCP)：session ownership 校验、会话上下文建立/修改与规则编程
- 用户面 GTP-U：TEID/F-TEID 的唯一性与隧道端点校验
- NF 内部上下文/会话生命周期：并发访问、清理/释放与敏感资产输出路径

文件/模块审查顺序与终止条件：
- 审查顺序（从入口到敏感 sink）：
  1. SBI 路由入口、NF 间 HTTP/2 处理器与鉴权/授权中间件（`SBI_AUTHORIZATION`）
  2. NAS/NGAP/PFCP decode/unmarshal 与 mandatory IE/字段/长度校验（`PROTOCOL_PARSING_VALIDATION`）
  3. PFCP Session Establishment/Modification 的 ownership 与会话上下文逻辑（`PFCP_SESSION_OWNERSHIP`）
  4. TEID/F-TEID 唯一性、合法范围校验与外部 header/转发表编程前置点（`TEID_FTEID_MANAGEMENT`）
  5. 密钥派生/存储/零化与密钥材料隔离通道（`CRYPTO_KEY_MANAGEMENT`）
  6. 敏感资产输出通道：日志、HTTP/PFCP 错误返回、响应构造（`SENSITIVE_ASSET_LEAKAGE`）
  7. 会话/上下文锁保护与生命周期清理路径（`CONCURRENCY_LIFECYCLE`）
  8. panic/recover 与错误返回策略（`ERROR_HANDLING_INFOLEAK`）
  9. 消息大小/资源上限控制（`DOS_RESOURCE_LIMITS`）
  10. unsafe/reflect/go:generate/init 等 Go 特有陷阱审查与缓解（`GENERAL_GO_SECURITY_TRAPS`）
- stop_conditions（总规则）：
  - 在“校验/鉴权完成”之后、进入任何“关键状态写入/规则编程/敏感输出/继续使用未校验字段”之前停止展开

后续 go-audit 阶段需要重点关注的 sink/source/净化检查点（文本化）：
- Source（不可信输入来源）：
  - token/mTLS 身份与元数据、SBI 请求头/路由参数
  - NAS/NGAP/PFCP 的原始消息 bytes、mandatory IE/字段值
  - NodeID/SEID/会话标识、TEID/F-TEID 值
  - 错误对象/异常上下文、日志参数与响应内容
- Sink（关键危险操作）：
  - SBI 鉴权通过后对关键状态的写入与协议转发
  - PFCP session/context 创建与 PDR/FAR/QER 等规则编程
  - TEID 构造隧道/转发表、Outer Header 生成与消息组包
  - 密钥材料的输出通道（日志/响应）与未清理的密钥生命周期末端
  - 日志/响应/错误返回中的敏感资产写入
  - 并发上下文释放后仍被使用（释放-使用竞态）、锁未覆盖的敏感字段访问
- Sanitizer/净化（需要检查的缓解）：
  - token/mTLS 校验与授权门控函数、mandatory IE/长度校验、边界检查与错误分支中止
  - ownership/归属一致性校验、TEID/F-TEID 唯一性与合法范围验证
  - key zeroize/清理、日志脱敏/掩码/redaction helpers
  - mutex/RWMutex 锁覆盖、cleanup/clear-on-release 路径与 defer 顺序校验
  - panic/recover 外部返回通用化、内部日志脱敏
  - decode 前的 MaxBytes/LimitReader/MaxRecvMsgSize 等上限约束
  - unsafe/reflect/go:generate/init 的危险构造审查与隔离


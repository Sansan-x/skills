# Auditing Strategy Plan

审计领域/模式：
- 审计模式：`深度审计`
- 审计领域：`云核领域`（5GC 分支：free5gc UDM 模块）

漏洞类别优先级（通用 + 5GC 分支细化）：
- 通用优先级：注入/认证/访问控制/敏感泄露/密码学/DoS/Go 特有陷阱
- 5GC 核心网类别优先级（按优先级从高到低列出 category_id）：
  1. `SBI_AUTHORIZATION` - OAuth2 token 验证、NF 间 HTTP/2 鉴权授权门控
  2. `CRYPTO_KEY_MANAGEMENT` - SUCI 解密（ECDH X25519/P-256）、密钥材料存储与生命周期
  3. `PROTOCOL_PARSING_VALIDATION` - SUPI/SUCI/GPSI 格式验证、JSON 反序列化 mandatory IE 校验
  4. `SENSITIVE_ASSET_LEAKAGE` - SUPI/SUCI/IMSI/GUTI/密钥材料的日志/响应泄露控制
  5. `CONCURRENCY_LIFECYCLE` - UE 上下文池（sync.Map）、订阅管理、锁覆盖与释放路径
  6. `ERROR_HANDLING_INFOLEAK` - panic/recover 中间件、错误返回与 ProblemDetails 构造
  7. `DOS_RESOURCE_LIMITS` - 请求体大小限制、消息解码上限
  8. `GENERAL_GO_SECURITY_TRAPS` - reflect.DeepEqual 时序攻击（已确认）、unsafe/reflect/go:generate/init

信任边界到关键模块映射：
- UE/RAN -> AMF(N1/NGAP)：UDM 不直接处理 NAS/NGAP，但接收 SUPI/SUCI 作为认证请求参数
- SBI(NFs 间 HTTP/2 + token/mTLS)：
  - 入口：internal/sbi/server.go newRouter() 创建 SBI 路由
  - 鉴权：internal/util/router_auth_check.go RouterAuthorizationCheck.Check()
  - OAuth2：internal/context/context.go AuthorizationCheck() 调用 oauth.VerifyOAuth()
  - Token 获取：internal/context/context.go GetTokenCtx() 调用 oauth.GetTokenCtx()
- UDM -> UDR(Nudr_DR)：
  - 客户端创建：internal/sbi/consumer/udr_service.go CreateUDMClientToUDR()
  - 数据查询：processor 调用 UDR API 获取认证数据/订阅数据
- UDM -> NRF(NNRF_NFM/NNRF_DISC)：
  - 注册：internal/sbi/consumer/nrf_service.go RegisterNFInstance()
  - 发现：internal/sbi/consumer/nrf_service.go SendSearchNFInstances()
- NF 内部上下文/会话生命周期：
  - UE 池：internal/context/context.go UdmUePool (sync.Map)
  - 订阅：internal/context/context.go SubscribeToNotifChange, SubscriptionOfSharedDataChange
  - 锁：UdmUeContext amSubsDataLock, smfSelSubsDataLock, SmSubsDataLock

审计覆盖粒度：
- 必审文件（glob/路径）：
  - `cmd/main.go` - 主入口点，信号处理与 panic recover
  - `internal/sbi/server.go` - SBI 服务器，路由创建，HTTP/2 启动与 TLS
  - `internal/sbi/router.go` - 路由定义与授权中间件绑定
  - `internal/util/router_auth_check.go` - OAuth2 token 验证门控
  - `internal/context/context.go` - UE 上下文池、AuthorizationCheck、GetTokenCtx
  - `pkg/suci/suci.go` - SUCI 解密、ECDH、AES-CTR、HMAC-SHA256 密钥处理
  - `internal/sbi/processor/generate_auth_data.go` - 5G AKA 认证向量生成、SQN 管理、MAC-S 验证（已知 reflect.DeepEqual 漏洞）
  - `pkg/factory/config.go` - 配置加载、验证、密钥材料（SuciProfiles.PrivateKey）
  - `pkg/service/init.go` - 应用初始化、shutdown 逻辑
- 必审目录（全量 .go，树下每个 `.go` 均需审查，受排除项约束）：
  - `internal/sbi/` - SBI API 处理器、路由、消费者、处理器
  - `internal/context/` - UE 上下文管理、订阅生命周期
  - `internal/util/` - 认证检查工具、上下文初始化
  - `internal/logger/` - 日志模块（敏感资产泄露检查点）
  - `pkg/suci/` - SUCI 解密密码学模块
  - `pkg/factory/` - 配置工厂、验证
  - `pkg/app/` - 应用接口定义
  - `pkg/service/` - 服务初始化
  - `pkg/mockapp/` - Mock 实现（需检查是否暴露敏感接口）
- 其余范围与尽量全量规则：
  - 除上述与排除项外，按下方「审查顺序」遍历仓库，尽量覆盖剩余 `.go`；无额外抽样，尽量全量
- 排除项（用于分母与枚举）：
  - `**/*_test.go` - 测试文件
  - `pkg/app/mock.go`, `pkg/mockapp/mock.go` - 自动生成的 mock 文件（reflect 用于测试，非生产路径）
  - `.claude/**` - Claude 配置与 skill 文件
  - `venv/**` - Python 虚拟环境
  - `reports/**` - 已生成报告

并行编排（must-cover + full-audit）：
- must_cover_categories（高危必覆盖）：
  - `FILE_OPS` - 文件操作（配置文件读取、日志文件写入）
  - `SQLI` - SQL 注入（UDM 通过 UDR API 访问数据，需检查参数传递）
  - `GO_RUNTIME` - Go 运行时安全（reflect.DeepEqual 时序攻击、unsafe/reflect、并发竞态）
- full_audit_categories（其余保持全量审计）：
  - `ALL_REMAINING` - 包括 SBI_AUTHORIZATION, CRYPTO_KEY_MANAGEMENT, PROTOCOL_PARSING_VALIDATION 等
- category_to_agent_map：
  - `FILE_OPS` -> `file-agent`（skill: `file-audit`）
  - `SQLI` -> `sqli-agent`（skill: `sqli-audit`）
  - `GO_RUNTIME` -> `go-runtime-agent`（skill: `go-runtime-audit`）
  - `ALL_REMAINING` -> `go-audit`（skill: `go-audit`）
- coverage_gates：
  - `must_audit_dir_coverage >= 100%` - 必审目录必须全量覆盖
  - `must_cover_categories` 的每一类都必须输出 `patterns_loaded/patterns_executed` 与 `sink_hits` 或 `no_finding_evidence`
  - `patterns_loaded` 与 `patterns_executed` 偏差超 10% 时触发 backfill
  - 并发模块必须有锁覆盖证据
- backfill_policy：
  - 仅重跑缺口类别与缺口目录（category + path scoped backfill）
  - 保留首次执行证据，补扫结果追加，不覆盖原记录

模块/目录审查顺序与终止条件（优先级顺序，不等于唯一文件集合；全量义务见上「审计覆盖粒度」）：
- 审查顺序（从入口到敏感 sink）：
  1. `internal/sbi/server.go`, `internal/sbi/router.go`（`SBI_AUTHORIZATION`）- HTTP/2 服务器入口、路由创建、授权中间件绑定
  2. `internal/util/router_auth_check.go`（`SBI_AUTHORIZATION`）- OAuth2 token 验证门控
  3. `internal/context/context.go`（`SBI_AUTHORIZATION`, `CONCURRENCY_LIFECYCLE`）- AuthorizationCheck、GetTokenCtx、UE 上下文池
  4. `pkg/suci/suci.go`（`CRYPTO_KEY_MANAGEMENT`）- SUCI 解密、ECDH 密钥派生、HMAC/AES-CTR
  5. `internal/sbi/processor/generate_auth_data.go`（`CRYPTO_KEY_MANAGEMENT`, `GENERAL_GO_SECURITY_TRAPS`）- 5G AKA 认证、SQN 管理、MAC-S 验证（已知漏洞 line 323）
  6. `internal/sbi/processor/subscriber_data_management.go`（`PROTOCOL_PARSING_VALIDATION`, `CONCURRENCY_LIFECYCLE`）- 订阅数据处理、锁使用
  7. `internal/sbi/api_*.go`（`PROTOCOL_PARSING_VALIDATION`）- API 处理器、参数验证、JSON 反序列化
  8. `internal/sbi/consumer/*.go`（`SBI_AUTHORIZATION`）- NF 客户端创建、Token 获取
  9. `pkg/factory/config.go`（`CRYPTO_KEY_MANAGEMENT`）- 配置验证、SuciProfiles.PrivateKey 加载
  10. `internal/logger/logger.go`（`SENSITIVE_ASSET_LEAKAGE`）- 日志模块检查点
  11. `pkg/service/init.go`（`ERROR_HANDLING_INFOLEAK`, `CONCURRENCY_LIFECYCLE`）- shutdown 逻辑、panic recover
  12. `cmd/main.go`（`GENERAL_GO_SECURITY_TRAPS`）- 主入口、信号处理、panic recover
- stop_conditions（总规则）：
  - SBI_AUTHORIZATION：在 OAuth2 token 验证完成后、进入任何 UE 上下文创建/订阅写入之前停止
  - CRYPTO_KEY_MANAGEMENT：在密钥材料正确存储/使用后、响应构造之前停止
  - PROTOCOL_PARSING_VALIDATION：在 mandatory IE 校验完成后、进入业务逻辑之前停止
  - CONCURRENCY_LIFECYCLE：在锁覆盖范围确认后、释放后的后续使用点再行展开（仅必要时）
  - GENERAL_GO_SECURITY_TRAPS：在 reflect.DeepEqual/unsafe 使用审查完成并确认风险等级后停止
  - 覆盖例外：若某高优先级模块 `uncovered`，允许向相邻模块扩展 1 层调用补扫
- 覆盖状态输出（必须）：
  - `covered`: 已审且有结论
  - `backfilled`: 原未覆盖，经补扫后已审
  - `uncovered`: 因证据不足/预算限制未审（需给出原因）

后续 go-audit 阶段需要重点关注的 sink/source/净化检查点（文本化）：

Source（不可信输入来源）：
- SBI 请求：HTTP/2 请求头（Authorization token）、路由参数（supi/supiOrSuci/ueId/subscriptionId）、查询参数（plmn-id/dnn/single-nssai）、请求体 JSON（AuthenticationInfoRequest/AuthEvent/SdmSubscription）
- SUCI 输入：supiOrSuci 参数（suci-0-mcc-mnc-routingIndicator-protectionScheme-publicKeyID-schemeOutput）
- UDR/NRF 响应：NF Discovery 结果、认证订阅数据（K/OPC/SQN/AMF）
- 配置输入：yaml 配置文件（SuciProfiles.PrivateKey/PublicKey）、环境变量（BindingIPv4/NfInstanceId）
- OAuth2 token：来自 NRF 的 OAuth2 token、OAuth2 required 标志

Sink（关键危险操作）：
- 认证状态写入：client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus() - 创建认证状态记录
- SQN 更新：client.AuthenticationSubscriptionDocumentApi.ModifyAuthenticationSubscription() - 更新序列号
- UE 上下文创建：context.NewUdmUe() / context.UdmUePool.Store() - 创建/存储 UE 上下文
- 订阅创建：context.CreateSubscriptiontoNotifChange() / context.CreateSubstoNotifSharedData() - 创建订阅
- 密钥材料使用：suci.profileA()/profileB() - ECDH 密钥派生、AES-CTR 解密
- HMAC 验证：HmacSha256() / hmac.Equal() - 密码学验证（注意 generate_auth_data.go:323 使用 reflect.DeepEqual）
- 响应构造：c.JSON() 返回认证向量（Kausf/XresStar/Autn/RAND）、订阅数据（SUPI/GPSI）
- 日志输出：logger.*Log.Infof/Errorf/Traceln - 可能包含敏感信息
- HTTP 响应头：c.Header("Location", ...) - Location URI 构造
- 错误返回：ProblemDetails 构造（Detail 字段可能泄露内部信息）

Sanitizer/净化（需要检查的缓解）：
- OAuth2 验证：oauth.VerifyOAuth() - token 验证函数
- OAuth2 获取：oauth.GetTokenCtx() - 安全获取 token 上下文
- SUPI/SUCI 验证：validator.IsValidSupi() / validator.IsValidSuci() / validator.IsValidGpsi() - 标识符格式验证
- Mandatory IE 检查：API 处理器中检查 nfInstanceId/ausfInstanceId/servingNetworkName/timeStamp/authType 等必填字段
- 配置验证：govalidator.ValidateStruct() - 配置结构验证
- 密钥格式验证：SuciProfiles PrivateKey/PublicKey 格式检查（hex 长度验证）
- 密钥索引验证：keyIndex range check (1 <= keyIndex <= len(suciProfiles))
- Protection Scheme 验证：scheme mismatch check
- HMAC 验证：decryptWithKdf() 中使用 hmac.Equal() - 正确的恒定时间比较
- 锁保护：amSubsDataLock/smfSelSubsDataLock/SmSubsDataLock - 订阅数据访问锁
- MU 锁保护：nfDRMu/nfMngmntMu/nfDiscMu - 客户端缓存锁
- Panic recover：main.go 和 server.go 中的 defer recover - 异常处理
- Shutdown 超时：defaultShutdownTimeout = 2s - 优雅关闭超时

已知漏洞关注点（从历史审计报告中提取）：
- VULN-003: `internal/sbi/processor/generate_auth_data.go:323` - reflect.DeepEqual 用于 MAC-S 验证存在时序攻击风险（严重级别，需替换为 hmac.Equal）

5G AKA 认证关键数据流：
- Source: supiOrSuci (来自 AUSF) -> suci.ToSupi() -> 解析 SUCI 或直接返回 SUPI
- 解密: SUCI scheme output -> profileA/profileB -> ECDH -> AES-CTR -> SUPi
- 密钥获取: UDR QueryAuthSubsData -> K/OPC/SQN/AMF
- 认证向量生成: milenage.GenerateAKAParameters() -> IK/CK/RES/AUTN
- KDF: ueauth.GetKDFValue() -> XresStar/Kausf (5G AKA) 或 ckPrime/ikPrime (EAP-AKA')
- SQN 管理: SQN++ -> ModifyAuthenticationSubscription 更新 UDR
- Sink: c.JSON(response) -> 返回 AuthenticationVector 给 AUSF

并发安全关键检查点：
- UdmUePool: sync.Map 使用 - Range/Store/Load 操作
- UdmUeContext 锁: amSubsDataLock (Mutex), smfSelSubsDataLock (Mutex), SmSubsDataLock (RWMutex)
- 客户端缓存锁: nfDRMu (RWMutex), nfMngmntMu (RWMutex), nfDiscMu (RWMutex)
- 订阅管理: SubscribeToNotifChange (map + 锁), SubscriptionOfSharedDataChange (sync.Map)


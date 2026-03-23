# 5GC安全审计检查清单

## 通用5GC安全检查项

### A. SBI接口安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| SBI-01 | 所有SBI端点是否启用mTLS | CRITICAL | 检查TLS配置，验证客户端证书验证 |
| SBI-02 | SBI请求是否验证OAuth2 access token | HIGH | 检查授权中间件配置 |
| SBI-03 | SBI请求参数是否经过输入验证 | HIGH | 数据流分析，检查参数校验逻辑 |
| SBI-04 | SBI错误响应是否泄露内部信息 | MEDIUM | 检查error handler，查看响应体 |
| SBI-05 | SBI API是否有速率限制 | MEDIUM | 检查限流中间件 |
| SBI-06 | SBI通信是否使用HTTP/2 | MEDIUM | 检查server配置 |
| SBI-07 | 3gpp-Sbi-*头部是否被验证 | HIGH | 检查自定义头部处理逻辑 |
| SBI-08 | NF服务消费者身份是否被验证 | CRITICAL | 检查NF身份验证机制 |

### B. 协议消息处理安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| MSG-01 | 消息长度字段是否有上限检查 | HIGH | 代码审计消息解码函数 |
| MSG-02 | 嵌套IE/TLV的深度是否有限制 | HIGH | 检查递归解码逻辑 |
| MSG-03 | 可选IE缺失时是否正确处理 | MEDIUM | 检查nil检查逻辑 |
| MSG-04 | 未知IE/消息类型是否安全忽略 | MEDIUM | 检查default分支处理 |
| MSG-05 | 消息解码错误是否导致panic | HIGH | 检查类型断言和slice操作 |
| MSG-06 | 重复IE是否正确处理 | MEDIUM | 检查是否允许覆盖 |
| MSG-07 | 消息解码后是否验证语义正确性 | MEDIUM | 检查值域验证 |

### C. 认证与密钥管理

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| AUTH-01 | 5G-AKA/EAP-AKA'实现是否正确 | CRITICAL | 逐步验证认证流程 |
| AUTH-02 | SUPI/SUCI转换是否使用正确的加密方案 | CRITICAL | 检查ECIES/Profile A/B实现 |
| AUTH-03 | 认证向量是否安全生成和存储 | CRITICAL | 检查随机数生成和存储 |
| AUTH-04 | 密钥派生（KDF）是否符合TS 33.501 | CRITICAL | 验证密钥推导函数参数 |
| AUTH-05 | 安全上下文是否正确建立和维护 | HIGH | 检查安全上下文状态管理 |
| AUTH-06 | 密钥是否在内存中安全处理 | HIGH | 检查密钥使用后是否清零 |
| AUTH-07 | NAS安全算法协商是否可被降级 | CRITICAL | 检查算法选择逻辑 |
| AUTH-08 | NF间通信证书链是否正确验证 | HIGH | 检查TLS证书验证代码 |

### D. 会话管理安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| SESS-01 | PDU会话建立是否验证UE身份 | CRITICAL | 检查SM上下文中的UE标识验证 |
| SESS-02 | QoS参数是否经过验证 | HIGH | 检查QoS策略执行逻辑 |
| SESS-03 | DNN/S-NSSAI是否与签约数据匹配 | HIGH | 检查签约数据验证 |
| SESS-04 | N4会话操作是否有授权检查 | HIGH | 检查PFCP消息处理 |
| SESS-05 | 会话状态机转换是否严格 | MEDIUM | 检查状态机实现 |
| SESS-06 | 并发会话操作是否有同步保护 | HIGH | 检查锁和原子操作 |
| SESS-07 | 会话释放是否彻底清理资源 | MEDIUM | 检查cleanup逻辑 |

### E. 数据面安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| DP-01 | GTP-U TEID是否验证属于合法会话 | CRITICAL | 检查TEID查找逻辑 |
| DP-02 | 上行分类规则(URR)是否正确执行 | HIGH | 检查包过滤规则应用 |
| DP-03 | 数据包大小是否有限制 | MEDIUM | 检查缓冲区分配 |
| DP-04 | GTP扩展头是否安全解析 | HIGH | 检查扩展头解码逻辑 |
| DP-05 | 用户面数据是否与控制面策略一致 | HIGH | 检查PDR/FAR一致性验证 |
| DP-06 | 流量统计是否存在整数溢出 | MEDIUM | 检查计数器类型 |

### F. 服务注册与发现安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| NRF-01 | NF注册是否验证注册者身份 | CRITICAL | 检查注册API认证 |
| NRF-02 | NF Profile是否包含过多敏感信息 | MEDIUM | 检查NF Profile字段 |
| NRF-03 | 服务发现结果是否被篡改保护 | HIGH | 检查响应完整性 |
| NRF-04 | NF心跳是否被验证 | MEDIUM | 检查心跳处理逻辑 |
| NRF-05 | NF去注册是否需要认证 | HIGH | 检查去注册API |
| NRF-06 | 订阅通知是否发送给正确的NF | HIGH | 检查callback URL验证 |

### G. 网络切片安全

| ID | 检查项 | 严重性 | 检查方法 |
|----|--------|--------|---------|
| SLICE-01 | S-NSSAI是否正确验证 | HIGH | 检查切片选择逻辑 |
| SLICE-02 | 切片间资源是否隔离 | CRITICAL | 检查资源分配逻辑 |
| SLICE-03 | 跨切片通信是否有访问控制 | CRITICAL | 检查切片间通信策略 |
| SLICE-04 | 切片特定认证是否正确实现 | HIGH | 检查NSSAA流程 |
| SLICE-05 | 切片准入控制是否有效 | HIGH | 检查准入策略执行 |

## 按NF的审计重点

### AMF审计重点

```
1. NAS消息处理
   □ Registration Request解码安全
   □ Authentication Response验证
   □ Security Mode Complete处理
   □ Service Request处理
   □ Deregistration处理

2. NGAP消息处理
   □ Initial UE Message处理
   □ UE Context Release处理
   □ Handover Required/Request处理
   □ Path Switch Request处理

3. UE上下文管理
   □ UE上下文创建/删除的同步
   □ GUTI分配的唯一性
   □ 安全上下文存储安全

4. 移动性管理
   □ 切换过程中的安全上下文迁移
   □ N2切换vs Xn切换的安全差异
   □ 切换回退处理
```

### SMF审计重点

```
1. PDU会话管理
   □ 会话建立/修改/释放的授权
   □ QoS参数验证和执行
   □ UPF选择和控制

2. N4接口（PFCP）
   □ PFCP Session Establishment
   □ PFCP Session Modification
   □ PFCP Session Deletion
   □ PFCP Association Setup

3. 策略执行
   □ PCF策略的正确应用
   □ 计费策略执行
   □ 流量控制策略
```

### UPF审计重点

```
1. 数据面处理
   □ GTP-U解封装/封装
   □ 包检测规则(PDR)匹配
   □ 转发动作规则(FAR)执行
   □ QoS执行规则(QER)
   □ 使用报告规则(URR)

2. N4接口
   □ PFCP消息处理
   □ Session管理同步
   □ 规则更新原子性

3. 性能与安全平衡
   □ 高性能路径中的安全检查
   □ DDoS防护能力
   □ 异常流量处理
```

### UDM/UDR审计重点

```
1. 用户数据保护
   □ SUPI/SUCI处理
   □ 认证数据访问控制
   □ 签约数据读写权限
   □ 数据完整性保护

2. 认证服务
   □ 认证向量生成
   □ 认证确认处理
   □ 密钥派生正确性

3. SBI访问控制
   □ Nudm_SubscriberDataManagement
   □ Nudm_UEAuthentication
   □ Nudm_UEContextManagement
```

## 3GPP安全规范映射

| 3GPP规范 | 对应审计领域 | 关键条款 |
|----------|------------|---------|
| TS 33.501 | 5G安全架构 | 6(认证), 7(密钥管理), 9(NAS安全) |
| TS 33.117 | 安全保障通用要求 | 4.2(网络产品安全), 4.3(安全功能) |
| TS 33.512 | AMF安全保障 | 4(安全功能要求) |
| TS 33.513 | UPF安全保障 | 4(安全功能要求) |
| TS 33.514 | UDM安全保障 | 4(安全功能要求) |
| TS 33.515 | SMF安全保障 | 4(安全功能要求) |
| TS 33.516 | AUSF安全保障 | 4(安全功能要求) |
| TS 33.517 | SEPP安全保障 | 4(安全功能要求) |
| TS 33.518 | NRF安全保障 | 4(安全功能要求) |
| TS 33.519 | NEF安全保障 | 4(安全功能要求) |

## 审计发现模板

```markdown
### [检查项ID] [检查项标题]

**状态**: 通过 / 不通过 / 部分通过 / 不适用

**严重性**: CRITICAL / HIGH / MEDIUM / LOW

**发现**:
[具体发现描述]

**代码位置**:
`file.go:line` - `函数名`

**证据**:
```go
// 相关代码
```

**风险**:
[安全风险说明]

**建议**:
[修复建议]

**3GPP参考**:
[相关3GPP规范条款]
```

# Go攻击模式分类体系

## 分类设计原则

1. **与CWE兼容**：每个分类下的模式可映射到一组CWE条目
2. **Go语言特性驱动**：分类反映Go语言特有的安全特征
3. **可操作性**：分类应直接指导代码审计策略
4. **5GC增强**：专设5GC特定分类处理核心网特有安全问题

## 一级分类（14类）

### 1. input_validation — 输入验证缺陷

**描述**: 未对外部输入进行充分验证导致的安全问题

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| missing_validation | CWE-20 | 完全缺少输入验证 |
| insufficient_validation | CWE-20 | 验证不充分，存在绕过 |
| type_confusion | CWE-843 | 输入类型混淆 |
| length_check | CWE-130 | 长度/大小检查缺失 |
| encoding_validation | CWE-838 | 编码验证不当 |

**Go语言相关特性**: `encoding_json`, `encoding_xml`, `io`, `net`, `http`

### 2. type_safety — 类型安全问题

**描述**: Go类型系统使用不当导致的安全问题

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| type_assertion | CWE-843 | 未检查的类型断言 |
| integer_overflow | CWE-190 | 整数溢出/下溢 |
| unsafe_pointer | CWE-788 | unsafe.Pointer误用 |
| nil_dereference | CWE-476 | nil指针/接口解引用 |
| type_conversion | CWE-681 | 不安全的类型转换 |

**Go语言相关特性**: `interface`, `type_assertion`, `unsafe`, `slice`

### 3. concurrency — 并发安全问题

**描述**: Go并发原语使用不当导致的竞态条件和同步问题

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| data_race | CWE-362 | 共享变量无同步保护 |
| goroutine_leak | CWE-404 | goroutine资源泄漏 |
| channel_misuse | CWE-362 | channel使用不当 |
| deadlock | CWE-833 | 死锁 |
| toctou | CWE-367 | 检查-使用竞态 |
| map_concurrent | CWE-362 | map并发读写 |

**Go语言相关特性**: `goroutine`, `channel`, `shared_variable`, `sync`, `atomic`, `map`

### 4. memory_safety — 内存安全问题

**描述**: 虽然Go有GC和边界检查，但仍存在的内存安全问题

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| buffer_overread | CWE-125 | 通过unsafe或cgo的缓冲区越界读 |
| use_after_free | CWE-416 | cgo场景下的释放后使用 |
| stack_overflow | CWE-121 | 深度递归导致栈溢出 |
| slice_aliasing | CWE-119 | slice共享底层数组的意外修改 |

**Go语言相关特性**: `unsafe`, `cgo`, `slice`

### 5. crypto_misuse — 密码学误用

**描述**: 密码学原语使用不当

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| weak_random | CWE-330 | 使用math/rand替代crypto/rand |
| insecure_tls | CWE-295 | TLS配置不安全 |
| hardcoded_secret | CWE-798 | 密钥/密码硬编码 |
| weak_algorithm | CWE-327 | 使用弱加密算法 |
| iv_reuse | CWE-329 | 初始化向量重用 |
| timing_attack | CWE-208 | 非常数时间比较 |

**Go语言相关特性**: `crypto`

### 6. auth_authz — 认证授权缺陷

**描述**: 认证和授权逻辑的安全缺陷

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| auth_bypass | CWE-287 | 认证绕过 |
| missing_authz | CWE-862 | 缺少授权检查 |
| privilege_escalation | CWE-269 | 权限提升 |
| session_fixation | CWE-384 | 会话固定 |
| token_weakness | CWE-613 | Token管理缺陷 |

**Go语言相关特性**: `http`, `context`

### 7. resource_mgmt — 资源管理问题

**描述**: 系统资源管理不当导致DoS或信息泄露

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| resource_exhaustion | CWE-400 | 资源耗尽 |
| connection_leak | CWE-404 | 连接泄漏 |
| unbounded_alloc | CWE-789 | 无限制的内存分配 |
| fd_leak | CWE-775 | 文件描述符泄漏 |
| no_timeout | CWE-400 | 缺少超时设置 |

**Go语言相关特性**: `http`, `net`, `io`, `context`, `defer`

### 8. error_handling — 错误处理缺陷

**描述**: Go的error处理模式使用不当

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| ignored_error | CWE-252 | 忽略error返回值 |
| panic_recovery | CWE-755 | 不当的panic恢复 |
| error_wrapping | CWE-209 | 错误信息泄露敏感数据 |
| partial_init | CWE-665 | 错误后的部分初始化 |

**Go语言相关特性**: `error_handling`, `panic_recover`, `defer`

### 9. injection — 注入类漏洞

**描述**: 将不可信数据注入到命令、查询或模板中

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| sql_injection | CWE-89 | SQL注入 |
| command_injection | CWE-78 | OS命令注入 |
| template_injection | CWE-94 | 模板注入 |
| ldap_injection | CWE-90 | LDAP注入 |
| header_injection | CWE-113 | HTTP头注入 |
| log_injection | CWE-117 | 日志注入 |

**Go语言相关特性**: `os_exec`, `database_sql`, `http`

### 10. path_traversal — 路径遍历

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| directory_traversal | CWE-22 | 目录穿越 |
| symlink_following | CWE-59 | 符号链接跟随 |
| zip_slip | CWE-22 | 压缩包解压路径穿越 |

**Go语言相关特性**: `filepath`, `io`

### 11. ssrf — 服务端请求伪造

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| full_ssrf | CWE-918 | 完全可控的SSRF |
| blind_ssrf | CWE-918 | 无回显SSRF |
| dns_rebinding | CWE-350 | DNS重绑定 |
| redirect_ssrf | CWE-601 | 通过重定向的SSRF |

**Go语言相关特性**: `http`, `net`

### 12. deserialization — 反序列化问题

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| json_bomb | CWE-400 | JSON解析资源耗尽 |
| yaml_attack | CWE-502 | YAML反序列化攻击 |
| gob_rce | CWE-502 | gob反序列化代码执行 |
| xml_xxe | CWE-611 | XML外部实体注入 |
| protobuf_abuse | CWE-502 | protobuf解析异常 |

**Go语言相关特性**: `encoding_json`, `encoding_xml`

### 13. protocol_parsing — 协议解析缺陷

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| length_overflow | CWE-130 | 长度字段溢出 |
| malformed_message | CWE-20 | 畸形消息处理 |
| state_confusion | CWE-372 | 协议状态机混乱 |
| version_confusion | CWE-20 | 协议版本混淆 |

**Go语言相关特性**: `net`, `io`, `encoding_json`

### 14. config_exposure — 配置与信息泄露

| 二级分类 | CWE | 说明 |
|---------|-----|------|
| sensitive_log | CWE-532 | 日志中输出敏感数据 |
| debug_endpoint | CWE-489 | 生产环境暴露调试接口 |
| default_creds | CWE-1188 | 使用默认凭证 |
| env_exposure | CWE-526 | 环境变量泄露 |

**Go语言相关特性**: `http`, `os_exec`

## 5GC扩展分类

5GC特定模式使用独立的 `5gc_specific` 标签体系：

| 5GC子分类 | 关联NF | 说明 |
|-----------|--------|------|
| sbi_security | 所有NF | SBI接口的API安全 |
| nas_security | AMF/UE | NAS消息处理安全 |
| ngap_security | AMF/gNB | NGAP消息处理安全 |
| gtp_security | UPF/SMF | GTP隧道安全 |
| pfcp_security | UPF/SMF | PFCP会话安全 |
| nrf_security | NRF | 服务注册与发现安全 |
| subscriber_data | UDM/UDR | 用户数据安全 |
| policy_security | PCF | 策略执行安全 |
| slice_security | NSSF | 网络切片隔离 |
| roaming_security | SEPP | 漫游接口安全 |

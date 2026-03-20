# Go攻击模式库索引

**最后更新：** 2026-03-19

## 库统计

| 指标 | 数值 |
|------|------|
| 模式总数 | 26 |
| 覆盖类别数 | 10 |
| 高置信度模式 | 24 |
| 中置信度模式 | 2 |
| 低置信度模式 | 0 |
| 来源报告数 | 2 |
| 最后更新 | 2026-03-19 |

## 类别分布

| 类别 | 模式数 | 文件 |
|------|--------|------|
| SQL注入 | 3 | [patterns/sqli-patterns.md](patterns/sqli-patterns.md) |
| 命令注入 | 3 | [patterns/cmdi-patterns.md](patterns/cmdi-patterns.md) |
| SSRF | 2 | [patterns/ssrf-patterns.md](patterns/ssrf-patterns.md) |
| 认证缺陷 | 2 | [patterns/auth-patterns.md](patterns/auth-patterns.md) |
| Go语言特有 | 5 | [patterns/golng-patterns.md](patterns/golng-patterns.md) |
| 竞态条件 | 2 | [patterns/race-patterns.md](patterns/race-patterns.md) |
| 密码学失败 | 3 | [patterns/crypto-patterns.md](patterns/crypto-patterns.md) |
| 路径穿越 | 2 | [patterns/ptr-patterns.md](patterns/ptr-patterns.md) |
| 反序列化 | 2 | [patterns/deser-patterns.md](patterns/deser-patterns.md) |
| 跨站脚本 | 2 | [patterns/xss-patterns.md](patterns/xss-patterns.md) |

## 严重性分布

| 严重性 | 模式数 |
|--------|--------|
| 严重 | 10 |
| 高危 | 14 |
| 中危 | 2 |
| 低危 | 0 |

## 模式ID索引

| ID | 名称 | 类别 | 严重性 |
|----|------|------|--------|
| GO-ATK-SQLI-001 | fmt.Sprintf构建SQL查询导致注入 | SQL注入 | 严重 |
| GO-ATK-SQLI-002 | GORM动态ORDER BY子句注入 | SQL注入 | 高危 |
| GO-ATK-SQLI-003 | 字符串拼接构建SQL查询 | SQL注入 | 严重 |
| GO-ATK-CMDI-001 | shell -c执行用户拼接命令 | 命令注入 | 严重 |
| GO-ATK-CMDI-002 | exec.Command参数注入 | 命令注入 | 高危 |
| GO-ATK-CMDI-003 | 白名单校验不严格绕过 | 命令注入 | 高危 |
| GO-ATK-SSRF-001 | 用户控制URL的HTTP请求无校验 | SSRF | 高危 |
| GO-ATK-SSRF-002 | 重定向绕过内网访问限制 | SSRF | 高危 |
| GO-ATK-AUTH-001 | JWT未验证签名算法（alg:none攻击） | 认证缺陷 | 严重 |
| GO-ATK-AUTH-002 | 硬编码凭证 | 认证缺陷 | 严重 |
| GO-ATK-GOLNG-001 | unsafe.Pointer类型转换绕过类型安全 | Go语言特有 | 严重 |
| GO-ATK-GOLNG-002 | reflect包动态方法调用导致任意方法执行 | Go语言特有 | 高危 |
| GO-ATK-GOLNG-003 | 数组/切片越界导致panic | Go语言特有 | 中危 |
| GO-ATK-GOLNG-004 | 空指针解引用导致panic | Go语言特有 | 中危 |
| GO-ATK-GOLNG-005 | goroutine泄漏导致资源耗尽 | Go语言特有 | 高危 |
| GO-ATK-RACE-001 | TOCTOU竞态导致双重支付 | 竞态条件 | 高危 |
| GO-ATK-RACE-002 | map并发读写导致panic | 竞态条件 | 高危 |
| GO-ATK-CRYPTO-001 | math/rand生成安全令牌 | 密码学失败 | 高危 |
| GO-ATK-CRYPTO-002 | 弱加密算法使用 | 密码学失败 | 高危 |
| GO-ATK-CRYPTO-003 | 硬编码加密密钥 | 密码学失败 | 严重 |
| GO-ATK-PTR-001 | Zip Slip任意文件写入 | 路径穿越 | 高危 |
| GO-ATK-PTR-002 | 用户输入直接拼接文件路径 | 路径穿越 | 高危 |
| GO-ATK-DESER-001 | JSON解码无请求体大小限制 | 反序列化 | 中危 |
| GO-ATK-DESER-002 | gob解码不可信数据 | 反序列化 | 严重 |
| GO-ATK-XSS-001 | 模板输出未转义用户输入 | 跨站脚本 | 高危 |
| GO-ATK-XSS-002 | fmt.Fprintf直接输出到响应 | 跨站脚本 | 高危 |

## 使用说明

1. **模式查找：** 根据漏洞类别在 `patterns/` 目录下找到对应的模式文件
2. **测试指导：** 每个模式包含检测点、测试步骤和适用工具
3. **修复参考：** 每个模式提供漏洞代码示例和安全代码示例
4. **工具集成：** 参考 `test_method.automation_hint` 字段集成静态分析工具

## 覆盖的CWE

本模式库覆盖以下CWE编号：

- CWE-22 (路径穿越)
- CWE-78 (OS命令注入)
- CWE-79 (跨站脚本)
- CWE-89 (SQL注入)
- CWE-129 (数组越界)
- CWE-287 (认证失败)
- CWE-321 (硬编码密钥)
- CWE-327 (弱密码算法)
- CWE-330 (随机数不安全)
- CWE-362 (竞态条件)
- CWE-400 (资源耗尽)
- CWE-470 (危险函数调用)
- CWE-476 (空指针解引用)
- CWE-502 (不安全反序列化)
- CWE-798 (硬编码凭证)
- CWE-843 (类型混淆)
- CWE-918 (SSRF)

---
name: go-vuln-insight
description: 收集和分析Go语言开源项目中的安全漏洞，提取攻击模式并生成结构化漏洞洞察报告。当用户需要分析Go语言CVE漏洞、提取Go安全漏洞的攻击模式、研究Go开源项目的历史安全问题、或者需要从Go漏洞中提炼可复用的漏洞检测规则时，使用此技能。也适用于分析govulncheck报告、研究Go标准库漏洞、或追踪特定Go模块的安全历史。
---

# Go漏洞洞察分析

对Go语言生态中的安全漏洞进行系统化收集、深度分析和攻击模式提取，输出结构化的漏洞洞察报告，为后续攻击模式库构建和代码审计提供情报基础。

## 工作流程

```
用户需求 → 确定分析目标
    ├─ 特定CVE/漏洞分析 → 单点深度分析流程
    ├─ 特定Go模块/项目 → 项目漏洞全景分析
    ├─ 特定漏洞类型研究 → 分类横向分析
    └─ 5GC相关Go组件 → 核心网定向分析
```

## 第一阶段：漏洞情报收集

### 1.1 数据源策略

按照优先级从以下数据源收集Go漏洞信息：

**一级数据源（权威官方）**
- Go官方漏洞数据库：`https://vuln.go.dev/` — 通过 `govulncheck` 工具或API查询
- GitHub Advisory Database：通过 `gh api` 查询Go相关advisory
- NVD/CVE数据库：搜索Go语言相关CVE条目

**二级数据源（社区与安全研究）**
- Go项目的GitHub Issues中标记为security的条目
- Go项目的CHANGELOG和release notes中的安全修复
- 安全研究博客和漏洞披露报告（如Snyk、Sonatype）

**三级数据源（代码考古）**
- Git commit历史中的安全修复commit（关键词：fix, vuln, security, CVE, overflow, injection, bypass）
- 代码diff分析：对比修复前后的代码变更

### 1.2 收集命令参考

```bash
# 使用govulncheck扫描项目
govulncheck ./...

# 使用GitHub CLI查询Go相关安全公告
gh api graphql -f query='
{
  securityAdvisories(ecosystem: GO, first: 20, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      severity
      publishedAt
      vulnerabilities(first: 5) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}'

# 搜索项目中的安全修复commit
git log --all --oneline --grep="CVE-" --grep="security" --grep="vulnerability" --grep="overflow" --grep="injection"
```

### 1.3 5GC组件重点关注列表

对以下5G核心网相关Go开源项目保持持续跟踪：

| 组件域 | 重点项目 | 关注漏洞类型 |
|--------|---------|------------|
| NF框架 | free5gc, open5gs(Go绑定), OAI-CN5G | 协议解析、认证绕过 |
| SBI接口 | OpenAPI生成的Go HTTP服务 | API注入、鉴权缺陷 |
| GTP/PFCP | Go实现的GTP-U/PFCP协议栈 | 包解析溢出、状态机混乱 |
| NAS/NGAP | Go实现的NAS/NGAP编解码 | ASN.1解析、缓冲区问题 |
| 数据面 | Go实现的UPF/数据面转发 | 内存安全、并发竞态 |
| 配置管理 | etcd, consul(5GC编排) | 权限提升、未授权访问 |

## 第二阶段：漏洞深度分析

对每个收集到的漏洞执行以下分析步骤：

### 2.1 漏洞基本信息提取

```
漏洞标识: [CVE编号 / GHSA编号 / 内部编号]
影响组件: [Go模块路径]
影响版本: [版本范围]
修复版本: [首个修复版本]
CVSS评分: [评分及向量]
漏洞类型: [CWE分类]
发现时间: [日期]
攻击前提: [触发条件]
```

### 2.2 根因分析（Root Cause Analysis）

对每个漏洞进行代码级根因分析：

1. **定位漏洞代码**：找到引入漏洞的具体函数和代码行
2. **理解数据流**：追踪从输入（source）到漏洞触发点（sink）的完整数据流
3. **识别缺失的安全检查**：分析应该存在但缺失的输入验证、边界检查或权限验证
4. **分析修复方案**：对比修复patch，理解修复策略

分析时重点关注以下Go语言特有的漏洞根因：

- **类型断言失败**：未检查的 `interface{}` 类型断言导致panic
- **slice/map并发访问**：缺少同步保护的并发读写
- **defer陷阱**：defer与goroutine生命周期不匹配导致资源泄漏
- **error忽略**：关键安全操作的error返回值被丢弃
- **unsafe.Pointer滥用**：不安全的指针转换绕过类型系统
- **整数溢出**：Go不检查整数溢出，在长度计算中尤为危险
- **nil指针解引用**：未初始化的接口或指针在特定路径上触发nil panic
- **goroutine泄漏**：无限等待的goroutine导致资源耗尽
- **路径遍历**：`filepath.Join` 不防御 `../` 前缀的路径
- **SSRF/开放重定向**：`http.Client` 默认跟随重定向

### 2.3 攻击模式提取

从每个漏洞中提取可复用的攻击模式，格式如下：

```yaml
attack_pattern:
  id: "AP-GO-XXXX"
  name: "模式名称"
  category: "漏洞大类（如：输入验证/并发安全/认证授权/密码学误用/资源管理）"
  language_specific: true
  go_features_involved:
    - "涉及的Go语言特性（如：goroutine/channel/interface/defer/unsafe）"
  
  description: "攻击模式的自然语言描述"
  
  preconditions:
    - "触发此模式需要的前提条件"
  
  vulnerable_pattern:
    code: |
      // 典型的脆弱代码模式（抽象化，非特定项目代码）
    explanation: "为什么这段代码存在安全问题"
  
  secure_pattern:
    code: |
      // 安全的编码方式
    explanation: "安全模式如何消除风险"
  
  detection_strategy:
    static_analysis: "静态分析如何发现此模式"
    code_review_clue: "代码审计时的关键线索"
    grep_pattern: "可用于初步搜索的正则表达式"
  
  real_world_examples:
    - cve: "CVE-XXXX-XXXX"
      project: "项目名"
      description: "简要描述"
  
  severity_factors:
    base_severity: "High/Medium/Low"
    context_amplifiers:
      - "在什么上下文中严重性会提升（如：5GC控制面）"
  
  related_patterns:
    - "关联的其他攻击模式ID"
```

## 第三阶段：洞察报告生成

### 3.1 报告结构

生成的每份洞察报告必须包含以下章节：

```markdown
# Go漏洞洞察报告：[分析主题]

## 报告元信息
- 分析范围：[目标项目/漏洞集合]
- 分析时间：[日期]
- 分析师：AI辅助 + [审计人员]
- 漏洞数量：[统计]

## 执行摘要
[200字以内的关键发现总结，面向管理层]

## 漏洞清单
[按严重程度排序的漏洞列表，每项包含基本信息]

## 攻击模式分析
[提取的攻击模式详细描述，按类别组织]

## Go语言特性关联分析
[哪些Go语言特性与哪类漏洞高度相关的统计分析]

## 5GC安全影响评估（如适用）
[漏洞对5G核心网的潜在影响分析]

## 趋势与洞察
[漏洞趋势、常见根因模式、生态风险评估]

## 建议的审计关注点
[基于分析结果，建议后续代码审计时重点关注的方向]

## 附录：原始数据
[分析过程中使用的原始数据引用]
```

### 3.2 输出格式

报告以Markdown格式生成，同时输出以下机器可读文件：

- `insight-report.md` — 完整的人类可读报告
- `attack-patterns.json` — 提取的攻击模式（供go-vuln-lib导入）
- `vuln-summary.json` — 漏洞摘要数据

`attack-patterns.json` 的格式详见 `references/attack-pattern-schema.md`。

## 分析策略指南

### 单点深度分析（特定CVE）

1. 获取CVE详细信息和受影响的Go模块
2. 克隆受影响项目，检出漏洞版本和修复版本
3. 执行git diff分析修复patch
4. 完成根因分析和攻击模式提取
5. 评估该攻击模式在其他Go项目中的普适性

### 项目漏洞全景分析

1. 收集目标项目的全部已知漏洞
2. 运行 `govulncheck` 扫描当前依赖
3. 审查security相关的Issues和PR
4. 分析安全修复commit的历史分布
5. 统计漏洞类型分布，识别系统性弱点
6. 输出项目安全态势评估

### 分类横向分析

1. 确定分析的漏洞类型（如：Go并发漏洞）
2. 跨多个项目收集该类型的所有实例
3. 提取共性模式和变体
4. 构建该类型的完整攻击模式族
5. 评估检测方法的覆盖率

### 5GC定向分析

1. 锁定5GC相关Go组件
2. 重点关注协议解析、SBI接口、NF间通信的漏洞
3. 评估漏洞在5GC部署环境中的可利用性
4. 关联3GPP安全规范（TS 33.501等）进行合规性分析
5. 输出5GC安全风险矩阵

## 质量要求

- 每个攻击模式必须包含至少一个真实CVE作为证据
- 脆弱代码模式必须是抽象化的、可在其他项目中匹配的通用模式
- 安全模式必须经过验证，确实能消除对应的安全风险
- 5GC影响评估需基于实际的5G网络架构，而非理论推演
- 所有分析结论必须可追溯到具体的代码或文档证据

## 参考文件

- `references/attack-pattern-schema.md` — 攻击模式JSON schema定义
- `references/vuln-sources.md` — 漏洞数据源详细清单和访问方法
- `references/go-security-features.md` — Go语言安全特性与常见陷阱参考

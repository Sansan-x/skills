---
name: go-vuln-insight
description: 收集和分析Go语言开源项目中的安全漏洞，提取攻击模式并生成结构化漏洞报告。当用户需要分析Go项目安全漏洞、提取漏洞模式、进行代码审计模式总结、分析5GC核心网安全漏洞、或需要生成漏洞洞察报告时，请使用此技能。即使用户只是提到"Go漏洞分析"、"安全审计模式"、"核心网安全"或"漏洞模式提取"，也应该触发此技能。
---

# Go漏洞洞察 (go-vuln-insight)

一个专注于Go语言开源项目安全漏洞收集与攻击模式提取的技能。通过分析GitHub上的安全Issue和修复PR，提取可用于代码审计的结构化攻击模式。

## 技能概述

本技能的核心工作流程：

1. **项目发现** — 从用户提供的Markdown文档中解析待分析的GitHub项目地址
2. **漏洞采集** — 通过GitHub API采集项目中带有`security`/`bug`/`vulnerability`标签的Issue及关联CVE
3. **深度分析** — 基于Issue Report和Fixing Pull Request，分析漏洞代码与修复代码（严禁臆想）
4. **模式提取** — 从漏洞中提取特征代码，总结成可复用的Go语言攻击模式
5. **报告生成** — 在`reports/`目录下输出结构化的漏洞洞察报告

## 执行流程

### 第一步：解析项目列表

从用户提供的Markdown文件中提取GitHub项目地址。使用脚本：

```bash
python scripts/parse_projects.py <markdown文件路径>
```

Markdown文件格式示例：
```markdown
# 待分析项目列表
- [free5gc](https://github.com/free5gc/free5gc)
- [open5gs](https://github.com/open5gs/open5gs)
```

脚本会输出JSON格式的项目列表，包含 `owner`、`repo`、`url` 字段。

### 第二步：采集安全漏洞

对每个项目，使用脚本采集安全相关的Issue：

```bash
python scripts/fetch_issues.py --owner <owner> --repo <repo> --labels security,bug,vulnerability --state all
```

脚本功能：
- 自动搜索带有安全相关标签的Issue
- 提取Issue中的CVE编号
- 获取关联的Pull Request信息
- 输出JSON格式的漏洞数据

**重要**：如果 `gh` CLI 可用且已认证，脚本会优先使用它（速度更快、配额更高）。否则回退到公开API。

### 第三步：获取修复代码差异

对每个关联了修复PR的漏洞，获取代码差异：

```bash
python scripts/fetch_pr_diff.py --owner <owner> --repo <repo> --pr <PR编号>
```

脚本功能：
- 获取PR的完整diff
- 提取变更的Go源文件
- 分离出漏洞代码（删除行）和修复代码（新增行）
- 输出结构化的代码变更数据

### 第四步：漏洞深度分析

对采集到的每个漏洞，执行以下分析（**必须基于实际的Issue和PR数据，严禁臆想**）：

#### 4.1 漏洞根因分析

基于Issue Report中的描述，确定：
- **漏洞触发条件**：什么输入/操作能触发漏洞
- **影响范围**：哪些组件/功能受影响
- **严重程度**：基于CVSS评分或实际影响评估

#### 4.2 漏洞代码分析

基于PR diff中的**删除行**（漏洞代码），分析：
- 代码中的具体缺陷点
- 缺失的安全检查
- 不当的数据处理逻辑

#### 4.3 修复代码分析

基于PR diff中的**新增行**（修复代码），分析：
- 添加了哪些安全检查
- 修复策略是什么
- 是否完整修复了漏洞

### 第五步：攻击模式提取

从分析结果中提取通用攻击模式。每个攻击模式必须包含以下结构：

```markdown
### 攻击模式：[模式名称]

**模式ID**：GOVULN-[分类]-[序号]
**漏洞类型**：[CWE分类]
**严重程度**：[高/中/低]
**适用场景**：[该模式适用的代码审计场景]

#### 漏洞描述
[详细描述该类漏洞的成因和危害]

#### 漏洞模式（漏洞代码案例）
```go
// 漏洞代码示例 — 来自真实项目
[从实际漏洞中提取的特征代码]
```

#### 检测规则
- [LLM在代码审计时应关注的代码特征]
- [触发该漏洞模式的条件]

#### 安全模式（修复代码案例）
```go
// 安全代码示例 — 来自实际修复
[从实际修复PR中提取的安全代码]
```

#### 测试方法
[如何构造测试用例验证该漏洞的存在]

#### 关联CVE
- [实际关联的CVE编号和链接]
```

**攻击模式分类体系**：

| 分类代码 | 类别 | 说明 |
|----------|------|------|
| NIL | 空指针解引用 | nil pointer dereference导致的panic |
| BOF | 缓冲区溢出 | 数组/切片越界访问 |
| INJ | 注入攻击 | SQL注入、命令注入等 |
| IIV | 输入验证不足 | 缺失或不完整的输入验证 |
| AUZ | 认证授权缺陷 | 认证绕过、权限提升 |
| CRY | 密码学缺陷 | 弱加密、密钥泄露 |
| RCE | 远程代码执行 | 不安全的反序列化、动态执行 |
| DOS | 拒绝服务 | 资源耗尽、panic触发 |
| RAC | 竞态条件 | data race、TOCTOU |
| INF | 信息泄露 | 敏感数据暴露 |
| PRO | 协议合规缺陷 | 违反通信协议规范（如3GPP） |

### 第六步：生成漏洞洞察报告

在 `reports/` 目录下生成报告文件，命名为 `vuln-insight-{项目名}.md`。

报告结构：

```markdown
# 漏洞洞察报告：{项目名}

> 项目地址：{GitHub URL}
> 分析时间：{日期}
> 漏洞总数：{数量}
> 攻击模式数：{数量}

## 概述
[项目简介和安全状况总结]

## 漏洞统计
[按类型、严重程度分类统计]

## 漏洞详情
### VULN-001: [漏洞标题]
- **CVE编号**：[如有]
- **Issue链接**：[GitHub Issue URL]
- **修复PR**：[GitHub PR URL]
- **严重程度**：[评级]
- **影响组件**：[组件名]

#### 漏洞分析
[基于Issue Report的详细分析]

#### 漏洞代码
```go
[实际漏洞代码]
```

#### 修复代码
```go
[实际修复代码]
```

#### 根因分析
[漏洞产生的根本原因]

---

## 攻击模式库
[提取的所有攻击模式，按上述结构输出]

## 代码审计检查清单
[基于提取的模式生成的审计检查清单]

## 参考资料
[所有引用的CVE、Issue、PR链接]
```

## 重要原则

### 数据驱动，严禁臆想

- **所有漏洞分析必须基于实际的Issue Report和PR数据**
- 如果无法获取到某个漏洞的具体代码，应明确标注"代码未获取"而非编造
- 引用代码时必须标注来源（文件路径、commit hash）
- 漏洞描述必须与原始Issue一致，不得添加未经证实的信息

### 攻击模式的实用性

- 每个攻击模式必须足够具体，使LLM在代码审计时能直接匹配
- 漏洞代码案例应保留足够上下文，包含函数签名和关键逻辑
- 检测规则应描述可观察的代码特征，而非抽象概念
- 安全模式必须展示完整的修复方案，包含防御性编码实践

### 5GC核心网特别关注点

当分析5GC相关项目（如free5gc、open5gs等）时，额外关注：
- NAS协议消息解析中的输入验证
- PFCP协议处理中的空指针和越界访问
- HTTP/2 SBI接口中的认证授权
- GTP-U隧道处理中的数据包验证
- 网络切片（Network Slicing）相关的隔离性问题
- SUPI/SUCI等身份标识的处理安全

## 脚本使用说明

所有脚本位于 `scripts/` 目录下，运行前请先查看帮助：

```bash
python scripts/parse_projects.py --help
python scripts/fetch_issues.py --help
python scripts/fetch_pr_diff.py --help
python scripts/analyze.py --help
```

### 环境要求

- Python 3.8+
- `gh` CLI（可选，用于更高效的GitHub API访问）
- 网络连接（访问GitHub API）

### 一键分析（推荐）

使用端到端分析脚本自动完成数据采集：

```bash
python scripts/analyze.py examples/projects.md --output-dir ./analysis_data
```

该脚本会自动：
1. 解析Markdown中的项目列表
2. 对每个项目采集安全Issue
3. 对关联PR获取代码diff
4. 将结构化数据输出到指定目录

采集完成后，Claude基于输出的JSON数据进行深度分析和报告生成。

### 分步执行

```bash
# 1. 解析项目列表
python scripts/parse_projects.py examples/projects.md

# 2. 采集漏洞信息
python scripts/fetch_issues.py --owner free5gc --repo free5gc --labels "" --state all --security-only

# 3. 获取修复PR的代码差异
python scripts/fetch_pr_diff.py --owner free5gc --repo nas --pr 43

# 4. 基于采集的数据进行分析并生成报告（由Claude完成）
```

## 示例

参考 `examples/` 目录下的示例文件：
- `projects.md` — 示例项目列表
- `vuln-insight-free5gc.md` — 示例漏洞洞察报告（展示报告结构和攻击模式格式）

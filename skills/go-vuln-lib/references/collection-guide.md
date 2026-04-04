# 来源收集指南

本文档提供从四种来源类型中提取Go攻击模式的详细方法论。

## 目录

1. [通用提取流程](#1-通用提取流程)
2. [从go-vuln-insight报告提取](#2-从go-vuln-insight报告提取)
3. [从go-codehub-issue报告提取](#3-从go-codehub-issue报告提取)
4. [从安全测试指导文档提取](#4-从安全测试指导文档提取)
5. [从专家漏洞案例提取](#5-从专家漏洞案例提取)
6. [多来源信息融合](#6-多来源信息融合)
7. [提取质量检查清单](#7-提取质量检查清单)

---

## 1. 通用提取流程

无论来源类型，提取流程均遵循以下步骤：

```
1. 定位来源文件
    ↓
2. 识别文档结构
    ↓
3. 定位安全相关章节
    ↓
4. 提取原始信息片段
    ↓
5. 映射到攻击模式字段
    ↓
6. 补充缺失信息
    ↓
7. 生成结构化条目
```

### 通用关键词搜索

在任何来源文档中，以下关键词指示可提取的攻击模式信息：

**漏洞相关：**
`漏洞`、`注入`、`绕过`、`泄露`、`越权`、`溢出`、`竞态`、`伪造`、`穿越`、
`vulnerability`、`injection`、`bypass`、`leak`、`overflow`、`race condition`

**代码相关：**
`unsafe`、`exec.Command`、`fmt.Sprintf`、`db.Query`、`template.HTML`、
`http.Get`、`os.Open`、`json.Unmarshal`、`reflect`、`cgo`

**修复相关：**
`修复`、`安全`、`防御`、`校验`、`净化`、`加固`、
`fix`、`secure`、`sanitize`、`validate`、`mitigate`

---

## 2. 从go-vuln-insight报告提取

### 2.1 报告结构识别

go-vuln-insight skill输出的报告通常包含：

```
报告标题
├── 执行摘要
├── 项目概况
├── 洞察方法
├── 安全洞察发现
│   ├── 洞察1: [漏洞类型]
│   │   ├── 发现描述
│   │   ├── 攻击方法分析
│   │   ├── 代码示例
│   │   └── 防御建议
│   ├── 洞察2: ...
│   └── ...
├── 攻击面总结
└── 建议
```

### 2.2 关键信息定位

**定位漏洞模式信息：**
- 在"安全洞察发现"章节中，每个洞察项即为一个候选攻击模式
- 关注标题中的漏洞类型关键词（注入、绕过、泄露等）
- 关注"攻击方法分析"子章节，其中包含具体攻击手段

**定位代码示例：**
- 搜索Go代码块（以 ````go` 开始的代码段）
- 区分漏洞代码和安全代码（通常通过注释或上下文区分）
- 注意报告中引用的源文件路径和行号

**定位数据流信息：**
- 搜索包含箭头（→、->）的文本
- 搜索"source"、"sink"、"污点"、"数据流"等关键词
- 检查是否有结构化的数据流追踪表格

### 2.3 字段映射模板

| 报告内容 | 映射到模式字段 |
|----------|--------------|
| 洞察标题 | `name` |
| 漏洞类型 | `category` |
| 严重性评级 | `severity` |
| CWE编号 | `cwe_ids` |
| 发现描述 | `description.summary` + `description.background` |
| 攻击方法分析 | `test_method.strategy` + `vuln_pattern.trigger_conditions` |
| 漏洞代码示例 | `vuln_pattern.code_example` |
| 数据流路径 | `vuln_pattern.dataflow` |
| Sink函数 | `vuln_pattern.sink_functions` |
| 防御建议 | `safe_pattern.fix_strategy` + `safe_pattern.defense_layers` |
| 安全代码示例 | `safe_pattern.code_example` |
| 影响分析 | `description.impact` |
| 前置条件 | `description.preconditions` |
| 涉及的Go库/框架 | `metadata.frameworks` |

### 2.4 提取示例

假设报告中包含以下洞察：

```markdown
### 洞察3：GORM动态ORDER BY注入

**严重性：** 高危
**CWE：** CWE-89

在分析的项目中发现，ListHandler函数直接将用户提供的sort参数传递给
GORM的Order方法，未进行白名单校验...

**漏洞代码：**
// [Go代码块]

**攻击方法：**
攻击者可通过sort参数注入SQL语句...

**修复建议：**
使用白名单校验sort参数...
```

提取映射：
- `name` ← "GORM动态ORDER BY注入"
- `category` ← "SQL注入"
- `severity` ← "高危"
- `cwe_ids` ← ["CWE-89"]
- `description.summary` ← 从描述段落提取
- `vuln_pattern.code_example` ← 漏洞代码块
- `test_method.strategy` ← 从攻击方法段落提取
- `safe_pattern.fix_strategy` ← 从修复建议段落提取
- `source_type` ← "vuln-insight"

---

## 3. 从go-codehub-issue报告提取

### 3.1 报告结构识别

go-codehub-issue skill输出的报告通常包含：

```
报告标题
├── 摘要
├── 项目信息
├── 安全问题列表
│   ├── 问题1
│   │   ├── Issue链接/编号
│   │   ├── 问题分类
│   │   ├── 问题描述
│   │   ├── 影响分析
│   │   ├── 复现步骤
│   │   └── 修复状态
│   ├── 问题2: ...
│   └── ...
├── 安全趋势分析
└── 建议
```

### 3.2 关键信息定位

**定位安全问题：**
- "安全问题列表"章节中的每个问题即为候选攻击模式
- 关注问题分类标签（bug、security、vulnerability等）
- 关注CVE编号和安全公告引用

**定位复现信息：**
- "复现步骤"子章节包含测试方法的核心信息
- 关注最小复现代码（PoC）
- 关注环境要求（Go版本、依赖版本等）

**定位修复信息：**
- 关注Pull Request引用和补丁代码
- 关注修复前后的代码对比（diff格式）
- 关注版本升级建议

### 3.3 字段映射模板

| 报告内容 | 映射到模式字段 |
|----------|--------------|
| 问题标题 | `name` |
| 问题分类 | `category` |
| CVE编号 | `cwe_ids`（需转换，CVE→CWE映射） |
| 问题描述 | `description.summary` + `description.background` |
| 影响分析 | `description.impact` + `severity` |
| 复现步骤 | `test_method.test_steps` |
| 最小复现代码 | `vuln_pattern.code_example` |
| 修复补丁 | `safe_pattern.code_example` |
| 环境要求 | `metadata.go_versions` + `metadata.frameworks` |
| Issue编号/链接 | `source_ref` |

### 3.4 CVE到CWE的映射

codehub-issue报告中常出现CVE编号而非CWE编号，需要进行映射：

1. 在CVE详情中查找关联的CWE编号
2. 如无直接关联，根据漏洞描述推断最相近的CWE
3. 记录映射关系以便追溯

### 3.5 提取注意事项

- 部分issue可能描述不充分，需结合PR代码和讨论补充
- 区分安全问题和普通bug（仅提取安全相关issue）
- 注意issue的修复状态——未修复的issue可能包含更真实的漏洞模式
- 多个issue可能描述同一漏洞的不同方面，需判断是否合并

---

## 4. 从安全测试指导文档提取

### 4.1 文档类型识别

安全测试指导文档可能以多种形式出现：

| 文档类型 | 特点 | 提取侧重 |
|----------|------|----------|
| 安全测试方法论 | 系统性、理论性强 | test_method字段 |
| 漏洞类型指南 | 按漏洞分类组织 | description + vuln_pattern |
| 安全编码规范 | 侧重安全实践 | safe_pattern字段 |
| 工具使用手册 | 侧重工具操作 | test_method.tools + automation_hint |
| Checklist清单 | 条目式、精简 | detection_points + test_steps |

### 4.2 关键信息定位

**定位测试方法：**
- 章节标题含"测试"、"检测"、"验证"、"审计"
- 步骤列表（编号或项目符号）
- 命令行示例（bash代码块）
- 工具配置示例

**定位漏洞说明：**
- 章节标题含漏洞类型名称
- "原理"、"背景"、"概述"子章节
- 危害说明和影响描述

**定位代码示例：**
- "示例"、"案例"、"演示"标签
- 对比格式（"不安全 vs 安全"、"修复前 vs 修复后"）
- 内联代码引用（`func_name()` 格式）

### 4.3 字段映射模板

| 文档内容 | 映射到模式字段 |
|----------|--------------|
| 漏洞类型标题 | `category` + `name` |
| 原理说明 | `description.background` |
| 危害描述 | `description.impact` |
| 检测方法 | `test_method.strategy` |
| 测试步骤 | `test_method.test_steps` |
| 检测点清单 | `test_method.detection_points` |
| 推荐工具 | `test_method.tools` |
| 不安全代码示例 | `vuln_pattern.code_example` |
| 安全代码示例 | `safe_pattern.code_example` |
| 修复建议 | `safe_pattern.fix_strategy` |
| 最佳实践 | `safe_pattern.defense_layers` |

### 4.4 提取注意事项

- 指导文档中的代码示例可能偏向示意性，不一定是完整的可编译代码
- 需要将抽象的测试方法论具体化为Go语言上下文
- 通用安全原则需要转化为Go特有的实现建议
- 注意文档的时效性，旧文档中的建议可能已过时

---

## 5. 从专家漏洞案例提取

### 5.1 案例结构识别

专家编写的漏洞案例通常结构最完整：

```
案例标题
├── 漏洞概述
│   ├── 发现背景
│   ├── 漏洞类型和严重性
│   └── 影响范围
├── 技术分析
│   ├── 漏洞根因
│   ├── 漏洞代码详解
│   ├── 数据流分析
│   └── 利用条件
├── 漏洞利用
│   ├── 利用步骤
│   ├── PoC代码
│   └── 攻击效果
├── 修复方案
│   ├── 直接修复
│   ├── 纵深防御
│   └── 修复验证
└── 经验总结
```

### 5.2 关键信息定位

**定位漏洞核心信息：**
- "漏洞概述"或"背景"章节提供 `description` 全部子字段
- "技术分析"章节提供 `vuln_pattern` 的核心信息
- "利用条件"或"前置条件"提供 `description.preconditions`

**定位代码和数据流：**
- "漏洞代码详解"通常包含带注释的完整漏洞代码
- "数据流分析"直接提供 source → sink 路径
- "PoC代码"可提取 `vuln_pattern.trigger_conditions`

**定位测试和修复信息：**
- "利用步骤"映射到 `test_method.test_steps`
- "修复方案"映射到 `safe_pattern` 全部子字段
- "经验总结"可提取 `safe_pattern.defense_layers` 的额外项

### 5.3 字段映射模板

| 案例内容 | 映射到模式字段 |
|----------|--------------|
| 案例标题 | `name` |
| 漏洞类型 | `category` |
| 严重性评级 | `severity` |
| CWE编号 | `cwe_ids` |
| 漏洞概述 | `description.summary` |
| 发现背景/漏洞根因 | `description.background` |
| 影响范围 | `description.impact` |
| 利用条件 | `description.preconditions` |
| 漏洞代码 | `vuln_pattern.code_example` |
| 涉及的危险API | `vuln_pattern.sink_functions` |
| 输入来源 | `vuln_pattern.source_types` |
| 数据流分析 | `vuln_pattern.dataflow` |
| 利用步骤/PoC | `test_method.test_steps` + `vuln_pattern.trigger_conditions` |
| 修复代码 | `safe_pattern.code_example` |
| 修复策略 | `safe_pattern.fix_strategy` |
| 纵深防御 | `safe_pattern.defense_layers` |
| 经验总结 | `metadata.tags`（提取关键主题词） |

### 5.4 案例脱敏处理

专家案例可能包含真实项目信息，提取时需脱敏：

- 替换真实项目名称为通用名称
- 移除内部URL和IP地址
- 保留技术细节但模糊化组织信息
- 保留CVE编号（公开信息）

---

## 6. 多来源信息融合

当同一漏洞模式从多个来源被提取时，需要进行信息融合。

### 6.1 融合策略

```
多来源信息 → 字段级别择优合并 → 统一条目
```

字段择优规则：

| 字段 | 优先来源（由高到低） |
|------|---------------------|
| `vuln_pattern.code_example` | 专家案例 > vuln-insight > codehub-issue > 指导文档 |
| `test_method` | 指导文档 > 专家案例 > vuln-insight > codehub-issue |
| `vuln_pattern.dataflow` | vuln-insight > 专家案例 > codehub-issue > 指导文档 |
| `safe_pattern` | 专家案例 > codehub-issue > 指导文档 > vuln-insight |
| `description.background` | 指导文档 > 专家案例 > vuln-insight > codehub-issue |

### 6.2 融合记录

融合后的条目需在 `source_ref` 中记录所有来源：

```
source_type: "mixed"
source_ref: "SRC-001(vuln_pattern), SRC-005(test_method), SRC-012(safe_pattern)"
```

### 6.3 冲突处理

当来源间存在信息冲突时：

1. **严重性评级冲突** — 取较高的评级（安全优先原则）
2. **修复方案冲突** — 保留所有方案，标注各方案的适用条件
3. **代码示例冲突** — 保留最完整、最接近真实场景的版本
4. **技术细节冲突** — 核实后选择准确版本，记录排除理由

---

## 7. 提取质量检查清单

每个提取的攻击模式条目应通过以下检查：

### 完整性检查

- [ ] 所有必填字段已填充
- [ ] 漏洞代码示例包含足够上下文
- [ ] 安全代码示例确实修复了漏洞
- [ ] 描述摘要准确反映模式内容

### 准确性检查

- [ ] 漏洞类别和CWE编号正确
- [ ] 严重性评级有依据
- [ ] 代码示例语法正确
- [ ] 数据流描述与代码匹配
- [ ] Sink函数列表准确

### 可操作性检查

- [ ] 测试步骤可按序执行
- [ ] 修复建议具体且可实施
- [ ] 检测点可指导代码审计
- [ ] 安全代码示例可直接参考

### 溯源性检查

- [ ] `source_type` 正确标注
- [ ] `source_ref` 可追溯到原始文档
- [ ] 脱敏处理已完成（如涉及真实项目）

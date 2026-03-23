# Go漏洞数据源详细清单

## 一级数据源（权威官方）

### 1. Go官方漏洞数据库 (vuln.go.dev)

- **访问方式**: Web界面 / govulncheck CLI / API
- **数据格式**: Go Advisory Database JSON
- **覆盖范围**: Go标准库 + 第三方模块

```bash
# 安装govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# 扫描当前项目
govulncheck ./...

# 以JSON格式输出
govulncheck -json ./...

# 扫描特定包
govulncheck -test ./pkg/...

# 扫描二进制文件
govulncheck -mode=binary ./path/to/binary
```

**API访问**:
```
GET https://vuln.go.dev/ID/GO-YYYY-XXXX.json
GET https://vuln.go.dev/index/modules.json
GET https://vuln.go.dev/index/vulns.json
```

### 2. GitHub Advisory Database

```bash
# 查询Go生态最新安全公告
gh api graphql -f query='
{
  securityAdvisories(ecosystem: GO, first: 50, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      ghsaId
      summary
      severity
      cvss { score vectorString }
      cwes(first: 5) { nodes { cweId name } }
      publishedAt
      updatedAt
      references { url }
      vulnerabilities(first: 10) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}'

# 按严重性查询
gh api graphql -f query='
{
  securityAdvisories(ecosystem: GO, severity: CRITICAL, first: 20) {
    nodes { ghsaId summary publishedAt }
  }
}'

# 查询特定包的安全公告
gh api graphql -f query='
{
  securityVulnerabilities(ecosystem: GO, package: "github.com/example/pkg", first: 10) {
    nodes {
      advisory { ghsaId summary severity }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}'
```

### 3. NVD/CVE数据库

- **访问方式**: NVD API v2.0
- **搜索策略**: 使用关键词 `golang`, `go language`, 以及具体的Go包名

```
# NVD API查询示例
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=golang&resultsPerPage=20
```

## 二级数据源（社区与安全研究）

### 4. Go项目Security Issues

```bash
# 搜索项目中标记为security的Issues
gh issue list -R <owner>/<repo> --label security --state all
gh issue list -R <owner>/<repo> --label vulnerability --state all

# 搜索security相关PR
gh pr list -R <owner>/<repo> --search "security fix" --state merged
```

### 5. 安全研究发布平台

| 平台 | URL | 关注内容 |
|------|-----|---------|
| Snyk漏洞库 | snyk.io/vuln | Go包漏洞，含详细分析 |
| OSV.dev | osv.dev | 开源漏洞聚合，统一格式 |
| Security Tracker | security-tracker.debian.org | Debian打包的Go项目 |
| Trail of Bits博客 | blog.trailofbits.com | Go安全审计案例 |
| Project Zero | googleprojectzero.blogspot.com | 高质量漏洞研究 |

### 6. Changelog与Release Notes分析

```bash
# 检查项目的release中security相关内容
gh release list -R <owner>/<repo> --limit 50
gh release view <tag> -R <owner>/<repo>
```

## 三级数据源（代码考古）

### 7. Git历史安全修复挖掘

```bash
# 搜索安全修复commit
git log --all --oneline --grep="CVE-"
git log --all --oneline --grep="security"
git log --all --oneline --grep="vulnerability"
git log --all --oneline --grep="overflow"
git log --all --oneline --grep="injection"
git log --all --oneline --grep="bypass"
git log --all --oneline --grep="GHSA-"
git log --all --oneline --grep="sanitize"
git log --all --oneline --grep="escape"
git log --all --oneline --grep="authenticate"
git log --all --oneline --grep="authorize"

# 查看安全修复的代码变更
git show <commit-hash> --stat
git diff <commit-hash>~1 <commit-hash>

# 查找修改了安全相关文件的commit
git log --all --oneline -- "**/auth*" "**/crypto*" "**/security*" "**/sanitize*"
```

### 8. OSV数据库API

```bash
# 查询特定Go包的已知漏洞
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "package": {
      "name": "github.com/example/module",
      "ecosystem": "Go"
    }
  }'

# 按漏洞ID查询
curl https://api.osv.dev/v1/vulns/GO-2024-XXXX
```

## 5GC相关项目漏洞跟踪

### 重点Go项目

| 项目 | 仓库 | 安全关注点 |
|------|------|-----------|
| free5gc | github.com/free5gc/free5gc | 全栈5GC，NF间通信安全 |
| free5gc各NF | github.com/free5gc/amf 等 | 单NF漏洞，协议解析 |
| go-gtp | github.com/wmnsk/go-gtp | GTP协议解析安全 |
| go-pfcp | github.com/wmnsk/go-pfcp | PFCP协议解析安全 |
| go-diameters | 各diameter Go实现 | Diameter协议安全 |
| OpenAPI Go生成器 | openapi-generator Go输出 | API安全，注入防护 |
| etcd | github.com/etcd-io/etcd | 5GC配置存储安全 |
| gRPC-Go | github.com/grpc/grpc-go | NF间RPC通信安全 |

### 5GC安全搜索策略

```bash
# 在GitHub上搜索5GC相关Go安全问题
gh search issues --language go "5g core security"
gh search issues --language go "free5gc vulnerability"
gh search issues --language go "NAS decode security"
gh search issues --language go "NGAP parse vulnerability"
```

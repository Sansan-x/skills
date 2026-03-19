#!/usr/bin/env python3
"""
从GitHub仓库采集安全相关的Issue信息。

用法：
    python fetch_issues.py --owner <owner> --repo <repo> [选项]
    python fetch_issues.py --help

功能：
    - 搜索带有安全相关标签的Issue
    - 提取Issue中的CVE编号
    - 获取关联的Pull Request信息
    - 输出JSON格式的漏洞数据
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from typing import Optional


API_BASE = "https://api.github.com"
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
PR_REF_PATTERN = re.compile(
    r'(?:#(\d+)|'
    r'https?://github\.com/[^/]+/[^/]+/pull/(\d+))',
    re.IGNORECASE
)


def gh_cli_available() -> bool:
    """检查gh CLI是否可用且已认证。"""
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def api_request(url: str, token: Optional[str] = None) -> dict | list:
    """发送GitHub API请求。"""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "go-vuln-lib/1.0"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403:
                reset = e.headers.get("X-RateLimit-Reset")
                if reset:
                    wait = max(int(reset) - int(time.time()), 1)
                    print(f"API速率限制，等待 {wait} 秒...", file=sys.stderr)
                    time.sleep(min(wait, 60))
                    continue
            if e.code == 404:
                return []
            raise
        except urllib.error.URLError:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise

    return []


def gh_cli_request(args: list[str]) -> str:
    """使用gh CLI执行API请求。"""
    result = subprocess.run(
        ["gh"] + args,
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"gh CLI 错误：{result.stderr}", file=sys.stderr)
        return "[]"
    return result.stdout


def extract_cves(text: str) -> list[str]:
    """从文本中提取CVE编号。"""
    return list(set(CVE_PATTERN.findall(text or "")))


def extract_pr_numbers(text: str) -> list[int]:
    """从文本中提取关联的PR编号。"""
    numbers = set()
    for match in PR_REF_PATTERN.finditer(text or ""):
        num = match.group(1) or match.group(2)
        if num:
            numbers.add(int(num))
    return sorted(numbers)


def _gh_api_get(endpoint: str, params: dict | None = None) -> list | dict:
    """使用gh api发送GET请求并解析JSON。"""
    cmd = ["api", endpoint, "--method", "GET"]
    for k, v in (params or {}).items():
        cmd.extend(["-f", f"{k}={v}"])
    raw = gh_cli_request(cmd)
    if not raw or not raw.strip():
        return []
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return []


def fetch_issues_gh_cli(owner: str, repo: str, labels: list[str],
                        state: str, limit: int) -> list[dict]:
    """使用gh CLI REST API采集Issue。"""
    issues = []

    for label in (labels if labels else []):
        if not label:
            continue
        page = 1
        while len(issues) < limit and page <= 5:
            data = _gh_api_get(
                f"/repos/{owner}/{repo}/issues",
                {"state": state, "per_page": "100", "page": str(page),
                 "labels": label}
            )
            if not isinstance(data, list) or not data:
                break
            for item in data:
                if "pull_request" not in item:
                    issues.append(item)
            if len(data) < 100:
                break
            page += 1

    security_keywords = [
        "CVE", "vulnerability", "security", "overflow",
        "crash", "panic", "null+pointer", "denial+of+service",
        "malformed", "bypass", "injection", "unauthorized",
        "[Bugs]", "compliance", "over-authoriz", "unauthenticated",
    ]
    for kw in security_keywords:
        q = f"repo:{owner}/{repo} is:issue {kw}"
        data = _gh_api_get("/search/issues", {"q": q, "per_page": "100"})
        items = data.get("items", []) if isinstance(data, dict) else []
        for item in items:
            if "pull_request" not in item:
                issues.append(item)

    page = 1
    while page <= 10:
        data = _gh_api_get(
            f"/repos/{owner}/{repo}/issues",
            {"state": state, "per_page": "100", "page": str(page),
             "sort": "created", "direction": "desc"}
        )
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if "pull_request" not in item:
                issues.append(item)
        if len(data) < 100:
            break
        page += 1

    seen_ids = set()
    unique = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        iid = issue.get("id") or issue.get("number")
        if iid and iid not in seen_ids:
            seen_ids.add(iid)
            unique.append(issue)

    return unique[:limit]


def fetch_issues_api(owner: str, repo: str, labels: list[str],
                     state: str, limit: int,
                     token: Optional[str] = None) -> list[dict]:
    """使用REST API采集Issue。"""
    issues = []

    for label in (labels if labels else [""]):
        page = 1
        while len(issues) < limit:
            url = (f"{API_BASE}/repos/{owner}/{repo}/issues"
                   f"?state={state}&per_page={min(100, limit - len(issues))}"
                   f"&page={page}")
            if label:
                url += f"&labels={label}"

            batch = api_request(url, token)
            if not batch:
                break

            for item in batch:
                if "pull_request" not in item:
                    issues.append(item)

            page += 1
            if len(batch) < 100:
                break

    security_keywords = [
        "CVE", "vulnerability", "security", "overflow",
        "crash+OR+panic", "null+pointer", "denial+of+service",
        "malformed", "bypass", "injection", "unauthorized",
        "[Bugs]", "compliance", "over-authoriz", "unauthenticated",
    ]
    for kw in security_keywords:
        search_url = (f"{API_BASE}/search/issues"
                      f"?q=repo:{owner}/{repo}+is:issue+{kw}"
                      f"&per_page=100")
        search_data = api_request(search_url, token)
        if isinstance(search_data, dict):
            for item in search_data.get("items", []):
                if "pull_request" not in item:
                    issues.append(item)

    page = 1
    while page <= 10:
        url = (f"{API_BASE}/repos/{owner}/{repo}/issues"
               f"?state={state}&per_page=100&page={page}"
               f"&sort=created&direction=desc")
        batch = api_request(url, token)
        if not isinstance(batch, list) or not batch:
            break
        for item in batch:
            if "pull_request" not in item:
                issues.append(item)
        if len(batch) < 100:
            break
        page += 1

    seen_ids = set()
    unique = []
    for issue in issues:
        if isinstance(issue, dict) and issue.get("id") not in seen_ids:
            if "pull_request" not in issue:
                seen_ids.add(issue["id"])
                unique.append(issue)

    return unique[:limit]


def process_issue(issue: dict) -> dict:
    """处理单个Issue，提取安全相关信息。"""
    body = issue.get("body", "") or ""
    title = issue.get("title", "") or ""
    full_text = f"{title}\n{body}"

    cves = extract_cves(full_text)
    pr_numbers = extract_pr_numbers(body)

    raw_labels = issue.get("labels", [])
    if isinstance(raw_labels, list) and raw_labels:
        if isinstance(raw_labels[0], dict):
            labels = [l.get("name", "") for l in raw_labels]
        else:
            labels = [str(l) for l in raw_labels]
    else:
        labels = []

    is_security = any(
        kw in label.lower()
        for label in labels
        for kw in ["security", "vulnerability", "cve", "bug"]
    ) or bool(cves) or any(
        kw in title.lower()
        for kw in ["vulnerability", "cve", "security", "exploit",
                    "overflow", "injection", "bypass", "dos",
                    "denial of service", "null pointer", "panic",
                    "crash", "malformed", "unauthorized",
                    "[bugs]", "compliance", "over-authoriz",
                    "unauthenticated", "unauth"]
    )

    url = (issue.get("html_url")
           or issue.get("url")
           or "")

    author = issue.get("author") or issue.get("user") or {}
    if isinstance(author, dict):
        user = author.get("login", "")
    else:
        user = str(author)

    return {
        "number": issue.get("number"),
        "title": title,
        "url": url,
        "state": issue.get("state", ""),
        "created_at": issue.get("created_at") or issue.get("createdAt", ""),
        "closed_at": issue.get("closed_at") or issue.get("closedAt"),
        "labels": labels,
        "cves": cves,
        "referenced_prs": pr_numbers,
        "is_security_related": is_security,
        "body_preview": body[:2000] if body else "",
        "user": user,
    }


def main():
    parser = argparse.ArgumentParser(
        description="从GitHub仓库采集安全相关的Issue",
        epilog="示例：python fetch_issues.py --owner free5gc --repo free5gc --labels security,bug"
    )
    parser.add_argument("--owner", required=True, help="仓库拥有者")
    parser.add_argument("--repo", required=True, help="仓库名称")
    parser.add_argument(
        "--labels",
        type=str,
        default="security,vulnerability,bug",
        help="Issue标签（逗号分隔，默认：security,vulnerability,bug）"
    )
    parser.add_argument(
        "--state",
        choices=["open", "closed", "all"],
        default="all",
        help="Issue状态（默认：all）"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="最大Issue数量（默认：200）"
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="仅输出安全相关的Issue"
    )
    parser.add_argument(
        "--token",
        type=str,
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub API Token（默认从GITHUB_TOKEN环境变量读取）"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="输出文件路径（默认输出到stdout）"
    )

    args = parser.parse_args()
    labels = [l.strip() for l in args.labels.split(",") if l.strip()]

    print(f"正在采集 {args.owner}/{args.repo} 的安全Issue...", file=sys.stderr)

    use_cli = gh_cli_available()
    if use_cli:
        print("使用 gh CLI 模式", file=sys.stderr)
        raw_issues = fetch_issues_gh_cli(
            args.owner, args.repo, labels, args.state, args.limit
        )
    else:
        print("使用 REST API 模式", file=sys.stderr)
        raw_issues = fetch_issues_api(
            args.owner, args.repo, labels, args.state, args.limit, args.token
        )

    processed = [process_issue(issue) for issue in raw_issues]

    if args.security_only:
        processed = [i for i in processed if i["is_security_related"]]

    processed.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    result = {
        "repository": f"{args.owner}/{args.repo}",
        "total_issues": len(processed),
        "security_issues": sum(1 for i in processed if i["is_security_related"]),
        "issues": processed,
    }

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        Path_obj = __import__('pathlib').Path(args.output)
        Path_obj.parent.mkdir(parents=True, exist_ok=True)
        Path_obj.write_text(output, encoding="utf-8")
        print(f"结果已保存至 {args.output}", file=sys.stderr)
    else:
        print(output)

    print(f"\n采集完成：共 {len(processed)} 个Issue，"
          f"其中 {sum(1 for i in processed if i['is_security_related'])} 个安全相关",
          file=sys.stderr)


if __name__ == "__main__":
    main()

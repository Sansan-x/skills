#!/usr/bin/env python3
"""
获取GitHub Pull Request的代码差异，分析漏洞代码和修复代码。

用法：
    python fetch_pr_diff.py --owner <owner> --repo <repo> --pr <PR编号>
    python fetch_pr_diff.py --help

功能：
    - 获取PR的完整diff
    - 提取变更的Go源文件
    - 分离漏洞代码（删除行）和修复代码（新增行）
    - 输出结构化的代码变更数据
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from typing import Optional


API_BASE = "https://api.github.com"


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


def fetch_pr_info_cli(owner: str, repo: str, pr_number: int) -> dict:
    """使用gh CLI获取PR信息。"""
    result = subprocess.run(
        ["gh", "api", f"/repos/{owner}/{repo}/pulls/{pr_number}"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def fetch_pr_diff_cli(owner: str, repo: str, pr_number: int) -> str:
    """使用gh CLI获取PR diff。"""
    result = subprocess.run(
        ["gh", "api", f"/repos/{owner}/{repo}/pulls/{pr_number}",
         "-H", "Accept: application/vnd.github.diff"],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f"获取diff失败：{result.stderr}", file=sys.stderr)
        return ""
    return result.stdout


def fetch_pr_info_api(owner: str, repo: str, pr_number: int,
                      token: Optional[str] = None) -> dict:
    """使用REST API获取PR信息。"""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "go-vuln-lib/1.0"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"获取PR信息失败：{e}", file=sys.stderr)
        return {}


def fetch_pr_diff_api(owner: str, repo: str, pr_number: int,
                      token: Optional[str] = None) -> str:
    """使用REST API获取PR diff。"""
    url = f"{API_BASE}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github.diff",
        "User-Agent": "go-vuln-lib/1.0"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"获取diff失败：{e}", file=sys.stderr)
        return ""


def fetch_pr_commits_cli(owner: str, repo: str, pr_number: int) -> list[dict]:
    """使用gh CLI获取PR关联的commits。"""
    result = subprocess.run(
        ["gh", "api", f"/repos/{owner}/{repo}/pulls/{pr_number}/commits",
         "--paginate"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def parse_diff(diff_text: str) -> list[dict]:
    """解析diff文本，提取文件变更信息。"""
    if not diff_text:
        return []

    files = []
    current_file = None
    current_hunks = []
    current_hunk = None

    for line in diff_text.split('\n'):
        if line.startswith('diff --git'):
            if current_file and current_hunks:
                files.append({
                    "file": current_file,
                    "hunks": current_hunks
                })
            match = re.search(r'b/(.+)$', line)
            current_file = match.group(1) if match else "unknown"
            current_hunks = []
            current_hunk = None

        elif line.startswith('@@'):
            if current_hunk:
                current_hunks.append(current_hunk)
            hunk_match = re.match(
                r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)',
                line
            )
            current_hunk = {
                "header": line,
                "old_start": int(hunk_match.group(1)) if hunk_match else 0,
                "new_start": int(hunk_match.group(3)) if hunk_match else 0,
                "context_label": hunk_match.group(5).strip() if hunk_match else "",
                "removed_lines": [],
                "added_lines": [],
                "context_lines": [],
            }

        elif current_hunk is not None:
            if line.startswith('-') and not line.startswith('---'):
                current_hunk["removed_lines"].append(line[1:])
            elif line.startswith('+') and not line.startswith('+++'):
                current_hunk["added_lines"].append(line[1:])
            elif line.startswith(' '):
                current_hunk["context_lines"].append(line[1:])

    if current_hunk:
        current_hunks.append(current_hunk)
    if current_file and current_hunks:
        files.append({
            "file": current_file,
            "hunks": current_hunks
        })

    return files


def filter_go_files(file_changes: list[dict]) -> list[dict]:
    """过滤出Go源文件的变更。"""
    return [
        f for f in file_changes
        if f["file"].endswith(".go") and not f["file"].endswith("_test.go")
    ]


def analyze_changes(file_changes: list[dict]) -> dict:
    """分析代码变更，生成漏洞代码和修复代码摘要。"""
    vuln_code_blocks = []
    fix_code_blocks = []

    for fc in file_changes:
        filepath = fc["file"]
        for hunk in fc["hunks"]:
            removed = hunk["removed_lines"]
            added = hunk["added_lines"]
            context = hunk["context_lines"]

            if removed:
                vuln_code_blocks.append({
                    "file": filepath,
                    "function": hunk.get("context_label", ""),
                    "start_line": hunk["old_start"],
                    "code": "\n".join(removed),
                    "context": "\n".join(context[:5]),
                })

            if added:
                fix_code_blocks.append({
                    "file": filepath,
                    "function": hunk.get("context_label", ""),
                    "start_line": hunk["new_start"],
                    "code": "\n".join(added),
                    "context": "\n".join(context[:5]),
                })

    return {
        "vulnerability_code": vuln_code_blocks,
        "fix_code": fix_code_blocks,
    }


def main():
    parser = argparse.ArgumentParser(
        description="获取GitHub PR的代码差异，分析漏洞代码和修复代码",
        epilog="示例：python fetch_pr_diff.py --owner free5gc --repo free5gc --pr 123"
    )
    parser.add_argument("--owner", required=True, help="仓库拥有者")
    parser.add_argument("--repo", required=True, help="仓库名称")
    parser.add_argument("--pr", required=True, type=int, help="PR编号")
    parser.add_argument(
        "--go-only",
        action="store_true",
        default=True,
        help="仅分析Go源文件（默认开启）"
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="包含测试文件（默认排除_test.go）"
    )
    parser.add_argument(
        "--token",
        type=str,
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub API Token"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="输出文件路径"
    )
    parser.add_argument(
        "--raw-diff",
        action="store_true",
        help="同时输出原始diff文本"
    )

    args = parser.parse_args()

    print(f"正在获取 {args.owner}/{args.repo} PR #{args.pr} 的信息...",
          file=sys.stderr)

    use_cli = gh_cli_available()

    if use_cli:
        print("使用 gh CLI 模式", file=sys.stderr)
        pr_info = fetch_pr_info_cli(args.owner, args.repo, args.pr)
        diff_text = fetch_pr_diff_cli(args.owner, args.repo, args.pr)
        commits = fetch_pr_commits_cli(args.owner, args.repo, args.pr)
    else:
        print("使用 REST API 模式", file=sys.stderr)
        pr_info = fetch_pr_info_api(args.owner, args.repo, args.pr, args.token)
        diff_text = fetch_pr_diff_api(args.owner, args.repo, args.pr, args.token)
        commits = []

    if not pr_info:
        print(f"错误：无法获取 PR #{args.pr} 的信息（可能不存在或为Issue而非PR）",
              file=sys.stderr)
        sys.exit(1)

    file_changes = parse_diff(diff_text)

    if args.go_only and not args.include_tests:
        go_changes = filter_go_files(file_changes)
    elif args.go_only:
        go_changes = [f for f in file_changes if f["file"].endswith(".go")]
    else:
        go_changes = file_changes

    analysis = analyze_changes(go_changes)

    result = {
        "repository": f"{args.owner}/{args.repo}",
        "pr_number": args.pr,
        "pr_title": pr_info.get("title", ""),
        "pr_url": pr_info.get("html_url", ""),
        "pr_state": pr_info.get("state", ""),
        "pr_merged": pr_info.get("merged", False),
        "pr_body_preview": (pr_info.get("body") or "")[:3000],
        "base_branch": pr_info.get("base", {}).get("ref", ""),
        "head_branch": pr_info.get("head", {}).get("ref", ""),
        "merge_commit_sha": pr_info.get("merge_commit_sha"),
        "commits": [
            {
                "sha": c.get("sha", ""),
                "message": c.get("commit", {}).get("message", "")[:500],
            }
            for c in commits[:20]
        ],
        "changed_go_files": [f["file"] for f in go_changes],
        "total_files_changed": len(file_changes),
        "go_files_changed": len(go_changes),
        "analysis": analysis,
    }

    if args.raw_diff:
        result["raw_diff"] = diff_text

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        from pathlib import Path
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"结果已保存至 {args.output}", file=sys.stderr)
    else:
        print(output)

    print(f"\n分析完成：PR #{args.pr} 共变更 {len(file_changes)} 个文件，"
          f"其中 {len(go_changes)} 个Go文件", file=sys.stderr)
    print(f"  漏洞代码块：{len(analysis['vulnerability_code'])} 个", file=sys.stderr)
    print(f"  修复代码块：{len(analysis['fix_code'])} 个", file=sys.stderr)


if __name__ == "__main__":
    main()

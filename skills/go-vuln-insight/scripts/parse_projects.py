#!/usr/bin/env python3
"""
从Markdown文档中解析GitHub项目地址。

用法：
    python parse_projects.py <markdown文件路径>
    python parse_projects.py --help

输出JSON格式的项目列表，包含owner、repo、url字段。
"""

import argparse
import json
import re
import sys
from pathlib import Path


def parse_github_urls(content: str) -> list[dict]:
    """从Markdown内容中提取GitHub项目地址。"""
    patterns = [
        r'https?://github\.com/([^/\s\)]+)/([^/\s\)#]+)',
        r'github\.com/([^/\s\)]+)/([^/\s\)#]+)',
    ]

    seen = set()
    projects = []

    for pattern in patterns:
        for match in re.finditer(pattern, content):
            owner = match.group(1)
            repo = match.group(2).rstrip('.git').rstrip('/')
            key = f"{owner}/{repo}"

            if key not in seen:
                seen.add(key)
                projects.append({
                    "owner": owner,
                    "repo": repo,
                    "url": f"https://github.com/{owner}/{repo}"
                })

    return projects


def main():
    parser = argparse.ArgumentParser(
        description="从Markdown文档中解析GitHub项目地址",
        epilog="示例：python parse_projects.py projects.md"
    )
    parser.add_argument(
        "markdown_file",
        type=str,
        help="包含GitHub项目地址的Markdown文件路径"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="美化JSON输出（默认开启）"
    )

    args = parser.parse_args()

    filepath = Path(args.markdown_file)
    if not filepath.exists():
        print(f"错误：文件不存在 - {filepath}", file=sys.stderr)
        sys.exit(1)

    content = filepath.read_text(encoding="utf-8")
    projects = parse_github_urls(content)

    if not projects:
        print("警告：未在文件中找到任何GitHub项目地址", file=sys.stderr)
        sys.exit(0)

    indent = 2 if args.pretty else None
    print(json.dumps(projects, indent=indent, ensure_ascii=False))
    print(f"\n共发现 {len(projects)} 个项目", file=sys.stderr)


if __name__ == "__main__":
    main()

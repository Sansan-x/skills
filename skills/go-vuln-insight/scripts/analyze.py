#!/usr/bin/env python3
"""
端到端漏洞分析流水线：从项目列表到结构化数据。

用法：
    python analyze.py <markdown文件路径> [--output-dir <输出目录>]
    python analyze.py --help

功能：
    1. 解析Markdown中的项目列表
    2. 对每个项目采集安全Issue
    3. 对关联的PR获取代码diff
    4. 将所有结构化数据输出到指定目录，供Claude进一步分析和报告生成
"""

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent


def run_script(script_name: str, args: list[str]) -> str:
    """运行同目录下的脚本并返回stdout。"""
    import subprocess
    cmd = [sys.executable, str(SCRIPT_DIR / script_name)] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(f"  警告：{script_name} 返回码 {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}", file=sys.stderr)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(
        description="端到端Go项目安全漏洞分析流水线",
        epilog="示例：python analyze.py projects.md --output-dir ./data"
    )
    parser.add_argument(
        "markdown_file",
        type=str,
        help="包含GitHub项目地址的Markdown文件路径"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./analysis_data",
        help="数据输出目录（默认：./analysis_data）"
    )
    parser.add_argument(
        "--issue-limit",
        type=int,
        default=100,
        help="每个项目最大Issue采集数量（默认：100）"
    )
    parser.add_argument(
        "--max-prs",
        type=int,
        default=20,
        help="每个项目最大PR分析数量（默认：20）"
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        default=True,
        help="仅采集安全相关Issue（默认开启）"
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60, file=sys.stderr)
    print("Go漏洞分析流水线启动", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    print(f"\n[1/3] 解析项目列表: {args.markdown_file}", file=sys.stderr)
    raw = run_script("parse_projects.py", [args.markdown_file])
    try:
        projects = json.loads(raw)
    except json.JSONDecodeError:
        print("错误：无法解析项目列表", file=sys.stderr)
        sys.exit(1)

    print(f"  发现 {len(projects)} 个项目", file=sys.stderr)
    (output_dir / "projects.json").write_text(
        json.dumps(projects, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    all_results = {}

    for idx, proj in enumerate(projects, 1):
        owner = proj["owner"]
        repo = proj["repo"]
        proj_key = f"{owner}_{repo}"

        print(f"\n[2/3] ({idx}/{len(projects)}) 分析项目: {owner}/{repo}",
              file=sys.stderr)

        proj_dir = output_dir / proj_key
        proj_dir.mkdir(exist_ok=True)

        issue_args = [
            "--owner", owner, "--repo", repo,
            "--labels", "",
            "--state", "all",
            "--limit", str(args.issue_limit),
            "--output", str(proj_dir / "issues.json"),
        ]
        if args.security_only:
            issue_args.append("--security-only")

        run_script("fetch_issues.py", issue_args)

        issues_file = proj_dir / "issues.json"
        if not issues_file.exists():
            print(f"  跳过：未能采集Issue", file=sys.stderr)
            continue

        issues_data = json.loads(issues_file.read_text(encoding="utf-8"))
        security_issues = [
            i for i in issues_data.get("issues", [])
            if i.get("is_security_related")
        ]
        print(f"  安全Issue: {len(security_issues)} 个", file=sys.stderr)

        pr_numbers = set()
        for issue in security_issues:
            for pr in issue.get("referenced_prs", []):
                pr_numbers.add(pr)

        pr_numbers = sorted(pr_numbers)[:args.max_prs]

        if pr_numbers:
            print(f"  [3/3] 分析关联PR: {pr_numbers}", file=sys.stderr)
            prs_dir = proj_dir / "prs"
            prs_dir.mkdir(exist_ok=True)

            for pr_num in pr_numbers:
                pr_output = prs_dir / f"pr_{pr_num}.json"
                run_script("fetch_pr_diff.py", [
                    "--owner", owner, "--repo", repo,
                    "--pr", str(pr_num),
                    "--output", str(pr_output),
                ])
                if pr_output.exists():
                    print(f"    PR #{pr_num}: 已分析", file=sys.stderr)
                else:
                    print(f"    PR #{pr_num}: 获取失败", file=sys.stderr)

        all_results[proj_key] = {
            "owner": owner,
            "repo": repo,
            "url": proj["url"],
            "total_issues": issues_data.get("total_issues", 0),
            "security_issues": len(security_issues),
            "analyzed_prs": len(pr_numbers),
            "data_dir": str(proj_dir),
        }

    summary = {
        "total_projects": len(projects),
        "projects": all_results,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n{'=' * 60}", file=sys.stderr)
    print(f"分析完成！数据输出到: {output_dir}", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)
    for key, info in all_results.items():
        print(f"  {key}: {info['security_issues']} 安全Issue, "
              f"{info['analyzed_prs']} PR已分析", file=sys.stderr)

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

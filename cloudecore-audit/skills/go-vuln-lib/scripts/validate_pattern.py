#!/usr/bin/env python3
"""
Go攻击模式条目验证脚本

验证攻击模式Markdown文件中的条目是否符合结构化存储规范。
检查必填字段、格式一致性和代码块有效性。

用法:
    python validate_pattern.py <pattern_file.md>
    python validate_pattern.py <patterns_directory>
"""

import re
import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


VALID_CATEGORIES = {
    "SQL注入", "命令注入", "跨站脚本", "服务端请求伪造", "路径穿越",
    "认证缺陷", "访问控制缺陷", "密码学失败", "反序列化漏洞", "竞态条件",
    "模板注入", "拒绝服务", "信息泄露", "不安全文件操作", "gRPC安全",
    "Go语言特有", "供应链攻击", "开放重定向", "日志注入", "XML外部实体",
}

VALID_SEVERITIES = {"严重", "高危", "中危", "低危"}
VALID_CONFIDENCES = {"高", "中", "低"}
VALID_SOURCE_TYPES = {"vuln-insight", "codehub-issue", "security-guide", "expert-case", "mixed"}

CATEGORY_CODES = {
    "SQLI", "CMDI", "XSS", "SSRF", "PTR", "AUTH", "IDOR", "CRYPTO",
    "DESER", "RACE", "SSTI", "DOS", "INFO", "FILE", "GRPC", "GOLNG",
    "SUPPLY", "REDIR", "LOG", "XXE",
}

PATTERN_ID_RE = re.compile(r"^GO-ATK-([A-Z]+)-(\d{3})$")
CWE_RE = re.compile(r"^CWE-\d+$")


@dataclass
class ValidationResult:
    pattern_id: str
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, msg: str):
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)


def extract_patterns_from_md(content: str) -> list[dict]:
    """从Markdown文件中提取攻击模式条目。"""
    patterns = []
    pattern_sections = re.split(r"^##\s+GO-ATK-", content, flags=re.MULTILINE)

    if len(pattern_sections) <= 1:
        pattern_sections = re.split(r"^###\s+GO-ATK-", content, flags=re.MULTILINE)

    for section in pattern_sections[1:]:
        pattern = {}
        id_match = re.match(r"([A-Z]+-\d{3})", section)
        if id_match:
            pattern["pattern_id"] = f"GO-ATK-{id_match.group(1)}"

        name_match = re.match(r"[A-Z]+-\d{3}[：:]\s*(.+)", section)
        if name_match:
            pattern["name"] = name_match.group(1).strip()

        severity_match = re.search(r"\*\*严重性[：:]\*\*\s*(.+)", section)
        if severity_match:
            pattern["severity"] = severity_match.group(1).strip()

        cwe_match = re.search(r"\*\*CWE[：:]\*\*\s*(.+)", section)
        if cwe_match:
            pattern["cwe_ids"] = re.findall(r"CWE-\d+", cwe_match.group(1))

        confidence_match = re.search(r"\*\*置信度[：:]\*\*\s*(.+)", section)
        if confidence_match:
            pattern["confidence"] = confidence_match.group(1).strip()

        source_match = re.search(r"\*\*来源[：:]\*\*\s*(.+)", section)
        if source_match:
            pattern["source_type"] = source_match.group(1).strip()

        go_blocks = re.findall(r"```go\n(.*?)```", section, re.DOTALL)
        pattern["code_blocks"] = go_blocks
        pattern["code_block_count"] = len(go_blocks)

        has_vuln_section = bool(re.search(r"(漏洞模式|典型代码|漏洞代码)", section))
        has_safe_section = bool(re.search(r"(安全模式|修复|安全代码)", section))
        pattern["has_vuln_pattern"] = has_vuln_section
        pattern["has_safe_pattern"] = has_safe_section

        has_test_section = bool(re.search(r"(测试方法|检测点|测试步骤)", section))
        pattern["has_test_method"] = has_test_section

        has_dataflow = bool(re.search(r"(数据流|Source.*Sink|source.*sink|→)", section))
        pattern["has_dataflow"] = has_dataflow

        has_description = bool(re.search(r"(漏洞描述|描述|概述)", section))
        pattern["has_description"] = has_description

        pattern["raw_section"] = section
        patterns.append(pattern)

    return patterns


def validate_pattern(pattern: dict) -> ValidationResult:
    """验证单个攻击模式条目。"""
    pid = pattern.get("pattern_id", "UNKNOWN")
    result = ValidationResult(pattern_id=pid)

    if not pattern.get("pattern_id"):
        result.add_error("缺少 pattern_id")
    else:
        m = PATTERN_ID_RE.match(pattern["pattern_id"])
        if not m:
            result.add_error(f"pattern_id 格式错误: {pattern['pattern_id']}（应为 GO-ATK-XXXX-NNN）")
        elif m.group(1) not in CATEGORY_CODES:
            result.add_error(f"pattern_id 类别编码未知: {m.group(1)}")

    if not pattern.get("name"):
        result.add_error("缺少 name（模式名称）")
    elif len(pattern["name"]) < 5:
        result.add_warning(f"name 过短（{len(pattern['name'])}字符），建议10-80字符")

    if pattern.get("severity"):
        if pattern["severity"] not in VALID_SEVERITIES:
            result.add_error(f"severity 值无效: {pattern['severity']}（允许: {VALID_SEVERITIES}）")
    else:
        result.add_error("缺少 severity（严重性等级）")

    if pattern.get("cwe_ids"):
        for cwe in pattern["cwe_ids"]:
            if not CWE_RE.match(cwe):
                result.add_error(f"CWE编号格式错误: {cwe}")
    else:
        result.add_warning("缺少 CWE 编号")

    if pattern.get("confidence"):
        if pattern["confidence"] not in VALID_CONFIDENCES:
            result.add_warning(f"置信度值非标准: {pattern['confidence']}（允许: {VALID_CONFIDENCES}）")

    if not pattern.get("has_description"):
        result.add_error("缺少漏洞描述章节")

    if pattern.get("code_block_count", 0) < 2:
        result.add_error(f"Go代码块不足（发现{pattern.get('code_block_count', 0)}个，至少需要2个：漏洞代码和安全代码）")

    if not pattern.get("has_vuln_pattern"):
        result.add_error("缺少漏洞模式/典型代码章节")

    if not pattern.get("has_safe_pattern"):
        result.add_error("缺少安全模式/修复章节")

    for i, block in enumerate(pattern.get("code_blocks", [])):
        if "func " not in block and "package " not in block and "import " not in block:
            if len(block.strip().split("\n")) > 3:
                result.add_warning(f"代码块#{i+1} 可能不是完整的Go代码（缺少func/package/import）")
        if "SINK" in block or "SOURCE" in block or "漏洞" in block:
            pass  # OK, has annotations

    if not pattern.get("has_test_method"):
        result.add_warning("缺少测试方法章节（推荐填充）")

    if not pattern.get("has_dataflow"):
        result.add_warning("缺少数据流描述（推荐填充）")

    return result


def validate_file(filepath: str) -> list[ValidationResult]:
    """验证Markdown文件中的所有攻击模式。"""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    patterns = extract_patterns_from_md(content)
    if not patterns:
        result = ValidationResult(pattern_id="FILE")
        result.add_warning(f"文件中未发现攻击模式条目: {filepath}")
        return [result]

    results = []
    seen_ids = set()
    for pattern in patterns:
        pid = pattern.get("pattern_id", "")
        if pid in seen_ids:
            r = ValidationResult(pattern_id=pid)
            r.add_error(f"pattern_id 重复: {pid}")
            results.append(r)
        seen_ids.add(pid)
        results.append(validate_pattern(pattern))

    return results


def print_results(results: list[ValidationResult], filepath: str):
    """打印验证结果。"""
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    total_patterns = len([r for r in results if r.pattern_id != "FILE"])

    print(f"\n{'='*60}")
    print(f"文件: {filepath}")
    print(f"模式数: {total_patterns} | 错误: {total_errors} | 警告: {total_warnings}")
    print(f"{'='*60}")

    for result in results:
        if result.errors or result.warnings:
            status = "❌ 不通过" if result.errors else "⚠️  有警告"
            print(f"\n  [{status}] {result.pattern_id}")
            for err in result.errors:
                print(f"    错误: {err}")
            for warn in result.warnings:
                print(f"    警告: {warn}")
        else:
            print(f"\n  [✅ 通过] {result.pattern_id}")

    return total_errors == 0


def main():
    if len(sys.argv) < 2:
        print("用法: python validate_pattern.py <pattern_file.md|patterns_directory>")
        print("\n验证Go攻击模式文件是否符合结构化存储规范。")
        print("\n示例:")
        print("  python validate_pattern.py vuln-lib/patterns/sqli-patterns.md")
        print("  python validate_pattern.py vuln-lib/patterns/")
        sys.exit(1)

    target = sys.argv[1]
    all_pass = True

    if os.path.isdir(target):
        md_files = sorted(Path(target).glob("**/*.md"))
        if not md_files:
            print(f"目录中未找到Markdown文件: {target}")
            sys.exit(1)
        for md_file in md_files:
            results = validate_file(str(md_file))
            if not print_results(results, str(md_file)):
                all_pass = False
    elif os.path.isfile(target):
        results = validate_file(target)
        all_pass = print_results(results, target)
    else:
        print(f"错误: 路径不存在: {target}")
        sys.exit(1)

    print(f"\n{'='*60}")
    if all_pass:
        print("总结: 所有模式验证通过 ✅")
    else:
        print("总结: 存在验证错误，请修复后重试 ❌")
    print(f"{'='*60}")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()

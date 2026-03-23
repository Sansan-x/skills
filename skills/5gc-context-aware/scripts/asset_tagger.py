#!/usr/bin/env python3
"""
Step 3: Sensitive Asset Tagging (敏感资产标记)

Scans Go source files to identify and tag sensitive 5GC variables, struct fields,
and function parameters at an AST-aware level using regex-based pattern matching.
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional


def load_sensitive_assets(skill_dir: str) -> dict:
    asset_path = Path(skill_dir) / "references" / "sensitive_assets.json"
    with open(asset_path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_go_structs(content: str, file_path: str) -> list[dict]:
    """Extract struct definitions from Go source."""
    structs = []
    struct_pattern = re.compile(
        r'type\s+(\w+)\s+struct\s*\{([^}]*)\}',
        re.DOTALL
    )

    for match in struct_pattern.finditer(content):
        struct_name = match.group(1)
        body = match.group(2)
        line_num = content[:match.start()].count("\n") + 1

        fields = []
        for field_match in re.finditer(
            r'^\s*(\w+)\s+(\S+)', body, re.MULTILINE
        ):
            fields.append({
                "name": field_match.group(1),
                "type": field_match.group(2)
            })

        structs.append({
            "name": struct_name,
            "file": file_path,
            "line": line_num,
            "fields": fields
        })

    return structs


def parse_go_functions(content: str, file_path: str) -> list[dict]:
    """Extract function signatures from Go source."""
    functions = []
    func_pattern = re.compile(
        r'func\s+(?:\((\w+)\s+\*?(\w+)\)\s+)?(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )

    for match in func_pattern.finditer(content):
        receiver_name = match.group(1)
        receiver_type = match.group(2)
        func_name = match.group(3)
        params = match.group(4)
        line_num = content[:match.start()].count("\n") + 1

        param_list = []
        if params.strip():
            for param in params.split(","):
                parts = param.strip().split()
                if len(parts) >= 2:
                    param_list.append({"name": parts[0], "type": " ".join(parts[1:])})

        functions.append({
            "name": func_name,
            "receiver": f"*{receiver_type}" if receiver_type else None,
            "file": file_path,
            "line": line_num,
            "parameters": param_list
        })

    return functions


def parse_variable_declarations(content: str, file_path: str) -> list[dict]:
    """Extract variable declarations from Go source."""
    variables = []
    var_patterns = [
        re.compile(r'var\s+(\w+)\s+(\S+)', re.MULTILINE),
        re.compile(r'(\w+)\s*:=\s*', re.MULTILINE),
        re.compile(r'var\s+\(\s*(.*?)\)', re.DOTALL),
    ]

    for match in re.finditer(var_patterns[0], content):
        line_num = content[:match.start()].count("\n") + 1
        variables.append({
            "name": match.group(1),
            "type": match.group(2),
            "file": file_path,
            "line": line_num,
            "declaration": "var"
        })

    for match in re.finditer(var_patterns[1], content):
        line_num = content[:match.start()].count("\n") + 1
        line = content[content.rfind("\n", 0, match.start())+1:content.find("\n", match.end())]
        if not line.strip().startswith("//") and not line.strip().startswith("func"):
            variables.append({
                "name": match.group(1),
                "type": "inferred",
                "file": file_path,
                "line": line_num,
                "declaration": "short"
            })

    return variables


def tag_sensitive_items(
    name: str,
    context_type: str,
    file_path: str,
    line: int,
    sensitive_assets: dict
) -> list[dict]:
    """Check if a name matches any sensitive asset pattern."""
    tags = []

    for category_key, category in sensitive_assets.items():
        if category_key.startswith("_") or category_key == "struct_types":
            continue

        if not isinstance(category, dict) or "variables" not in category:
            continue

        for var_def in category["variables"]:
            pattern = var_def["pattern"]
            try:
                if re.search(pattern, name):
                    tags.append({
                        "name": name,
                        "context_type": context_type,
                        "file": file_path,
                        "line": line,
                        "category": category_key,
                        "sensitivity": category.get("sensitivity", "unknown"),
                        "matched_pattern": pattern,
                        "description": var_def.get("description", ""),
                        "spec_reference": var_def.get("spec", "")
                    })
            except re.error:
                continue

    return tags


def tag_sensitive_structs(
    struct_name: str,
    file_path: str,
    line: int,
    sensitive_assets: dict
) -> list[dict]:
    """Check if a struct type matches known sensitive struct patterns."""
    tags = []
    struct_types = sensitive_assets.get("struct_types", {}).get("entries", [])

    for struct_def in struct_types:
        try:
            if re.search(struct_def["pattern"], struct_name):
                tags.append({
                    "name": struct_name,
                    "context_type": "struct_definition",
                    "file": file_path,
                    "line": line,
                    "category": "sensitive_struct",
                    "sensitivity": "critical",
                    "matched_pattern": struct_def["pattern"],
                    "description": struct_def.get("description", ""),
                    "contains": struct_def.get("contains", [])
                })
        except re.error:
            continue

    return tags


def scan_project_assets(project_dir: str, skill_dir: str) -> dict:
    """Main scanning function that processes all Go files for sensitive assets."""
    sensitive_assets = load_sensitive_assets(skill_dir)

    all_tags = []
    stats = defaultdict(lambda: defaultdict(int))
    go_files = list(Path(project_dir).rglob("*.go"))
    files_scanned = 0

    for go_file in go_files[:1000]:
        if "vendor" in str(go_file):
            continue
        try:
            content = go_file.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        files_scanned += 1
        rel_path = str(go_file.relative_to(project_dir))

        structs = parse_go_structs(content, rel_path)
        for struct in structs:
            struct_tags = tag_sensitive_structs(
                struct["name"], rel_path, struct["line"], sensitive_assets
            )
            all_tags.extend(struct_tags)

            for field in struct["fields"]:
                field_tags = tag_sensitive_items(
                    field["name"], f"struct_field:{struct['name']}",
                    rel_path, struct["line"], sensitive_assets
                )
                all_tags.extend(field_tags)

        functions = parse_go_functions(content, rel_path)
        for func in functions:
            func_tags = tag_sensitive_items(
                func["name"], "function_name",
                rel_path, func["line"], sensitive_assets
            )
            all_tags.extend(func_tags)

            for param in func["parameters"]:
                param_tags = tag_sensitive_items(
                    param["name"], f"parameter:{func['name']}",
                    rel_path, func["line"], sensitive_assets
                )
                all_tags.extend(param_tags)

        variables = parse_variable_declarations(content, rel_path)
        for var in variables:
            var_tags = tag_sensitive_items(
                var["name"], "variable",
                rel_path, var["line"], sensitive_assets
            )
            all_tags.extend(var_tags)

    for tag in all_tags:
        stats[tag["category"]][tag["sensitivity"]] += 1

    category_summary = {}
    for cat, sev_counts in stats.items():
        category_summary[cat] = dict(sev_counts)

    hotspots = defaultdict(list)
    for tag in all_tags:
        hotspots[tag["file"]].append(tag)

    top_hotspots = sorted(
        hotspots.items(), key=lambda x: len(x[1]), reverse=True
    )[:20]

    return {
        "step": "asset_tagging",
        "project_dir": project_dir,
        "files_scanned": files_scanned,
        "total_tags": len(all_tags),
        "category_summary": category_summary,
        "top_hotspot_files": [
            {"file": f, "tag_count": len(tags), "categories": list(set(t["category"] for t in tags))}
            for f, tags in top_hotspots
        ],
        "sensitive_assets": all_tags[:200],
        "truncated": len(all_tags) > 200
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python asset_tagger.py <project_dir> [skill_dir]")
        sys.exit(1)

    project_dir = sys.argv[1]
    skill_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(__file__).parent.parent)

    result = scan_project_assets(project_dir, skill_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

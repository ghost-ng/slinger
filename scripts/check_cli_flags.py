#!/usr/bin/env python3
"""
CLI Flag Naming Standards Checker

Checks that all CLI flags in the project adhere to the naming standard:
- Single letter flags: Use single hyphen (e.g., -l, -v, -h)
- Multi-letter flags: Use double hyphen (e.g., --list, --verbose, --help)

Usage:
    python scripts/check_cli_flags.py
    python scripts/check_cli_flags.py --fix-suggestions
"""

import re
import sys
import ast
import argparse
from pathlib import Path
from typing import List, Tuple, Optional


def extract_add_argument_calls(file_path: Path) -> List[Tuple[str, int, str]]:
    """Extract all add_argument calls from a Python file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)
        violations = []

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"
            ):

                # Get the first argument (the flag name)
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Str):
                        flag_name = arg.s
                    elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        flag_name = arg.value
                    else:
                        continue

                    # Check for violations
                    violation = check_flag_standards(flag_name, node.lineno)
                    if violation:
                        violations.append((str(file_path), node.lineno, violation))

        return violations
    except Exception as e:
        print(f"Warning: Error parsing {file_path}: {e}")
        return []


def check_flag_standards(flag_name: str, line_no: int) -> Optional[str]:
    """Check if flag name adheres to standards"""
    # Skip positional arguments (no hyphens)
    if not flag_name.startswith("-"):
        return None

    # Single letter flags should use single hyphen
    if len(flag_name) == 2 and flag_name.startswith("-") and not flag_name.startswith("--"):
        if flag_name[1].isalpha() or flag_name[1].isdigit():
            return None  # Correct: -l, -v, -1, etc.

    # Multi-letter flags should use double hyphen
    if len(flag_name) > 2 and flag_name.startswith("--"):
        return None  # Correct: --list, --verbose, etc.

    # Check for violations

    # Single letter with double hyphen: --l
    if len(flag_name) == 3 and flag_name.startswith("--") and flag_name[2].isalnum():
        return f'Single letter flag "{flag_name}" should use single hyphen: "-{flag_name[2]}"'

    # Multi-letter with single hyphen: -list
    elif len(flag_name) > 2 and flag_name.startswith("-") and not flag_name.startswith("--"):
        return f'Multi-letter flag "{flag_name}" should use double hyphen: "-{flag_name}"'

    return None


def suggest_fix(flag_name: str) -> str:
    """Suggest a fix for a non-standard flag name"""
    if len(flag_name) == 3 and flag_name.startswith("--"):
        return f"-{flag_name[2:]}"
    elif len(flag_name) > 2 and flag_name.startswith("-") and not flag_name.startswith("--"):
        return f"-{flag_name}"
    return flag_name


def main():
    parser = argparse.ArgumentParser(description="Check CLI flag naming standards")
    parser.add_argument(
        "--fix-suggestions", action="store_true", help="Show suggested fixes for violations"
    )
    parser.add_argument("--src-dir", default="src", help="Source directory to check (default: src)")
    args = parser.parse_args()

    # Check all Python files in src directory
    src_dir = Path(args.src_dir)
    all_violations = []

    if not src_dir.exists():
        print(f"❌ Source directory '{src_dir}' does not exist")
        sys.exit(1)

    print(f"🔍 Checking CLI flag standards in {src_dir}/...")
    print("=" * 60)
    print("Standard: Single letter flags use single hyphen (-l)")
    print("          Multi-letter flags use double hyphen (--list)")
    print("=" * 60)

    for py_file in src_dir.rglob("*.py"):
        violations = extract_add_argument_calls(py_file)
        all_violations.extend(violations)

    # Report violations
    if all_violations:
        print(f"❌ Found {len(all_violations)} CLI flag standard violation(s):")
        print()

        current_file = None
        for file_path, line_no, violation in sorted(all_violations):
            if file_path != current_file:
                print(f"📁 {file_path}")
                current_file = file_path

            print(f"   Line {line_no}: {violation}")

            if args.fix_suggestions:
                # Extract the flag name from the violation message
                import re

                flag_match = re.search(r'"([^"]*)"', violation)
                if flag_match:
                    flag_name = flag_match.group(1)
                    suggested_fix = suggest_fix(flag_name)
                    print(f"   💡 Suggested fix: {suggested_fix}")
            print()

        print("=" * 60)
        print(f"Total violations: {len(all_violations)}")
        print()
        print("Common patterns to fix:")
        print("  ❌ --l, --v, --h  →  ✅ -l, -v, -h")
        print("  ❌ -list, -verbose  →  ✅ --list, --verbose")
        print("  ❌ -output-file  →  ✅ --output-file")

        sys.exit(1)
    else:
        print("✅ All CLI flags adhere to naming standards!")
        print(f"   Checked {len(list(src_dir.rglob('*.py')))} Python files")


if __name__ == "__main__":
    main()

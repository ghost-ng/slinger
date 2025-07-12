"""
Test Coverage Validator - Ensures all commands have corresponding tests
"""

import ast
import os
import re
import json
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional, Any
from datetime import datetime
import subprocess


class TestCoverageValidator:
    """Validates that all Slinger commands have corresponding tests"""

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path(__file__).parent.parent
        self.src_path = self.project_root / "src"
        self.test_path = self.project_root / "tests"

        # Command discovery results
        self.cli_commands: Set[str] = set()
        self.command_modules: Dict[str, str] = {}  # command -> module path
        self.test_files: Dict[str, Path] = {}  # command -> test file path

        # Coverage metrics
        self.coverage_data: Dict[str, Dict] = {}

        # Discover commands and tests
        self._discover_commands()
        self._discover_tests()

    def _discover_commands(self) -> None:
        """Parse CLI parser to find all commands"""
        cli_path = self.src_path / "slingerpkg" / "utils" / "cli.py"

        if not cli_path.exists():
            raise FileNotFoundError(f"CLI parser not found at {cli_path}")

        with open(cli_path, "r") as f:
            content = f.read()

        # Parse AST to find add_parser calls
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Look for subparser.add_parser() calls
                if hasattr(node.func, "attr") and node.func.attr == "add_parser" and node.args:

                    # Extract command name
                    if isinstance(node.args[0], ast.Str):
                        command = node.args[0].s
                    elif isinstance(node.args[0], ast.Constant):
                        command = node.args[0].value
                    else:
                        continue

                    self.cli_commands.add(command)

                    # Try to find the module implementing this command
                    self._find_command_module(command)

    def _find_command_module(self, command: str) -> None:
        """Find the module that implements a command"""
        # Common patterns for command implementation
        patterns = [
            f"def {command}(",
            f"def cmd_{command}(",
            f"def handle_{command}(",
            f"class {command.title()}",
            f"{command}_handler",
        ]

        # Search in lib modules
        lib_path = self.src_path / "slingerpkg" / "lib"
        if lib_path.exists():
            for py_file in lib_path.rglob("*.py"):
                content = py_file.read_text()
                for pattern in patterns:
                    if pattern in content:
                        self.command_modules[command] = str(py_file)
                        break

    def _discover_tests(self) -> None:
        """Find all test files and extract what commands they test"""
        # Look for test files following naming conventions
        for test_file in self.test_path.rglob("test_*.py"):
            # Extract potential command names from filename
            filename = test_file.stem

            # Try different naming patterns
            if filename.startswith("test_"):
                # Direct mapping: test_ls.py -> ls command
                potential_command = filename[5:]  # Remove "test_" prefix

                # Check if this matches a known command
                if potential_command in self.cli_commands:
                    self.test_files[potential_command] = test_file

                # Also check file content for tested commands
                self._extract_tested_commands(test_file)

    def _extract_tested_commands(self, test_file: Path) -> None:
        """Extract commands being tested from test file content"""
        try:
            content = test_file.read_text()

            # Look for command references in test names and docstrings
            # Pattern: test_<command>_* or "Test <command> command"
            command_patterns = [
                r"def test_(\w+)_",
                r'""".*Test[s]?\s+(\w+)\s+command',
                r"# Test[s]?\s+(\w+)\s+command",
                r'send_command\(["\'](\w+)',
            ]

            for pattern in command_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match in self.cli_commands and match not in self.test_files:
                        self.test_files[match] = test_file

        except Exception:
            pass

    def validate_coverage(self) -> Tuple[bool, List[str]]:
        """
        Check if all commands have tests.
        Returns (all_covered, list_of_missing_commands)
        """
        missing_commands = self.cli_commands - set(self.test_files.keys())
        return len(missing_commands) == 0, sorted(list(missing_commands))

    def get_coverage_percentage(self) -> float:
        """Calculate test coverage percentage"""
        if not self.cli_commands:
            return 0.0

        covered = len(self.test_files)
        total = len(self.cli_commands)
        return (covered / total) * 100

    def generate_coverage_report(self) -> Dict[str, Any]:
        """Generate detailed coverage report"""
        all_covered, missing = self.validate_coverage()

        # Build coverage data for each command
        coverage_details = []
        for command in sorted(self.cli_commands):
            has_test = command in self.test_files

            detail = {
                "command": command,
                "has_test": has_test,
                "test_file": str(self.test_files.get(command, "")) if has_test else None,
                "module": self.command_modules.get(command, "Unknown"),
                "test_types": [],
            }

            if has_test:
                # Check what types of tests exist
                test_file = self.test_files[command]
                if "unit" in str(test_file):
                    detail["test_types"].append("unit")
                if "integration" in str(test_file):
                    detail["test_types"].append("integration")
                if "e2e" in str(test_file):
                    detail["test_types"].append("e2e")

            coverage_details.append(detail)

        return {
            "timestamp": datetime.now().isoformat(),
            "all_covered": all_covered,
            "coverage_percentage": self.get_coverage_percentage(),
            "total_commands": len(self.cli_commands),
            "covered_commands": len(self.test_files),
            "missing_commands": missing,
            "coverage_details": coverage_details,
        }

    def generate_test_matrix(self) -> List[Dict[str, str]]:
        """Generate test matrix showing coverage by test type"""
        matrix = []

        for command in sorted(self.cli_commands):
            # Check for different test types
            unit_test = self._has_test_type(command, "unit")
            integration_test = self._has_test_type(command, "integration")
            e2e_test = self._has_test_type(command, "e2e")

            matrix.append(
                {
                    "command": command,
                    "unit_test": "✓" if unit_test else "✗",
                    "integration_test": "✓" if integration_test else "✗",
                    "e2e_test": "✓" if e2e_test else "✗",
                    "coverage": self._calculate_command_coverage(command),
                }
            )

        return matrix

    def _has_test_type(self, command: str, test_type: str) -> bool:
        """Check if a command has a specific type of test"""
        test_file_path = self.test_path / test_type / f"test_{command}.py"
        if test_file_path.exists():
            return True

        # Also check if command is tested in a general test file
        general_test_files = [
            self.test_path / test_type / "test_commands.py",
            self.test_path / test_type / f"test_{test_type}.py",
        ]

        for test_file in general_test_files:
            if test_file.exists() and command in test_file.read_text():
                return True

        return False

    def _calculate_command_coverage(self, command: str) -> str:
        """Calculate coverage level for a command"""
        coverage_points = 0

        if self._has_test_type(command, "unit"):
            coverage_points += 40
        if self._has_test_type(command, "integration"):
            coverage_points += 40
        if self._has_test_type(command, "e2e"):
            coverage_points += 20

        return f"{coverage_points}%"

    def generate_markdown_report(self) -> str:
        """Generate markdown formatted coverage report"""
        report = self.generate_coverage_report()
        matrix = self.generate_test_matrix()

        markdown = f"""# Slinger Test Coverage Report

Generated: {report['timestamp']}

## Summary

- **Total Commands**: {report['total_commands']}
- **Covered Commands**: {report['covered_commands']}
- **Coverage Percentage**: {report['coverage_percentage']:.1f}%
- **All Commands Covered**: {'✅ Yes' if report['all_covered'] else '❌ No'}

## Test Coverage Matrix

| Command | Unit Tests | Integration Tests | E2E Tests | Coverage |
|---------|------------|-------------------|-----------|----------|
"""

        for row in matrix:
            markdown += f"| {row['command']} | {row['unit_test']} | {row['integration_test']} | {row['e2e_test']} | {row['coverage']} |\n"

        if report["missing_commands"]:
            markdown += f"\n## Missing Tests\n\nThe following commands need tests:\n\n"
            for cmd in report["missing_commands"]:
                markdown += f"- `{cmd}`\n"

        markdown += "\n## Coverage Details\n\n"

        for detail in report["coverage_details"]:
            if not detail["has_test"]:
                markdown += f"- ❌ **{detail['command']}**: No tests found\n"

        return markdown

    def write_coverage_badge(self, output_path: Path) -> None:
        """Generate coverage badge SVG"""
        coverage = self.get_coverage_percentage()

        # Determine color based on coverage
        if coverage >= 80:
            color = "brightgreen"
        elif coverage >= 60:
            color = "yellow"
        elif coverage >= 40:
            color = "orange"
        else:
            color = "red"

        # Simple badge template
        badge_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="104" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="104" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h63v20H0z"/>
    <path fill="{color}" d="M63 0h41v20H63z"/>
    <path fill="url(#b)" d="M0 0h104v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="325" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="530">coverage</text>
    <text x="325" y="140" transform="scale(.1)" textLength="530">coverage</text>
    <text x="825" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="310">{coverage:.0f}%</text>
    <text x="825" y="140" transform="scale(.1)" textLength="310">{coverage:.0f}%</text>
  </g>
</svg>"""

        output_path.write_text(badge_svg)

    def check_new_commands(self, base_branch: str = "main") -> List[str]:
        """Check for new commands added since base branch"""
        try:
            # Get list of modified files
            result = subprocess.run(
                ["git", "diff", f"{base_branch}...HEAD", "--name-only"],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return []

            # Check if cli.py was modified
            if "src/slingerpkg/utils/cli.py" not in result.stdout:
                return []

            # Get the diff of cli.py
            diff_result = subprocess.run(
                ["git", "diff", f"{base_branch}...HEAD", "src/slingerpkg/utils/cli.py"],
                capture_output=True,
                text=True,
            )

            # Look for new add_parser calls
            new_commands = []
            for line in diff_result.stdout.split("\n"):
                if line.startswith("+") and "add_parser(" in line:
                    # Extract command name
                    match = re.search(r'add_parser\(["\'](\w+)["\']', line)
                    if match:
                        new_commands.append(match.group(1))

            return new_commands

        except Exception:
            return []


def main():
    """Run coverage validation"""
    validator = TestCoverageValidator()

    # Generate report
    report = validator.generate_markdown_report()
    print(report)

    # Check coverage
    all_covered, missing = validator.validate_coverage()

    if not all_covered:
        print(f"\n❌ Missing tests for {len(missing)} commands:")
        for cmd in missing:
            print(f"  - {cmd}")
        exit(1)
    else:
        print("\n✅ All commands have tests!")
        exit(0)


if __name__ == "__main__":
    main()

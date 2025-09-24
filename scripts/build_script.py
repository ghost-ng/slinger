import argparse
import re
import sys
import subprocess
from unittest.mock import MagicMock
from pathlib import Path

import toml

# Dynamically add the src directory to the Python path
current_dir = Path(__file__).resolve().parent
src_path = current_dir.parent / "src"
sys.path.insert(0, str(src_path))

from slingerpkg.utils.cli import setup_cli_parser


def parse_requirements(filename):
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"File {filename} not found. Skipping requirements parsing.")
        return []


def extract_commands_and_args(parser):
    commands = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for command, subparser in action.choices.items():
                usage = subparser.format_usage() if hasattr(subparser, "format_usage") else ""
                usage = usage.replace("usage: slinger ", "").strip()
                desc = getattr(subparser, "description", "No description provided")
                help_text = f"{usage}\n{desc}" if usage else desc

                commands[command] = {
                    "description": desc,
                    "help": help_text,
                    "epilog": getattr(subparser, "epilog", None),
                    "arguments": [],
                    "subcommands": {},
                }

                # Extract regular arguments
                for sub_action in subparser._actions:
                    if isinstance(sub_action, argparse._StoreAction):
                        commands[command]["arguments"].append(
                            {
                                "name": sub_action.dest,
                                "help": sub_action.help,
                                "choices": sub_action.choices,
                                "default": sub_action.default,
                                "required": (
                                    sub_action.required
                                    if hasattr(sub_action, "required")
                                    else False
                                ),
                            }
                        )
                    # Extract nested subparsers (like wmiexec query, eventlog query, etc.)
                    elif isinstance(sub_action, argparse._SubParsersAction):
                        for subcommand, sub_subparser in sub_action.choices.items():
                            sub_usage = (
                                sub_subparser.format_usage()
                                if hasattr(sub_subparser, "format_usage")
                                else ""
                            )
                            sub_usage = sub_usage.replace("usage: slinger ", "").strip()
                            sub_desc = getattr(
                                sub_subparser, "description", "No description provided"
                            )
                            sub_help_text = f"{sub_usage}\n{sub_desc}" if sub_usage else sub_desc

                            commands[command]["subcommands"][subcommand] = {
                                "description": sub_desc,
                                "help": sub_help_text,
                                "epilog": getattr(sub_subparser, "epilog", None),
                                "arguments": [],
                            }

                            # Extract arguments for the nested subcommand
                            for sub_sub_action in sub_subparser._actions:
                                if isinstance(sub_sub_action, argparse._StoreAction):
                                    commands[command]["subcommands"][subcommand][
                                        "arguments"
                                    ].append(
                                        {
                                            "name": sub_sub_action.dest,
                                            "help": sub_sub_action.help,
                                            "choices": sub_sub_action.choices,
                                            "default": sub_sub_action.default,
                                            "required": (
                                                sub_sub_action.required
                                                if hasattr(sub_sub_action, "required")
                                                else False
                                            ),
                                        }
                                    )
    return commands


def generate_markdown(commands, output_file):
    with open(output_file, "w") as md_file:
        md_file.write("# CLI Commands Documentation\n\n")
        for command, details in commands.items():
            md_file.write(f"## `{command}`\n\n")
            md_file.write(f"**Description:** {details['description']}\n\n")
            md_file.write(f"**Help:**\n```\n{details['help']}\n```\n\n")
            if details["epilog"]:
                md_file.write(f"**Example Usage:**\n```\n{details['epilog']}\n```\n\n")
            if details["arguments"]:
                md_file.write("### Arguments\n\n")
                for arg in details["arguments"]:
                    md_file.write(
                        f"- **`{arg['name']}`**: {arg['help'] or 'No description provided'}\n".replace(
                            "(default: %(default)s)", ""
                        )
                    )
                    if arg["choices"]:
                        md_file.write(f"  - Choices: {', '.join(arg['choices'])}\n")
                    if arg["default"] is not None:
                        md_file.write(f"  - Default: `{arg['default']}`\n")
                    required_text = "Yes" if arg["required"] else "No"
                    md_file.write(f"  - Required: {required_text}\n\n")

            # Handle nested subcommands (like wmiexec query, eventlog query)
            if details.get("subcommands"):
                md_file.write("### Subcommands\n\n")
                for subcommand, sub_details in details["subcommands"].items():
                    md_file.write(f"#### `{command} {subcommand}`\n\n")
                    md_file.write(f"**Description:** {sub_details['description']}\n\n")
                    md_file.write(f"**Help:**\n```\n{sub_details['help']}\n```\n\n")
                    if sub_details["epilog"]:
                        md_file.write(f"**Example Usage:**\n```\n{sub_details['epilog']}\n```\n\n")
                    if sub_details["arguments"]:
                        md_file.write("##### Arguments\n\n")
                        for arg in sub_details["arguments"]:
                            md_file.write(
                                f"- **`{arg['name']}`**: {arg['help'] or 'No description provided'}\n".replace(
                                    "(default: %(default)s)", ""
                                )
                            )
                            if arg["choices"]:
                                choices_text = ", ".join(map(str, arg["choices"]))
                                md_file.write(f"  - Choices: {choices_text}\n")
                            if arg["default"] is not None:
                                md_file.write(f"  - Default: `{arg['default']}`\n")
                            required_text = "Yes" if arg["required"] else "No"
                    md_file.write(f"  - Required: {required_text}\n\n")
                    md_file.write("---\n\n")
            else:
                md_file.write("---\n\n")


def get_package_dir():
    """Locate the main package directory dynamically."""
    src_path = Path(__file__).resolve().parent.parent / "src"
    for package_dir in src_path.iterdir():
        if package_dir.is_dir() and (package_dir / "__init__.py").exists():
            return package_dir
    raise FileNotFoundError("Could not locate the main package directory containing __init__.py")


def get_version_from_init(package_dir):
    """Extract the version from the top-level __init__.py file."""
    init_file = package_dir / "__init__.py"
    version_pattern = r"^__version__\s*=\s*['\"]([^'\"]+)['\"]"
    with open(init_file, "r") as f:
        for line in f:
            match = re.match(version_pattern, line)
            if match:
                return match.group(1)
    raise ValueError("Version not found in __init__.py")


def update_version_in_pyproject(pyproject_file, new_version):
    """Update the version in pyproject.toml."""
    pyproject_data = toml.load(pyproject_file)
    if "project" in pyproject_data and "version" in pyproject_data["project"]:
        pyproject_data["project"]["version"] = new_version
        with open(pyproject_file, "w") as f:
            toml.dump(pyproject_data, f)
        print(f"Updated version in {pyproject_file} to {new_version}")


def run_build():
    """Run the Python build process."""
    try:
        # Ensure `build` is installed
        subprocess.run(["pip", "install", "--upgrade", "build"], check=True)

        # Run the build command
        subprocess.run(["python", "-m", "build"], check=True)
        print("Build completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
    except FileNotFoundError:
        print("Ensure that Python and the `build` module are installed.")


def generate_help_markdown():
    # Create a mock slingerClient
    mock_client = MagicMock()

    # Set up the parser using the mock client
    parser = setup_cli_parser(mock_client)

    # Extract commands and arguments
    commands = extract_commands_and_args(parser)

    # Generate the markdown file in docs/ directory
    docs_dir = Path(__file__).resolve().parent.parent / "docs"
    docs_dir.mkdir(exist_ok=True)  # Ensure docs directory exists
    output_file = docs_dir / "cli_menu.md"
    generate_markdown(commands, output_file)
    print(f"Markdown documentation generated: {output_file}")


def update_dependencies():
    # Parse requirements
    dependencies = parse_requirements("requirements.txt")
    if dependencies:
        print("Dependencies:", dependencies)
    else:
        print("No dependencies found.")

    # Update dependencies in pyproject.toml
    pyproject_file = current_dir.parent / "pyproject.toml"
    pyproject_data = toml.load(pyproject_file)

    # Update dependencies
    pyproject_data["project"]["dependencies"] = dependencies
    with open(pyproject_file, "w") as f:
        toml.dump(pyproject_data, f)
    print(f"Updated dependencies in {pyproject_file}")


def main():
    # Locate necessary files
    current_dir = Path(__file__).resolve().parent
    pyproject_file = current_dir.parent / "pyproject.toml"
    package_dir = get_package_dir()

    # Get version from __init__.py
    init_version = get_version_from_init(package_dir)
    print(f"Current version in __init__.py: {init_version}")

    # Get version from pyproject.toml
    pyproject_data = toml.load(pyproject_file)
    pyproject_version = pyproject_data.get("project", {}).get("version")
    print(f"Current version in pyproject.toml: {pyproject_version}")

    # Update pyproject.toml if versions do not match
    if pyproject_version != init_version:
        update_version_in_pyproject(pyproject_file, init_version)

    # Run the build process
    generate_help_markdown()
    update_dependencies()
    run_build()


if __name__ == "__main__":
    main()

import argparse
from pathlib import Path
import sys
from unittest.mock import MagicMock
import subprocess


# Dynamically add the src directory to the Python path
current_dir = Path(__file__).resolve().parent
src_path = current_dir / "src"
sys.path.insert(0, str(src_path))

from src.slingerpkg.utils.cli import setup_cli_parser


def parse_requirements(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"File {filename} not found. Skipping requirements parsing.")
        return []


def extract_commands_and_args(parser):
    commands = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for command, subparser in action.choices.items():
                commands[command] = {
                    "description": getattr(subparser, "description", "No description provided"),
                    "help": getattr(subparser, "format_help", lambda: "No help message provided")(),
                    "epilog": getattr(subparser, "epilog", None),
                    "arguments": [],
                }
                for sub_action in subparser._actions:
                    if isinstance(sub_action, argparse._StoreAction):
                        commands[command]["arguments"].append({
                            "name": sub_action.dest,
                            "help": sub_action.help,
                            "choices": sub_action.choices,
                            "default": sub_action.default,
                            "required": sub_action.required if hasattr(sub_action, 'required') else False,
                        })
    return commands



def generate_markdown(commands, output_file):
    with open(output_file, "w") as md_file:
        md_file.write("# CLI Commands Documentation\n\n")
        for command, details in commands.items():
            md_file.write(f"## `{command}`\n\n")
            md_file.write(f"**Description:** {details['description'] or 'No description provided'}\n\n")
            md_file.write(f"**Help:** {details['help'] or 'No help message provided'}\n\n")
            if details['epilog']:
                md_file.write(f"**Example Usage:**\n```\n{details['epilog']}\n```\n\n")
            if details['arguments']:
                md_file.write("### Arguments\n\n")
                for arg in details['arguments']:
                    md_file.write(f"- **`{arg['name']}`**: {arg['help'] or 'No description provided'}\n")
                    if arg['choices']:
                        md_file.write(f"  - Choices: {', '.join(arg['choices'])}\n")
                    if arg['default'] is not None:
                        md_file.write(f"  - Default: `{arg['default']}`\n")
                    md_file.write(f"  - Required: {'Yes' if arg['required'] else 'No'}\n\n")
            md_file.write("---\n\n")

def run_build():
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

def main():
    print("Generating CLI documentation...")

    # Create a mock slingerClient
    mock_client = MagicMock()

    # Set up the parser using the mock client
    parser = setup_cli_parser(mock_client)

    # Extract commands and arguments
    commands = extract_commands_and_args(parser)

    # Generate the markdown file
    output_file = "HELP_MENU.md"
    generate_markdown(commands, output_file)
    print(f"Markdown documentation generated: {output_file}")

    # Parse requirements (optional)
    dependencies = parse_requirements('requirements.txt')
    if dependencies:
        print("Dependencies:", dependencies)
    else:
        print("No dependencies found.")

    # Run the build process
    print("Starting the build process...")
    run_build()


if __name__ == "__main__":
    main()

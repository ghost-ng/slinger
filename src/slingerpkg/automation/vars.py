import re
from unittest.mock import MagicMock

from slingerpkg.utils.cli import extract_commands_and_args, setup_cli_parser

ANSI = r"\x1b\[[0-9;]*[A-Za-z]"
PROMPT = re.compile(rf"(?:{ANSI})*\[sl\].*?> ")

mock_client = MagicMock()
parser = setup_cli_parser(mock_client)
COMMAND_LIST = ", ".join(extract_commands_and_args(parser).keys())

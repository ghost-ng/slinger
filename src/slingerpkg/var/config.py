from pathlib import Path
from slingerpkg import __version__, __package__


def get_main_package_dir():
    current_dir = Path(__file__).resolve().parent
    while current_dir != current_dir.root:
        # Check if it contains a top-level __init__.py (indicating it's a package)
        init_file = (Path(__file__).parent.parent / "__init__.py").resolve()
        if init_file.exists():
            return current_dir / "src" / "slingerpkg"
        current_dir = current_dir.parent

    raise FileNotFoundError("Main package directory not found.")


plugin_dir = get_main_package_dir() / "plugins"

config_vars = [
    {"Name": "Debug", "Value": False, "Description": "Enable debug messages", "Type": "bool"},
    {
        "Name": "Logs_Folder",
        "Value": "~/.slinger/logs",
        "Description": "Folder to store history files",
        "Type": "str",
    },
    {
        "Name": "History_File",
        "Value": "~/.slinger/history",
        "Description": "History file location",
        "Type": "str",
    },
    {
        "Name": "Codec",
        "Value": "utf-8",
        "Description": "Codec to use for print decoding",
        "Type": "str",
    },
    {
        "Name": "Plugin_Folders",
        "Value": ["~/.slinger/plugins", plugin_dir],
        "Description": "Folder to store plugins",
        "Type": "str",
    },
    {
        "Name": "Verbose",
        "Value": False,
        "Description": "Enable verbose output for operations",
        "Type": "bool",
    },
]

logwriter = None
version = __version__
program_name = __package__
smb_conn_timeout = 999999

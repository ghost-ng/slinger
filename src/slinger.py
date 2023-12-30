#!/usr/bin/env python3
from slingerpkg.utils.printlib import *
from slingerpkg.lib.slingerclient import SlingerClient
from slingerpkg.utils.common import get_config_value, set_config_value, run_local_command
from slingerpkg.utils.cli import setup_cli_parser, get_prompt, CommandCompleter, setup_completer, merge_parsers, force_help, get_subparser_aliases
from slingerpkg.lib.plugin_base import load_plugins
from slingerpkg.var.config import version
import shlex, argparse, sys, os, pty, termios
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.formatted_text import to_formatted_text, ANSI
from prompt_toolkit.completion import Completer, Completion


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

    # setup folder structure -> ~/.slinger/logs, ~/.slinger/plugins
    if not os.path.exists(os.path.expanduser(get_config_value('Logs_Folder'))):
        os.makedirs(os.path.expanduser(get_config_value('Logs_Folder')))

    if not os.path.exists(os.path.expanduser(get_config_value('Plugin_Folder'))):
        os.makedirs(os.path.expanduser(get_config_value('Plugin_Folder')))

    original_settings = termios.tcgetattr(0)

    parser = argparse.ArgumentParser(description='impacket swiss army knife (sort of)')
    parser.add_argument('--host', required=True, help='Host to connect to')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-pass', '--password', required=True, help='Password for authentication')
    parser.add_argument('-d', '--domain', default='', help='Domain for authentication')
    parser.add_argument('-p', '--port', type=int, default=445, help='Port to connect to')
    parser.add_argument('--nojoy', action='store_true', help='Turn off emojis')
    parser.add_argument('--ntlm', help='NTLM hash for authentication')
    parser.add_argument('--kerberos', action='store_true', help='Use Kerberos for authentication')
    parser.add_argument('--debug', action='store_true', help='Turn on debug output')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    prgm_args = parser.parse_args()
    if prgm_args.debug:
        set_config_value('debug', True)
    slingerClient = SlingerClient(prgm_args.host, prgm_args.username, prgm_args.password, prgm_args.domain, prgm_args.port, prgm_args.ntlm, prgm_args.kerberos)

    slinger_parser = setup_cli_parser(slingerClient)

    # load plugins
    plugins_folder = os.path.expanduser(get_config_value('Plugin_Folder'))

    plugins = load_plugins(plugins_folder, slingerClient)
    # merge all parsers from the plugins into the main parser
    for plugin in plugins:
        plugin_parser = plugin.get_parser()
        slinger_parser = merge_parsers(slinger_parser, plugin_parser)

    hist_file_location = os.path.expanduser(get_config_value('History_File'))
    completer = CommandCompleter(setup_completer(slinger_parser))
    session = PromptSession(history=FileHistory(hist_file_location),completer=completer)

    try:
        slingerClient.login()
        if slingerClient.is_logged_in:
            print_good(f"Successfully logged in to {prgm_args.host}:{prgm_args.port}")
        else:
            print_bad(f"Failed to log in to {prgm_args.host}:{prgm_args.port}")
            print_debug('',sys.exc_info())
            sys.exit()
    except Exception as e:
        if 'Errno 111' in str(e) and 'Connection refused' in str(e):
            print_bad("Connection error: Connection refused.  Verify there is a host listening on the specified port.")
        elif "Errno 113" in str(e):
            print_bad("Connection error: No route to host.  Verify the host is up and the port is open.")
        else:
            print_debug(str(e))
            print_bad(f"Error: {e}: {sys.exc_info()}")
        
        print_debug('',sys.exc_info())
        sys.exit()
        

    while True:
        try:
            prompt_text = get_prompt(slingerClient, prgm_args.nojoy)

            try:
                #formatted_text(ANSI(prompt_text),end='')
                user_input = session.prompt(to_formatted_text(ANSI(prompt_text)))
                logwriter.info(user_input)
                split = shlex.split(user_input)
                #user_input = prompt('', history=history)
                #user_input = input(prompt_text)
                split = shlex.split(user_input)
                args = slinger_parser.parse_args(split)
                if hasattr(args, 'func'):
                    args.func(args)
                #print(args)
            except (argparse.ArgumentError, ValueError):
                print_debug('',sys.exc_info())
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
                print_debug(str(e), sys.exc_info())
                print_bad(f"Error: {e}: {sys.exc_info()}")
                continue
            except argparse.ArgumentError as e:
                #print("Unknown command")
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
            #elif args.command == "info":
            #    slingerClient.info()
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
                        print_debug('',sys.exc_info())
                        print_log(f"Failed to change local directory to {new_dir}: {e}")
                else:
                    print_info("Running Local Command: " + local_command)
                    run_local_command(local_command)
            elif args.command == "help":
                if args.cmd:
                    # force cmd -h
                    force_help(slinger_parser, args.cmd)
                else:
                    slinger_parser.print_help()
                
            elif args.command == "exit":
                slingerClient.exit()
                break

            # elif args.command== "upload" or args.command == "put":
            #     remote_path = ""
            #     if slingerClient.check_if_connected():
            #         if args.remote_path == "." or args.remote_path == "" or args.remote_path is None:
            #             remote_path = os.path.basename(args.local_path)
            #         else:
            #             remote_path = args.remote_path
            #         if os.path.exists(args.local_path):
            #             print_info(f"Uploading: {args.local_path} --> {slingerClient.share}\\{remote_path}")
            #             slingerClient.upload(args.local_path, remote_path)
            #         else:
            #             print_warning(f"Local path {args.local_path} does not exist.")

            # elif args.command == "download" or args.command == "get":
            #     # handle if remote_path is a file name (relative to current path)
            #     remote_path = os.path.normpath(os.path.join(slingerClient.relative_path, args.remote_path))
            #     local_path = ""
            #     if slingerClient.check_if_connected():
            #         if not slingerClient.file_exists(args.remote_path):
            #             print_warning(f"Remote file {args.remote_path} does not exist.")
            #             continue
            #         if args.local_path == "." or args.local_path == "" or args.local_path is None:
            #             local_path = os.path.join(os.getcwd(), os.path.basename(args.remote_path))
            #         else:
            #             local_path = args.local_path
            #         if os.path.isdir(os.path.dirname(local_path)):
            #             print_info(f"Downloading: {slingerClient.share}\\{remote_path} --> {local_path}")
            #             slingerClient.download(remote_path, local_path)
            #         else:
            #             print_warning(f"Local path {args.local_path} does not exist.")
            else:
                pass
        except Exception as e:
            print_warning(f"Uncaught Error: {e}: {sys.exc_info()}")
            print_debug('',sys.exc_info())

    slingerClient.exit()

if __name__ == "__main__":
    print_log(banner_art)
    
    main()
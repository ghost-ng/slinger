#!/usr/bin/env python3
import sys
import os

# Add the src directory to Python path when running directly
if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.dirname(script_dir)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

from slingerpkg.utils.printlib import *
from slingerpkg.lib.slingerclient import SlingerClient
from slingerpkg.lib.local_log_processor import LocalLogProcessor
from slingerpkg.utils.common import (
    get_config_value,
    set_config_value,
    run_local_command,
    show_config,
)
from slingerpkg.utils.cli import (
    print_all_commands,
    print_all_help,
    setup_cli_parser,
    get_prompt,
    CommandCompleter,
    setup_completer,
    merge_parsers,
    force_help,
    file_to_slinger_script,
)
from slingerpkg.lib.plugin_base import load_plugins
from slingerpkg.var.config import version
import shlex, argparse, sys, os, pty, termios
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.formatted_text import to_formatted_text, ANSI
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
import getpass


session = None
banner_art = f"""
      __,_____
     / __.==--"   SLINGER
    /#(-'             v{version}
    `-'                    a ghost-ng special
"""
commands_and_args = None
plugin_list = None


class ArgparseCompleter(Completer):
    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()
        for cmd in commands_and_args:
            if cmd.startswith(word_before_cursor):
                yield Completion(cmd, start_position=-len(word_before_cursor))


def create_ntlm_hash(password):
    """
    Create an NTLM hash from a password.
    """
    try:
        from passlib.hash import nthash

        try:
            ntlm_hash = nthash.hash(password)
        except Exception as e:
            print_warning(f"Failed to generate NTLM hash: {e}")
            return None
        return ntlm_hash
    except ImportError:
        print_warning("passlib module not found. Cannot create NTLM hash.")
        return None


def main():
    global slingerClient
    global commands_and_args
    global session
    global plugin_list

    # setup folder structure -> ~/.slinger/logs, ~/.slinger/plugins
    if not os.path.exists(os.path.expanduser(get_config_value("Logs_Folder"))):
        os.makedirs(os.path.expanduser(get_config_value("Logs_Folder")))

    plugin_folders = get_config_value("Plugin_Folders")
    for folder in plugin_folders:
        if not os.path.exists(os.path.expanduser(folder)):
            os.makedirs(os.path.expanduser(folder))

    original_settings = termios.tcgetattr(0)

    parser = argparse.ArgumentParser(
        description="impacket smb swiss army knife (sort of)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # version, standalone argument
    if "-v" in sys.argv or "--version" in sys.argv:
        print(f"Version Information: {parser.prog} {version}")
        sys.exit(0)
    if "--gen-ntlm-hash" in sys.argv:
        hash = create_ntlm_hash(sys.argv[2])
        if hash:
            print(f"NTLM hash: :{hash}")
        sys.exit(0)

    parser.add_argument("--host", required=True, help="Host to connect to")
    parser.add_argument(
        "-u",
        "--user",
        "--username",
        required=True,
        help="Username for authentication",
        dest="username",
    )
    parser.add_argument("-d", "--domain", default="", help="Domain for authentication")
    parser.add_argument("-p", "--port", type=int, default=445, help="Port to connect to")
    parser.add_argument(
        "--timeout",
        type=int,
        default=86400,
        help="Global SMB connection timeout in seconds (default: 86400 = 24 hours)",
    )
    parser.add_argument("--nojoy", action="store_true", help="Turn off emojis")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    # authentication mutually exclusive group
    auth_group = parser.add_mutually_exclusive_group(required=False)
    auth_group.add_argument(
        "--pass",
        "--password",
        help="Password for authentication",
        dest="password",
        nargs="?",
        default=None,
    )
    auth_group.add_argument("--ntlm", help="NTLM hash for authentication")
    auth_group.add_argument(
        "--kerberos", action="store_true", help="Use Kerberos for authentication"
    )
    parser.add_argument("--debug", action="store_true", help="Turn on debug output")
    parser.add_argument("--gen-ntlm-hash", help="Generate NTLM hash from password", nargs=1)
    parser.add_argument("-v", "--version", action="version", help="Show version information")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    prgm_args = parser.parse_args()
    password = None
    if prgm_args.debug:
        set_config_value("debug", True)
    if prgm_args.verbose:
        set_config_value("Verbose", True)
    # Set global SMB connection timeout
    if prgm_args.timeout:
        import slingerpkg.var.config as config

        config.smb_conn_timeout = prgm_args.timeout
        print_debug(f"Global SMB timeout set to {prgm_args.timeout} seconds")

    if prgm_args.password is None and not prgm_args.ntlm and not prgm_args.kerberos:
        password = getpass.getpass(prompt="Password: ")
    elif prgm_args.password is not None:
        password = prgm_args.password
    elif not prgm_args.ntlm and not prgm_args.kerberos and prgm_args.password is None:
        print_bad("No authentication method provided.  Exiting.")
        sys.exit(1)
    slingerClient = SlingerClient(
        prgm_args.host,
        prgm_args.username,
        password,
        prgm_args.domain,
        prgm_args.port,
        prgm_args.ntlm,
        prgm_args.kerberos,
    )

    slinger_parser = setup_cli_parser(slingerClient)

    # load plugins
    folders = get_config_value("Plugin_Folders")
    plugins_folders = []
    for folder in folders:
        plugins_folders.append(os.path.expanduser(folder))

    plugins = load_plugins(plugins_folders, slingerClient)
    plugin_list = plugins
    # merge all parsers from the plugins into the main parser
    for plugin in plugins:
        plugin_parser = plugin.get_parser()
        slinger_parser = merge_parsers(slinger_parser, plugin_parser)

    hist_file_location = os.path.expanduser(get_config_value("History_File"))
    completer = CommandCompleter(setup_completer(slinger_parser))

    # Create custom key bindings
    kb = KeyBindings()

    # Double ESC to clear the line
    @kb.add(Keys.Escape, Keys.Escape)
    def _(event):
        """Clear the current input line on double ESC"""
        event.current_buffer.reset()

    session = PromptSession(
        history=FileHistory(hist_file_location), completer=completer, key_bindings=kb
    )

    try:
        slingerClient.login()
        if slingerClient.is_logged_in:
            print_good(f"Successfully logged in to {prgm_args.host}:{prgm_args.port}")
        else:
            print_bad(f"Failed to log in to {prgm_args.host}:{prgm_args.port}")
            print_debug("", sys.exc_info())
            sys.exit()
    except Exception as e:
        if "Errno 111" in str(e) and "Connection refused" in str(e):
            print_bad(
                "Connection error: Connection refused.  Verify there is a host listening on the specified port."
            )
            sys.exit()
        elif "Errno 113" in str(e):
            print_bad(
                "Connection error: No route to host.  Verify the host is up and the port is open."
            )
            sys.exit()
        else:
            print_debug(str(e))
            print_bad(f"Error: {e}: {sys.exc_info()}")

        print_debug("", sys.exc_info())

    slingerQueue = []
    graceful_exit = False
    while True:
        try:
            prompt_text = get_prompt(slingerClient, prgm_args.nojoy)

            try:
                # formatted_text(ANSI(prompt_text),end='')
                if slingerQueue:
                    user_input = slingerQueue.pop(0)
                else:
                    user_input = session.prompt(
                        to_formatted_text(ANSI(prompt_text)),
                        complete_while_typing=False,
                        complete_style="readline",
                    )

                logwriter.info(user_input)
                try:
                    split = shlex.split(user_input)
                except ValueError:
                    # Fall back to simple split if shlex fails
                    split = user_input.split()
                args = slinger_parser.parse_args(split)
                if hasattr(args, "func"):
                    args.func(args)
                # print(args)
            except (argparse.ArgumentError, ValueError):
                print_debug("", sys.exc_info())
                print_warning("Failed to parse command. Try quoting your arguments.")
                print_log(sys.exc_info())
                continue
            except KeyboardInterrupt:
                try:
                    ans = input("Do you really want to exit? [y/n] ")

                    if ans.lower() == "y":
                        slingerClient.exit()
                        break
                    continue
                except KeyboardInterrupt:
                    print()
                    continue
            except SystemExit:
                continue
            except Exception as e:
                if "Invalid command entered" in str(e):
                    pass
                elif "STATUS_PIPE_NOT_AVAILABLE" in str(e):
                    try:
                        print_warning("Broken pipe error. Try to reconnect...")
                    except Exception as reconnect_error:
                        print_bad(f"Reconnection failed: {reconnect_error}")
                else:
                    print_warning(f"Uncaught Error: {e}")
                    print_debug(str(e), sys.exc_info())

                continue
            except argparse.ArgumentError as e:
                # print("Unknown command")
                pass
            if args.command is None or args.command == "":
                continue

            #############################################################
            #############################################################
            #############################################################

            if args.command == "reload":
                slinger_parser = setup_cli_parser(slingerClient)
                # load plugins
                plugin_folders = []
                folders = get_config_value("Plugin_Folders")
                for folder in folders:
                    plugin_folders.append(os.path.expanduser(folder))
                plugins = load_plugins(plugins_folders, slingerClient)
                plugin_list = plugins
                # merge all parsers from the plugins into the main parser
                for plugin in plugins:
                    plugin_parser = plugin.get_parser()
                    slinger_parser = merge_parsers(slinger_parser, plugin_parser)

                hist_file_location = os.path.expanduser(get_config_value("History_File"))
                completer = CommandCompleter(setup_completer(slinger_parser))

                # Create custom key bindings
                kb = KeyBindings()

                # Double ESC to clear the line
                @kb.add(Keys.Escape, Keys.Escape)
                def _(event):
                    """Clear the current input line on double ESC"""
                    event.current_buffer.reset()

                session = PromptSession(
                    history=FileHistory(hist_file_location), completer=completer, key_bindings=kb
                )
                print_good(f"Loaded {len(plugins)} plugins")

                for plugin in plugins:
                    print_info(f"Loaded plugin:\n {plugin.name} v{plugin.author_block['version']}")
                    print_log(f"Author: {plugin.author_block['name']}")
                    print_log(f"Meta: {plugin.author_block['meta']}")
                    print_log(f"Credits: {plugin.author_block['credits']}")

                print_info("Reloaded plugins")
            elif args.command == "plugins":
                print_good(f"Found {len(plugins)} plugins")
                for plugin in plugin_list:
                    print_info(f"Loaded plugin:\n {plugin.name} v{plugin.author_block['version']}")
                    print_log(f"Author: {plugin.author_block['name']}")
                    print_log(f"Meta: {plugin.author_block['meta']}")
                    print_log(f"Credits: {plugin.author_block['credits']}")

            elif args.command == "set":
                if args.varname:
                    set_config_value(args.varname, args.value if args.value is not None else "")
                    if args.varname.lower() == "debug":
                        if get_config_value("debug"):
                            print_info("Debug mode enabled")
                        else:
                            print_info("Debug mode disabled")
                else:
                    print_warning("Invalid arguments.  Usage: set <key> <value>")
            elif args.command == "config":
                show_config()
            # elif args.command == "info":
            #    slingerClient.info()
            elif args.command == "#shell":
                os.system("clear")
                print_info("You're in local terminal mode. Type exit to return.")
                pty.spawn("/bin/bash")
                termios.tcsetattr(0, termios.TCSANOW, original_settings)

            elif args.command == "!":
                local_command = " ".join(args.commands)

                # Enhanced bang command processing with log processing support
                if local_command.startswith("cd "):
                    new_dir = local_command[3:]
                    try:
                        os.chdir(new_dir)
                        print_info(f"Changed local directory to {new_dir}")
                    except Exception as e:
                        print_debug("", sys.exc_info())
                        print_log(f"Failed to change local directory to {new_dir}: {e}")

                # Check for log processing commands
                elif any(
                    local_command.startswith(cmd)
                    for cmd in [
                        "logparse",
                        "logclean",
                        "logreplace",
                        "logmerge",
                        "logexport",
                        "logstats",
                    ]
                ):
                    try:
                        # Initialize local log processor if not already done
                        if not hasattr(slingerClient, "local_log_processor"):
                            slingerClient.local_log_processor = LocalLogProcessor()

                        # Process the log command
                        command_line = f"! {local_command}"
                        success = slingerClient.local_log_processor.process_bang_command(
                            command_line
                        )

                        if success:
                            print_good("Log processing command completed successfully")
                        else:
                            print_warning("Log processing command failed or had warnings")

                    except Exception as e:
                        print_bad(f"Log processing error: {e}")
                        print_debug("Log processing error details", sys.exc_info())

                else:
                    print_info("Running Local Command: " + local_command)
                    run_local_command(local_command)
            elif args.command == "help":
                if args.cmd:
                    if args.cmd.lower() == "all":
                        print_all_help(slinger_parser)
                    else:
                        # force cmd -h
                        force_help(slinger_parser, args.cmd)
                else:
                    # Use verbose flag if present
                    verbose = getattr(args, "verbose", False)
                    print_all_commands(slinger_parser, verbose=verbose)
            elif args.command == "clear":
                os.system("clear")
            elif args.command == "exit" or args.command == "logoff":
                slingerClient.exit()
                graceful_exit = True
                break

            elif args.command == "run":

                if args.file:
                    file_path = os.path.expanduser(args.file)
                    if not os.path.exists(file_path):
                        print_warning(f"File {args.file} does not exist")
                        continue
                    lines = file_to_slinger_script(file_path)

                    for line in lines:
                        slingerQueue.append(line)

                elif args.cmd_chain:
                    if ";" in args.cmd_chain:
                        lines = args.cmd_chain.split(";")

                        for line in lines:
                            slingerQueue.append(line)
                    else:
                        print_warning(
                            "Invalid command sequence.  Use ';' to separate commands and wrap in quotes."
                        )

            else:
                pass
        except Exception as e:
            print_warning(f"Uncaught Error: {e}: {sys.exc_info()}")
            print_debug("", sys.exc_info())

    if not graceful_exit:
        slingerClient.exit()


if __name__ == "__main__":
    print_log(banner_art)
    # print python debug info
    print_debug("Python Version: " + sys.version)
    print_debug("Python Path: " + sys.executable)
    print_debug("Python Prefix: " + sys.prefix)
    print_debug("Python Path: " + sys.path[0])
    print_debug("Python Platform: " + sys.platform)
    print_debug("Python Version Info: " + str(sys.version_info))

    main()

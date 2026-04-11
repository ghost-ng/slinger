import ntpath
from time import sleep
from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import build_task_xml
from tabulate import tabulate
import os
import traceback


class atexec:
    def __init__(self):
        print_debug("ATExec Module Loaded!")

    def _get_default_output_path(self):
        """Return a share-relative output directory appropriate for the current share.

        The standard default (\\Users\\Public\\Downloads\\) only exists on C$.
        Other shares need a path that actually exists on them.
        """
        share = getattr(self, "share", None)
        if not share:
            return "\\Users\\Public\\Downloads\\"
        share_upper = share.upper()
        if share_upper == "C$":
            return "\\Users\\Public\\Downloads\\"
        elif share_upper == "ADMIN$":
            return "\\Temp\\"
        else:
            # Other drive shares (D$, E$) or custom shares — use root
            return "\\"

    def _resolve_output_path(self, sp):
        """Return the output path to use, replacing the CLI default if on a non-C$ share.

        If the user explicitly set --sp to something custom, honour it.
        If it's None or the CLI default (\\Users\\Public\\Downloads\\), use a
        share-appropriate path via _get_default_output_path().
        """
        cli_default = "\\Users\\Public\\Downloads\\"
        if not sp or sp == cli_default:
            return self._get_default_output_path()
        return sp

    def _cmd_split(self, cmdline):
        cmdline = cmdline.split(" ", 1)
        cmd = cmdline[0]
        args = cmdline[1] if len(cmdline) > 1 else ""

        return [cmd, args]

    def _create_task(self, args):
        # Connection should already be established by caller
        # Don't call setup_dce_transport() or _connect() here

        cmd = "cmd.exe"
        no_output = getattr(args, "no_output", False)
        if no_output:
            arguments = f"/C {args.command}"
            random_save_name = None
        else:
            share_path = args.share_path.rstrip("\\")
            if not args.sn:
                random_save_name = generate_random_string(8, 10) + ".txt"
            else:
                random_save_name = args.sn
            save_file_path = ntpath.join(share_path, random_save_name)
            arguments = f"/C {args.command} > {save_file_path} 2>&1"
            print_debug(f"Task '{args.tn}' will save output to: {save_file_path}")
        xml = build_task_xml(
            command=cmd,
            arguments=arguments,
            author=args.ta,
            description=args.td,
            task_name=args.tn,
            folder_path=args.tf,
        )
        resp = self.dce_transport._create_task(args.tn, args.tf, xml)
        return resp, random_save_name

    def atexec(self, args):

        task_name = args.tn
        task_author = args.ta
        task_description = args.td
        task_command = args.command
        task_folder = args.tf

        no_output = getattr(args, "no_output", False)

        # Share path only needed when capturing output
        if not no_output:
            # Always use the currently connected share
            share_name = getattr(self, "share", None)
            if not share_name:
                print_bad("Not connected to a share. Use 'use <sharename>' first.")
                return

            # Look up the share's disk root path
            share_info_dict = self.list_shares(args=None, echo=False, ret=True)
            if share_info_dict is None or len(share_info_dict) == 0:
                print_bad("Failed to list shares")
                return
            share_root = None
            for share_info in share_info_dict:
                if share_info["name"].upper() == share_name.upper():
                    share_root = share_info["path"].rstrip("\\")
                    break

            if share_root is None:
                print_bad(f"Share '{share_name}' not found in share list")
                return

            user_path = args.sp.lstrip("\\").rstrip("\\")
            args.share_path = f"{share_root}\\{user_path}"
            args._read_path = user_path
            print_debug(f"Using share path: {args.share_path}")

            # Pre-flight: verify the output directory exists on the share
            try:
                check_path = user_path if user_path else ""
                saved_rp = self.relative_path
                self.relative_path = ""
                self.conn.listPath(self.share, check_path + "\\*")
                self.relative_path = saved_rp
            except Exception:
                self.relative_path = saved_rp
                print_bad(
                    f"Path '{args.sp}' does not exist on share '{share_name}'. "
                    f"Output cannot be saved or retrieved. "
                    f"Use --sp to specify a valid path on this share"
                )
                return

        # Connect to the pipe
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        # Create the task
        save_file_name = None
        try:
            response, save_file_name = self._create_task(args)
            if response["ErrorCode"] == 0:
                print_good(f"Task '{args.tn}' created successfully")
            else:
                print_bad(f"Failed to create task '{args.tn}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            if "ERROR_ALREADY_EXISTS" in str(e):
                print_warning(f"Task file '{args.tn}' already exists, please delete it first")
            return

        # Reconnect to the pipe
        self.dce_transport._connect("atsvc")

        # Run the task
        try:
            full_task_path = ntpath.join(task_folder, task_name)
            response = self.dce_transport._run_task(full_task_path)
            if response["ErrorCode"] == 0:
                print_good(f"Task '{full_task_path}' executed successfully")
            else:
                print_bad(f"Failed to execute task '{full_task_path}'")
                return
        except Exception as e:
            print_debug(f"Exception during task run: {e}", sys.exc_info())
            return

        # Reconnect to the pipe
        self.dce_transport._connect("atsvc")

        # Delete the task
        try:
            response = self.dce_transport._delete_task(full_task_path)
            if response["ErrorCode"] == 0:
                print_good(f"Task '{args.tn}' deleted successfully")
            else:
                print_bad(f"Failed to delete task '{args.tn}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return

        # Retrieve the output (skip if --no-output)
        if getattr(args, "no_output", False) or save_file_name is None:
            print_info("Command executed (no output capture)")
            self._track(
                "EXEC",
                "atexec",
                args.command[:100] if hasattr(args, "command") else "unknown",
            )
            return

        try:
            # Read the output file relative to the current share using _read_path
            # _read_path is the share-relative directory (set during share resolution above)
            read_dir = getattr(args, "_read_path", args.sp.lstrip("\\").rstrip("\\"))
            args.remote_path = f"{read_dir}\\{save_file_name}"

            # Temporarily reset relative_path so cat/delete use share root
            saved_relative_path = self.relative_path
            self.relative_path = ""

            print_debug(f"Retrieving output from: {args.remote_path}")
            sleep(args.wait)
            print_info("Command output:")
            self.cat(args, echo=False)
            # Retry delete on sharing violation (file may still be locked)
            for attempt in range(3):
                try:
                    self.delete(args.remote_path)
                    break
                except Exception as del_err:
                    if "SHARING_VIOLATION" in str(del_err) and attempt < 2:
                        sleep(1)
                    else:
                        print_warning(f"Failed to delete output file: {del_err}")
                        break
            self._track(
                "EXEC",
                "atexec",
                args.command[:100] if hasattr(args, "command") else "unknown",
            )

            # Restore state
            self.relative_path = saved_relative_path
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return

    def atexec_handler(self, args):
        # Check if connected to a share (same pattern as other SMB commands)
        if not self.check_if_connected():
            return

        # Generate default task name if not provided
        if args.tn is None:
            from slingerpkg.utils.common import generate_random_string

            args.tn = f"SlingerTask_{generate_random_string(6, 8)}"

        # Adjust default output path based on connected share type
        args.sp = self._resolve_output_path(args.sp)
        print_debug(f"Using output path for {self.share}: {args.sp}")

        cmd = None
        # Reject absolute, UNC, and share-style paths — sp must be relative to connected share
        if ":" in args.sp or args.sp.startswith("\\\\") or "$" in args.sp:
            print_bad("--sp must be a path relative to the connected share (e.g., \\Temp\\)")
            return
        if args.shell:
            print_warning(
                "Entering semi-interactive mode.  Type 'exit' to return to the main menu."
            )
            print_info("Tip: Type 'config' to view current atexec configuration")
            while cmd != "exit":
                print_debug("Type 'config' to view current settings")
                cmd = input("atexec> ")
                if cmd == "exit":
                    break
                elif cmd == "config":
                    # Display current atexec configuration
                    print_info("Current atexec configuration:")
                    print_info(f"  Task Name (-tn): {args.tn}")
                    print_info(f"  Share: {self.share}")
                    print_info(f"  Path (-sp): {args.sp}")
                    print_info(f"  Author (-ta): {args.ta}")
                    print_info(f"  Description (-td): {args.td}")
                    print_info(f"  Folder (-tf): {args.tf}")
                    print_info(f"  Wait Time (-w): {args.wait}s")
                    print_info(f"  Save Name (-sn): {args.sn}")
                    print()
                    continue

                # Create a shallow copy of args to avoid state pollution between commands
                # Note: Cannot use deepcopy due to socket objects in args
                import copy

                shell_args = copy.copy(args)
                shell_args.command = cmd

                # Generate a unique task name for each shell command
                from slingerpkg.utils.common import generate_random_string

                shell_args.tn = f"SlingerTask_{generate_random_string(6, 8)}"

                # Display arguments for user reference
                print_info(f"Executing with arguments:")
                print_info(f"  Command: {shell_args.command}")
                print_info(f"  Task Name: {shell_args.tn}")
                print_info(f"  Share: {self.share}")
                print_info(f"  Path: {shell_args.sp}")
                print_info(f"  Author: {shell_args.ta}")
                print_info(f"  Wait Time: {shell_args.wait}s")
                print()

                self.atexec(shell_args)
        else:
            # handle if no command is specified
            if args.command is None:
                print_bad("No command specified")
                return
            self.atexec(args)

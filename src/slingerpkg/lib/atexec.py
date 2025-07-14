import ntpath
from time import sleep
from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import enum_struct, generate_random_date, validate_xml, xml_escape
from tabulate import tabulate
import os
import traceback


class atexec:
    def __init__(self):
        print_debug("ATExec Module Loaded!")

    def _cmd_split(self, cmdline):
        cmdline = cmdline.split(" ", 1)
        cmd = cmdline[0]
        args = cmdline[1] if len(cmdline) > 1 else ""

        return [cmd, args]

    def _create_task(self, args):
        # Connection should already be established by caller
        # Don't call setup_dce_transport() or _connect() here

        cmd = "cmd.exe"
        # arguments = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self.__command, tmpFileName)
        share_path = args.share_path
        # remove trailing backslash
        share_path = share_path.rstrip("\\")
        cmd = "cmd.exe"
        if not args.save_name:
            random_save_name = generate_random_string(8, 10) + ".txt"
        else:
            random_save_name = args.save_name
        # save_file_path = args.path + f"{share_path}\\{random_save_name}"
        save_file_path = ntpath.join(share_path, random_save_name)
        arguments = f"/C {args.command} > {save_file_path} 2>&1"
        timestamp = generate_random_date()
        xml_escaped_args = xml_escape(arguments)
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<RegistrationInfo>
        <Author>{xml_escape(args.author)}</Author>
        <Description>{xml_escape(args.description)}</Description>
        <URI>\\{xml_escape(args.name)}</URI>
	</RegistrationInfo>
	<Triggers>
        <CalendarTrigger>
            <StartBoundary>{timestamp}</StartBoundary>
            <Enabled>true</Enabled>
            <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
            </ScheduleByDay>
        </CalendarTrigger>
	</Triggers>
	<Principals>
        <Principal id="LocalSystem">
            <UserId>S-1-5-18</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
	</Principals>
	<Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
        <Priority>7</Priority>
	</Settings>
	<Actions Context="LocalSystem">
        <Exec>
            <Command>{xml_escape(cmd)}</Command>
            <Arguments>{xml_escaped_args}</Arguments>
        </Exec>
	</Actions>
</Task>
"""
        print_debug(f"Task '{args.name}' will save output to: {save_file_path}")
        resp = self.dce_transport._create_task(args.name, args.folder, xml)
        return resp, random_save_name

    def atexec(self, args):

        task_name = args.name
        task_author = args.author
        task_description = args.description
        task_command = args.command
        task_folder = args.folder

        # get a list of shares
        share_info_dict = self.list_shares(args=None, echo=False, ret=True)
        # print(share_info_dict)
        share_exists = False
        if share_info_dict is None or len(share_info_dict) == 0:
            print_bad("Failed to list shares")
            return
        # check if the share exists
        for share_info in share_info_dict:
            if share_info["name"] == args.share:
                share_exists = True
                # Ensure proper path construction with backslashes
                share_root = share_info["path"].rstrip("\\")  # Remove trailing backslash
                user_path = args.path.lstrip("\\").rstrip(
                    "\\"
                )  # Remove only leading/trailing backslashes
                args.share_path = f"{share_root}\\{user_path}"
                print_debug(f"Using share path: {args.share_path}")
                break

        if not share_exists:
            print_bad(f"Share '{args.name}' does not exist")
            return

        # Connect to the pipe
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        # Create the task
        save_file_name = None
        try:
            response, save_file_name = self._create_task(args)
            if response["ErrorCode"] == 0:
                print_good(f"Task '{args.name}' created successfully")
            else:
                print_bad(f"Failed to create task '{args.name}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            if "ERROR_ALREADY_EXISTS" in str(e):
                print_warning(f"Task file '{args.name}' already exists, please delete it first")
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
                print_good(f"Task '{args.name}' deleted successfully")
            else:
                print_bad(f"Failed to delete task '{args.name}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return

        # Retrieve the output
        try:
            # Create relative path from share root (no leading backslashes)
            # Ensure proper path construction with backslashes
            relative_path = args.path.lstrip("\\").rstrip(
                "\\"
            )  # Remove only leading/trailing backslashes
            args.remote_path = f"{relative_path}\\{save_file_name}"
            # Ensure we're connected to the share for file operations
            print_debug(f"Current share: {getattr(self, 'share', 'None')}, needed: {args.share}")
            if not hasattr(self, "share") or self.share != args.share:
                print_debug(f"Connecting to share: {args.share}")
                self.connect_share(args)
            else:
                print_debug(f"Already on correct share: {self.share}")
            print_debug(f"Retrieving output from: {args.remote_path}")
            sleep(args.wait)
            print_info(f"Command output:")
            self.cat(args, echo=False)  # Show the output content without download progress
            self.delete(args.remote_path)
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return

    def atexec_handler(self, args):
        # Check if connected to a share (same pattern as other SMB commands)
        if not self.check_if_connected():
            return

        # Generate default task name if not provided
        if args.name is None:
            from slingerpkg.utils.common import generate_random_string

            args.name = f"SlingerTask_{generate_random_string(6, 8)}"

        # Update share to match currently connected share
        if hasattr(self, "share") and self.share:
            args.share = self.share

            # Adjust default path based on share type
            if args.path == "\\Users\\Public\\Downloads\\" and args.share == "ADMIN$":
                args.path = "\\Temp\\"
                print_debug(f"Using ADMIN$ appropriate path: {args.path}")

        cmd = None
        # handle mistakes in which the user specifies a full path
        if ":" in args.path:
            print_bad("Invalid path name, please use a relative path")
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
                    print_info(f"  Task Name (-tn): {args.name}")
                    print_info(f"  Share (-sh): {args.share}")
                    print_info(f"  Path (-sp): {args.path}")
                    print_info(f"  Author (-ta): {args.author}")
                    print_info(f"  Description (-td): {args.description}")
                    print_info(f"  Folder (-tf): {args.folder}")
                    print_info(f"  Wait Time (-w): {args.wait}s")
                    print_info(f"  Save Name (-sn): {args.save_name}")
                    print()
                    continue

                # Create a shallow copy of args to avoid state pollution between commands
                # Note: Cannot use deepcopy due to socket objects in args
                import copy

                shell_args = copy.copy(args)
                shell_args.command = cmd

                # Generate a unique task name for each shell command
                from slingerpkg.utils.common import generate_random_string

                shell_args.name = f"SlingerTask_{generate_random_string(6, 8)}"

                # Display arguments for user reference
                print_info(f"Executing with arguments:")
                print_info(f"  Command: {shell_args.command}")
                print_info(f"  Task Name: {shell_args.name}")
                print_info(f"  Share: {shell_args.share}")
                print_info(f"  Path: {shell_args.path}")
                print_info(f"  Author: {shell_args.author}")
                print_info(f"  Wait Time: {shell_args.wait}s")
                print()

                self.atexec(shell_args)
        else:
            # handle if no command is specified
            if args.command is None:
                print_bad("No command specified")
                return
            self.atexec(args)

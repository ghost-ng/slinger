import ntpath
from time import sleep
from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import enum_struct, generate_random_date, validate_xml, xml_escape
from tabulate import tabulate
import os
import traceback


class atexec():
    def __init__(self):
        print_debug("ATExec Module Loaded!")
    
    def _cmd_split(self, cmdline):
        cmdline = cmdline.split(" ", 1)
        cmd = cmdline[0]
        args = cmdline[1] if len(cmdline) > 1 else ''

        return [cmd, args]


    def _create_task(self, args):    
        self.setup_dce_transport()
        self.dce_transport._connect('atsvc')

        cmd = "cmd.exe"
        #arguments = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self.__command, tmpFileName)
        share_path = args.share_path
        # remove trailing backslash
        share_path = share_path.rstrip("\\")
        cmd = "cmd.exe"
        if not args.save_name:
            random_save_name = generate_random_string(8,10) + ".txt"
        else:
            random_save_name = args.save_name
        #save_file_path = args.path + f"{share_path}\\{random_save_name}"
        save_file_path = ntpath.join(share_path, random_save_name)
        arguments = f"/C {args.command} > {save_file_path} 2>&1"
        timestamp = generate_random_date()
        xml_escaped_args = xml_escape(arguments)
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<RegistrationInfo>
        <Author>{args.author}</Author>
        <Description>{args.description}</Description>
        <URI>\\{args.name}</URI>
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
        print_info(f"""Task Details: 
Name:     '{args.name}'
Command:  '{args.command}'
Share Path: '{share_path}'
Saved to: '{save_file_path}'""")
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
        #print(share_info_dict)
        share_exists = False
        if share_info_dict is None:
            print_bad("Failed to list shares")
            return
        # check if the share exists
        for share_info in share_info_dict:
            if share_info['name'] == args.share:
                share_exists = True
                args.share_path = ntpath.join(share_info['path'], args.path)
                print_info(f"Share '{args.share}' resolves to '{share_info['path']}'")
                print_debug(f"Full Resolved Path: '{args.share_path}'")
                break
        
        if not share_exists:
            print_bad(f"Share '{args.name}' does not exist")
            return


        # Connect to the pipe
        self.setup_dce_transport()
        self.dce_transport._connect('atsvc')
        # Create the task
        save_file_name = None
        try:
            response, save_file_name = self._create_task(args)
            if response['ErrorCode'] == 0:
                print_good(f"Task '{args.name}' created successfully")
            else:
                print_bad(f"Failed to create task '{args.name}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            if "ERROR_ALREADY_EXISTS" in str(e):
                print_warning(f"Task file '{args.name}' already exists, please delete it first")
            return
        
        
        #Reconnect to the pipe
        self.dce_transport._connect('atsvc')
        
        # Run the task
        try:
            full_task_path = ntpath.join(task_folder, task_name)
            response = self.dce_transport._run_task(full_task_path)
            if response['ErrorCode'] == 0:
                print_good(f"Task '{full_task_path}' executed successfully")
            else:
                print_bad(f"Failed to execute task '{full_task_path}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return
        
        # Reconnect to the pipe
        self.dce_transport._connect('atsvc')

        # Delete the task
        try:
            
            response = self.dce_transport._delete_task(full_task_path)
            if response['ErrorCode'] == 0:
                print_good(f"Task '{args.name}' deleted successfully")
            else:
                print_bad(f"Failed to delete task '{args.name}'")
                return
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return
        
        # Retrieve the output
        try:
            args.remote_path = ntpath.join("\\",args.path, save_file_name)
            # connect to the share
            self.connect_share(args)
            # reverse the slashes
            #args.remote_path = args.remote_path.replace("\\", "/")
            print_info(f"Output saved to '{args.remote_path}'")
            sleep(args.wait)
            self.cat(args, echo=False)
            self.delete(args.remote_path)
        except Exception as e:
            print_debug(f"Exception: {e}", sys.exc_info())
            return
        
    def atexec_handler(self, args):
        cmd = None
        # handle mistakes in which the user specifies a full path
        if ":" in args.path:
            print_bad("Invalid path name, please use a relative path")
            return
        if args.shell:
            print_warning("Entering interactive mode.  Type 'exit' to return to the main menu.")
            while cmd != "exit":
                cmd = input("atexec> ")
                if cmd == "exit":
                    break
                args.command = cmd
                self.atexec(args)
        else:
            # handle if no command is specified
            if args.command is None:
                print_bad("No command specified")
                return
            self.atexec(args)
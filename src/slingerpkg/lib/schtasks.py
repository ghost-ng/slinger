from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import enum_struct, generate_random_date, validate_xml, xml_escape
from tabulate import tabulate
import os
import traceback


class schtasks:
    """
    This class provides methods for interacting with the Windows Task Scheduler.
    """

    def __init__(self):
        print_debug("Scheduled Tasks Module Loaded!")
        self.visited_folders = set()
        self.files = []
        self.task_folder_tree = None
        self.folder_list = ["\\"]
        self.folder_list_dict = {}
        self.task_id = 1  # Initialize the task ID counter
        self.tasks_list = []  # Store cached task list for filtering

    def filter_tasks(self, filtered):
        # filter format: name=blah, folder=blah
        new_list = []
        if "folder" in filtered:
            folder = filtered.split("=")[1]
            for task in self.tasks_list:
                if folder.lower() in task["Folder"].lower():
                    new_list.append(task)
            return new_list
        elif "name" in filtered:
            name = filtered.split("=")[1]
            for task in self.tasks_list:
                if name.lower() in task["TaskName"].lower():
                    new_list.append(task)
            return new_list
        else:
            return self.tasks_list

    def enum_folders_old(self, folder_path="\\", start_index=0):
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        # Call SchRpcEnumFolders

        response = self.dce_transport._enum_folders(folder_path, start_index)
        if response["ErrorCode"] == 0:

            folders = response["pNames"]
            # print_log(response.dump())

            for folder in folders:
                folder_name = folder["Data"]
                full_folder_path = reduce_slashes(
                    os.path.normpath(folder_path + "\\" + folder_name.rstrip("\\"))
                )

                if folder_name is not None and full_folder_path not in self.folder_list:
                    print_info("Found Folder: " + full_folder_path)
                    self.folder_list.append(full_folder_path)

    def enum_folders(self, folder_path="\\", start_index=0):
        """
        Enumerate folders recursively starting from the specified folder path.

        Args:
            folder_path (str): The path of the folder to start enumeration from. Default is "\\".
            start_index (int): The index to start enumeration from. Default is 0.

        Returns:
            None
        """
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")
        response = self.dce_transport._enum_folders(folder_path, start_index)
        if response["ErrorCode"] == 0:
            folders = response["pNames"]
            found_folders = [f["Data"].strip("\x00") for f in folders]
            for folder_name in found_folders:
                if not folder_path == "\\":
                    full_folder_path = folder_path + "\\" + folder_name
                else:
                    full_folder_path = folder_path + folder_name
                self.folder_list.append(full_folder_path)
                self.enum_folders(full_folder_path)
        else:
            return

    def enum_task_folders_recursive(self, args):
        """
        Enumerates the Task Scheduler folders recursively.

        Args:
            args: Command arguments containing filter and new options
        """
        try:
            force = args.new
        except:
            force = False
        try:
            filtered = args.filter
        except:
            filtered = None

        # Check if we should use cached data
        if force or len(self.tasks_list) == 0:
            print_debug("Getting all tasks, this might take a while...")
            folder = "\\"
            start_index = 0
            print_debug("Enumerating Task Scheduler...")
            self.folder_list = ["\\"]
            self.folder_list_dict = {}
            self.enum_folders(folder, start_index)
            self.task_id = 1  # Reset the task ID counter
            self.view_tasks_in_folder()

            # Build and cache the tasks list
            self.tasks_list = [
                {"ID": task_id, "Folder": folder, "TaskName": task}
                for folder, tasks in self.folder_list_dict.items()
                for task_id, task in tasks
            ]
        else:
            print_debug("Using stored tasks list...")

        # Apply filtering if provided
        if filtered:
            print_debug("Filtering tasks...")
            filtered_tasks = self.filter_tasks(filtered)
        else:
            filtered_tasks = self.tasks_list

        # Display results
        self.display_tasks(filtered_tasks)

    def display_tasks(self, tasks_data):
        """
        Display tasks in table format, similar to services
        """
        # Generate table
        table = tabulate(tasks_data, headers="keys", tablefmt="psql")

        # Display results
        print_log(table)
        print_log("Total Tasks: %d" % len(self.tasks_list))
        if len(tasks_data) != len(self.tasks_list):
            print_log("Filtered Tasks: %d" % len(tasks_data))

    def print_folder_tree(self, args=None):
        """
        Prints the folder tree along with the tasks in each folder.

        Args:
            args: Command arguments containing filter and save options
        """
        # Build initial data
        all_data = [
            {"ID": task_id, "Folder": folder, "TaskName": task}
            for folder, tasks in self.folder_list_dict.items()
            for task_id, task in tasks
        ]

        # Apply filter if provided
        if args and hasattr(args, "filter") and args.filter:
            filtered_data = [
                item for item in all_data if args.filter.lower() in item["TaskName"].lower()
            ]
            print_info(
                f"Applied filter '{args.filter}': {len(filtered_data)} of {len(all_data)} tasks shown"
            )
            data = filtered_data
        else:
            data = all_data

        # Generate table
        table = tabulate(data, headers="keys", tablefmt="psql")

        # Save to file if requested
        if args and hasattr(args, "save") and args.save:
            try:
                with open(args.save, "w") as f:
                    f.write(table)
                print_good(f"Results saved to: {args.save}")
            except Exception as e:
                print_bad(f"Failed to save to file: {e}")

        # Display results
        print_log(table)
        print_info(f"Found {len(data)} tasks")

    def parse_folder_tasks(self, response, folder):
        """
        Parses the tasks in a specific folder from the response and updates the folder_list_dict.

        Args:
            response (dict): The response containing the tasks.
            folder (str): The folder name.

        Returns:
            None: If the response has an error code.

        """
        if response["ErrorCode"] == 0:
            tasks = response["pNames"]
            for task in tasks:
                data = task["Data"]
                if folder.strip("\x00") == "":
                    folder = "\\"
                # print_info(f"\tFound Task: {folder}\\{data}")
                if folder in self.folder_list_dict:
                    self.folder_list_dict[folder].append(
                        (self.task_id, data)
                    )  # Add the task ID to the task data
                else:
                    self.folder_list_dict[folder] = [
                        (self.task_id, data)
                    ]  # Add the task ID to the task data

                self.task_id += 1  # Increment the task ID counter
        else:
            return None

    def view_tasks_in_folder(self, folder=None):
        self.setup_dce_transport()
        # self.dce_transport.connect('atsvc')

        folder_paths = self.folder_list if folder is None else [folder]

        for folder_path in folder_paths:
            self.dce_transport._connect("atsvc")
            folder_path = folder_path.rstrip("\\")
            try:
                print_debug(f"Enumerating tasks in folder: {folder_path}")
                response = self.dce_transport._view_tasks_in_folder(folder_path)
                # print_log(response.dump())
                # print_info(f"Parsing Tasks in {folder_path}:")
                self.parse_folder_tasks(response, folder_path)
            except Exception as e:
                if "Bind context rejected: reason_not_specified" in str(e):
                    if folder is not None:
                        print_warning(
                            "Unable to view tasks in folder: " + folder + " - invalid context"
                        )
                elif "ERROR_INVALID_NAME" in str(e):
                    if folder is not None:
                        print_warning(
                            "Unable to view tasks in folder: " + folder + " - invalid name"
                        )
                else:
                    print_bad("Unable to view tasks in folder: " + folder_path)
                    print_log(e)

    def task_run(self, args):
        abs_path = args.task_path
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")
        response = self.dce_transport._run_task(abs_path)
        if response["ErrorCode"] == 0:
            print_good(f"Task '{abs_path}' run successfully.")
        else:
            print_bad(f"Error running task '{abs_path}': {response['ErrorCode']}")

    def task_create(self, args):
        task_name = args.name
        program = args.program
        arguments = args.arguments
        folder_path = args.folder
        # generate random date in last year using format 2023-01-01T08:00:00

        if args.date:
            new_date = reformat_datetime(args.date)
        else:
            new_date = generate_random_date()

        interval = None
        if args.interval:
            # if less than 60, -> PT_M
            # if greater than 60, -> PT_H
            if int(args.interval) % 60 == 0:
                h = int(args.interval) / 60
                interval = f"PT{h}H"
            elif int(args.interval) < 60:
                interval = f"PT{args.interval}M"
            else:
                h = round(int(args.interval) / 60)
                m = int(args.interval) % 60
                interval = f"PT{h}H{m}M"

        task_xml_once = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{new_date}</Date>
    <Author>SYSTEM</Author>
    <URI>{folder_path}\\{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{new_date}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
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
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{program}</Command>
      <Arguments>{xml_escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

        task_xml_interval = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{new_date}</Date>
    <Author>SYSTEM</Author>
    <URI>{folder_path}\\{task_name}</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>{interval}</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>{new_date}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
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
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{program}</Command>
      <Arguments>{xml_escape(arguments)}</Arguments>
    </Exec>
  </Actions>
</Task>
"""
        task_xml = task_xml_interval if args.interval else task_xml_once
        # validate_xml(task_xml)
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        print_info("Using Program: " + program)
        print_info("Using Arguments: " + arguments)
        print_info("Using Date: " + new_date)
        print_info("Using Interval: " + interval if args.interval else "Using Interval: None")
        print_debug("Task XML:")
        print_debug(task_xml)
        abs_path = folder_path + "\\" + task_name
        abs_path = abs_path.replace(r"\\", chr(92))
        print_log(f"Creating Task: {abs_path}")
        try:
            response = self.dce_transport._create_task(task_name, folder_path, task_xml)
        except Exception as e:
            if "ERROR_ALREADY_EXISTS" in str(e):
                print_warning(f"Task '{task_name}' already exists in folder '{folder_path}'")
                return
            else:
                print_bad(f"Error creating task '{task_name}': {e}")
                return

        if response["ErrorCode"] == 0:
            print_log(f"Task '{task_name}' created successfully.")
        else:
            print_log(f"Error creating task '{task_name}': {response['ErrorCode']}")

    def task_delete_handler(self, args):
        if not self.folder_list_dict and args.task_id:
            print_warning("No tasks have been enumerated. Run enumtasks first.")
        else:
            task_arg = args.task_id if args.task_id else args.task_path
            self.task_delete(task_arg)

    def task_delete(self, task_arg):
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        task_name = None
        task_path = None
        task_abs_path = None
        if type(task_arg) is int:
            for folder, tasks in self.folder_list_dict.items():
                for task in tasks:
                    if task[0] == task_arg:
                        task_name = task[1]
                        task_path = folder
                        task_abs_path = os.path.normpath(folder + "\\" + task_name).replace(
                            r"\\", chr(92)
                        )
                        break

        else:
            task_abs_path = task_arg
            delim = "\\" if "\\" in task_arg else "/"
            task_name = task_arg.split(delim)[-1]
            task_path = task_arg.replace(task_name, "")
        try:
            if task_path is None:
                print_warning("Task ID not found")
                return
            else:
                # print_info(f"Chosen Task:\nTask Path: {task_path}\nTask Name: {task_name}")
                try:
                    response = self.dce_transport._delete_task(task_abs_path)
                    if response["ErrorCode"] == 0:
                        print_good(f"Task '{task_abs_path}' deleted successfully.")
                    else:
                        print_bad(f"Error deleting task '{task_abs_path}': {response['ErrorCode']}")
                except Exception as e:
                    if "ERROR_FILE_NOT_FOUND" in str(e) or "ERROR_INVALID_NAME" in str(e):
                        print_warning(f"Task '{task_abs_path}' does not exist.")
                        return
                    else:
                        print_bad(f"Error deleting task '{task_abs_path}': {e}")
                        return

        except Exception as e:
            task_arg = str(task_arg)
            if "Bind context rejected: reason_not_specified" in str(e):
                print_warning("Unable to delete task: " + task_arg + " - invalid context")
            elif "ERROR_INVALID_NAME" in str(e):
                print_warning("Unable to delete task: " + task_arg + " - invalid name")
            else:
                print_bad("Unable to delete task: " + task_arg)
                print_debug("An error occurred:", sys.exc_info())

    def task_show_handler(self, args):

        if not self.folder_list_dict and args.task_id:
            print_warning("No tasks have been enumerated. Run enumtasks first.")
        elif args.task_path:
            task_arg = args.task_id if args.task_id else args.task_path
            self.view_task_details(task_arg)
        else:
            print_warning(
                "No task specified. Use taskshow -i <taskid> or taskshow <name> to specify a task."
            )

    def task_manager(self):
        pass

    def view_task_details(self, task_arg):
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")
        # lookup taskpath and task name from dict with task_id
        task_name = None
        task_path = None
        abs_task_name = None
        if type(task_arg) is int:
            for folder, tasks in self.folder_list_dict.items():
                for task in tasks:
                    if task[0] == task_arg:
                        task_name = task[1]
                        task_path = folder
                        break
        else:
            if "/" in task_arg:
                delim = "/"
            else:
                delim = "\\"
            task_name = task_arg.split(delim)[-1]
            task_path = task_arg.replace(task_name, "")
        try:
            if task_path is None:
                print_warning("Task ID not found")
                return
            else:
                print_info(f"Chosen Task:\nTask Path: {task_path}\nTask Name: {task_name}")
                response = self.dce_transport._view_tasks(task_name, task_path)
            if response["ErrorCode"] == 0:
                task_xml = response["pXml"]
                print_log(f"{task_xml}")
            else:
                print_log(f"Error retrieving task '{task_name}': {response['ErrorCode']}")

        except Exception as e:
            if "Bind context rejected: reason_not_specified" in str(e):
                print_warning("Unable to view task: " + task_arg + " - invalid context")
            elif "ERROR_INVALID_NAME" in str(e) or "ERROR_FILE_NOT_FOUND" in str(e):
                print_warning("Unable to view task: " + task_arg + " - invalid name")
            else:
                print_bad("Unable to view task: " + task_arg)
                print_bad("An error occurred:")
                traceback.print_exc()

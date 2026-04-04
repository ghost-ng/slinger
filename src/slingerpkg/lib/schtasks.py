from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import build_task_xml, generate_random_date
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
        # filter format: name=blah, folder=blah, or plain substring
        new_list = []
        if "=" in filtered and filtered.split("=")[0].lower() == "folder":
            folder = filtered.split("=", 1)[1]
            for task in self.tasks_list:
                if folder.lower() in task["Folder"].lower():
                    new_list.append(task)
        elif "=" in filtered and filtered.split("=")[0].lower() == "name":
            name = filtered.split("=", 1)[1]
            for task in self.tasks_list:
                if name.lower() in task["TaskName"].lower():
                    new_list.append(task)
        else:
            # Plain substring: match against both task name and folder
            search = filtered.lower()
            for task in self.tasks_list:
                if search in task["TaskName"].lower() or search in task["Folder"].lower():
                    new_list.append(task)
        return new_list

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
        arguments = args.arguments or ""
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

        task_xml = build_task_xml(
            command=program,
            arguments=arguments,
            author="SYSTEM",
            task_name=task_name,
            folder_path=folder_path,
            date=new_date,
            interval=interval,
            principal_id="Author",
            execution_time_limit="PT72H",
            disallow_start_on_batteries=True,
            stop_on_batteries=True,
            actions_context="Author",
            include_date=True,
        )
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

    def _parse_task_xml(self, file_path):
        """Parse a task XML file and return (root, task_xml_str) or (None, None)."""
        import xml.etree.ElementTree as ET

        file_path = os.path.expanduser(file_path)
        if not os.path.exists(file_path):
            print_bad(f"File not found: {file_path}")
            return None, None

        with open(file_path, "r") as f:
            task_xml = f.read()

        try:
            root = ET.fromstring(task_xml)
        except ET.ParseError as e:
            print_bad(f"Invalid XML: {e}")
            return None, None

        return root, task_xml

    def _validate_task_xml(self, root):
        """Validate task XML has required elements for Task Scheduler.

        Returns (is_valid, errors) where errors is a list of strings.
        """
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        errors = []
        warnings = []

        def _find(xpath):
            ns_xpath = "/".join(f"t:{part}" for part in xpath.split("/"))
            elem = root.find(f".//{ns_xpath}", ns)
            if elem is None:
                elem = root.find(f".//{xpath}")
            return elem

        # Required: root must be <Task>
        tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
        if tag != "Task":
            errors.append(f"Root element is '{tag}', expected 'Task'")

        # Required: Actions/Exec/Command
        if _find("Actions/Exec/Command") is None:
            errors.append("Missing required element: Actions/Exec/Command")

        # Required: Triggers (at least one)
        triggers = root.find(".//t:Triggers", ns) or root.find(".//Triggers")
        if triggers is None or len(triggers) == 0:
            errors.append("Missing required element: Triggers (need at least one trigger)")

        # Required: Principals
        if _find("Principals/Principal") is None:
            errors.append("Missing required element: Principals/Principal")

        # Required: Settings section
        settings = root.find(".//t:Settings", ns) or root.find(".//Settings")
        if settings is None:
            errors.append("Missing required element: Settings")
        else:
            # Check critical settings that Windows requires
            required_settings = [
                "MultipleInstancesPolicy",
                "DisallowStartIfOnBatteries",
                "StopIfGoingOnBatteries",
                "AllowHardTerminate",
                "StartWhenAvailable",
                "RunOnlyIfNetworkAvailable",
                "IdleSettings",
                "AllowStartOnDemand",
                "Enabled",
                "RunOnlyIfIdle",
                "WakeToRun",
                "ExecutionTimeLimit",
                "Priority",
            ]
            for setting_name in required_settings:
                ns_path = f".//t:Settings/t:{setting_name}"
                plain_path = f".//Settings/{setting_name}"
                if root.find(ns_path, ns) is None and root.find(plain_path) is None:
                    warnings.append(f"Missing Settings/{setting_name}")

        # Warn if no RegistrationInfo/URI
        if _find("RegistrationInfo/URI") is None:
            warnings.append(
                "Missing RegistrationInfo/URI - task name will be derived from filename"
            )

        return errors, warnings

    def _extract_task_info(self, root, file_path, task_name=None, folder_path=""):
        """Extract task metadata from XML. Returns dict with all parsed fields."""
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

        def _find(xpath):
            """Find element with or without namespace."""
            # Try with namespace prefix on each path component
            ns_xpath = "/".join(f"t:{part}" for part in xpath.split("/"))
            elem = root.find(f".//{ns_xpath}", ns)
            if elem is None:
                # Try without namespace (plain XML)
                elem = root.find(f".//{xpath}")
            return elem.text if elem is not None else None

        # Extract name/folder from URI if not provided
        if not task_name:
            uri_text = _find("RegistrationInfo/URI")
            if uri_text:
                parts = uri_text.rsplit("\\", 1)
                task_name = parts[-1]
                if len(parts) > 1 and not folder_path:
                    folder_path = parts[0]
            else:
                task_name = os.path.splitext(os.path.basename(file_path))[0]

        return {
            "task_name": task_name,
            "folder_path": folder_path,
            "uri": _find("RegistrationInfo/URI"),
            "author": _find("RegistrationInfo/Author"),
            "description": _find("RegistrationInfo/Description"),
            "date": _find("RegistrationInfo/Date"),
            "command": _find("Actions/Exec/Command"),
            "arguments": _find("Actions/Exec/Arguments"),
            "working_dir": _find("Actions/Exec/WorkingDirectory"),
            "user_id": _find("Principals/Principal/UserId"),
            "run_level": _find("Principals/Principal/RunLevel"),
            "start_boundary": _find("Triggers/CalendarTrigger/StartBoundary")
            or _find("Triggers/TimeTrigger/StartBoundary"),
            "enabled": _find("Settings/Enabled"),
            "hidden": _find("Settings/Hidden"),
            "execution_time_limit": _find("Settings/ExecutionTimeLimit"),
        }

    def task_import(self, args):
        """Import a scheduled task from a local XML definition file."""
        root, task_xml = self._parse_task_xml(args.file)
        if root is None:
            return

        # Validate XML structure
        force = getattr(args, "force", False)
        errors, warnings = self._validate_task_xml(root)

        task_name = getattr(args, "name", None)
        folder_path = getattr(args, "folder", "") or ""
        info = self._extract_task_info(
            root, args.file, task_name=task_name, folder_path=folder_path
        )
        task_name = info["task_name"]
        folder_path = info["folder_path"]

        # --test flag: parse and display without deploying
        if getattr(args, "test", False):
            print_info(f"Task XML Analysis: {os.path.expanduser(args.file)}")
            print_log(f"  Task Name:       {task_name}")
            print_log(f"  Folder:          {folder_path or chr(92)}")
            if info["uri"]:
                print_log(f"  URI:             {info['uri']}")
            if info["author"]:
                print_log(f"  Author:          {info['author']}")
            if info["description"]:
                print_log(f"  Description:     {info['description']}")
            if info["date"]:
                print_log(f"  Date:            {info['date']}")
            print_log(f"  Command:         {info['command'] or 'N/A'}")
            if info["arguments"]:
                print_log(f"  Arguments:       {info['arguments']}")
            if info["working_dir"]:
                print_log(f"  Working Dir:     {info['working_dir']}")
            if info["user_id"]:
                print_log(f"  User ID:         {info['user_id']}")
            if info["run_level"]:
                print_log(f"  Run Level:       {info['run_level']}")
            if info["start_boundary"]:
                print_log(f"  Start Boundary:  {info['start_boundary']}")
            print_log(f"  Enabled:         {info['enabled'] or 'true'}")
            print_log(f"  Hidden:          {info['hidden'] or 'false'}")
            if info["execution_time_limit"]:
                print_log(f"  Time Limit:      {info['execution_time_limit']}")
            # Show validation results
            if errors:
                print_bad(f"Validation FAILED ({len(errors)} error(s)):")
                for err in errors:
                    print_bad(f"  - {err}")
            if warnings:
                print_warning(f"Validation warnings ({len(warnings)}):")
                for warn in warnings:
                    print_warning(f"  - {warn}")
            if not errors:
                print_good("XML is valid and ready for import")
            else:
                print_info("Use --force to import despite validation errors")
            return

        # Block import if validation fails (unless --force)
        if errors and not force:
            print_bad(f"Validation FAILED ({len(errors)} error(s)):")
            for err in errors:
                print_bad(f"  - {err}")
            if warnings:
                print_warning(f"Validation warnings ({len(warnings)}):")
                for warn in warnings:
                    print_warning(f"  - {warn}")
            print_info("Use --force to import despite validation errors")
            return
        if warnings and not force:
            for warn in warnings:
                print_warning(f"  - {warn}")
        if force and errors:
            print_warning(f"Forcing import despite {len(errors)} validation error(s)")

        print_info(f"Importing task '{task_name}' to folder '{folder_path or chr(92)}'")
        self.setup_dce_transport()
        self.dce_transport._connect("atsvc")

        try:
            response = self.dce_transport._create_task(task_name, folder_path, task_xml)
            if response["ErrorCode"] == 0:
                print_good(f"Task '{task_name}' imported successfully")
            else:
                print_bad(f"Error importing task '{task_name}': {response['ErrorCode']}")
        except Exception as e:
            error_str = str(e)
            if "SCHED_S_TASK_DISABLED" in error_str:
                print_good(f"Task '{task_name}' imported (disabled state)")
            elif "already exists" in error_str.lower():
                print_warning(f"Task '{task_name}' already exists in '{folder_path}'")
            else:
                print_bad(f"Error importing task: {e}")

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

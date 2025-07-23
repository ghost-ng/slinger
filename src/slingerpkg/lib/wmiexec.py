import time
import sys
import os
from slingerpkg.utils.common import generate_random_string
from slingerpkg.utils.printlib import *
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from slingerpkg.utils.common import set_config_value
from slingerpkg.utils.printlib import colors


class wmiexec:
    """WMI Command Execution Module - Traditional DCOM Implementation"""

    def __init__(self):
        print_debug("WMIExec Module Loaded!")

    def wmiexec_handler(self, args):
        """Main handler for wmiexec command - Routes to appropriate method"""
        print_verbose("WMI execution handler called")

        if not self.check_if_connected():
            print_warning("You must be connected to a share to use WMI execution.")
            return

        # Route to appropriate WMI method based on args.wmi_method
        wmi_method = getattr(
            args, "wmi_method", "dcom"
        )  # Default to dcom for backwards compatibility

        if wmi_method == "dcom":
            # Traditional DCOM method using this module
            return self._handle_wmiexec_dcom(args)
        elif wmi_method in ["task", "ps", "event"]:
            # Route to the WMI Named Pipe module for other methods
            if hasattr(self, "execute_wmi_command_namedpipe"):
                # Call the WMI Named Pipe execution directly
                from slingerpkg.lib.wmi_namedpipe import WMINamedPipeExec

                return WMINamedPipeExec.wmiexec_handler(self, args)
            else:
                print_bad(
                    f"WMI method '{wmi_method}' not available - WMI Named Pipe module not loaded"
                )
                return
        else:
            print_bad(f"Unknown WMI method: {wmi_method}")
            print_info("Available methods: dcom, task, ps, event")
            return

    def _handle_wmiexec_dcom(self, args):
        """Handle traditional DCOM WMI execution"""
        print_verbose("Using traditional DCOM WMI execution")

        # Check for interactive mode
        if getattr(args, "interactive", False):
            return self._handle_interactive_dcom_shell(args)

        # Validate command argument for non-interactive mode
        if not args.command:
            print_warning("Command is required unless using --interactive mode")
            print_info("Use 'wmiexec dcom --help' for usage information")
            return

        try:
            # Execute command via WMI DCOM with optimized parameters
            result = self.execute_wmi_command(
                command=args.command,
                capture_output=not args.no_output,
                timeout=args.timeout,
                output_file=args.output,
                working_dir=args.working_dir,
                sleep_time=getattr(args, "sleep_time", 1.0),
                target_share=getattr(args, "share", None),
                save_name=getattr(args, "save_name", None),
                raw_command=getattr(args, "raw_command", False),
                shell=getattr(args, "shell", "cmd"),
            )

            if result["success"]:
                print_good(f"WMI execution completed. Process ID: {result['process_id']}")
                if result.get("output"):
                    print(result["output"])
                if args.output:
                    print_good(f"Output saved to: {args.output}")
            else:
                print_bad("WMI execution failed")
                print_info(f"Error: {result.get('error')}")
                print_info("Traditional DCOM WMI may be blocked by firewall/policy")

        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"WMI execution error: {e}")

    def execute_wmi_command(
        self,
        command,
        capture_output=True,
        timeout=30,
        output_file=None,
        working_dir="C:\\",
        sleep_time=1.0,
        target_share=None,
        save_name=None,
        raw_command=False,
        shell="cmd",
    ):
        """
        Execute command via WMI using traditional DCOM approach - Optimized Version

        Args:
            command: Command to execute
            capture_output: Whether to capture and return output
            timeout: Execution timeout in seconds
            output_file: Optional file to save output to
            working_dir: Working directory for command execution
            sleep_time: Time to sleep before capturing output (seconds)
            target_share: Target share for output capture (None = current share)
            save_name: Custom filename for output capture (None = auto-generate)
            raw_command: Execute raw command without shell wrapper
            shell: Shell to use ('cmd' or 'powershell')

        Returns:
            dict with 'success', 'process_id', 'output', 'error' keys
        """
        print_verbose(f"Executing WMI command: {command}")
        print_verbose(f"Working directory: {working_dir}")

        try:
            # Extract credentials properly
            lm_hash = ""
            nt_hash = ""
            if hasattr(self, "ntlm_hash") and self.ntlm_hash:
                if ":" in self.ntlm_hash:
                    lm_hash = self.ntlm_hash.split(":")[0]
                    nt_hash = self.ntlm_hash.split(":")[1]
                else:
                    nt_hash = self.ntlm_hash

            print_debug("Creating DCOM connection for WMI")

            # Create DCOM connection exactly like Impacket's wmiexec.py
            dcom = DCOMConnection(
                self.host,
                self.username,
                getattr(self, "password", ""),
                getattr(self, "domain", ""),
                lm_hash,
                nt_hash,
                aesKey="",
                oxidResolver=True,
                doKerberos=getattr(self, "use_kerberos", False),
            )

            print_debug("DCOM connection established")

            try:
                print_debug("Connecting to WMI namespace")

                # Create WMI interface
                iInterface = dcom.CoCreateInstanceEx(
                    wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
                )
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
                iWbemLevel1Login.RemRelease()

                print_debug("WMI namespace connection successful")

                # Get Win32_Process class
                win32Process, _ = iWbemServices.GetObject("Win32_Process")

                # Determine target share for output capture
                if target_share:
                    share_name = target_share
                    print_verbose(f"Using custom share for output capture: {share_name}")
                else:
                    # For WMI output capture, always default to C$ unless explicitly specified
                    # This is because WMI output redirection via 127.0.0.1 needs a writable path
                    current_share = getattr(self, "current_share", "C$")
                    if current_share in ["IPC$", "PIPE$"]:
                        share_name = "C$"
                        print_verbose(
                            f"Current share ({current_share}) not suitable for output capture, using C$ instead"
                        )
                    else:
                        share_name = current_share
                        print_verbose(f"Using current share for output capture: {share_name}")

                # Prepare command based on shell and options
                if capture_output:
                    # Generate output filename
                    if save_name:
                        output_filename = save_name
                        print_verbose(f"Using custom save filename: {output_filename}")
                    else:
                        output_filename = f"{generate_random_string()}.txt"
                        print_verbose(f"Generated output filename: {output_filename}")

                    output_path = f"\\\\127.0.0.1\\{share_name}\\{output_filename}"

                    # Prepare command based on shell type and raw mode
                    if raw_command:
                        full_command = f"{command} 1> {output_path} 2>&1"
                        print_verbose("Using raw command execution (no shell wrapper)")
                    elif shell == "powershell":
                        full_command = f'powershell.exe -Command "{command}" > {output_path} 2>&1'
                        print_verbose("Using PowerShell execution")
                    else:  # shell == 'cmd' (default)
                        full_command = f"cmd.exe /Q /c {command} 1> {output_path} 2>&1"
                        print_verbose("Using CMD execution")
                else:
                    # No output capture
                    if raw_command:
                        full_command = command
                        print_verbose(
                            "Using raw command execution (no shell wrapper, no output capture)"
                        )
                    elif shell == "powershell":
                        full_command = f'powershell.exe -Command "{command}"'
                        print_verbose("Using PowerShell execution (no output capture)")
                    else:  # shell == 'cmd' (default)
                        full_command = f"cmd.exe /Q /c {command}"
                        print_verbose("Using CMD execution (no output capture)")
                    output_filename = None

                print_debug(f"Executing: {full_command}")
                print_debug(f"Working directory: {working_dir}")

                # Execute via WMI Win32_Process.Create
                result = win32Process.Create(full_command, working_dir, None)
                process_id = result.ProcessId
                return_value = result.ReturnValue

                print_debug(f"WMI execution result: ReturnValue={return_value}, PID={process_id}")

                if return_value == 0:
                    print_verbose(f"WMI process created with PID: {process_id}")

                    # Capture output if enabled
                    output_text = None
                    if capture_output and output_filename:
                        print_debug(f"Capturing command output after {sleep_time} second sleep")
                        time.sleep(sleep_time)

                        try:
                            # Use existing smblib methods for file operations
                            import tempfile

                            temp_local = tempfile.NamedTemporaryFile(delete=False).name

                            # If we need to access a different share for the output file, handle it
                            current_share = getattr(self, "current_share", "C$")
                            if share_name != current_share:
                                print_verbose(
                                    f"Temporarily switching to {share_name} for output capture"
                                )
                                # Save current share
                                saved_share = current_share
                                saved_tree_id = getattr(self, "tree_id", None)

                                try:
                                    # Download the output file using low-level SMB operations
                                    output_text = self._read_file_from_share(
                                        output_filename, share_name
                                    )

                                    # Clean up remote output file
                                    self._delete_file_from_share(output_filename, share_name)

                                finally:
                                    # Restore original share connection
                                    if saved_tree_id:
                                        self.tree_id = saved_tree_id
                                        self.current_share = saved_share
                            else:
                                # Same share, use normal operations
                                self.download(output_filename, temp_local, echo=False)

                                # Read the content
                                with open(temp_local, "r", encoding="utf-8", errors="ignore") as f:
                                    output_text = f.read().strip()

                                # Clean up local temp file
                                os.unlink(temp_local)

                                # Clean up remote output file using existing smblib method
                                self.delete(output_filename)

                            if not output_text:
                                output_text = f"Command executed with PID {process_id}"
                        except Exception as e:
                            print_debug(f"Output capture failed: {e}")
                            output_text = (
                                f"Command executed with PID {process_id} (output capture failed)"
                            )
                    else:
                        output_text = f"Command executed with PID {process_id}"

                    # Save to file if requested
                    if output_file and output_text:
                        self._save_output_to_file(output_text, output_file)

                    return {
                        "success": True,
                        "output": output_text,
                        "process_id": process_id,
                        "error": None,
                    }
                else:
                    error_msg = f"Win32_Process.Create failed with return code: {return_value}"
                    return {
                        "success": False,
                        "output": None,
                        "process_id": None,
                        "error": error_msg,
                    }

            finally:
                try:
                    dcom.disconnect()
                    print_debug("DCOM connection cleaned up")
                except:
                    pass

        except Exception as e:
            print_debug(f"WMI execution failed: {e}")
            return {"success": False, "output": None, "process_id": None, "error": str(e)}

    def _save_output_to_file(self, output, output_file):
        """Save output to local file"""
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print_verbose(f"Output saved to: {output_file}")
        except Exception as e:
            print_warning(f"Could not save output to file: {e}")

    def _read_file_from_share(self, filename, share_name):
        """Read file from a specific share using low-level SMB operations"""
        try:
            print_debug(f"Reading file {filename} from share {share_name}")

            # Connect to the target share
            tree_id = self.conn.connectTree(share_name)

            # Open the file
            file_handle = self.conn.openFile(
                tree_id,
                filename,
                desiredAccess=0x00000001,  # FILE_READ_DATA
                shareMode=0x00000001,  # FILE_SHARE_READ
            )

            # Read file contents
            file_content = ""
            offset = 0
            chunk_size = 4096

            while True:
                chunk = self.conn.readFile(tree_id, file_handle, offset, chunk_size)
                if not chunk:
                    break
                file_content += chunk.decode("utf-8", errors="ignore")
                offset += len(chunk)

            self.conn.closeFile(tree_id, file_handle)
            self.conn.disconnectTree(tree_id)

            return file_content.strip()

        except Exception as e:
            print_debug(f"Error reading file from share {share_name}: {e}")
            return None

    def _delete_file_from_share(self, filename, share_name):
        """Delete file from a specific share using low-level SMB operations"""
        try:
            print_debug(f"Deleting file {filename} from share {share_name}")

            # Connect to the target share
            tree_id = self.conn.connectTree(share_name)

            # Delete the file
            self.conn.deleteFile(tree_id, filename)

            self.conn.disconnectTree(tree_id)

        except Exception as e:
            print_debug(f"Error deleting file from share {share_name}: {e}")

    def _handle_interactive_dcom_shell(self, args):
        """Handle interactive DCOM WMI shell session"""
        print_info("Starting WMI DCOM interactive shell...")
        print_info("Type 'exit' to quit the WMI shell")
        print_info("Use 'cd <path>' to change directories")

        # Determine shell prompt prefix
        shell_type = getattr(args, "shell", "cmd")
        if shell_type == "powershell":
            prompt_prefix = "PS-WMI"
        else:
            prompt_prefix = "WMI"

        # Initialize current working directory
        current_working_dir = getattr(args, "working_dir", "C:\\")
        print_info(f"Starting directory: {current_working_dir}")

        print()
        session_output = []

        try:
            while True:
                try:
                    # Display prompt with current directory
                    prompt = f"{prompt_prefix} {current_working_dir}> "
                    command = input(prompt).strip()

                    if command.lower() in ["exit", "quit"]:
                        break

                    if not command:
                        continue

                    # Handle cd command locally
                    if command.lower().startswith("cd ") or command.lower() == "cd":
                        new_dir = self._handle_cd_command(command, current_working_dir)
                        if new_dir:
                            current_working_dir = new_dir
                            print_info(f"Changed directory to: {current_working_dir}")
                            session_output.append(f"{prompt}{command}")
                            session_output.append(f"Directory changed to: {current_working_dir}")
                        else:
                            print_warning("Failed to change directory")
                            session_output.append(f"{prompt}{command}")
                            session_output.append("ERROR: Failed to change directory")
                        continue

                    # Handle pwd command
                    if command.lower() == "pwd":
                        print(current_working_dir)
                        session_output.append(f"{prompt}{command}")
                        session_output.append(current_working_dir)
                        continue

                    # Execute command via DCOM WMI using current directory
                    result = self.execute_wmi_command(
                        command=command,
                        capture_output=not args.no_output,
                        timeout=args.timeout,
                        output_file=None,  # Don't save individual commands to file
                        working_dir=current_working_dir,  # Use current working directory
                        sleep_time=getattr(args, "sleep_time", 1.0),
                        target_share=getattr(args, "share", None),
                        save_name=getattr(args, "save_name", None),
                        raw_command=getattr(args, "raw_command", False),
                        shell=getattr(args, "shell", "cmd"),
                    )

                    if result["success"]:
                        if result.get("output"):
                            print(result["output"])
                            session_output.append(f"{prompt}{command}")
                            session_output.append(result["output"])
                        else:
                            print_info("Command executed (no output captured)")
                            session_output.append(f"{prompt}{command}")
                            session_output.append("Command executed (no output captured)")
                    else:
                        print_bad(f"Command failed: {result.get('error', 'Unknown error')}")
                        session_output.append(f"{prompt}{command}")
                        session_output.append(f"ERROR: {result.get('error', 'Unknown error')}")

                except KeyboardInterrupt:
                    print()
                    print_info("Use 'exit' to quit WMI DCOM shell")
                    continue
                except EOFError:
                    set_config_value("Extra_Prompt", "")
                    break

            # Save session output if requested
            if getattr(args, "output", None) and session_output:
                full_output = "\n".join(session_output)
                self._save_output_to_file(full_output, args.output)
                print_good(f"Session output saved to: {args.output}")

            print_good("WMI DCOM interactive shell session completed")
            return {
                "success": True,
                "output": "\n".join(session_output) if session_output else None,
                "session_commands": len(
                    [
                        line
                        for line in session_output
                        if f"{prompt_prefix} " in line and "> " in line
                    ]
                ),
            }

        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"Interactive shell error: {e}")
            return {"success": False, "error": str(e)}

    def _handle_cd_command(self, command, current_dir):
        """Handle cd command and return new directory path"""
        try:
            # Parse cd command
            parts = command.strip().split()

            # Handle 'cd' with no arguments (go to root or user home)
            if len(parts) == 1:
                # For Windows, 'cd' alone shows current directory
                return current_dir

            target_path = parts[1]

            # Handle special cases
            if target_path == ".":
                return current_dir
            elif target_path == "..":
                # Go up one directory
                return self._get_parent_directory(current_dir)
            elif target_path.startswith("..\\") or target_path.startswith("../"):
                # Relative path starting with ..
                parent_dir = self._get_parent_directory(current_dir)
                relative_part = target_path[3:]  # Remove ..\ or ../
                return self._resolve_path(parent_dir, relative_part)
            elif target_path[1:3] == ":\\" or target_path[1:3] == ":/":
                # Absolute path (C:\path)
                return self._normalize_path(target_path)
            elif target_path.startswith("\\"):
                # Root-relative path (\path)
                drive = current_dir.split(":")[0] + ":"
                return self._normalize_path(drive + target_path)
            else:
                # Relative path
                return self._resolve_path(current_dir, target_path)

        except Exception as e:
            print_debug(f"Error handling cd command: {e}")
            return None

    def _get_parent_directory(self, path):
        """Get parent directory of given path"""
        try:
            # Normalize path separators
            path = path.replace("/", "\\")

            # Remove trailing backslash
            if path.endswith("\\") and len(path) > 3:
                path = path[:-1]

            # Find last backslash
            last_slash = path.rfind("\\")

            if last_slash == -1:
                return path  # No parent found
            elif last_slash == 2 and path[1] == ":":
                # Root directory (C:\)
                return path[:3]
            else:
                return path[:last_slash]

        except Exception as e:
            print_debug(f"Error getting parent directory: {e}")
            return path

    def _resolve_path(self, current_dir, relative_path):
        """Resolve relative path against current directory"""
        try:
            # Normalize separators
            current_dir = current_dir.replace("/", "\\")
            relative_path = relative_path.replace("/", "\\")

            # Ensure current_dir doesn't end with backslash (unless root)
            if current_dir.endswith("\\") and len(current_dir) > 3:
                current_dir = current_dir[:-1]

            # Combine paths
            if relative_path.startswith("\\"):
                # Absolute from current drive
                drive = current_dir.split(":")[0] + ":"
                new_path = drive + relative_path
            else:
                # Relative path
                new_path = current_dir + "\\" + relative_path

            return self._normalize_path(new_path)

        except Exception as e:
            print_debug(f"Error resolving path: {e}")
            return None

    def _normalize_path(self, path):
        """Normalize Windows path"""
        try:
            # Replace forward slashes with backslashes
            path = path.replace("/", "\\")

            # Handle multiple consecutive backslashes
            while "\\\\" in path:
                path = path.replace("\\\\", "\\")

            # Handle . and .. in path
            parts = path.split("\\")
            normalized_parts = []

            for part in parts:
                if part == "." or part == "":
                    continue
                elif part == "..":
                    if normalized_parts and normalized_parts[-1] != "..":
                        normalized_parts.pop()
                    else:
                        normalized_parts.append(part)
                else:
                    normalized_parts.append(part)

            # Rebuild path
            if len(normalized_parts) == 0:
                return "C:\\"

            # Handle drive letters
            if len(normalized_parts[0]) == 2 and normalized_parts[0][1] == ":":
                result = "\\".join(normalized_parts)
                if not result.endswith("\\") and len(result) == 2:
                    result += "\\"
                return result
            else:
                return "\\".join(normalized_parts)

        except Exception as e:
            print_debug(f"Error normalizing path: {e}")
            return path

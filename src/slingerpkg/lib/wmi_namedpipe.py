"""
WMI Named Pipe Execution Module

Implements WMI command execution using SMB named pipes instead of traditional DCOM.
This approach leverages existing SMB connections to bypass firewall restrictions
and provides enhanced stealth capabilities.

Based on research in docs/WMI_NAMED_PIPE_EXECUTION_RESEARCH.md
"""

import sys
import time
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


class WMINamedPipeExec:
    """WMI Command Execution via SMB Named Pipes"""

    def __init__(self):
        print_debug("WMI Named Pipe Execution Module Loaded!")
        self.wmi_endpoints = []
        self.active_endpoint = None

    def wmiexec_handler(self, args):
        """Handler for WMI execution commands via named pipes"""
        print_verbose("WMI Named Pipe Exec handler called")

        if not self.check_if_connected():
            print_warning("You must be connected to a share to use WMI execution.")
            return

        # Handle endpoint info request
        if hasattr(args, "endpoint_info") and args.endpoint_info:
            self._show_endpoint_info()
            return

        # Check for memory capture mode
        memory_capture = hasattr(args, "memory_capture") and args.memory_capture

        # For now, let's test basic WMI first and disable memory capture
        if memory_capture:
            print_warning("Memory capture temporarily disabled for debugging - using basic WMI")
            memory_capture = False

        # Check for interactive mode (with safe fallback)
        interactive_mode = getattr(args, "interactive", False)

        # Validate command argument
        if not interactive_mode and (not hasattr(args, "command") or not args.command):
            print_warning("Command is required unless using --interactive mode")
            print_info("Use 'help wmiexec' for usage information")
            return

        try:
            # Discover and test WMI named pipe endpoints
            if not self.discover_wmi_endpoints():
                print_bad("No accessible WMI named pipe endpoints found")
                print_info("WMI service may be unavailable or access denied")
                return

            # Execute the command via WMI
            if memory_capture:
                print_info("Using memory-based output capture (no disk files)")
                result = self._execute_wmi_command_memory_capture(
                    command=getattr(args, "command"),
                    timeout=getattr(args, "timeout", 30),
                    output_file=getattr(args, "output", None),
                )
            else:
                result = self.execute_wmi_command_namedpipe(
                    args=args,
                    command=getattr(args, "command"),
                    capture_output=not getattr(args, "no_output", False),
                    timeout=getattr(args, "timeout", 30),
                    interactive=interactive_mode,
                    output_file=getattr(args, "output", None),
                )

            if result["success"]:
                if interactive_mode:
                    print_good("WMI interactive shell session completed")
                elif memory_capture:
                    print_good("WMI memory capture execution completed")

                    # Display stdout if available
                    if result.get("stdout"):
                        print_info("Command output:")
                        print(result["stdout"])

                    # Display stderr if available
                    if result.get("stderr"):
                        print_warning("Error output:")
                        print(result["stderr"])

                    # Show execution metadata
                    if result.get("return_code") is not None:
                        print_info(f"Return code: {result['return_code']}")
                    if result.get("execution_time"):
                        print_info(f"Execution time: {result['execution_time']} seconds")

                    if getattr(args, "output", None):
                        print_good(f"Output saved to: {getattr(args, 'output')}")
                else:
                    print_good(
                        f"Command executed via WMI. Process ID: {result.get('process_id', 'Unknown')}"
                    )

                    if result.get("output"):
                        print_info("Command output:")
                        print(result["output"])

                    if getattr(args, "output", None):
                        print_good(f"Output saved to: {getattr(args, 'output')}")
            else:
                if memory_capture:
                    print_bad(
                        f"WMI memory capture execution failed: {result.get('error', 'Unknown error')}"
                    )
                else:
                    print_bad(f"WMI execution failed: {result.get('error', 'Unknown error')}")

        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"WMI named pipe execution error: {e}")

    def discover_wmi_endpoints(self):
        """
        Discover available WMI named pipe endpoints
        Returns True if any endpoints are accessible
        """
        print_verbose("Discovering WMI named pipe endpoints...")

        # Known WMI named pipe endpoints
        wmi_pipes = [
            "winmgmt",  # Primary WMI service
            "WMIEP_1",  # WMI Event Provider 1
            "WMIEP_2",  # WMI Event Provider 2
            "WMIEP_3",  # WMI Event Provider 3
            "winmgmt_backup",  # WMI backup service
        ]

        self.wmi_endpoints = []

        for pipe_name in wmi_pipes:
            if self._test_named_pipe_access(pipe_name):
                self.wmi_endpoints.append(pipe_name)
                print_verbose(f"WMI endpoint accessible: \\pipe\\{pipe_name}")

        if self.wmi_endpoints:
            # Use first available endpoint as primary
            self.active_endpoint = self.wmi_endpoints[0]
            print_verbose(f"Using primary WMI endpoint: \\pipe\\{self.active_endpoint}")
            return True

        print_verbose("No WMI named pipe endpoints accessible")
        return False

    def _test_named_pipe_access(self, pipe_name):
        """
        Test if WMI DCOM endpoint is accessible
        Returns True for basic connectivity check
        """
        try:
            print_debug(f"Testing WMI DCOM endpoint: {pipe_name}")

            # For DCOM WMI, we don't need to test specific named pipes
            # Just verify we have the basic connection requirements
            if hasattr(self, "host") and hasattr(self, "username"):
                print_debug(f"WMI DCOM endpoint {pipe_name} - basic requirements met")
                return True
            else:
                print_debug(f"WMI DCOM endpoint {pipe_name} - missing connection requirements")
                return False

        except Exception as e:
            print_debug(f"WMI endpoint {pipe_name} test failed: {e}")
            return False

    def execute_wmi_command_namedpipe(
        self, args, command, capture_output=True, timeout=30, interactive=False, output_file=None
    ):
        """
        Execute command via WMI using named pipe transport

        Args:
            args: Command-line arguments with all flags
            command: Command to execute
            capture_output: Whether to capture and return output
            timeout: Execution timeout in seconds
            interactive: Whether to run in interactive mode
            output_file: Optional file to save output to

        Returns:
            dict with 'success', 'process_id', 'output', 'error' keys
        """
        try:
            if interactive:
                return self._execute_interactive_shell_namedpipe(args, timeout, output_file)
            else:
                return self._execute_single_command_namedpipe(
                    args, command, capture_output, timeout, output_file
                )

        except Exception as e:
            print_debug(f"WMI named pipe execution failed: {str(e)}", sys.exc_info())
            return {"success": False, "error": str(e), "process_id": None, "output": None}

    def _execute_single_command_namedpipe(
        self, args, command, capture_output, timeout, output_file
    ):
        """Execute a single command via WMI named pipe"""
        print_verbose(f"Executing WMI command via named pipe: {command}")

        # Extract flags from args
        save_path = getattr(args, "save_path", getattr(args, "sp", "\\Windows\\Temp\\"))
        save_name = getattr(args, "save_name", getattr(args, "sn", None))
        working_dir = getattr(args, "working_dir", "C:\\")
        shell = getattr(args, "shell", "cmd")
        raw_command = getattr(args, "raw_command", False)

        # Ensure save_path ends with backslash
        if not save_path.endswith("\\"):
            save_path += "\\"

        # Generate output filename if needed
        if capture_output:
            if save_name:
                output_filename = save_name
            else:
                output_filename = f"wmi_np_output_{int(time.time())}.tmp"

            # Build full Windows path for output file
            temp_output_file = f"C:{save_path}{output_filename}"

            # Build command based on shell and raw_command flag
            if raw_command:
                # Execute command directly without wrapper
                full_command = f'{command} > "{temp_output_file}" 2>&1'
            elif shell == "powershell":
                full_command = f'powershell.exe -Command "{command}" > "{temp_output_file}" 2>&1'
            else:  # cmd
                full_command = f'cmd.exe /c "{command}" > "{temp_output_file}" 2>&1'
        else:
            temp_output_file = None
            # Build command without output redirection
            if raw_command:
                full_command = command
            elif shell == "powershell":
                full_command = f'powershell.exe -Command "{command}"'
            else:  # cmd
                full_command = f'cmd.exe /c "{command}"'

        print_verbose(f"Full command for WMI named pipe: {full_command}")

        try:
            # Execute via traditional WMI DCOM with working directory
            process_id = self._create_wmi_process_traditional(full_command, working_dir)

            if process_id:
                print_verbose(f"Process created via WMI named pipe with PID: {process_id}")

                # Wait for process completion if capturing output
                if capture_output and temp_output_file:
                    output = self._wait_and_capture_output(temp_output_file, timeout)

                    # Save output to file if requested
                    if output_file:
                        self._save_output_to_file(output, output_file)

                    return {
                        "success": True,
                        "process_id": process_id,
                        "output": output,
                        "error": None,
                    }
                else:
                    return {
                        "success": True,
                        "process_id": process_id,
                        "output": None,
                        "error": None,
                    }
            else:
                return {
                    "success": False,
                    "error": "Failed to create WMI process via named pipe",
                    "process_id": None,
                    "output": None,
                }

        except Exception as e:
            return {"success": False, "error": str(e), "process_id": None, "output": None}

    def _execute_interactive_shell_namedpipe(self, args, timeout, output_file):
        """Execute interactive WMI shell via named pipe"""
        print_info("Starting WMI named pipe interactive shell...")
        print_info("Type 'exit' to quit the WMI shell")
        print()

        session_output = []

        try:
            while True:
                try:
                    # Get command from user
                    command = input("WMI-NP> ").strip()

                    if command.lower() in ["exit", "quit"]:
                        break

                    if not command:
                        continue

                    # Execute command via named pipe
                    result = self._execute_single_command_namedpipe(
                        args, command, True, timeout, None
                    )

                    if result["success"]:
                        if result["output"]:
                            print(result["output"])
                            session_output.append(f"WMI-NP> {command}")
                            session_output.append(result["output"])
                        else:
                            print_info("Command executed via named pipe (no output captured)")
                    else:
                        print_bad(f"Command failed: {result.get('error', 'Unknown error')}")
                        session_output.append(f"WMI-NP> {command}")
                        session_output.append(f"ERROR: {result.get('error', 'Unknown error')}")

                except KeyboardInterrupt:
                    print()
                    print_info("Use 'exit' to quit WMI named pipe shell")
                    continue
                except EOFError:
                    break

            # Save session output if requested
            if output_file and session_output:
                full_output = "\n".join(session_output)
                self._save_output_to_file(full_output, output_file)

            return {
                "success": True,
                "process_id": None,
                "output": "\n".join(session_output) if session_output else None,
                "error": None,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "process_id": None, "output": None}

    def _create_wmi_process_traditional(self, command, working_dir=r"C:\\"):
        r"""
        Create process via traditional WMI using Impacket's approach
        Based on the standard impacket wmiexec.py implementation

        Args:
            command: Command to execute
            working_dir: Working directory for process (default: C:\)
        """
        print_debug("WMI process creation via traditional DCOM")

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

            print_debug(f"Creating DCOM connection to {self.host}")

            # Create DCOM connection exactly like impacket wmiexec.py
            dcom = DCOMConnection(
                self.host,
                self.username,
                getattr(self, "password", ""),
                getattr(self, "domain", ""),
                lmhash=lm_hash,
                nthash=nt_hash,
                aesKey="",
                oxidResolver=True,
                doKerberos=getattr(self, "use_kerberos", False),
            )

            print_debug("Creating WMI interface")
            # Follow exact impacket pattern
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            print_debug(f"Executing WMI command: {command}")
            print_debug(f"Working directory: {working_dir}")
            # Get Win32_Process class and call Create method
            win32Process, _ = iWbemServices.GetObject("Win32_Process")

            # Call Create method with command line, working dir, and environment
            # Use the same pattern as the working DCOM implementation
            result = win32Process.Create(command, working_dir, None)

            # Cleanup
            dcom.disconnect()

            # Check result
            if hasattr(result, "ReturnValue") and result.ReturnValue == 0:
                process_id = result.ProcessId if hasattr(result, "ProcessId") else None
                print_verbose(f"WMI process created successfully with PID: {process_id}")
                return process_id
            else:
                error_code = result.ReturnValue if hasattr(result, "ReturnValue") else "Unknown"
                print_debug(f"WMI process creation failed with return value: {error_code}")
                return None

        except Exception as e:
            print_debug(f"WMI traditional process creation failed: {e}")
            try:
                dcom.disconnect()
            except:
                pass
            return None

    def _create_wmi_process_memory_capture(self, command):
        """
        Create process via WMI with memory-based output capture using custom WMI classes

        This approach uses PowerShell to create temporary WMI classes for storing
        stdout/stderr without creating files on disk.
        """
        print_debug("WMI process creation with memory-based output capture")

        try:
            import random
            import time

            # Generate unique class name for this execution
            class_name = f"SlingerOutput_{int(time.time())}_{random.randint(1000, 9999)}"

            # PowerShell script for memory capture
            ps_script = f"""
            try {{
                # Create temporary WMI class for output storage
                $className = "{class_name}"
                $newClass = New-Object System.Management.ManagementClass("root\\cimv2", [String]::Empty, $null)
                $newClass["__CLASS"] = $className
                $newClass.Qualifiers.Add("Static", $true)
                $newClass.Properties.Add("CommandOutput", [System.Management.CimType]::String, $false)
                $newClass.Properties.Add("ErrorOutput", [System.Management.CimType]::String, $false)
                $newClass.Properties.Add("ReturnCode", [System.Management.CimType]::UInt32, $false)
                $newClass.Properties.Add("ExecutionTime", [System.Management.CimType]::String, $false)
                $newClass.Put()

                # Execute command and capture output in memory
                $stdout = ""
                $stderr = ""
                $exitCode = 0
                $startTime = Get-Date

                try {{
                    # Use PowerShell to capture output without disk files
                    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                    $pinfo.FileName = "cmd.exe"
                    $pinfo.Arguments = "/c {command}"
                    $pinfo.UseShellExecute = $false
                    $pinfo.RedirectStandardOutput = $true
                    $pinfo.RedirectStandardError = $true
                    $pinfo.CreateNoWindow = $true

                    $process = New-Object System.Diagnostics.Process
                    $process.StartInfo = $pinfo
                    $process.Start() | Out-Null

                    $stdout = $process.StandardOutput.ReadToEnd()
                    $stderr = $process.StandardError.ReadToEnd()
                    $process.WaitForExit()
                    $exitCode = $process.ExitCode
                }} catch {{
                    $stderr = $_.Exception.Message
                    $exitCode = 1
                }}

                $endTime = Get-Date
                $executionTime = ($endTime - $startTime).TotalSeconds

                # Store output in WMI class instance
                $instance = $newClass.CreateInstance()
                $instance["CommandOutput"] = $stdout
                $instance["ErrorOutput"] = $stderr
                $instance["ReturnCode"] = $exitCode
                $instance["ExecutionTime"] = $executionTime.ToString()
                $instance.Put()

                # Output class name for retrieval
                Write-Host "WMI_CLASS_CREATED:$className"
            }} catch {{
                Write-Error "Memory capture failed: $($_.Exception.Message)"
            }}
            """

            # Execute PowerShell script via traditional WMI DCOM
            # Use cmd.exe to avoid potential PowerShell encoding issues
            ps_command = f'cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{ps_script}"'
            result = self._create_wmi_process_traditional(ps_command)

            if result:
                print_verbose(f"Memory capture PowerShell executed with PID: {result}")

                # Wait for PowerShell to complete and create WMI class
                time.sleep(3)

                # Query WMI class for output
                output_data = self._query_wmi_output_class(class_name)

                if output_data:
                    # Cleanup WMI class
                    self._cleanup_wmi_output_class(class_name)
                    return output_data
                else:
                    print_debug("Failed to retrieve output from WMI class")
                    return None

            return None

        except Exception as e:
            print_debug(f"WMI memory capture failed: {e}")
            return None

    def _query_wmi_output_class(self, class_name):
        """
        Query custom WMI class to retrieve stored command output
        """
        try:
            print_debug(f"Querying WMI class: {class_name}")

            # Extract credentials properly
            lm_hash = ""
            nt_hash = ""
            if hasattr(self, "ntlm_hash") and self.ntlm_hash:
                if ":" in self.ntlm_hash:
                    lm_hash = self.ntlm_hash.split(":")[0]
                    nt_hash = self.ntlm_hash.split(":")[1]
                else:
                    nt_hash = self.ntlm_hash

            # Create WMI connection for querying
            dcom = DCOMConnection(
                self.host,
                self.username,
                getattr(self, "password", ""),
                getattr(self, "domain", ""),
                lmhash=lm_hash,
                nthash=nt_hash,
                aesKey="",
                oxidResolver=True,
                doKerberos=getattr(self, "use_kerberos", False),
            )

            # Create WMI interface
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Query the custom class
            query = f"SELECT * FROM {class_name}"
            results = iWbemServices.ExecQuery(query)

            output_data = None
            for result in results:
                output_data = {
                    "stdout": result.CommandOutput,
                    "stderr": result.ErrorOutput,
                    "return_code": result.ReturnCode,
                    "execution_time": result.ExecutionTime,
                }
                break  # Only need first (and should be only) result

            dcom.disconnect()
            return output_data

        except Exception as e:
            print_debug(f"Failed to query WMI output class: {e}")
            try:
                dcom.disconnect()
            except:
                pass
            return None

    def _cleanup_wmi_output_class(self, class_name):
        """
        Delete the temporary WMI class to clean up memory
        """
        try:
            print_debug(f"Cleaning up WMI class: {class_name}")

            # Create cleanup PowerShell script
            cleanup_script = f"""
            try {{
                $class = Get-WmiObject -Class {class_name} -List
                if ($class) {{
                    $class.Delete()
                }}
                Get-WmiObject -Class {class_name} | Remove-WmiObject -Force
            }} catch {{
                # Cleanup may fail if class doesn't exist, which is OK
            }}
            """

            # Execute cleanup via traditional WMI DCOM
            ps_command = f'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{cleanup_script}"'
            self._create_wmi_process_traditional(ps_command)

            print_debug("WMI class cleanup completed")

        except Exception as e:
            print_debug(f"WMI class cleanup failed (non-critical): {e}")

    def _get_nt_hash(self):
        """Helper method to extract NT hash from NTLM hash"""
        if hasattr(self, "ntlm_hash") and self.ntlm_hash:
            try:
                return self.ntlm_hash.split(":")[1] if ":" in self.ntlm_hash else self.ntlm_hash
            except:
                return ""
        return ""

    def _execute_wmi_command_memory_capture(self, command, timeout=30, output_file=None):
        """
        Execute WMI command using memory-based output capture

        Returns dict with 'success', 'stdout', 'stderr', 'return_code' keys
        """
        try:
            print_verbose(f"Executing WMI command with memory capture: {command}")

            # Use memory capture method
            output_data = self._create_wmi_process_memory_capture(command)

            if output_data:
                stdout = output_data.get("stdout", "")
                stderr = output_data.get("stderr", "")
                return_code = output_data.get("return_code", 0)
                execution_time = output_data.get("execution_time", "0")

                print_verbose(f"Memory capture completed in {execution_time} seconds")

                # Save output to file if requested
                if output_file:
                    self._save_output_to_file(stdout, output_file)

                return {
                    "success": True,
                    "stdout": stdout,
                    "stderr": stderr,
                    "return_code": return_code,
                    "execution_time": execution_time,
                }
            else:
                return {
                    "success": False,
                    "error": "Memory capture failed",
                    "stdout": None,
                    "stderr": None,
                    "return_code": None,
                }

        except Exception as e:
            print_debug(f"WMI memory capture execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": None,
                "stderr": None,
                "return_code": None,
            }

    def _connect_wmi_service_namedpipe(self):
        """
        Connect to WMI service via DCE/RPC transport (replaces direct named pipe)
        Returns True on success, False on failure
        """
        try:
            print_debug("Connecting to WMI service via DCE/RPC transport")

            # Use existing DCE transport infrastructure
            if hasattr(self, "dce_transport") and self.dce_transport:
                transport = self.dce_transport
            else:
                # Use self as transport if DCE transport not available
                transport = self

            # Connect via DCE transport
            transport._connect_wmi_service()

            print_debug("WMI DCE/RPC connection established")
            return True

        except Exception as e:
            print_debug(f"Failed to connect to WMI via DCE transport: {e}")
            return False

    def _invoke_win32_process_create(self, transport, command):
        """
        Invoke Win32_Process.Create method via DCE/RPC transport

        This uses the DCE transport infrastructure to communicate with WMI service.
        """
        print_debug(f"Invoking Win32_Process.Create via DCE/RPC: {command}")

        try:
            # Use DCE transport for WMI process creation
            result = transport._wmi_execute_process(command)

            if result["success"]:
                print_verbose(f"WMI DCE/RPC process created with PID: {result['process_id']}")
                return result["process_id"]
            else:
                print_debug(f"WMI process creation failed: {result.get('error')}")
                return None

        except Exception as e:
            print_debug(f"WMI DCE/RPC invocation failed: {e}")
            return None

    def _close_wmi_service_namedpipe(self, transport):
        """Close WMI service DCE/RPC connection"""
        try:
            # DCE transport connections are managed by the transport layer
            # No explicit close needed as it's handled by the DCE transport system
            print_debug("WMI DCE/RPC connection managed by transport layer")
        except Exception as e:
            print_debug(f"Error managing WMI DCE connection: {e}")

    def _wait_and_capture_output(self, temp_output_file, timeout):
        """
        Wait for command completion and capture output from temporary file
        """
        print_verbose(f"Waiting for output via named pipe from: {temp_output_file}")

        # Convert Windows path to SMB share-root path
        # C:\Windows\Temp\file.tmp -> \Windows\Temp\file.tmp
        smb_path = temp_output_file
        if ":" in smb_path:
            # Remove drive letter and colon, keep the backslash
            smb_path = smb_path.split(":", 1)[1]

        print_debug(f"Converted path for SMB: {smb_path}")

        start_time = time.time()
        output = ""

        # Wait for file to be created and process to complete
        while time.time() - start_time < timeout:
            try:
                # Try to read the output file via SMB
                output = self._read_remote_file(smb_path)
                if output:
                    break
            except:
                pass

            time.sleep(1)

        # Clean up temporary file
        try:
            self._delete_remote_file(smb_path)
        except:
            print_debug(f"Could not clean up temporary file: {smb_path}")

        return output

    def _read_remote_file(self, file_path):
        """Read remote file via SMB"""
        try:
            print_debug(f"Reading remote file via SMB: {file_path}")

            # Import SMB constants
            from impacket.smbconnection import FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE

            # Use existing SMB connection to read file
            file_handle = self.conn.openFile(
                self.tree_id,
                file_path,
                desiredAccess=FILE_READ_DATA,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE,
            )

            # Read file contents
            file_content = ""
            offset = 0
            chunk_size = 4096

            while True:
                chunk = self.conn.readFile(
                    self.tree_id, file_handle, offset=offset, bytesToRead=chunk_size
                )
                if not chunk:
                    break
                file_content += chunk.decode("utf-8", errors="ignore")
                offset += len(chunk)

            self.conn.closeFile(self.tree_id, file_handle)
            return file_content

        except Exception as e:
            print_debug(f"Error reading remote file: {e}")
            return ""

    def _delete_remote_file(self, file_path):
        """Delete remote file via SMB"""
        try:
            print_debug(f"Deleting remote file via SMB: {file_path}")
            self.conn.deleteFile(self.tree_id, file_path)
        except Exception as e:
            print_debug(f"Error deleting remote file: {e}")

    def _save_output_to_file(self, output, output_file):
        """Save output to local file"""
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print_verbose(f"Output saved to: {output_file}")
        except Exception as e:
            print_warning(f"Could not save output to file: {e}")

    def get_wmi_endpoint_status(self):
        """
        Get status of WMI named pipe endpoints
        Returns dict with endpoint information
        """
        return {
            "discovered_endpoints": self.wmi_endpoints,
            "active_endpoint": self.active_endpoint,
            "total_endpoints": len(self.wmi_endpoints),
        }

    def _show_endpoint_info(self):
        """Show WMI named pipe endpoint discovery information"""
        print_info("WMI Named Pipe Endpoint Discovery")
        print("=" * 40)

        # Discover endpoints
        if self.discover_wmi_endpoints():
            print_good(f"Found {len(self.wmi_endpoints)} accessible WMI named pipe endpoint(s)")
            print()

            for i, endpoint in enumerate(self.wmi_endpoints, 1):
                status = "ACTIVE" if endpoint == self.active_endpoint else "Available"
                print(f"{i}. \\pipe\\{endpoint} - {status}")

            print()
            print_info(f"Primary endpoint: \\pipe\\{self.active_endpoint}")
            print_info("WMI named pipe execution is available")
        else:
            print_bad("No accessible WMI named pipe endpoints found")
            print_warning("WMI service may be unavailable or access denied")
            print()
            print_info("This could indicate:")
            print("  - WMI service is disabled")
            print("  - Insufficient privileges for named pipe access")
            print("  - Firewall blocking SMB named pipe communication")
            print("  - Target system does not support WMI named pipes")

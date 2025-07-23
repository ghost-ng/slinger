import time
import sys
import os
from slingerpkg.utils.common import generate_random_string
from slingerpkg.utils.printlib import *
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


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
                        output_filename = f"wmi_out_{generate_random_string()}.txt"
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

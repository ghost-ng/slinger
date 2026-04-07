"""
Windows EventLog module for querying event logs via RPC
Legacy Even interface only for list and query operations
"""

from datetime import datetime, timedelta
from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.rpcrt import DCERPCException
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import tee_output
from tabulate import tabulate
import json
import csv
import io
import sys
import traceback


class EventLog:
    """
    Windows EventLog RPC client using legacy Even interface
    """

    def __init__(self):
        pass

    def _connect_eventlog_fresh(self):
        """Connect to eventlog pipe fresh — same pattern as other pipes.

        Does setup_dce_transport() + _connect("eventlog") + _bind(EVEN).
        Returns True on success, False on failure with user-facing error.
        """
        try:
            self.setup_dce_transport()
            self.dce_transport._connect("eventlog")
            self.dce_transport._bind(even.MSRPC_UUID_EVEN)
            return True
        except Exception as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            if "STATUS_OBJECT_NAME_NOT_FOUND" in error_str:
                print_bad("Event Log pipe not found on target")
                print_info(
                    "Run 'eventlog status' to check pipes. "
                    "Start service with: servicestart EventLog"
                )
            else:
                print_bad(f"Cannot connect to Event Log service: {error_str}")
            return False

    def _build_atexec_args(self, command, no_output=False, parent_args=None):
        """Build atexec args namespace, inheriting user-provided atexec options from parent_args."""
        import argparse as _argparse
        from slingerpkg.utils.common import generate_random_string

        # Use user-provided values from parent_args (eventlog CLI), fall back to defaults
        tn = getattr(parent_args, "tn", None) if parent_args else None
        if not tn:
            tn = f"SlingerTask_{generate_random_string(6, 8)}"

        return _argparse.Namespace(
            command=command,
            no_output=no_output,
            tn=tn,
            ta=getattr(parent_args, "ta", "SYSTEM") if parent_args else "SYSTEM",
            td=(
                getattr(parent_args, "td", "System Maintenance")
                if parent_args
                else "System Maintenance"
            ),
            tf=getattr(parent_args, "tf", "\\Windows") if parent_args else "\\Windows",
            sp=(
                getattr(parent_args, "sp", "\\Users\\Public\\Downloads\\")
                if parent_args
                else "\\Users\\Public\\Downloads\\"
            ),
            sn=getattr(parent_args, "sn", None) if parent_args else None,
            sh=getattr(parent_args, "sh", None) or getattr(self, "share", "C$") or "C$",
            wait=getattr(parent_args, "wait", 3) if parent_args else 3,
            shell=False,
        )

    def _run_wevtutil(self, command, method, parent_args=None):
        """Run a wevtutil command via atexec or wmiexec. Returns output string or None."""
        if method == "atexec":
            if not self.check_if_connected():
                print_bad("Not connected to a share. Use 'use <sharename>' first.")
                return None
            atexec_args = self._build_atexec_args(command, parent_args=parent_args)
            self.atexec(atexec_args)
            return ""  # atexec prints output directly
        elif method == "wmiexec":
            result = self.execute_wmi_command(
                command=command,
                capture_output=True,
                timeout=60,
                working_dir=self.wmi_working_dir,
                shell="cmd",
            )
            if result.get("success") and result.get("output"):
                return result["output"]
            elif not result.get("success"):
                print_bad("WMI execution failed")
            return None
        return None

    def list_event_logs(self, args):
        """List available Windows Event Logs"""
        method = getattr(args, "method", "rpc")

        if method in ("atexec", "wmiexec"):
            print_info(f"Listing event logs via {method} (wevtutil el)...")
            output = self._run_wevtutil("wevtutil el", method, parent_args=args)
            if output is not None and output:
                print(output)
            return

        if not self._connect_eventlog_fresh():
            return
        print_info("Listing available event logs...")

        try:

            # Common Windows event logs to check
            common_logs = [
                # Core Windows Logs
                "Application",
                "System",
                "Security",
                "Setup",
                # Forwarded Logs
                "ForwardedEvents",
                # PowerShell and Scripting
                "Windows PowerShell",
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-Scripting",
                # Remote Desktop Services
                "Microsoft-Windows-TerminalServices-LocalSessionManager",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                "Microsoft-Windows-TerminalServices-SessionBroker-Client",
                "Microsoft-Windows-TerminalServices-SessionBroker-Manager",
                "Microsoft-Windows-TerminalServices-SessionBroker-RemoteDesktop",
                "Microsoft-Windows-TerminalServices-Printers",
                # Logon and Authentication
                "Microsoft-Windows-Security-Auditing",
                "Microsoft-Windows-User Profile Service",
                "Microsoft-Windows-GroupPolicy",
                "Microsoft-Windows-Kerberos",
                # Task Scheduler
                "Microsoft-Windows-TaskScheduler",
                # DNS Client and Server
                "Microsoft-Windows-DNS-Client",
                "Microsoft-Windows-DNSServer",
                "Microsoft-Windows-DNSServer",
                # Network and Firewall
                "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                "Microsoft-Windows-NetworkProfile",
                "Microsoft-Windows-NetworkProvider",
                # System Integrity & Updates
                "Microsoft-Windows-Winlogon",
                "Microsoft-Windows-CodeIntegrity",
                "Microsoft-Windows-Windows Defender",
                "Microsoft-Windows-WindowsUpdateClient",
                # Application Compatibility and Errors
                "Microsoft-Windows-Application-Experience/Program-Telemetry",
                "Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant",
                "Microsoft-Windows-Application-Experience/Program-Inventory",
                # Sysmon (if installed)
                "Microsoft-Windows-Sysmon",
            ]

            results = []
            accessible_count = 0

            for log_name in common_logs:
                try:
                    # Try to open the log
                    exists, count = self.check_event_log(log_name, echo=False)
                    if not exists:
                        results.append([log_name, "✗ Not found"])
                        continue

                    # If we got here, it's accessible
                    accessible_count += 1
                    status = f"✓ Accessible ({count} records)"

                except Exception as e:
                    error_msg = str(e)
                    if (
                        "ERROR_EVT_INVALID_CHANNEL_PATH" in error_msg
                        or "rpc_s_access_denied" in error_msg
                    ):
                        status = "✗ Not found"
                    elif "ERROR_ACCESS_DENIED" in error_msg:
                        status = "✗ Access denied"
                    else:
                        status = (
                            f"✗ {error_msg.split(':')[0] if ':' in error_msg else error_msg[:30]}"
                        )

                results.append([log_name, status])

            # Display results
            headers = ["Log Name", "Status"]
            print(tabulate(results, headers=headers, tablefmt="grid"))
            print_good(f"Found {len(results)} logs ({accessible_count} accessible)")

        except Exception as e:
            print_bad(f"Failed to list event logs: {e}")
            print_debug(f"Traceback: {traceback.format_exc()}")

    def _query_via_wevtutil(self, args, method):
        """Query event log via wevtutil qe running as SYSTEM."""
        log_name = args.log
        limit = getattr(args, "limit", 10)
        output_file = getattr(args, "output", None)

        # Build wevtutil command
        cmd = f'wevtutil qe "{log_name}" /c:{limit} /f:text /rd:true'
        event_id = getattr(args, "id", None)
        if event_id:
            cmd += f' /q:"*[System[EventID={event_id}]]"'

        print_info(f"Querying '{log_name}' via {method} (wevtutil, limit={limit})...")

        if method == "atexec":
            if not self.check_if_connected():
                print_bad("Not connected to a share. Use 'use <sharename>' first.")
                return
            atexec_args = self._build_atexec_args(cmd, parent_args=args)
            self.atexec(atexec_args)
        elif method == "wmiexec":
            result = self.execute_wmi_command(
                command=cmd,
                capture_output=True,
                timeout=60,
                working_dir=self.wmi_working_dir,
                shell="cmd",
            )
            if result.get("success") and result.get("output"):
                if output_file:
                    with tee_output(output_file):
                        print(result["output"])
                    print_good(f"Output saved to {output_file}")
                else:
                    print(result["output"])
            elif not result.get("success"):
                print_bad("WMI query execution failed")

    def query_event_log(self, args):
        """Query events from a specific Windows Event Log"""
        method = getattr(args, "method", "rpc")

        if method in ("atexec", "wmiexec"):
            self._query_via_wevtutil(args, method)
            return

        # RPC method
        if not self._connect_eventlog_fresh():
            return
        log_name = args.log
        limit = getattr(args, "limit", 10)
        verbose = getattr(args, "verbose", False)

        # Get filter arguments
        event_id = getattr(args, "id", None)
        level = getattr(args, "level", None)
        since = getattr(args, "since", None)
        source = getattr(args, "source", None)
        last_minutes = getattr(args, "last", None)
        find_string = getattr(args, "find", None)
        verbose = True if find_string else verbose

        # Build filter description
        filters = []
        if event_id:
            filters.append(f"ID={event_id}")
        if level:
            filters.append(f"Level={level}")
        if source:
            filters.append(f"Source={source}")
        if since:
            filters.append(f"Since={since}")
        if last_minutes:
            filters.append(f"Last {last_minutes} minutes")
        if find_string:
            filters.append(f"Contains '{find_string}'")

        # Note: no separate check_event_log call here — it would consume the pipe
        # connection. The query itself will fail with a clear error if the log doesn't exist.

        filter_desc = f" with filters: {', '.join(filters)}" if filters else ""
        print_info(f"Querying '{log_name}' event log for {limit} events{filter_desc}...")

        try:
            # Already connected via _connect_eventlog_fresh() above
            # Open the log
            log_handle = self.dce_transport._eventlog_open_log(log_name, use_even6=False)

            try:
                # Get log info
                total_records = self.dce_transport._eventlog_get_record_count(log_handle)
                oldest_record = self.dce_transport._eventlog_get_oldest_record(log_handle)

                if total_records == 0:
                    print_warning(f"No events in '{log_name}'")
                    return

                print_debug(f"Log has {total_records} records, oldest: {oldest_record}")

                # Read events - read more than requested to account for filtering
                all_events = []
                filtered_events = []
                bytes_to_read = 65536  # 64KB chunks
                read_flags = even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_BACKWARDS_READ
                max_read_events = (
                    limit * 10
                    if any([event_id, level, source, since, last_minutes, find_string])
                    else limit
                )

                while len(all_events) < max_read_events and len(filtered_events) < limit:
                    try:
                        resp = self.dce_transport._eventlog_read_events(
                            log_handle,
                            read_flags,
                            0,  # record offset (0 for sequential)
                            bytes_to_read,
                        )

                        if resp["NumberOfBytesRead"] == 0:
                            print_debug("No bytes read, breaking")
                            break

                        bytes_read = resp["NumberOfBytesRead"]
                        print_debug(f"Read {bytes_read} bytes")

                        # Parse events from buffer
                        buffer = resp["Buffer"]
                        if isinstance(buffer, list):
                            buffer = b"".join(buffer)

                        print_debug(f"Buffer size: {len(buffer)} bytes")

                        # Only parse up to NumberOfBytesRead
                        if bytes_read < len(buffer):
                            buffer = buffer[:bytes_read]
                            print_debug(f"Truncated buffer to {bytes_read} bytes")

                        parsed_events = self._parse_event_buffer(
                            buffer, max_read_events - len(all_events)
                        )

                        # Apply filters to newly parsed events
                        for event in parsed_events:
                            if self._filter_event(
                                event, event_id, level, source, since, last_minutes, find_string
                            ):
                                filtered_events.append(event)
                                if len(filtered_events) >= limit:
                                    break

                        all_events.extend(parsed_events)

                        if len(parsed_events) == 0:
                            # No more events to parse
                            break

                    except DCERPCException as e:
                        if "ERROR_HANDLE_EOF" in str(e):
                            # End of log
                            break
                        raise

                # Use filtered events if filters were applied, otherwise use all events
                events = (
                    filtered_events
                    if any([event_id, level, source, since, last_minutes, find_string])
                    else all_events[:limit]
                )

                # Display results
                if events:
                    display_events = events[:limit]
                    fmt = getattr(args, "format", "list")
                    output_file = getattr(args, "output", None)

                    # Format output
                    if fmt == "table":
                        formatted = self._format_events_table(display_events)
                    elif fmt == "json":
                        formatted = self._format_events_json(display_events)
                    elif fmt == "csv":
                        formatted = self._format_events_csv(display_events)
                    else:
                        # Default list format — use existing display
                        if output_file:
                            with tee_output(output_file):
                                self._display_events(display_events, verbose)
                        else:
                            self._display_events(display_events, verbose)
                        print_good(f"Retrieved {len(display_events)} events from '{log_name}'")
                        if output_file:
                            print_good(f"Output saved to {output_file}")
                        return

                    # Print formatted output (table/json/csv)
                    if output_file:
                        with tee_output(output_file):
                            print(formatted)
                        print_good(f"Output saved to {output_file}")
                    else:
                        print(formatted)
                    print_good(f"Retrieved {len(display_events)} events from '{log_name}'")
                else:
                    print_warning(f"No events found in '{log_name}'")

            finally:
                # Close the log handle
                self.dce_transport._eventlog_close_log(log_handle, use_even6=False)

        except DCERPCException as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            if "ACCESS_DENIED" in error_str or "access_denied" in error_str:
                print_bad(f"Access denied to '{log_name}'")
                print_info(
                    "Try --method atexec or --method wmiexec, " "or use a domain admin account"
                )
            elif "END_OF_FILE" in error_str:
                pass  # Normal — just means we read all available events
            elif "PIPE_CLOSING" in error_str or "PIPE_BROKEN" in error_str:
                print_bad(f"RPC pipe closed while querying '{log_name}'")
                print_info("Try --method atexec or --method wmiexec instead")
            else:
                print_bad(f"RPC error querying '{log_name}': {error_str}")
        except Exception as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            print_bad(f"Error querying '{log_name}': {error_str}")
            print_debug(f"Traceback: {traceback.format_exc()}")

    def _parse_event_buffer(self, buffer, max_events):
        """Parse EVENTLOGRECORD structures from buffer"""
        events = []
        offset = 0

        # The buffer might contain only valid data up to NumberOfBytesRead
        # Let's check the actual size we should process
        print_debug(f"Parsing buffer of {len(buffer)} bytes for up to {max_events} events")

        while offset < len(buffer) and len(events) < max_events:
            # Check if we have enough data for a record header (at least Length field)
            if len(buffer[offset:]) < 4:
                print_debug(
                    f"Not enough data at offset {offset}, only {len(buffer[offset:])} bytes left"
                )
                break

            # Read the length field
            import struct

            try:
                length = struct.unpack("<I", buffer[offset : offset + 4])[0]
            except:
                print_debug(f"Failed to read length at offset {offset}")
                break

            if offset == 0:
                print_debug(f"First record length: {length}")
                print_debug(f"First 64 bytes (hex): {buffer[:64].hex()}")

            # Validate length
            if length < 48 or length > 0x10000:  # Min size and sanity check
                print_debug(f"Invalid record length {length} at offset {offset}")
                break

            if offset + length > len(buffer):
                print_debug(
                    f"Record extends beyond buffer: offset={offset}, length={length}, buffer_size={len(buffer)}"
                )
                break

            try:
                # Parse EVENTLOGRECORD structure manually
                # Extract exactly the record length
                record_data = buffer[offset : offset + length]
                if len(record_data) < length:
                    print_debug(
                        f"Not enough data for record: need {length}, have {len(record_data)}"
                    )
                    break

                # Use manual parsing instead of Impacket's broken EVENTLOGRECORD
                record = self._manual_parse_eventlogrecord(record_data)

                # Convert to our event format
                event = self._parse_eventlog_record(record)
                if event:
                    events.append(event)
                    print_debug(
                        f"Successfully parsed event {len(events)}: ID={event['EventID']}, Source={event['SourceName']}"
                    )

                # Move to next record
                offset += record["Length"]

            except Exception as e:
                print_debug(f"Error parsing record at offset {offset}: {e}")
                if offset == 0:
                    print_debug(f"First record parse error details: {traceback.format_exc()}")
                # Skip this record and try the next
                offset += length

        print_debug(f"Parsed {len(events)} events from buffer")
        return events

    def _manual_parse_eventlogrecord(self, data):
        """Manually parse EVENTLOGRECORD structure to avoid Impacket's broken parser"""
        import struct

        if len(data) < 48:  # Minimum size check
            raise ValueError("Data too small for EVENTLOGRECORD")

        record = {}
        offset = 0

        # Fixed header fields (48 bytes)
        record["Length"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["Reserved"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["RecordNumber"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["TimeGenerated"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["TimeWritten"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["EventID"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["EventType"] = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        record["NumStrings"] = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        record["EventCategory"] = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        record["ReservedFlags"] = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        record["ClosingRecordNumber"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["StringOffset"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["UserSidLength"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["UserSidOffset"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["DataLength"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        record["DataOffset"] = struct.unpack("<L", data[offset : offset + 4])[0]
        offset += 4

        # Now we're at offset 56 - parse variable fields

        # SourceName (null-terminated string - can be ASCII or UTF-16 LE)
        # First check if it looks like UTF-16 LE (every other byte is 0x00 for ASCII chars)
        is_wide = False
        if offset + 2 < len(data) and data[offset + 1] == 0:
            # Likely UTF-16 LE
            is_wide = True
            source_end = offset
            while source_end + 1 < len(data):
                if data[source_end] == 0 and data[source_end + 1] == 0:
                    break
                source_end += 2
            if source_end + 1 < len(data):
                record["SourceName"] = data[offset:source_end]
                offset = source_end + 2  # Skip double null
            else:
                raise ValueError("SourceName not null-terminated")
        else:
            # ASCII string
            source_end = data.find(b"\x00", offset)
            if source_end == -1:
                raise ValueError("SourceName not null-terminated")
            record["SourceName"] = data[offset:source_end]
            offset = source_end + 1

        # Computername (null-terminated string - can be ASCII or UTF-16 LE)
        is_wide = False
        if offset + 2 < len(data) and data[offset + 1] == 0:
            # Likely UTF-16 LE
            is_wide = True
            computer_end = offset
            while computer_end + 1 < len(data):
                if data[computer_end] == 0 and data[computer_end + 1] == 0:
                    break
                computer_end += 2
            if computer_end + 1 < len(data):
                record["Computername"] = data[offset:computer_end]
                offset = computer_end + 2  # Skip double null
            else:
                raise ValueError("Computername not null-terminated")
        else:
            # ASCII string
            computer_end = data.find(b"\x00", offset)
            if computer_end == -1:
                raise ValueError("Computername not null-terminated")
            record["Computername"] = data[offset:computer_end]
            offset = computer_end + 1

        # UserSid (if present)
        if record["UserSidLength"] > 0 and record["UserSidOffset"] < len(data):
            record["UserSid"] = data[
                record["UserSidOffset"] : record["UserSidOffset"] + record["UserSidLength"]
            ]
        else:
            record["UserSid"] = None

        # Strings (if present)
        if (
            record["NumStrings"] > 0
            and record["StringOffset"] > 0
            and record["StringOffset"] < len(data)
        ):
            # Calculate where strings end
            if record["DataOffset"] > 0:
                strings_end = record["DataOffset"]
            else:
                # Strings end before Length2 (last 4 bytes)
                strings_end = record["Length"] - 4

            if strings_end > record["StringOffset"] and strings_end <= len(data):
                strings_data = data[record["StringOffset"] : strings_end]
                record["Strings"] = strings_data
            else:
                record["Strings"] = b""
        else:
            record["Strings"] = b""

        # Data (if present)
        if (
            record["DataLength"] > 0
            and record["DataOffset"] > 0
            and record["DataOffset"] < len(data)
        ):
            record["Data"] = data[
                record["DataOffset"] : record["DataOffset"] + record["DataLength"]
            ]
        else:
            record["Data"] = None

        # Length2 (last 4 bytes)
        if len(data) >= 4:
            record["Length2"] = struct.unpack("<L", data[-4:])[0]
        else:
            record["Length2"] = 0

        # Validate structure
        if record["Length"] != record["Length2"]:
            print_debug(f"Length mismatch - Length={record['Length']}, Length2={record['Length2']}")

        # Create a dict-like object that supports both dict access and attribute access
        class RecordDict(dict):
            def __getitem__(self, key):
                return self.get(key)

            def __getattr__(self, key):
                return self.get(key)

        return RecordDict(record)

    def _parse_eventlog_record(self, record):
        """Parse EVENTLOGRECORD structure into our event format"""
        try:
            # Map event types
            event_type_map = {
                even.EVENTLOG_ERROR_TYPE: "Error",
                even.EVENTLOG_WARNING_TYPE: "Warning",
                even.EVENTLOG_INFORMATION_TYPE: "Information",
                even.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
                even.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
            }

            # Convert timestamp
            time_generated = datetime.fromtimestamp(record["TimeGenerated"])

            # Source name and computer name need proper decoding
            # They can be either ASCII or UTF-16 LE
            source_name_bytes = record["SourceName"]
            if isinstance(source_name_bytes, bytes):
                # Check if it's UTF-16 LE (has null bytes between chars)
                if len(source_name_bytes) >= 2 and source_name_bytes[1:2] == b"\x00":
                    source_name = source_name_bytes.decode("utf-16-le", errors="ignore").rstrip(
                        "\x00"
                    )
                else:
                    source_name = source_name_bytes.decode("ascii", errors="ignore").rstrip("\x00")
            else:
                source_name = str(source_name_bytes)

            computer_name_bytes = record["Computername"]
            if isinstance(computer_name_bytes, bytes):
                # Check if it's UTF-16 LE
                if len(computer_name_bytes) >= 2 and computer_name_bytes[1:2] == b"\x00":
                    computer_name = computer_name_bytes.decode("utf-16-le", errors="ignore").rstrip(
                        "\x00"
                    )
                else:
                    computer_name = computer_name_bytes.decode("ascii", errors="ignore").rstrip(
                        "\x00"
                    )
            else:
                computer_name = str(computer_name_bytes)

            # Create event dictionary
            event = {
                "RecordNumber": record["RecordNumber"],
                "EventID": record["EventID"] & 0xFFFF,  # Lower 16 bits
                "SourceName": source_name,
                "ComputerName": computer_name,
                "TimeGeneratedStr": time_generated.strftime("%Y-%m-%d %H:%M:%S"),
                "EventTypeStr": event_type_map.get(
                    record["EventType"], f'Type {record["EventType"]}'
                ),
                "Strings": [],
            }

            # Try to extract strings if present
            if record["NumStrings"] > 0 and record["StringOffset"] > 0:
                try:
                    # Strings field contains the string data
                    strings_data = record["Strings"]
                    if isinstance(strings_data, bytes) and len(strings_data) > 0:
                        strings = []

                        # Check if strings are UTF-16 LE or ASCII
                        if len(strings_data) >= 2 and strings_data[1:2] == b"\x00":
                            # UTF-16 LE strings
                            offset = 0
                            for i in range(record["NumStrings"]):
                                if offset >= len(strings_data):
                                    break

                                # Find double-null terminator for UTF-16 LE
                                end = offset
                                while end + 1 < len(strings_data):
                                    if strings_data[end] == 0 and strings_data[end + 1] == 0:
                                        break
                                    end += 2

                                if end > offset:
                                    string_bytes = strings_data[offset:end]
                                    try:
                                        string_value = string_bytes.decode(
                                            "utf-16-le", errors="ignore"
                                        )
                                        if string_value:
                                            strings.append(string_value)
                                    except:
                                        pass

                                offset = end + 2  # Skip double null
                        else:
                            # ASCII strings
                            parts = strings_data.split(b"\x00")
                            for part in parts[: record["NumStrings"]]:
                                if part:
                                    try:
                                        string_value = part.decode("ascii", errors="ignore")
                                        if string_value:
                                            strings.append(string_value)
                                    except:
                                        pass

                        event["Strings"] = strings
                except Exception as e:
                    print_debug(f"Error extracting strings: {e}")

            return event

        except Exception as e:
            print_debug(f"Error parsing EVENTLOGRECORD: {e}")
            return None

    def _filter_event(
        self,
        event,
        event_id=None,
        level=None,
        source=None,
        since=None,
        last_minutes=None,
        find_string=None,
    ):
        """Apply filters to an event"""
        # Filter by Event ID
        if event_id is not None and event["EventID"] != event_id:
            return False

        # Filter by level/type
        if level is not None:
            level_map = {
                "error": "Error",
                "warning": "Warning",
                "information": "Information",
                "success": "Audit Success",
                "failure": "Audit Failure",
            }
            expected_type = level_map.get(level.lower())
            if expected_type and event.get("EventTypeStr") != expected_type:
                return False

        # Filter by source
        if source is not None:
            if source.lower() not in event.get("SourceName", "").lower():
                return False

        # Filter by date/time
        if since is not None or last_minutes is not None:
            try:
                event_time = datetime.strptime(
                    event.get("TimeGeneratedStr", ""), "%Y-%m-%d %H:%M:%S"
                )

                if last_minutes is not None:
                    # Calculate cutoff time
                    cutoff_time = datetime.now() - timedelta(minutes=last_minutes)
                    if event_time < cutoff_time:
                        return False

                if since is not None:
                    # Parse since date
                    if " " in since:
                        since_time = datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
                    else:
                        since_time = datetime.strptime(since, "%Y-%m-%d")
                    if event_time < since_time:
                        return False
            except:
                # If date parsing fails, skip this filter
                pass

        # Filter by content string
        if find_string is not None:
            find_lower = find_string.lower()
            # Search in source name
            if find_lower in event.get("SourceName", "").lower():
                return True
            # Search in computer name
            if find_lower in event.get("ComputerName", "").lower():
                return True
            # Search in event strings
            for string in event.get("Strings", []):
                if find_lower in string.lower():
                    return True
            # If find_string specified but not found, exclude event
            return False

        return True

    def _format_events_table(self, events):
        """Format events as a tabulate grid table."""
        table = []
        for e in events:
            table.append(
                [
                    e.get("RecordNumber", ""),
                    e.get("EventID", ""),
                    e.get("EventTypeStr", ""),
                    e.get("SourceName", ""),
                    e.get("TimeGeneratedStr", ""),
                    (e.get("Strings", [""])[0] or "")[:80] if e.get("Strings") else "",
                ]
            )
        headers = ["Record", "ID", "Type", "Source", "Time", "Message"]
        return tabulate(table, headers=headers, tablefmt="grid")

    def _format_events_json(self, events):
        """Format events as JSON array."""
        clean = []
        for e in events:
            clean.append(
                {
                    "record_number": e.get("RecordNumber"),
                    "event_id": e.get("EventID"),
                    "type": e.get("EventTypeStr"),
                    "source": e.get("SourceName"),
                    "computer": e.get("ComputerName"),
                    "time": e.get("TimeGeneratedStr"),
                    "strings": e.get("Strings", []),
                }
            )
        return json.dumps(clean, indent=2)

    def _format_events_csv(self, events):
        """Format events as CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["RecordNumber", "EventID", "Type", "Source", "Computer", "Time", "Message"]
        )
        for e in events:
            msg = "; ".join(e.get("Strings", [])) if e.get("Strings") else ""
            writer.writerow(
                [
                    e.get("RecordNumber", ""),
                    e.get("EventID", ""),
                    e.get("EventTypeStr", ""),
                    e.get("SourceName", ""),
                    e.get("ComputerName", ""),
                    e.get("TimeGeneratedStr", ""),
                    msg,
                ]
            )
        return output.getvalue()

    def _display_events(self, events, verbose=False):
        """Display events in readable format"""
        for i, event in enumerate(events, 1):
            print(f"\n{'=' * 60}")
            print(f"Event #{i}")
            print(f"{'=' * 60}")
            print(f"Record Number: {event.get('RecordNumber', 'N/A')}")
            print(f"Event ID: {event.get('EventID', 'N/A')}")
            print(f"Source: {event.get('SourceName', 'N/A')}")
            print(f"Computer: {event.get('ComputerName', 'N/A')}")
            print(f"Time: {event.get('TimeGeneratedStr', 'N/A')}")
            print(f"Type: {event.get('EventTypeStr', 'N/A')}")

            if event.get("Strings"):
                # Always show first string as message summary
                strings = event["Strings"]
                msg = strings[0] if strings[0] else ""
                if msg:
                    print(f"Message: {msg[:200]}")
                # Show all strings in verbose mode
                if verbose and len(strings) > 1:
                    print("Event Data:")
                    for j, string in enumerate(strings):
                        print(f"  [{j}] {string}")

    def _clear_via_rpc(self, log_name):
        """Clear event log via RPC \\pipe\\eventlog.

        WARNING: On some Windows versions, hElfrClearELFW crashes the
        EventLog service. Prefer --method atexec or --method wmiexec.
        """
        print_warning("RPC clear may crash the EventLog service on some Windows versions")
        if not self._connect_eventlog_fresh():
            raise Exception("Event Log pipe not available")
        self.dce_transport._clear_event_log(log_name)

    def _clear_via_atexec(self, log_name, parent_args=None):
        """Clear event log via wevtutil cl running as SYSTEM through Task Scheduler."""
        if not self.check_if_connected():
            print_bad("Not connected to a share. Use 'use <sharename>' first.")
            return False
        atexec_args = self._build_atexec_args(
            f'wevtutil cl "{log_name}"', no_output=True, parent_args=parent_args
        )
        self.atexec(atexec_args)
        return True

    def _clear_via_wmiexec(self, log_name):
        """Clear event log via wevtutil cl using WMI DCOM execution."""
        import argparse

        wmi_args = argparse.Namespace(
            command=f'wevtutil cl "{log_name}"',
            no_output=True,
            timeout=30,
            output=None,
            save_name=None,
            save_path=None,
            raw_command=False,
            shell="cmd",
            sleep_time=1.0,
        )
        result = self.execute_wmi_command(
            command=wmi_args.command,
            capture_output=False,
            timeout=wmi_args.timeout,
            working_dir=self.wmi_working_dir,
            raw_command=False,
            shell="cmd",
        )
        return result.get("success", False)

    def clear_event_log(self, args):
        """Clear a Windows Event Log."""
        log_name = args.log
        force = getattr(args, "force", False)
        method = args.method

        # Confirm
        if not force:
            try:
                ans = input(f"Clear event log '{log_name}'? This cannot be undone. [y/N]: ")
                if ans.lower() != "y":
                    print_info("Cancelled")
                    return
            except (EOFError, KeyboardInterrupt):
                print_info("Cancelled")
                return

        print_info(f"Clearing event log '{log_name}' via {method}...")

        try:
            if method == "rpc":
                self._clear_via_rpc(log_name)
            elif method == "atexec":
                if not self._clear_via_atexec(log_name, parent_args=args):
                    return
            elif method == "wmiexec":
                if not self._clear_via_wmiexec(log_name):
                    print_bad(f"WMI DCOM execution failed for '{log_name}'")
                    print_info("Check DCOM connectivity (ports 135 + dynamic range)")
                    return
            print_good(f"Event log '{log_name}' cleared via {method}")
            self._track("EXEC", "eventlog_clear", log_name, f"method={method}")
        except TypeError:
            # impacket bytes-in-__str__ on Python 3.14 — likely succeeded
            print_good(f"Event log '{log_name}' cleared via {method}")
            self._track("EXEC", "eventlog_clear", log_name, f"method={method}")
        except Exception as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            print_bad(f"Failed to clear '{log_name}': {error_str}")
            if method == "rpc":
                if "access_denied" in error_str.lower():
                    print_info(
                        "RPC requires elevated privileges. Try --method atexec or --method wmiexec"
                    )
                elif "PIPE_CLOSING" in error_str or "PIPE_BROKEN" in error_str:
                    print_info(
                        "RPC clear crashed the EventLog service. "
                        "Use --method atexec or --method wmiexec instead. "
                        "Restart service with: servicestart EventLog"
                    )

    def check_event_log(self, log_name, echo=True, method="rpc", parent_args=None):
        """Check if a specific Windows Event Log exists and is accessible"""
        if method in ("atexec", "wmiexec"):
            cmd = f'wevtutil gli "{log_name}"'
            print_debug(f"Checking event log '{log_name}' via {method}")
            output = self._run_wevtutil(cmd, method, parent_args=parent_args)
            if output is not None:
                if echo and output:
                    print(output)
                return True, 0
            return False, 0

        if not self._connect_eventlog_fresh():
            return False, 0
        print_debug(f"Checking if event log '{log_name}' exists...")
        log_exist, count = self.dce_transport._does_eventlog_exist(log_name, use_even6=False)
        if log_exist == "access_denied":
            if echo:
                print_bad(f"Access denied to event log '{log_name}'")
                print_info(
                    "Try --method atexec or --method wmiexec, " "or use a domain admin account"
                )
            return False, 0
        elif log_exist:
            if echo:
                print_good(f"Event log '{log_name}' exists and is accessible ({count} records).")
            return True, count
        else:
            if echo:
                print_bad(f"Event log '{log_name}' does not exist.")
            return False, 0

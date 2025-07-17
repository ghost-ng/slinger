"""
Windows EventLog module for querying event logs via RPC
Legacy Even interface only for list and query operations
"""

from datetime import datetime, timedelta
from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.rpcrt import DCERPCException
from slingerpkg.utils.printlib import *
from tabulate import tabulate
import traceback


class EventLog:
    """
    Windows EventLog RPC client using legacy Even interface
    """

    def __init__(self):
        pass

    def list_event_logs(self, args):
        """List available Windows Event Logs"""
        print_info("Listing available event logs...")

        try:
            # Setup transport and connect to eventlog
            self.setup_dce_transport()
            self.dce_transport._connect_eventlog(use_even6=False)

            # Common Windows event logs to check
            common_logs = [
                "Application",
                "System",
                "Security",
                "Setup",
                "ForwardedEvents",
                "Windows PowerShell",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-PowerShell/Operational",
            ]

            results = []
            accessible_count = 0

            for log_name in common_logs:
                try:
                    # Try to open the log
                    log_handle = self.dce_transport._eventlog_open_log(log_name, use_even6=False)

                    # Get record count
                    record_count = self.dce_transport._eventlog_get_record_count(log_handle)

                    # If we got here, it's accessible
                    accessible_count += 1
                    status = f"✓ Accessible ({record_count} records)"

                    # Close the handle
                    self.dce_transport._eventlog_close_log(log_handle, use_even6=False)

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

    def query_event_log(self, args):
        """Query events from a specific Windows Event Log"""
        log_name = args.log
        count = getattr(args, "count", 10)
        verbose = getattr(args, "verbose", False)

        # Get filter arguments
        event_id = getattr(args, "id", None)
        level = getattr(args, "level", None)
        since = getattr(args, "since", None)
        source = getattr(args, "source", None)
        last_minutes = getattr(args, "last", None)
        find_string = getattr(args, "find", None)

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

        filter_desc = f" with filters: {', '.join(filters)}" if filters else ""
        print_info(f"Querying '{log_name}' event log for {count} events{filter_desc}...")

        try:
            # Setup transport and connect
            self.setup_dce_transport()
            self.dce_transport._connect_eventlog(use_even6=False)

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
                    count * 10
                    if any([event_id, level, source, since, last_minutes, find_string])
                    else count
                )

                while len(all_events) < max_read_events and len(filtered_events) < count:
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
                                if len(filtered_events) >= count:
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
                    else all_events[:count]
                )

                # Display results
                if events:
                    self._display_events(events[:count], verbose)
                    print_good(f"Retrieved {len(events[:count])} events from '{log_name}'")
                else:
                    print_warning(f"No events found in '{log_name}'")

            finally:
                # Close the log handle
                self.dce_transport._eventlog_close_log(log_handle, use_even6=False)

        except DCERPCException as e:
            if "ERROR_ACCESS_DENIED" in str(e) or "rpc_s_access_denied" in str(e):
                print_bad(f"Access denied to '{log_name}' - insufficient privileges")
            else:
                print_bad(f"RPC error querying '{log_name}': {e}")
        except Exception as e:
            print_bad(f"Error querying '{log_name}': {e}")
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

    def _display_events(self, events, verbose=False):
        """Display events in readable format"""
        for i, event in enumerate(events, 1):
            print(f"\n{'='*60}")
            print(f"Event #{i}")
            print(f"{'='*60}")
            print(f"Record Number: {event.get('RecordNumber', 'N/A')}")
            print(f"Event ID: {event.get('EventID', 'N/A')}")
            print(f"Source: {event.get('SourceName', 'N/A')}")
            print(f"Computer: {event.get('ComputerName', 'N/A')}")
            print(f"Time: {event.get('TimeGeneratedStr', 'N/A')}")
            print(f"Type: {event.get('EventTypeStr', 'N/A')}")

            if event.get("Strings") and verbose:
                print(f"Event Data:")
                for j, string in enumerate(event["Strings"]):
                    print(f"  [{j}] {string}")

    def list_event_sources(self, args):
        """List unique event sources from a specific Windows Event Log"""
        log_name = args.log
        scan_count = getattr(args, "count", 1000)

        print_info(
            f"Scanning '{log_name}' event log for unique sources (up to {scan_count} events)..."
        )

        try:
            # Setup transport and connect
            self.setup_dce_transport()
            self.dce_transport._connect_eventlog(use_even6=False)

            # Open the log
            log_handle = self.dce_transport._eventlog_open_log(log_name, use_even6=False)

            try:
                # Get log info
                total_records = self.dce_transport._eventlog_get_record_count(log_handle)

                if total_records == 0:
                    print_warning(f"No events in '{log_name}'")
                    return

                print_debug(f"Log has {total_records} records")

                # Read events and collect sources
                sources = {}  # source_name -> count
                events_read = 0
                bytes_to_read = 65536  # 64KB chunks
                read_flags = even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_BACKWARDS_READ

                while events_read < scan_count:
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

                        # Parse events from buffer
                        buffer = resp["Buffer"]
                        if isinstance(buffer, list):
                            buffer = b"".join(buffer)

                        # Parse events
                        parsed_events = self._parse_event_buffer(buffer, scan_count - events_read)

                        # Collect sources
                        for event in parsed_events:
                            source = event.get("SourceName", "Unknown")
                            sources[source] = sources.get(source, 0) + 1
                            events_read += 1

                        if len(parsed_events) == 0:
                            break

                    except DCERPCException as e:
                        if "ERROR_HANDLE_EOF" in str(e):
                            break
                        raise

                # Display results
                if sources:
                    print_good(f"Found {len(sources)} unique sources in {events_read} events:")

                    # Sort by count (descending) then by name
                    sorted_sources = sorted(sources.items(), key=lambda x: (-x[1], x[0]))

                    # Display as table
                    headers = ["Source Name", "Event Count", "Percentage"]
                    table_data = []

                    for source, count in sorted_sources:
                        percentage = (count / events_read * 100) if events_read > 0 else 0
                        table_data.append([source, count, f"{percentage:.1f}%"])

                    print(tabulate(table_data, headers=headers, tablefmt="grid"))
                else:
                    print_warning(f"No event sources found in '{log_name}'")

            finally:
                # Close the log handle
                self.dce_transport._eventlog_close_log(log_handle, use_even6=False)

        except DCERPCException as e:
            if "ERROR_ACCESS_DENIED" in str(e) or "rpc_s_access_denied" in str(e):
                print_bad(f"Access denied to '{log_name}' - insufficient privileges")
            else:
                print_bad(f"RPC error accessing '{log_name}': {e}")
        except Exception as e:
            print_bad(f"Error scanning '{log_name}': {e}")
            print_debug(f"Traceback: {traceback.format_exc()}")


    def check_event_log(self, args):
        """Check if a specific Windows Event Log exists and is accessible"""
        log_name = args.log

        print_info(f"Checking if event log '{log_name}' exists...")

        try:
            # Setup transport and connect to eventlog
            self.setup_dce_transport()
            self.dce_transport._connect_eventlog(use_even6=False)

            # Try to open the log first - this should fail for truly invalid log names
            print_debug(f"Attempting to open log '{log_name}' for validation...")
            
            try:
                # Try to open the log - if it fails with specific errors, the log doesn't exist
                log_handle = self.dce_transport._eventlog_open_log(log_name, use_even6=False)
                
                try:
                    # Get record count using the handle
                    count_resp = even.hElfrNumberOfRecords(self.dce_transport.dce, log_handle)
                    print_debug(f"Raw count response: {repr(count_resp)}, type: {type(count_resp)}")
                    
                    # Extract the actual count from the response
                    if isinstance(count_resp, dict) and "NumberOfRecords" in count_resp:
                        count = count_resp["NumberOfRecords"]
                    elif hasattr(count_resp, 'NumberOfRecords'):
                        count = count_resp.NumberOfRecords
                    else:
                        count = count_resp
                    
                    # Convert bytes to int if necessary
                    if isinstance(count, bytes):
                        count = int.from_bytes(count, byteorder='little')
                    elif isinstance(count, str):
                        count = int(count)
                        
                    print_debug(f"Extracted count: {count}, type: {type(count)}")
                    print_good(f"Event log '{log_name}' exists and is accessible!")
                    print_info(f"  Total records: {count}")
                    
                    # Try to get additional info
                    if count > 0:
                        try:
                            oldest_record = self.dce_transport._eventlog_get_oldest_record(log_handle)
                            print_info(f"  Oldest record number: {oldest_record}")

                            # Try to get a sample event to show sources
                            print_debug("Attempting to read a sample event...")
                            try:
                                # Read just one event to get source info
                                resp = self.dce_transport._eventlog_read_events(
                                    log_handle,
                                    even.EVENTLOG_SEQUENTIAL_READ | even.EVENTLOG_BACKWARDS_READ,
                                    0,
                                    4096,  # Small buffer for one event
                                )

                                if resp["NumberOfBytesRead"] > 0:
                                    buffer = resp["Buffer"]
                                    if isinstance(buffer, list):
                                        buffer = b"".join(buffer)

                                    events = self._parse_event_buffer(buffer, 1)
                                    if events:
                                        print_info(
                                            f"  Sample event source: {events[0].get('SourceName', 'Unknown')}"
                                        )
                                        print_info(
                                            f"  Sample event type: {events[0].get('EventTypeStr', 'Unknown')}"
                                        )

                            except Exception as e:
                                print_debug(f"Could not read sample event: {e}")
                                
                        except Exception as e:
                            print_debug(f"Could not get additional info: {e}")
                    
                    else:
                        print_info("  Log is empty (0 records)")
                        
                finally:
                    # Always close the handle
                    try:
                        self.dce_transport._eventlog_close_log(log_handle, use_even6=False)
                    except:
                        pass
                    
            except DCERPCException as e:
                error_msg = str(e)
                if '0x5' in error_msg or 'STATUS_ACCESS_DENIED' in error_msg or "ERROR_ACCESS_DENIED" in error_msg or "rpc_s_access_denied" in error_msg:
                    print_bad(f"Access denied to event log '{log_name}'")
                    print_info("This log exists but requires elevated privileges to access")
                elif '0xc0000022' in error_msg or 'STATUS_INVALID_NAME' in error_msg or "ERROR_EVT_INVALID_CHANNEL_PATH" in error_msg:
                    print_bad(f"Event log '{log_name}' does NOT exist on this system")
                    print_info("Note: Log names are case-sensitive. Use 'eventlog list' to see available logs")
                else:
                    print_bad(f"Error checking event log '{log_name}': {e}")
                    print_debug(f"Full error: {error_msg}")

        except Exception as e:
            print_bad(f"Error checking event log '{log_name}': {e}")
            print_debug(f"Traceback: {traceback.format_exc()}")

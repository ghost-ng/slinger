"""
Windows Event Log RPC Interface
Direct named pipe communication with Event Log service
"""

from slingerpkg.utils.printlib import *
import sys
import struct
from datetime import datetime, timedelta
from impacket.dcerpc.v5 import transport, even
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import smbconnection


class EventLogRPC:
    """
    Direct RPC communication with Windows Event Log service via named pipes
    Provides independent operation without requiring SMB share connections
    """

    def __init__(self, host, username, password, domain="", ntlm_hash=None, smb_connection=None):
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.ntlm_hash = ntlm_hash
        self.smb_connection = smb_connection
        self.dce = None
        self.rpctransport = None

    def connect(self):
        """Connect to EventLog service via named pipe"""
        try:
            print_debug("Connecting to EventLog service via named pipe...")

            # Create RPC transport for eventlog named pipe
            self.rpctransport = transport.SMBTransport(
                self.host, filename=r"\eventlog", smb_connection=self.smb_connection
            )

            # Set authentication
            if self.ntlm_hash:
                lmhash, nthash = (
                    self.ntlm_hash.split(":") if ":" in self.ntlm_hash else ("", self.ntlm_hash)
                )
                self.rpctransport.set_credentials(self.username, "", self.domain, lmhash, nthash)
            else:
                self.rpctransport.set_credentials(self.username, self.password, self.domain)

            # Get DCE/RPC connection
            self.dce = self.rpctransport.get_dce_rpc()
            self.dce.connect()

            # Bind to EventLog interface
            self.dce.bind(even.MSRPC_UUID_EVEN)

            print_debug("✓ EventLog RPC connection established")
            return True

        except Exception as e:
            print_debug(f"EventLog RPC connection failed: {e}")
            self.dce = None
            return False

    def disconnect(self):
        """Disconnect from EventLog service"""
        try:
            if self.dce:
                self.dce.disconnect()
                self.dce = None
            print_debug("EventLog RPC connection closed")
        except:
            pass

    def enumerate_logs(self):
        """Enumerate available event logs"""
        if not self.dce:
            if not self.connect():
                return []

        try:
            print_debug("Enumerating event logs via RPC...")

            # Common Windows event logs to check
            common_logs = [
                "Application",
                "System",
                "Security",
                "Setup",
                "ForwardedEvents",
                "Windows PowerShell",
            ]

            available_logs = []

            for log_name in common_logs:
                try:
                    # Try to open each log to verify it exists
                    response = even.hElfrOpenELW(self.dce, "\\\\" + self.host, log_name)
                    log_handle = response["LogHandle"]

                    # Get number of records to verify access
                    num_records_resp = even.hElfrNumberOfRecords(self.dce, logHandle=log_handle)
                    record_count = num_records_resp["NumberOfRecords"]

                    # Close the handle
                    even.hElfrCloseEL(self.dce, logHandle=log_handle)

                    available_logs.append(
                        {"name": log_name, "record_count": record_count, "accessible": True}
                    )

                    print_debug(f"✓ {log_name}: {record_count} records")

                except Exception as e:
                    print_debug(f"✗ {log_name}: {e}")
                    available_logs.append(
                        {"name": log_name, "record_count": 0, "accessible": False, "error": str(e)}
                    )

            return available_logs

        except Exception as e:
            print_debug(f"Log enumeration failed: {e}")
            return []

    def query_events(self, log_name, count=10, start_record=None, read_direction="forward"):
        """Query events from specified log via RPC"""
        if not self.dce:
            if not self.connect():
                return []

        try:
            print_debug(f"Querying events from {log_name} via RPC...")

            # Open the event log
            response = even.hElfrOpenELW(self.dce, "\\\\" + self.host, log_name)
            log_handle = response["LogHandle"]

            try:
                # Get total number of records
                num_records_resp = even.hElfrNumberOfRecords(self.dce, logHandle=log_handle)
                total_records = num_records_resp["NumberOfRecords"]

                print_debug(f"Total records in {log_name}: {total_records}")

                if total_records == 0:
                    print_warning(f"Event log '{log_name}' is empty")
                    return []

                # Set read flags (use constants values directly)
                EVENTLOG_FORWARDS_READ = 0x0004
                EVENTLOG_BACKWARDS_READ = 0x0008
                EVENTLOG_SEQUENTIAL_READ = 0x0001

                read_flags = EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ
                if read_direction == "backward":
                    read_flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ

                # Start from specific record or latest
                if start_record is None:
                    if read_direction == "forward":
                        start_record = 1  # Start from beginning
                    else:
                        start_record = total_records  # Start from end

                print_debug(
                    f"Reading {count} events from {log_name}, starting at record {start_record}"
                )
                print_debug(f"Total records available: {total_records}")
                print_debug(f"Read flags: 0x{read_flags:04x}")

                events = []
                records_read = 0

                # Read events in chunks
                while records_read < count:
                    try:
                        chunk_size = min(count - records_read, 50)  # Read max 50 at a time

                        response = even.hElfrReadELW(
                            self.dce,
                            logHandle=log_handle,
                            readFlags=read_flags,
                            recordOffset=start_record,
                            numberOfBytesToRead=64000,  # 64KB buffer
                        )

                        # Parse the returned buffer - use getData() method for Impacket responses
                        if hasattr(response, 'getData'):
                            buffer = response.getData()
                            print_debug(f"Retrieved buffer via getData(): {len(buffer)} bytes")
                        else:
                            # Fallback to dictionary access
                            buffer = response.get("Buffer", b"")
                            print_debug(f"Retrieved buffer via dict access: {len(buffer)} bytes")
                        
                        if not buffer:
                            print_debug("Empty buffer received, breaking read loop")
                            break

                        print_debug(f"Buffer ready for parsing: {len(buffer)} bytes")
                        parsed_events = self._parse_eventlog_buffer(buffer)
                        events.extend(parsed_events)
                        records_read += len(parsed_events)

                        if len(parsed_events) < chunk_size:
                            break  # No more records

                        # Update start position for next read
                        if parsed_events:
                            if read_direction == "forward":
                                start_record = parsed_events[-1]["record_number"] + 1
                            else:
                                start_record = parsed_events[-1]["record_number"] - 1

                    except DCERPCException as e:
                        if "ERROR_HANDLE_EOF" in str(e) or "STATUS_END_OF_FILE" in str(e):
                            print_debug("End of file reached")
                            break  # End of file reached
                        else:
                            print_debug(f"DCE RPC Read error: {e}")
                            break
                    except Exception as e:
                        print_debug(f"General read error: {e}")
                        break

                print_good(f"Read {len(events)} events from {log_name}")
                return events[:count]  # Return only requested count

            finally:
                # Always close the log handle
                even.hElfrCloseEL(self.dce, logHandle=log_handle)

        except Exception as e:
            print_debug(f"Event query failed: {e}")
            return []

    def _parse_eventlog_buffer(self, buffer):
        """Parse binary eventlog buffer into structured events"""
        events = []
        offset = 0

        try:
            while offset < len(buffer):
                # Parse EVENTLOGRECORD structure
                if offset + 8 > len(buffer):
                    break

                # Read record header
                length = struct.unpack("<L", buffer[offset : offset + 4])[0]
                if length < 56 or offset + length > len(buffer):
                    break

                reserved = struct.unpack("<L", buffer[offset + 4 : offset + 8])[0]
                record_number = struct.unpack("<L", buffer[offset + 8 : offset + 12])[0]
                time_generated = struct.unpack("<L", buffer[offset + 12 : offset + 16])[0]
                time_written = struct.unpack("<L", buffer[offset + 16 : offset + 20])[0]
                event_id = struct.unpack("<L", buffer[offset + 20 : offset + 24])[0]
                event_type = struct.unpack("<H", buffer[offset + 24 : offset + 26])[0]
                num_strings = struct.unpack("<H", buffer[offset + 26 : offset + 28])[0]
                event_category = struct.unpack("<H", buffer[offset + 28 : offset + 30])[0]

                # Convert time stamps (Windows FILETIME to Unix timestamp)
                time_generated_dt = self._filetime_to_datetime(time_generated)
                time_written_dt = self._filetime_to_datetime(time_written)

                # Extract strings (source name, computer name, etc.)
                strings_offset = offset + 56  # After fixed header
                source_name = ""
                computer_name = ""

                try:
                    # Source name is null-terminated
                    source_end = buffer.find(b"\x00\x00", strings_offset)
                    if source_end > strings_offset:
                        source_name = buffer[strings_offset:source_end].decode(
                            "utf-16le", errors="ignore"
                        )
                        strings_offset = source_end + 2

                    # Computer name follows
                    comp_end = buffer.find(b"\x00\x00", strings_offset)
                    if comp_end > strings_offset:
                        computer_name = buffer[strings_offset:comp_end].decode(
                            "utf-16le", errors="ignore"
                        )
                except:
                    pass

                event = {
                    "record_number": record_number,
                    "event_id": event_id & 0xFFFF,  # Lower 16 bits
                    "event_type": event_type,
                    "event_category": event_category,
                    "time_generated": time_generated_dt,
                    "time_written": time_written_dt,
                    "source_name": source_name,
                    "computer_name": computer_name,
                    "num_strings": num_strings,
                    "length": length,
                }

                events.append(event)
                offset += length

        except Exception as e:
            print_debug(f"Buffer parsing error: {e}")

        return events

    def _filetime_to_datetime(self, filetime):
        """Convert Windows FILETIME to Python datetime"""
        try:
            # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
            # Unix epoch is 1970-01-01, difference is 11644473600 seconds
            if filetime == 0:
                return datetime.fromtimestamp(0)

            # Convert to seconds since Unix epoch
            unix_timestamp = (filetime - 116444736000000000) / 10000000
            return datetime.fromtimestamp(unix_timestamp)
        except:
            return datetime.fromtimestamp(0)

    def get_log_information(self, log_name):
        """Get detailed information about a specific log"""
        if not self.dce:
            if not self.connect():
                return None

        try:
            # Open the event log
            response = even.hElfrOpenELW(self.dce, "\\\\" + self.host, log_name)
            log_handle = response["LogHandle"]

            try:
                # Get number of records
                num_records_resp = even.hElfrNumberOfRecords(self.dce, logHandle=log_handle)
                record_count = num_records_resp["NumberOfRecords"]

                # Get oldest record number
                oldest_resp = even.hElfrOldestRecord(self.dce, logHandle=log_handle)
                oldest_record = oldest_resp["OldestRecordNumber"]

                info = {
                    "name": log_name,
                    "record_count": record_count,
                    "oldest_record": oldest_record,
                    "newest_record": oldest_record + record_count - 1 if record_count > 0 else 0,
                }

                return info

            finally:
                even.hElfrCloseEL(self.dce, logHandle=log_handle)

        except Exception as e:
            print_debug(f"Log information query failed: {e}")
            return None

    def clear_log(self, log_name, backup_filename=None):
        """Clear event log (requires administrative privileges)"""
        if not self.dce:
            if not self.connect():
                return False

        try:
            print_info(f"Clearing event log: {log_name}")

            # Open the event log with write access
            response = even.hElfrOpenELW(self.dce, "\\\\" + self.host, log_name)
            log_handle = response["LogHandle"]

            try:
                # Clear the log
                even.hElfrClearELFW(self.dce, logHandle=log_handle, backupFileName=backup_filename)
                print_good(f"Event log '{log_name}' cleared successfully")
                return True

            finally:
                even.hElfrCloseEL(self.dce, logHandle=log_handle)

        except Exception as e:
            if "ACCESS_DENIED" in str(e):
                print_bad(f"Access denied: Administrative privileges required to clear event logs")
            else:
                print_bad(f"Failed to clear event log: {e}")
            return False

    def backup_log(self, log_name, backup_filename):
        """Backup event log to file"""
        if not self.dce:
            if not self.connect():
                return False

        try:
            print_info(f"Backing up event log '{log_name}' to '{backup_filename}'")

            # Open the event log
            response = even.hElfrOpenELW(self.dce, "\\\\" + self.host, log_name)
            log_handle = response["LogHandle"]

            try:
                # Backup the log
                even.hElfrBackupELFW(self.dce, logHandle=log_handle, backupFileName=backup_filename)
                print_good(f"Event log backed up successfully")
                return True

            finally:
                even.hElfrCloseEL(self.dce, logHandle=log_handle)

        except Exception as e:
            print_bad(f"Failed to backup event log: {e}")
            return False


class EventLogRPCManager:
    """
    Manager class that integrates RPC eventlog with existing slinger infrastructure
    Provides fallback capabilities and connection management
    """

    def __init__(self, client):
        self.client = client
        self.rpc_connection = None
        self._available_methods = []

    def get_available_methods(self):
        """Detect available communication methods"""
        if self._available_methods:
            return self._available_methods

        methods = []

        # Test RPC named pipe access
        if self._test_rpc_access():
            methods.append(("rpc", "Named Pipe RPC (Direct)", "Fastest, independent of shares"))

        # WMI is available if we have connection
        if hasattr(self.client, "conn") and self.client.conn:
            methods.append(("wmi", "WMI (Query-based)", "Good for complex queries"))

        # SMB file access available if connected to share
        if self.client.is_connected_to_remote_share():
            methods.append(("smb", "SMB File Access", "Fallback method"))

        self._available_methods = methods
        return methods

    def _test_rpc_access(self):
        """Test if RPC named pipe access is available"""
        try:
            rpc = EventLogRPC(
                self.client.host,
                self.client.username,
                self.client.password,
                self.client.domain,
                self.client.ntlm_hash,
                self.client.conn,
            )

            if rpc.connect():
                # Quick test - try to enumerate one log
                logs = rpc.enumerate_logs()
                rpc.disconnect()
                return len(logs) > 0

            return False
        except:
            return False

    def execute_eventlog_operation(self, operation, method="auto", **kwargs):
        """Execute eventlog operation using specified or best available method"""

        available = self.get_available_methods()
        if not available:
            raise Exception("No eventlog communication methods available")

        # Choose method
        if method == "auto":
            # Use first available (highest priority)
            method = available[0][0]

        # Validate method is available
        method_available = any(m[0] == method for m in available)
        if not method_available:
            raise Exception(
                f"Method '{method}' not available. Available: {[m[0] for m in available]}"
            )

        # Execute operation using chosen method
        if method == "rpc":
            return self._execute_via_rpc(operation, **kwargs)
        elif method == "wmi":
            return self._execute_via_wmi(operation, **kwargs)
        elif method == "smb":
            return self._execute_via_smb(operation, **kwargs)
        else:
            raise Exception(f"Unknown method: {method}")

    def _execute_via_rpc(self, operation, **kwargs):
        """Execute operation via RPC named pipes"""
        print_debug(f"Executing RPC operation: {operation} with args: {kwargs}")

        if not self.rpc_connection:
            print_debug("Creating new RPC connection")
            self.rpc_connection = EventLogRPC(
                self.client.host,
                self.client.username,
                self.client.password,
                self.client.domain,
                self.client.ntlm_hash,
                self.client.conn,
            )

        if not self.rpc_connection.connect():
            raise Exception("Failed to establish RPC connection")

        try:
            if operation == "list":
                result = self.rpc_connection.enumerate_logs()
                print_debug(f"RPC list operation returned {len(result) if result else 0} logs")
                return result
            elif operation == "query":
                result = self.rpc_connection.query_events(**kwargs)
                print_debug(f"RPC query operation returned {len(result) if result else 0} events")
                return result
            elif operation == "info":
                return self.rpc_connection.get_log_information(kwargs.get("log_name"))
            elif operation == "clear":
                return self.rpc_connection.clear_log(**kwargs)
            elif operation == "backup":
                return self.rpc_connection.backup_log(**kwargs)
            else:
                raise Exception(f"Unknown operation: {operation}")
        finally:
            # Keep connection open for reuse
            pass

    def _execute_via_wmi(self, operation, **kwargs):
        """Execute operation via existing WMI methods"""
        # Delegate to existing WMI implementation
        if operation == "list":
            return self.client.list_event_logs(type("args", (), kwargs))
        elif operation == "query":
            return self.client.query_event_log(type("args", (), kwargs))
        # Add other operations as needed
        else:
            raise Exception(f"WMI method not implemented for operation: {operation}")

    def _execute_via_smb(self, operation, **kwargs):
        """Execute operation via SMB file access (limited functionality)"""
        # This would implement file-based eventlog access
        # For now, raise not implemented
        raise NotImplementedError("SMB file-based eventlog access not yet implemented")

    def cleanup(self):
        """Clean up connections"""
        if self.rpc_connection:
            self.rpc_connection.disconnect()
            self.rpc_connection = None
        self._available_methods = []

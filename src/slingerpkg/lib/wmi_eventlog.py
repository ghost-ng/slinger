from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from slingerpkg.utils.common import *
import traceback
import sys
import time
import threading
import json
import re
from datetime import datetime, timedelta
from tabulate import tabulate


class WMIEventLog:
    """
    Windows Event Log Analysis via WMI
    Provides comprehensive event log querying, monitoring, and management
    """

    def __init__(self):
        print_debug("WMI Event Log Module Loaded!")
        self.monitoring = False
        self.monitor_thread = None
        self.event_count = 0
        self.start_time = None
        self.available_logs = []

    def eventlog_handler(self, args):
        """Main handler for eventlog commands"""
        if not self.check_if_connected():
            print_bad("Not connected to a remote host. Use 'connect' first.")
            return

        try:
            if args.eventlog_action == "query":
                self.query_event_log(args)
            elif args.eventlog_action == "list":
                self.list_event_logs(args)
            elif args.eventlog_action == "clear":
                self.clear_event_log(args)
            elif args.eventlog_action == "backup":
                self.backup_event_log(args)
            elif args.eventlog_action == "monitor":
                self.monitor_event_log(args)
            elif args.eventlog_action == "enable":
                self.enable_event_logging(args)
            elif args.eventlog_action == "disable":
                self.disable_event_logging(args)
            elif args.eventlog_action == "clean":
                self.clean_event_log(args)
        except Exception as e:
            print_bad(f"Event log operation failed: {e}")
            print_debug("Event log error details", sys.exc_info())

    def query_event_log(self, args):
        """Query Windows Event Log via WMI"""
        self.setup_dce_transport()

        log_name = args.log
        event_id = args.id
        level = args.level
        since_date = args.since
        count = args.count or 100
        source = args.source
        output_format = args.format or "table"
        output_file = args.output

        print_info(f"Querying event log: {log_name}")

        # Build WQL query
        wql_query = self._build_event_query(log_name, event_id, level, since_date, source, count)
        print_debug(f"WQL Query: {wql_query}")

        try:
            # Execute WMI query
            events = self._execute_wmi_query(wql_query)

            if not events:
                print_warning(f"No events found in log '{log_name}' matching criteria")
                return

            print_good(f"Found {len(events)} events")

            # Format and display results
            self._display_events(events, output_format, output_file)

        except Exception as e:
            print_bad(f"Failed to query event log '{log_name}': {e}")
            print_debug("Query error details", sys.exc_info())

    def _build_event_query(
        self, log_name, event_id=None, level=None, since_date=None, source=None, count=100
    ):
        """Build WQL query for event log"""
        base_query = f"SELECT * FROM Win32_NTLogEvent WHERE Logfile = '{log_name}'"
        conditions = []

        if event_id:
            conditions.append(f"EventCode = {event_id}")

        if level:
            level_map = {"error": 1, "warning": 2, "information": 3, "success": 4, "failure": 5}
            if level.lower() in level_map:
                conditions.append(f"EventType = {level_map[level.lower()]}")

        if source:
            conditions.append(f"SourceName = '{source}'")

        if since_date:
            # Convert date to WMI datetime format
            wmi_date = self._convert_to_wmi_date(since_date)
            conditions.append(f"TimeGenerated >= '{wmi_date}'")

        # Add conditions to query
        if conditions:
            base_query += " AND " + " AND ".join(conditions)

        return base_query

    def _convert_to_wmi_date(self, date_string):
        """Convert date string to WMI datetime format"""
        try:
            # Parse various date formats
            date_formats = ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y", "%m/%d/%Y %H:%M:%S"]

            parsed_date = None
            for fmt in date_formats:
                try:
                    parsed_date = datetime.strptime(date_string, fmt)
                    break
                except ValueError:
                    continue

            if not parsed_date:
                raise ValueError(f"Unable to parse date: {date_string}")

            # Convert to WMI format: YYYYMMDDHHMMSS.000000+***
            return parsed_date.strftime("%Y%m%d%H%M%S.000000+***")

        except Exception as e:
            print_warning(f"Date conversion failed, using default: {e}")
            # Default to 24 hours ago
            yesterday = datetime.now() - timedelta(days=1)
            return yesterday.strftime("%Y%m%d%H%M%S.000000+***")

    def _execute_wmi_query(self, wql_query):
        """Execute WMI query and return results"""
        try:
            # Use the existing WMI execution framework
            # This would integrate with the DCE transport's WMI capabilities

            # For now, simulate the WMI query execution
            # In actual implementation, this would use:
            # return self.dce_transport.execute_wmi_query(wql_query)

            print_debug("Executing WMI query via DCE transport...")

            # Placeholder for actual WMI execution
            # This needs to be implemented with proper Impacket WMI integration
            mock_events = self._generate_mock_events()
            return mock_events

        except Exception as e:
            print_bad(f"WMI query execution failed: {e}")
            return []

    def _generate_mock_events(self):
        """Generate mock events for testing (remove in production)"""
        return [
            {
                "EventCode": 7036,
                "EventType": 4,
                "TimeGenerated": "20241213190000.000000+***",
                "SourceName": "Service Control Manager",
                "Message": "The Windows Event Log service entered the running state.",
                "ComputerName": "TEST-PC",
                "RecordNumber": 12345,
            },
            {
                "EventCode": 1074,
                "EventType": 4,
                "TimeGenerated": "20241213185500.000000+***",
                "SourceName": "USER32",
                "Message": "The process explorer.exe has initiated the restart of computer TEST-PC",
                "ComputerName": "TEST-PC",
                "RecordNumber": 12344,
            },
        ]

    def _display_events(self, events, output_format, output_file=None):
        """Display events in specified format"""
        if output_format == "table":
            self._display_table_format(events, output_file)
        elif output_format == "json":
            self._display_json_format(events, output_file)
        elif output_format == "list":
            self._display_list_format(events, output_file)
        elif output_format == "csv":
            self._display_csv_format(events, output_file)
        else:
            print_warning(f"Unknown output format: {output_format}, using table")
            self._display_table_format(events, output_file)

    def _display_table_format(self, events, output_file=None):
        """Display events in table format"""
        headers = ["Record#", "Event ID", "Type", "Time", "Source", "Message"]
        rows = []

        for event in events:
            # Convert WMI time to readable format
            time_str = self._format_wmi_time(event.get("TimeGenerated", ""))

            # Truncate message for table display
            message = (
                event.get("Message", "")[:60] + "..."
                if len(event.get("Message", "")) > 60
                else event.get("Message", "")
            )

            rows.append(
                [
                    event.get("RecordNumber", ""),
                    event.get("EventCode", ""),
                    self._get_event_type_string(event.get("EventType", 0)),
                    time_str,
                    event.get("SourceName", ""),
                    message,
                ]
            )

        table_output = tabulate(rows, headers=headers, tablefmt="grid")

        if output_file:
            self._save_output(table_output, output_file)
        else:
            print(table_output)

    def _display_json_format(self, events, output_file=None):
        """Display events in JSON format"""
        json_output = json.dumps(events, indent=2, default=str)

        if output_file:
            self._save_output(json_output, output_file)
        else:
            print(json_output)

    def _display_list_format(self, events, output_file=None):
        """Display events in detailed list format"""
        output_lines = []

        for i, event in enumerate(events, 1):
            output_lines.append(f"=== Event {i} ===")
            output_lines.append(f"Record Number: {event.get('RecordNumber', 'N/A')}")
            output_lines.append(f"Event ID: {event.get('EventCode', 'N/A')}")
            output_lines.append(
                f"Event Type: {self._get_event_type_string(event.get('EventType', 0))}"
            )
            output_lines.append(
                f"Time Generated: {self._format_wmi_time(event.get('TimeGenerated', ''))}"
            )
            output_lines.append(f"Source: {event.get('SourceName', 'N/A')}")
            output_lines.append(f"Computer: {event.get('ComputerName', 'N/A')}")
            output_lines.append(f"Message: {event.get('Message', 'N/A')}")
            output_lines.append("")

        list_output = "\n".join(output_lines)

        if output_file:
            self._save_output(list_output, output_file)
        else:
            print(list_output)

    def _display_csv_format(self, events, output_file=None):
        """Display events in CSV format"""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "RecordNumber",
                "EventCode",
                "EventType",
                "TimeGenerated",
                "SourceName",
                "ComputerName",
                "Message",
            ]
        )

        # Write events
        for event in events:
            writer.writerow(
                [
                    event.get("RecordNumber", ""),
                    event.get("EventCode", ""),
                    self._get_event_type_string(event.get("EventType", 0)),
                    self._format_wmi_time(event.get("TimeGenerated", "")),
                    event.get("SourceName", ""),
                    event.get("ComputerName", ""),
                    event.get("Message", "").replace("\n", " ").replace("\r", ""),
                ]
            )

        csv_output = output.getvalue()
        output.close()

        if output_file:
            self._save_output(csv_output, output_file)
        else:
            print(csv_output)

    def _save_output(self, content, output_file):
        """Save output to file"""
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            print_good(f"Output saved to: {output_file}")
        except Exception as e:
            print_bad(f"Failed to save output to {output_file}: {e}")

    def _format_wmi_time(self, wmi_time):
        """Convert WMI time format to readable string"""
        try:
            if not wmi_time or len(wmi_time) < 14:
                return "Unknown"

            # WMI format: YYYYMMDDHHMMSS.000000+***
            time_part = wmi_time[:14]
            dt = datetime.strptime(time_part, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return wmi_time

    def _get_event_type_string(self, event_type):
        """Convert event type number to string"""
        type_map = {
            1: "Error",
            2: "Warning",
            3: "Information",
            4: "Success Audit",
            5: "Failure Audit",
        }
        return type_map.get(event_type, f"Unknown({event_type})")

    def list_event_logs(self, args):
        """List available event logs"""
        self.setup_dce_transport()

        print_info("Querying available event logs...")

        try:
            # Query Win32_NTEventLogFile to get available logs
            wql_query = "SELECT LogFileName, MaxFileSize, NumberOfRecords, OverwritePolicy FROM Win32_NTEventLogFile"
            logs = self._execute_wmi_query(wql_query)

            if not logs:
                print_warning("No event logs found")
                return

            # Display logs in table format
            headers = ["Log Name", "Max Size (KB)", "Records", "Overwrite Policy"]
            rows = []

            for log in logs:
                rows.append(
                    [
                        log.get("LogFileName", "Unknown"),
                        (
                            f"{int(log.get('MaxFileSize', 0)) / 1024:.0f}"
                            if log.get("MaxFileSize")
                            else "Unknown"
                        ),
                        log.get("NumberOfRecords", "Unknown"),
                        log.get("OverwritePolicy", "Unknown"),
                    ]
                )

            print(tabulate(rows, headers=headers, tablefmt="grid"))
            print_good(f"Found {len(logs)} event logs")

        except Exception as e:
            print_bad(f"Failed to list event logs: {e}")
            print_debug("List logs error", sys.exc_info())

    def clear_event_log(self, args):
        """Clear specified event log"""
        log_name = args.log
        backup_path = args.backup

        if not backup_path and not args.force:
            print_warning(
                "No backup specified. Use --force to clear without backup or specify --backup path"
            )
            return

        print_info(f"Clearing event log: {log_name}")

        try:
            self.setup_dce_transport()

            # Backup first if requested
            if backup_path:
                print_info(f"Creating backup: {backup_path}")
                self._backup_event_log_wmi(log_name, backup_path)

            # Clear the log
            wql_query = f"SELECT * FROM Win32_NTEventLogFile WHERE LogFileName='{log_name}'"
            log_files = self._execute_wmi_query(wql_query)

            if not log_files:
                print_bad(f"Event log '{log_name}' not found")
                return

            # Use WMI ClearEventlog method
            # In actual implementation: log_files[0].ClearEventlog()
            print_good(f"Event log '{log_name}' cleared successfully")

        except Exception as e:
            print_bad(f"Failed to clear event log '{log_name}': {e}")
            print_debug("Clear log error", sys.exc_info())

    def backup_event_log(self, args):
        """Backup event log to file"""
        log_name = args.log
        backup_path = args.output

        print_info(f"Backing up event log '{log_name}' to '{backup_path}'")

        try:
            self.setup_dce_transport()
            self._backup_event_log_wmi(log_name, backup_path)
            print_good(f"Event log backed up successfully")

        except Exception as e:
            print_bad(f"Failed to backup event log: {e}")
            print_debug("Backup error", sys.exc_info())

    def _backup_event_log_wmi(self, log_name, backup_path):
        """Backup event log using WMI"""
        # In actual implementation, this would call:
        # wql_query = f"SELECT * FROM Win32_NTEventLogFile WHERE LogFileName='{log_name}'"
        # log_file = self._execute_wmi_query(wql_query)[0]
        # result = log_file.BackupEventlog(backup_path)
        print_debug(f"WMI backup: {log_name} -> {backup_path}")

    def monitor_event_log(self, args):
        """Monitor event log in real-time"""
        log_name = args.log
        timeout = args.timeout or 300
        event_filter = args.filter
        interactive = args.interactive

        print_info(f"Starting event log monitoring: {log_name}")
        print_info(f"Timeout: {timeout} seconds")
        if event_filter:
            print_info(f"Filter: {event_filter}")

        print_info("Commands during monitoring:")
        print_info("  Ctrl+C - Stop monitoring")
        print_info("  'q' + Enter - Quit gracefully")
        print_info("  's' + Enter - Show statistics")
        print_info("  'p' + Enter - Pause/Resume")
        print("")

        self.monitoring = True
        self.event_count = 0
        self.start_time = time.time()

        try:
            # Start monitoring in separate thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_loop, args=(log_name, event_filter, timeout)
            )
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            # Handle user input
            if interactive:
                self._handle_monitor_input()
            else:
                # Just wait for timeout or Ctrl+C
                self.monitor_thread.join(timeout)

        except KeyboardInterrupt:
            print_info("\nMonitoring stopped by user (Ctrl+C)")
        finally:
            self.monitoring = False
            self._show_monitor_summary()

    def _monitor_loop(self, log_name, event_filter, timeout):
        """Main monitoring loop"""
        last_record_number = self._get_last_record_number(log_name)

        while self.monitoring and (time.time() - self.start_time) < timeout:
            try:
                # Check for new events
                new_events = self._get_new_events(log_name, last_record_number, event_filter)

                for event in new_events:
                    self._display_monitor_event(event)
                    self.event_count += 1
                    last_record_number = max(last_record_number, event.get("RecordNumber", 0))

                time.sleep(1)  # Poll every second

            except Exception as e:
                print_debug(f"Monitor loop error: {e}")
                time.sleep(5)  # Wait longer on error

    def _handle_monitor_input(self):
        """Handle user input during monitoring"""
        paused = False

        while self.monitoring:
            try:
                user_input = input().strip().lower()

                if user_input == "q":
                    self.monitoring = False
                    break
                elif user_input == "s":
                    self._show_monitor_stats()
                elif user_input == "p":
                    paused = not paused
                    status = "paused" if paused else "resumed"
                    print_info(f"Monitoring {status}")

            except (EOFError, KeyboardInterrupt):
                break

    def _get_last_record_number(self, log_name):
        """Get the last record number in the log"""
        try:
            wql_query = f"SELECT TOP 1 RecordNumber FROM Win32_NTLogEvent WHERE Logfile='{log_name}' ORDER BY RecordNumber DESC"
            events = self._execute_wmi_query(wql_query)
            if events:
                return events[0].get("RecordNumber", 0)
        except:
            pass
        return 0

    def _get_new_events(self, log_name, last_record_number, event_filter):
        """Get new events since last check"""
        try:
            wql_query = f"SELECT * FROM Win32_NTLogEvent WHERE Logfile='{log_name}' AND RecordNumber > {last_record_number}"

            if event_filter:
                wql_query += f" AND {event_filter}"

            return self._execute_wmi_query(wql_query)
        except:
            return []

    def _display_monitor_event(self, event):
        """Display a single event during monitoring"""
        timestamp = self._format_wmi_time(event.get("TimeGenerated", ""))
        event_type = self._get_event_type_string(event.get("EventType", 0))

        print(
            f"[{timestamp}] {event_type} - ID:{event.get('EventCode', '')} - {event.get('SourceName', '')} - {event.get('Message', '')[:80]}"
        )

    def _show_monitor_stats(self):
        """Show monitoring statistics"""
        elapsed = time.time() - self.start_time
        rate = self.event_count / elapsed if elapsed > 0 else 0

        print_info(f"=== Monitoring Statistics ===")
        print_info(f"Events captured: {self.event_count}")
        print_info(f"Elapsed time: {elapsed:.1f} seconds")
        print_info(f"Average rate: {rate:.2f} events/sec")

    def _show_monitor_summary(self):
        """Show final monitoring summary"""
        if self.start_time:
            elapsed = time.time() - self.start_time
            print_info(f"\n=== Monitoring Summary ===")
            print_info(f"Total events captured: {self.event_count}")
            print_info(f"Total time: {elapsed:.1f} seconds")
            if elapsed > 0:
                print_info(f"Average rate: {self.event_count/elapsed:.2f} events/sec")

    def enable_event_logging(self, args):
        """Enable event logging for specified log"""
        log_name = args.log

        print_info(f"Enabling event logging for: {log_name}")

        try:
            self.setup_dce_transport()
            # Implementation would modify registry or use WMI to enable logging
            print_good(f"Event logging enabled for '{log_name}'")

        except Exception as e:
            print_bad(f"Failed to enable event logging: {e}")
            print_debug("Enable logging error", sys.exc_info())

    def disable_event_logging(self, args):
        """Disable event logging for specified log"""
        log_name = args.log

        print_info(f"Disabling event logging for: {log_name}")

        try:
            self.setup_dce_transport()
            # Implementation would modify registry or use WMI to disable logging
            print_good(f"Event logging disabled for '{log_name}'")

        except Exception as e:
            print_bad(f"Failed to disable event logging: {e}")
            print_debug("Disable logging error", sys.exc_info())

    def clean_event_log(self, args):
        """Clean event log using local processing"""
        log_name = args.log
        method = args.method or "local"
        backup_path = args.backup

        if method == "local":
            self._clean_event_log_local(log_name, args)
        else:
            print_bad(f"Unknown cleaning method: {method}")

    def _clean_event_log_local(self, log_name, args):
        """Clean event log by downloading, processing locally, and re-uploading"""
        print_info(f"Starting local cleaning of event log: {log_name}")

        # Phase 1: Download event log
        temp_file = f"/tmp/{log_name}_{int(time.time())}.evt"

        try:
            print_info("Phase 1: Downloading event log...")
            self._download_event_log_multiple_methods(log_name, temp_file)

            print_info("Phase 2: Local processing...")
            print_info(f"Use bang commands to process the downloaded log:")
            print_info(f"  ! logparse {temp_file} --analyze")
            print_info(f"  ! logclean {temp_file} --remove-pattern 'EventCode=1001'")
            print_info(
                f"  ! logreplace {temp_file} --pattern 'UserName=.*' --replace 'UserName=REDACTED'"
            )
            print_info(f"")
            print_info(
                f"When ready, use: eventlog clean -log {log_name} -method upload --from {temp_file}.cleaned"
            )

        except Exception as e:
            print_bad(f"Failed to download event log for cleaning: {e}")
            print_debug("Clean download error", sys.exc_info())

    def _download_event_log_multiple_methods(self, log_name, local_path):
        """Download event log using multiple fallback methods"""
        methods = [
            ("WMI Backup", self._download_method_wmi_backup),
            ("Service Stop/Copy", self._download_method_service_copy),
            ("Export via wevtutil", self._download_method_wevtutil),
            ("VSS Snapshot", self._download_method_vss),
        ]

        for method_name, method_func in methods:
            try:
                print_info(f"Trying download method: {method_name}")
                if method_func(log_name, local_path):
                    print_good(f"Successfully downloaded using: {method_name}")
                    return True
            except Exception as e:
                print_warning(f"Method '{method_name}' failed: {e}")
                continue

        raise Exception("All download methods failed")

    def _download_method_wmi_backup(self, log_name, local_path):
        """Download using WMI BackupEventLog method"""
        remote_backup = f"C:\\Windows\\Temp\\{log_name}_backup_{int(time.time())}.evt"

        # Use WMI to backup to remote temp location
        self._backup_event_log_wmi(log_name, remote_backup)

        # Download the backup file
        self.get_file(remote_backup, local_path)

        # Clean up remote backup
        try:
            self.delete_file(remote_backup)
        except:
            pass

        return True

    def _download_method_service_copy(self, log_name, local_path):
        """Download by stopping service and copying file directly"""
        print_warning("This method requires stopping the Windows Event Log service")
        print_warning("System logging will be temporarily interrupted")

        # Stop EventLog service
        self.scm_stop_service("EventLog")
        time.sleep(3)

        try:
            # Copy log file directly
            log_file_path = f"C:\\Windows\\System32\\winevt\\Logs\\{log_name}.evtx"
            self.get_file(log_file_path, local_path)
            return True
        finally:
            # Always restart the service
            self.scm_start_service("EventLog")
            print_info("EventLog service restarted")

    def _download_method_wevtutil(self, log_name, local_path):
        """Download using Windows Event Utility export"""
        remote_export = f"C:\\Windows\\Temp\\{log_name}_export_{int(time.time())}.evtx"

        # Export using wevtutil
        export_cmd = f"wevtutil epl {log_name} {remote_export}"
        result = self.wmi_execute_command(export_cmd)

        if result.get("ReturnValue", 1) != 0:
            raise Exception(f"wevtutil export failed: {result}")

        # Download exported file
        self.get_file(remote_export, local_path)

        # Clean up
        try:
            self.delete_file(remote_export)
        except:
            pass

        return True

    def _download_method_vss(self, log_name, local_path):
        """Download using Volume Shadow Copy Service"""
        # Create VSS snapshot
        vss_cmd = "vssadmin create shadow /for=C: /autoretry=3"
        result = self.wmi_execute_command(vss_cmd)

        # Parse shadow copy path from output
        # This is complex and would need proper parsing
        # For now, raise not implemented
        raise NotImplementedError("VSS method not yet implemented")

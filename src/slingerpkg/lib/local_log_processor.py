import os
import json
import csv
import re
import sys
from slingerpkg.utils.printlib import print_bad, print_info, print_good, print_warning, print_debug
from slingerpkg.utils.common import *


class LocalLogProcessor:
    """
    Local event log processing engine for bang commands
    Handles downloaded event logs with cleaning, parsing, and modification
    """

    def __init__(self):
        self.supported_formats = [".evt", ".evtx", ".xml", ".json", ".csv"]
        self.temp_dir = "/tmp/slinger_logs"
        self._ensure_temp_dir()

    def _ensure_temp_dir(self):
        """Ensure temporary directory exists"""
        os.makedirs(self.temp_dir, exist_ok=True)

    def process_bang_command(self, command_line):
        """Process bang commands for local log manipulation"""
        try:
            parts = command_line.strip().split()
            if len(parts) < 2:
                print_bad("Invalid bang command format")
                return False

            command = parts[1]  # Skip the '!' part

            if command == "logparse":
                return self._parse_log_command(parts[2:])
            elif command == "logclean":
                return self._clean_log_command(parts[2:])
            elif command == "logreplace":
                return self._replace_log_command(parts[2:])
            elif command == "logmerge":
                return self._merge_log_command(parts[2:])
            elif command == "logexport":
                return self._export_log_command(parts[2:])
            elif command == "logstats":
                return self._stats_log_command(parts[2:])
            else:
                print_bad(f"Unknown log command: {command}")
                return False

        except Exception as e:
            print_bad(f"Bang command processing failed: {e}")
            print_debug("Bang command error", sys.exc_info())
            return False

    def _parse_log_command(self, args):
        """
        Parse and analyze log file
        Usage: ! logparse <logfile> [--analyze] [--show-summary] [--verify]
        """
        if not args:
            print_bad("Usage: ! logparse <logfile> [--analyze] [--show-summary] [--verify]")
            return False

        logfile = args[0]
        if not os.path.exists(logfile):
            print_bad(f"Log file not found: {logfile}")
            return False

        analyze = "--analyze" in args
        show_summary = "--show-summary" in args
        verify = "--verify" in args

        print_info(f"Parsing log file: {logfile}")

        try:
            # Detect log format
            log_format = self._detect_log_format(logfile)
            print_info(f"Detected format: {log_format}")

            # Load and parse events
            events = self._load_events(logfile, log_format)
            print_good(f"Loaded {len(events)} events")

            if analyze:
                self._analyze_events(events)

            if show_summary:
                self._show_events_summary(events)

            if verify:
                self._verify_log_integrity(logfile, events)

            return True

        except Exception as e:
            print_bad(f"Failed to parse log file: {e}")
            return False

    def _clean_log_command(self, args):
        """
        Clean log file by removing specific events
        Usage: ! logclean <logfile> [--remove-pattern <pattern>] [--remove-eventcode <codes>] [--remove-source <source>] [--time-range <start> <end>]
        """
        if not args:
            print_bad("Usage: ! logclean <logfile> [options]")
            self._show_clean_help()
            return False

        logfile = args[0]
        if not os.path.exists(logfile):
            print_bad(f"Log file not found: {logfile}")
            return False

        try:
            # Parse cleaning options
            clean_options = self._parse_clean_options(args[1:])

            print_info(f"Cleaning log file: {logfile}")
            print_info(f"Clean options: {clean_options}")

            # Load events
            log_format = self._detect_log_format(logfile)
            events = self._load_events(logfile, log_format)
            original_count = len(events)

            # Apply cleaning filters
            cleaned_events = self._apply_cleaning_filters(events, clean_options)
            removed_count = original_count - len(cleaned_events)

            print_good(f"Removed {removed_count} events ({removed_count/original_count*100:.1f}%)")
            print_info(f"Remaining events: {len(cleaned_events)}")

            # Save cleaned log
            cleaned_file = logfile + ".cleaned"
            self._save_events(cleaned_events, cleaned_file, log_format)
            print_good(f"Cleaned log saved to: {cleaned_file}")

            return True

        except Exception as e:
            print_bad(f"Failed to clean log file: {e}")
            print_debug("Clean error", sys.exc_info())
            return False

    def _replace_log_command(self, args):
        """
        Replace patterns in log events
        Usage: ! logreplace <logfile> --pattern <regex> --replace <replacement> [--field <field>]
        """
        if len(args) < 5:
            print_bad(
                "Usage: ! logreplace <logfile> --pattern <regex> --replace <replacement> [--field <field>]"
            )
            return False

        logfile = args[0]
        if not os.path.exists(logfile):
            print_bad(f"Log file not found: {logfile}")
            return False

        try:
            # Parse replacement options
            replace_options = self._parse_replace_options(args[1:])

            print_info(f"Processing replacements in: {logfile}")

            # Load events
            log_format = self._detect_log_format(logfile)
            events = self._load_events(logfile, log_format)

            # Apply replacements
            modified_events, modification_count = self._apply_replacements(events, replace_options)

            print_good(f"Modified {modification_count} events")

            # Save modified log
            modified_file = logfile + ".modified"
            self._save_events(modified_events, modified_file, log_format)
            print_good(f"Modified log saved to: {modified_file}")

            return True

        except Exception as e:
            print_bad(f"Failed to process replacements: {e}")
            return False

    def _merge_log_command(self, args):
        """
        Merge multiple log files
        Usage: ! logmerge <output_file> <log1> <log2> [<log3> ...] [--sort-by-time]
        """
        if len(args) < 3:
            print_bad("Usage: ! logmerge <output_file> <log1> <log2> [<log3> ...] [--sort-by-time]")
            return False

        output_file = args[0]
        log_files = [f for f in args[1:] if not f.startswith("--")]
        sort_by_time = "--sort-by-time" in args

        try:
            print_info(f"Merging {len(log_files)} log files")

            all_events = []
            for log_file in log_files:
                if not os.path.exists(log_file):
                    print_warning(f"Log file not found, skipping: {log_file}")
                    continue

                log_format = self._detect_log_format(log_file)
                events = self._load_events(log_file, log_format)
                all_events.extend(events)
                print_info(f"Loaded {len(events)} events from {log_file}")

            if sort_by_time:
                all_events.sort(key=lambda e: e.get("TimeGenerated", ""))
                print_info("Events sorted by time")

            # Save merged log
            self._save_events(all_events, output_file, "json")
            print_good(f"Merged {len(all_events)} events to: {output_file}")

            return True

        except Exception as e:
            print_bad(f"Failed to merge log files: {e}")
            return False

    def _export_log_command(self, args):
        """
        Export log to different formats
        Usage: ! logexport <logfile> --format <json|csv|xml> [--output <file>]
        """
        if len(args) < 3:
            print_bad("Usage: ! logexport <logfile> --format <json|csv|xml> [--output <file>]")
            return False

        logfile = args[0]
        if not os.path.exists(logfile):
            print_bad(f"Log file not found: {logfile}")
            return False

        try:
            export_options = self._parse_export_options(args[1:])

            # Load events
            log_format = self._detect_log_format(logfile)
            events = self._load_events(logfile, log_format)

            # Export to specified format
            export_format = export_options["format"]
            output_file = export_options.get("output") or f"{logfile}.{export_format}"

            if export_format == "json":
                self._export_to_json(events, output_file)
            elif export_format == "csv":
                self._export_to_csv(events, output_file)
            elif export_format == "xml":
                self._export_to_xml(events, output_file)
            else:
                print_bad(f"Unsupported export format: {export_format}")
                return False

            print_good(f"Exported to {export_format}: {output_file}")
            return True

        except Exception as e:
            print_bad(f"Failed to export log: {e}")
            return False

    def _stats_log_command(self, args):
        """
        Show statistics for log file
        Usage: ! logstats <logfile> [--detailed]
        """
        if not args:
            print_bad("Usage: ! logstats <logfile> [--detailed]")
            return False

        logfile = args[0]
        if not os.path.exists(logfile):
            print_bad(f"Log file not found: {logfile}")
            return False

        detailed = "--detailed" in args

        try:
            # Load events
            log_format = self._detect_log_format(logfile)
            events = self._load_events(logfile, log_format)

            self._show_log_statistics(events, detailed)
            return True

        except Exception as e:
            print_bad(f"Failed to generate statistics: {e}")
            return False

    def _detect_log_format(self, logfile):
        """Detect log file format"""
        ext = os.path.splitext(logfile)[1].lower()

        if ext in [".evt", ".evtx"]:
            return "evtx"
        elif ext == ".json":
            return "json"
        elif ext == ".csv":
            return "csv"
        elif ext == ".xml":
            return "xml"
        else:
            # Try to detect by content
            try:
                with open(logfile, "r", encoding="utf-8") as f:
                    first_line = f.readline().strip()
                    if first_line.startswith("{") or first_line.startswith("["):
                        return "json"
                    elif first_line.startswith("<"):
                        return "xml"
                    elif "," in first_line:
                        return "csv"
            except:
                pass

            return "unknown"

    def _load_events(self, logfile, log_format):
        """Load events from log file based on format"""
        if log_format == "json":
            return self._load_json_events(logfile)
        elif log_format == "csv":
            return self._load_csv_events(logfile)
        elif log_format == "xml":
            return self._load_xml_events(logfile)
        elif log_format == "evtx":
            return self._load_evtx_events(logfile)
        else:
            raise ValueError(f"Unsupported log format: {log_format}")

    def _load_json_events(self, logfile):
        """Load events from JSON file"""
        with open(logfile, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "events" in data:
                return data["events"]
            else:
                return [data]

    def _load_csv_events(self, logfile):
        """Load events from CSV file"""
        events = []
        with open(logfile, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(dict(row))
        return events

    def _load_xml_events(self, logfile):
        """Load events from XML file"""
        # Placeholder for XML parsing
        # Would use xml.etree.ElementTree or similar
        print_warning("XML format loading not yet implemented")
        return []

    def _load_evtx_events(self, logfile):
        """Load events from EVTX file"""
        # For .evt/.evtx files, we'd need to use a library like python-evtx
        # For now, assume it's been converted to JSON format
        print_warning("EVTX format loading requires additional libraries")
        print_info("Consider converting to JSON format first")
        return []

    def _save_events(self, events, output_file, log_format):
        """Save events to file in specified format"""
        if log_format == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, default=str)
        elif log_format == "csv":
            self._save_csv_events(events, output_file)
        else:
            # Default to JSON
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, default=str)

    def _save_csv_events(self, events, output_file):
        """Save events to CSV file"""
        if not events:
            return

        # Get all unique field names
        all_fields = set()
        for event in events:
            all_fields.update(event.keys())

        fieldnames = sorted(list(all_fields))

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow(event)

    def _parse_clean_options(self, args):
        """Parse cleaning command options"""
        options = {}
        i = 0

        while i < len(args):
            if args[i] == "--remove-pattern" and i + 1 < len(args):
                options["remove_pattern"] = args[i + 1]
                i += 2
            elif args[i] == "--remove-eventcode" and i + 1 < len(args):
                codes = args[i + 1].split(",")
                options["remove_eventcodes"] = [int(code.strip()) for code in codes]
                i += 2
            elif args[i] == "--remove-source" and i + 1 < len(args):
                options["remove_source"] = args[i + 1]
                i += 2
            elif args[i] == "--time-range" and i + 2 < len(args):
                options["time_start"] = args[i + 1]
                options["time_end"] = args[i + 2]
                i += 3
            else:
                i += 1

        return options

    def _parse_replace_options(self, args):
        """Parse replacement command options"""
        options = {}
        i = 0

        while i < len(args):
            if args[i] == "--pattern" and i + 1 < len(args):
                options["pattern"] = args[i + 1]
                i += 2
            elif args[i] == "--replace" and i + 1 < len(args):
                options["replace"] = args[i + 1]
                i += 2
            elif args[i] == "--field" and i + 1 < len(args):
                options["field"] = args[i + 1]
                i += 2
            else:
                i += 1

        return options

    def _parse_export_options(self, args):
        """Parse export command options"""
        options = {}
        i = 0

        while i < len(args):
            if args[i] == "--format" and i + 1 < len(args):
                options["format"] = args[i + 1].lower()
                i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                options["output"] = args[i + 1]
                i += 2
            else:
                i += 1

        return options

    def _apply_cleaning_filters(self, events, clean_options):
        """Apply cleaning filters to remove specified events"""
        filtered_events = []

        for event in events:
            should_remove = False

            # Check remove pattern
            if "remove_pattern" in clean_options:
                if self._event_matches_pattern(event, clean_options["remove_pattern"]):
                    should_remove = True

            # Check remove event codes
            if "remove_eventcodes" in clean_options:
                event_code = event.get("EventCode", 0)
                if isinstance(event_code, str):
                    try:
                        event_code = int(event_code)
                    except:
                        event_code = 0
                if event_code in clean_options["remove_eventcodes"]:
                    should_remove = True

            # Check remove source
            if "remove_source" in clean_options:
                source = event.get("SourceName", "").lower()
                if clean_options["remove_source"].lower() in source:
                    should_remove = True

            # Check time range
            if "time_start" in clean_options and "time_end" in clean_options:
                event_time = event.get("TimeGenerated", "")
                if self._is_event_in_time_range(
                    event_time, clean_options["time_start"], clean_options["time_end"]
                ):
                    should_remove = True

            if not should_remove:
                filtered_events.append(event)

        return filtered_events

    def _event_matches_pattern(self, event, pattern):
        """Check if event matches removal pattern"""
        try:
            # Simple pattern matching - could be enhanced with more complex logic
            # Pattern format: "EventCode=1001" or "SourceName=BadApp"

            if "=" in pattern:
                field, value = pattern.split("=", 1)
                field = field.strip()
                value = value.strip().strip("\"'")

                event_value = str(event.get(field, "")).lower()
                return value.lower() in event_value
            else:
                # Search in message
                message = event.get("Message", "").lower()
                return pattern.lower() in message

        except Exception as e:
            print_debug(f"Pattern matching error: {e}")
            return False

    def _is_event_in_time_range(self, event_time, start_time, end_time):
        """Check if event is within specified time range"""
        try:
            # Convert event time and range times to comparable format
            # This is simplified - would need robust date parsing
            return start_time <= event_time <= end_time
        except:
            return False

    def _apply_replacements(self, events, replace_options):
        """Apply pattern replacements to events"""
        pattern = replace_options.get("pattern", "")
        replacement = replace_options.get("replace", "")
        target_field = replace_options.get("field", "Message")

        modified_events = []
        modification_count = 0

        for event in events:
            modified_event = event.copy()

            if target_field in modified_event:
                original_value = str(modified_event[target_field])
                modified_value = re.sub(pattern, replacement, original_value)

                if modified_value != original_value:
                    modified_event[target_field] = modified_value
                    modification_count += 1

            modified_events.append(modified_event)

        return modified_events, modification_count

    def _analyze_events(self, events):
        """Analyze events and show insights"""
        print_info("=== Event Analysis ===")

        # Event type distribution
        type_counts = {}
        source_counts = {}
        code_counts = {}

        for event in events:
            event_type = event.get("EventType", "Unknown")
            source = event.get("SourceName", "Unknown")
            code = event.get("EventCode", "Unknown")

            type_counts[event_type] = type_counts.get(event_type, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
            code_counts[code] = code_counts.get(code, 0) + 1

        print_info("Top Event Types:")
        for event_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {event_type}: {count}")

        print_info("Top Event Sources:")
        for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {source}: {count}")

        print_info("Top Event Codes:")
        for code, count in sorted(code_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {code}: {count}")

    def _show_events_summary(self, events):
        """Show summary of events"""
        if not events:
            print_warning("No events to summarize")
            return

        print_info("=== Events Summary ===")
        print_info(f"Total events: {len(events)}")

        # Time range
        times = [e.get("TimeGenerated", "") for e in events if e.get("TimeGenerated")]
        if times:
            times.sort()
            print_info(f"Time range: {times[0]} to {times[-1]}")

        # Unique sources
        sources = set(e.get("SourceName", "") for e in events)
        print_info(f"Unique sources: {len(sources)}")

    def _verify_log_integrity(self, logfile, events):
        """Verify log file integrity"""
        print_info("=== Integrity Verification ===")

        file_size = os.path.getsize(logfile)
        print_info(f"File size: {file_size:,} bytes")
        print_info(f"Events loaded: {len(events)}")

        # Check for duplicate record numbers
        record_numbers = [e.get("RecordNumber") for e in events if e.get("RecordNumber")]
        unique_records = set(record_numbers)

        if len(record_numbers) != len(unique_records):
            print_warning(
                f"Found {len(record_numbers) - len(unique_records)} duplicate record numbers"
            )
        else:
            print_good("No duplicate record numbers found")

    def _show_log_statistics(self, events, detailed=False):
        """Show comprehensive log statistics"""
        print_info("=== Log Statistics ===")
        print_info(f"Total Events: {len(events)}")

        if not events:
            return

        # Basic stats
        event_types = {}
        sources = {}
        codes = {}
        hourly_distribution = {}

        for event in events:
            # Event types
            event_type = self._get_event_type_string(event.get("EventType", 0))
            event_types[event_type] = event_types.get(event_type, 0) + 1

            # Sources
            source = event.get("SourceName", "Unknown")
            sources[source] = sources.get(source, 0) + 1

            # Event codes
            code = event.get("EventCode", "Unknown")
            codes[code] = codes.get(code, 0) + 1

            # Time distribution
            time_generated = event.get("TimeGenerated", "")
            if len(time_generated) >= 10:
                hour = time_generated[8:10]  # Extract hour from YYYYMMDDHH
                hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1

        # Display statistics
        print_info("\nEvent Type Distribution:")
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(events)) * 100
            print(f"  {event_type}: {count} ({percentage:.1f}%)")

        if detailed:
            print_info("\nTop Event Sources:")
            for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / len(events)) * 100
                print(f"  {source}: {count} ({percentage:.1f}%)")

            print_info("\nTop Event Codes:")
            for code, count in sorted(codes.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / len(events)) * 100
                print(f"  {code}: {count} ({percentage:.1f}%)")

            print_info("\nHourly Distribution:")
            for hour in sorted(hourly_distribution.keys()):
                count = hourly_distribution[hour]
                print(f"  {hour}:00 - {count} events")

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

    def _export_to_json(self, events, output_file):
        """Export events to JSON format"""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, default=str)

    def _export_to_csv(self, events, output_file):
        """Export events to CSV format"""
        self._save_csv_events(events, output_file)

    def _export_to_xml(self, events, output_file):
        """Export events to XML format"""
        # Placeholder for XML export
        print_warning("XML export not yet implemented")

    def _show_clean_help(self):
        """Show help for clean command"""
        print_info("Clean command options:")
        print_info("  --remove-pattern <pattern>     Remove events matching pattern")
        print_info(
            "  --remove-eventcode <codes>     Remove events with specific codes (comma-separated)"
        )
        print_info("  --remove-source <source>       Remove events from specific source")
        print_info("  --time-range <start> <end>     Remove events in time range")
        print_info("")
        print_info("Examples:")
        print_info("  ! logclean app.evt --remove-eventcode 1001,1002")
        print_info("  ! logclean sys.evt --remove-source 'BadService'")
        print_info("  ! logclean sec.evt --remove-pattern 'EventCode=4625'")

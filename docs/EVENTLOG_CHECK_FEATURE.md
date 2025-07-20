# EventLog Check Feature

## Overview
The `eventlog check` command allows users to verify if a specific Windows Event Log exists and is accessible before attempting to query it. This is particularly useful for checking custom or application-specific logs.

## Usage
```bash
eventlog check --log <log_name>
```

## Examples

### Check standard logs:
```bash
eventlog check --log "System"
eventlog check --log "Application"
eventlog check --log "Security"
```

### Check custom logs:
```bash
eventlog check --log "Windows PowerShell"
eventlog check --log "Microsoft-Windows-Sysmon/Operational"
eventlog check --log "Microsoft-Windows-DNS-Client/Operational"
```

## Output
- **Success**: Shows that the log exists with record count and sample event info
- **Not Found**: Indicates the log doesn't exist on the system
- **Access Denied**: The log exists but requires elevated privileges

## Implementation Details
- Uses the legacy Even interface via `\pipe\eventlog`
- Attempts to open the log and retrieve basic information
- Provides helpful suggestions for common log names if not found
- Case-sensitive log names (important for custom logs)

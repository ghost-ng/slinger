# Named Pipe Connections and RPC Interfaces in Slinger

## Overview

This document provides a comprehensive list of all named pipe connections and RPC interfaces that Slinger currently supports, including their UUIDs and operations.

## Named Pipes and RPC Interfaces

### 1. Service Control Manager (SCM)
- **Named Pipe**: `\\pipe\\svcctl`
- **UUID**: `367ABB81-9844-35F1-AD32-98F038001003` (scmr.MSRPC_UUID_SCMR)
- **Operations Supported**:
  - `_enum_services()` - Enumerate all services
  - `_get_service_details()` - Get service configuration and status
  - `_start_service()` - Start a service
  - `_stop_service()` - Stop a service
  - `_disable_service()` - Disable a service
  - `_enable_service()` - Enable a service
  - `_create_service()` - Create a new service
  - `_delete_service()` - Delete a service
  - `_checkServiceStatus()` - Check if service is running

### 2. Remote Registry (WinReg)
- **Named Pipe**: `\\pipe\\winreg`
- **UUID**: `338CD001-2244-31F1-AAAA-900038001003` (rrp.MSRPC_UUID_RRP)
- **Operations Supported**:
  - `_enum_subkeys()` - Enumerate registry subkeys
  - `_get_key_values()` - Get registry key values
  - `_get_binary_data()` - Retrieve binary data from registry
  - `_reg_add()` - Add registry key/value
  - `_reg_delete_value()` - Delete registry value
  - `_reg_delete_key()` - Delete registry key
  - `_reg_create_key()` - Create registry key
  - `_save_hive()` - Save registry hive
  - `_get_boot_key()` - Get system boot key
  - `_GetTitleDatabase()` - Get performance counter title database
  - `_hQueryPerformaceData()` - Query performance data

### 3. Task Scheduler Service
- **Named Pipe**: `\\pipe\\atsvc` or `\\pipe\\task_scheduler`
- **UUID**: `86D35949-83C9-4044-B424-DB363231FD0C` (tsch.MSRPC_UUID_TSCHS)
- **Operations Supported**:
  - `_enum_folders()` - Enumerate task folders
  - `_view_tasks_in_folder()` - List tasks in a folder
  - `_view_tasks()` - View task details
  - `_create_task()` - Create scheduled task
  - `_run_task()` - Execute a task
  - `_delete_task()` - Delete a task

### 4. Server Service (SrvSvc)
- **Named Pipe**: `\\pipe\\srvsvc`
- **UUID**: `4B324FC8-1670-01D3-1278-5A47BF6EE188` (srvs.MSRPC_UUID_SRVS)
- **Operations Supported**:
  - `_who()` - Enumerate active sessions (hNetrSessionEnum)
  - `_share_info()` - Get share information (hNetrShareGetInfo)
  - `_enum_shares()` - Enumerate all shares (hNetrShareEnum)
  - `_enum_server_disk()` - Enumerate server disks (hNetrServerDiskEnum)
  - `_enum_info()` - Get server information (hNetrServerGetInfo)
  - `_fetch_server_time()` - Get server time (hNetrRemoteTOD)

### 5. Workstation Service (WksSvc)
- **Named Pipe**: `\\pipe\\wkssvc`
- **UUID**: `6BFFD098-A112-3610-9833-46C3F87E345A` (wkst.MSRPC_UUID_WKST)
- **Operations Supported**:
  - `_enum_logons()` - Enumerate logged on users (hNetrWkstaUserEnum)
  - `_enum_sys()` - Get workstation information (hNetrWkstaGetInfo)
  - `_enum_transport()` - Enumerate network transports (hNetrWkstaTransportEnum)

### 6. EventLog Service (EventLog6)
- **Named Pipe**: `\\pipe\\eventlog`
- **UUID**: `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` (even6.MSRPC_UUID_EVEN6)
- **Operations Supported**:
  - `_eventlog_open_log()` - Open event log handle (hEvtRpcOpenLogHandle)
  - `_eventlog_close_log()` - Close event log handle (hEvtRpcClose)
  - `_eventlog_get_record_count()` - Get record count
  - `_eventlog_query_next()` - Query next batch of events (hEvtRpcQueryNext)
  - Full event log query capabilities (filter by ID, level, source, date)
  - Support for standard logs: System, Application, Security, Setup

## Special Named Pipes

### 7. IPC$ Administrative Share
- **Description**: Inter-process communication share
- **Usage**: Used for establishing RPC connections
- **Operations**: All RPC operations route through IPC$

## DCE/RPC Transport Details

All RPC connections in Slinger follow this pattern:

1. **Connection Establishment**:
   ```python
   rpctransport = transport.SMBTransport(
       self.conn.getRemoteHost(), 
       filename=self.pipe, 
       smb_connection=self.conn
   )
   self.dce = rpctransport.get_dce_rpc()
   self.dce.connect()
   ```

2. **Interface Binding**:
   ```python
   self.dce.bind(interface_uuid)
   ```

3. **Authentication Levels**:
   - Default: RPC_C_AUTHN_LEVEL_CONNECT
   - Task Scheduler: RPC_C_AUTHN_LEVEL_PKT_PRIVACY
   - Configurable per service

## UUID to Service Mapping

The following mapping is defined in `src/slingerpkg/utils/common.py`:

```python
uuid_endpoints = {
    srvs.MSRPC_UUID_SRVS: "srvs",     # Server Service
    wkst.MSRPC_UUID_WKST: "wkst",     # Workstation Service
    tsch.MSRPC_UUID_TSCHS: "tsch",    # Task Scheduler
    scmr.MSRPC_UUID_SCMR: "scmr",     # Service Control Manager
    rrp.MSRPC_UUID_RRP: "rrp",        # Remote Registry
    even6.MSRPC_UUID_EVEN6: "even6",  # EventLog6
}
```

## Potential for System Cleanup

Several of these interfaces can be used for system cleanup and event log manipulation:

1. **EventLog6 (`\\pipe\\eventlog`)**: 
   - Can query and potentially clear event logs
   - Supports filtering and selective event retrieval
   - Modern interface for Windows Vista+

2. **Remote Registry (`\\pipe\\winreg`)**: 
   - Can modify registry keys related to event logs
   - Can access performance data
   - Can manipulate system configuration

3. **Service Control Manager (`\\pipe\\svcctl`)**: 
   - Can stop/start event log service
   - Can disable services
   - Can create/delete services for cleanup

4. **Task Scheduler (`\\pipe\\atsvc`)**: 
   - Can create tasks for deferred cleanup
   - Can run cleanup commands as SYSTEM
   - Hidden task support

## Security Considerations

- All pipes require authentication
- Some operations require administrative privileges
- RemoteRegistry service must be running for registry operations
- Event log operations require appropriate permissions
- Path traversal protections are implemented

## Additional Named Pipes (Not Yet Implemented)

Based on the research, these additional pipes could be implemented:

- `\\pipe\\lsarpc` - Local Security Authority
- `\\pipe\\samr` - Security Account Manager
- `\\pipe\\netlogon` - Domain authentication
- `\\pipe\\spoolss` - Print spooler service
- `\\pipe\\browser` - Computer browser service
- `\\pipe\\epmapper` - RPC endpoint mapper
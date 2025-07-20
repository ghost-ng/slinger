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

# Windows Named Pipe Enumeration via SMB/RPC: Technical Research

## Executive Summary

This research document provides comprehensive technical details on Windows named pipe enumeration via SMB/RPC, including implementation approaches for the Slinger framework. Named pipes are a critical component of Windows inter-process communication (IPC) that can be enumerated remotely through SMB connections, providing valuable reconnaissance information for system administration and security testing.

## 1. What are Windows Named Pipes and How They Work

### 1.1 Named Pipe Fundamentals

**Definition**: Named pipes are a form of inter-process communication (IPC) in Windows that allows processes to communicate locally or across networks through the SMB protocol.

**Technical Implementation**:
- Named pipes are implemented by the NPFS.SYS (Named Pipe File System) driver
- They appear as files in the `\\.\pipe\` namespace on local systems
- Remotely accessible via the IPC$ share as `\\target\pipe\pipename`
- Each pipe has a unique name and can support bidirectional communication

**Communication Model**:
```
Client Process → Named Pipe → Server Process
     ↓              ↓             ↓
   SMB Client → IPC$ Share → Remote Service
```

### 1.2 Named Pipe Types

**1. Local Named Pipes**: Communication between processes on the same machine
**2. Remote Named Pipes**: Communication across network via SMB protocol
**3. Anonymous Pipes**: Unnamed pipes for parent-child process communication

### 1.3 Security Context

Named pipes support **impersonation**, allowing the server process to impersonate the client's security context using `ImpersonateNamedPipeClient()` API. This requires `SeImpersonatePrivilege` and is a common attack vector for privilege escalation.

## 2. Remote Named Pipe Enumeration via SMB/RPC

### 2.1 SMB Transport Layer

**Protocol Stack**:
```
Application Layer (WMI, Services, Registry)
         ↓
    MSRPC Layer
         ↓
   Named Pipes Layer
         ↓
    SMB Protocol
         ↓
   TCP/IP (Port 445)
```

### 2.2 IPC$ Share Access

The IPC$ share is a special administrative share that:
- Provides access to named pipes for inter-process communication
- Does not allow file system access
- Enables RPC service communication
- May allow NULL session access on older Windows versions

### 2.3 Enumeration Methods

**Method 1: Direct Named Pipe Discovery**
- Connect to IPC$ share
- Attempt to list contents of `\\target\pipe\` directory
- Enumerate available pipe names

**Method 2: RPC Endpoint Enumeration**
- Query the RPC Endpoint Mapper (`\pipe\epmapper`)
- Enumerate registered RPC services and their associated named pipes
- Use tools like `rpcdump.py` from Impacket

**Method 3: Service-Specific Enumeration**
- Connect to known named pipes (e.g., `\pipe\srvsvc`, `\pipe\samr`)
- Query service capabilities and information
- Infer additional named pipes based on service responses

## 3. Information Gathered from Named Pipes

### 3.1 Named Pipe Names and Functions

**Common Named Pipes**:
```
\pipe\epmapper      - RPC Endpoint Mapper (DCOM/WMI)
\pipe\lsarpc        - Local Security Authority (LSA) RPC
\pipe\samr          - Security Account Manager (SAM) RPC
\pipe\svcctl        - Service Control Manager RPC
\pipe\atsvc         - Task Scheduler (AT Service) RPC
\pipe\eventlog      - Event Log Service RPC
\pipe\winreg        - Windows Registry RPC
\pipe\srvsvc        - Server Service RPC
\pipe\wkssvc        - Workstation Service RPC
\pipe\spoolss       - Print Spooler Service RPC
\pipe\netlogon      - Netlogon Service RPC
\pipe\trkwks        - Distributed Link Tracking Client
\pipe\InitShutdown  - System Shutdown Service
\pipe\ntsvcs        - NT Services RPC
```

### 3.2 Information Types

**1. Service Discovery**:
- Available RPC services
- Service versions and capabilities
- Active service endpoints

**2. System Information**:
- Operating system version
- Domain membership status
- Installed services and features

**3. User and Group Information**:
- Local user accounts (via SAMR)
- Domain information
- Group memberships

**4. Network Information**:
- Active sessions
- Network shares
- Connected users

### 3.3 Permissions and Access Control

Named pipes have individual access control lists (ACLs) that determine:
- Who can connect to the pipe
- What operations are permitted
- Authentication requirements

## 4. Security Implications

### 4.1 Attack Vectors

**1. Information Disclosure**:
- Enumerate system services and configurations
- Discover user accounts and groups
- Identify potential attack targets

**2. Lateral Movement**:
- Use named pipes for command execution (psexec, wmiexec)
- Pivot through compromised systems
- Maintain persistence through service manipulation

**3. Privilege Escalation**:
- Named pipe impersonation attacks
- Service account token theft
- DLL hijacking via service manipulation

**4. Defense Evasion**:
- Blend malicious traffic with legitimate SMB communications
- Bypass firewall restrictions (uses standard SMB port 445)
- Avoid detection by using legitimate Windows APIs

### 4.2 Common Exploitation Scenarios

**Scenario 1: NULL Session Enumeration**
```python
# Pseudo-code for NULL session named pipe enumeration
connection = SMBConnection('target', null_session=True)
connection.connect_tree('IPC$')
pipes = connection.list_directory('\\pipe\\')
```

**Scenario 2: Authenticated Service Enumeration**
```python
# Use valid credentials to enumerate services
connection = SMBConnection('target', username='user', password='pass')
rpc_client = DCERPCConnection(connection, '\pipe\svcctl')
services = rpc_client.enumerate_services()
```

## 5. SMB Protocol Implementation Challenges and Solutions

### 5.1 Technical Implementation Challenges

**Primary Challenge: IPC$ Share Directory Listing Restrictions**
According to recent research findings, there are specific technical limitations when attempting to enumerate named pipes:

- **Share Type Limitation**: When listing the IPC$ share of a remote system, the SMB Tree Connect Response indicates Share Type 0x02 (named pipe), whereas regular file shares return 0x01 (disk)
- **API Restrictions**: Standard Windows APIs cannot list IPC$ share contents remotely - the directory listing fails because Share Type 0x02 is not supported for standard file listing operations
- **Individual Pipe Testing**: While the Win32 APIs can determine existence of a specific remote named pipe with `\\server\IPC$\pipename`, listing the `\\server\IPC$\` "folder" results in an error

**Workaround Solutions**
Research shows that specialized SMB implementations can bypass these limitations:

- **Custom SMB Stack**: Tools like Impacket's smbclient.py implement the entire SMB stack themselves and can manually call SMB functions like `SMB2_FIND_FULL_DIRECTORY_INFO` regardless of the Tree Connect Response
- **Direct Protocol Calls**: These implementations can call the same `NtQueryDirectoryFile` API that would normally fail through direct SMB protocol operations

### 5.2 SMB Protocol Methods for Named Pipe Enumeration

**SMB2_FIND_FULL_DIRECTORY_INFO Method**
```python
# This SMB function can be called directly to bypass API restrictions
# Tools like smbclient.py use this approach:
# - Connect to IPC$ share (returns Share Type 0x02)
# - Call SMB2_FIND_FULL_DIRECTORY_INFO directly
# - Parse directory information regardless of share type restrictions
```

**SMB2 QUERY_DIRECTORY Request Implementation**
```python
# SMB2 QUERY_DIRECTORY Request packet structure:
# - Information Level: SMB2_FIND_FULL_DIRECTORY_INFO
# - File Pattern: "\\pipe\\*" for named pipe enumeration
# - Search Flags: RESTART_SCANS | RETURN_SINGLE_ENTRY
```

### 5.3 Connection Management for Multiple Shares

**Maintaining Multiple Tree Connections**
Research indicates that SMB clients can maintain connections to multiple shares simultaneously:

```
SMB Session (authenticated)
├── Tree Connect: C$ (disk share) - TID 1
├── Tree Connect: IPC$ (pipe share) - TID 2
└── Tree Connect: ADMIN$ (disk share) - TID 3
```

**File ID (FID) Management**
- FIDs are unique per SMB connection, not per share
- Each share connection has its own Tree ID (TID)
- Connection reuse reduces overhead and maintains session state

## 6. Relation to Existing Slinger Codebase

### 6.1 Current Named Pipe Usage in Slinger

**Existing Implementation Analysis** (`src/slingerpkg/lib/dcetransport.py`):

```python
def _connect(self, named_pipe):
    self.pipe = "\\" + named_pipe
    if self.conn is None:
        raise Exception("SMB connection is not initialized")
    rpctransport = transport.SMBTransport(
        self.conn.getRemoteHost(), filename=self.pipe, smb_connection=self.conn
    )
    self.dce = rpctransport.get_dce_rpc()
    self.dce.connect()
    self.is_connected = True
```

**Currently Supported Named Pipes**:
- `winreg` - Windows Registry operations
- `svcctl` - Service Control Manager operations
- `srvsvc` - Server service operations (share enumeration)
- `eventlog` - Event log access (via WMI implementation)

### 6.2 Python SMB Libraries for Named Pipe Enumeration

**Impacket Library (Current Foundation)**
Slinger already uses Impacket, which provides the necessary capabilities:
- **Proven Functionality**: Impacket's smbclient.py successfully enumerates named pipes via IPC$
- **SMB Stack Implementation**: Full SMB protocol implementation that can bypass standard API restrictions
- **Direct Protocol Access**: Can call SMB2_FIND_FULL_DIRECTORY_INFO regardless of Tree Connect Response

**Alternative Libraries Considered**:

1. **smbprotocol** - Modern Python SMBv2/v3 client
   - Advantages: Modern SMBv2/v3 focused implementation
   - Considerations: Would require additional dependency and integration work

2. **pysmb** - Alternative SMB/CIFS library
   - Advantages: Well-documented SMB1/SMB2 support
   - Considerations: Different API patterns from current Impacket usage

**Recommendation**: Continue with Impacket-based implementation for consistency with existing codebase.

### 6.3 Information Disclosure Potential

**Security Intelligence from Named Pipe Enumeration**:
Research shows that named pipe enumeration can reveal significant system information:

- **Active Services**: Windows Search service (MsFteWds), Terminal Services (TSVCPIPE)
- **Application Usage**: Chromium-based browsers (mojo.*), Adobe Creative Cloud services
- **Development Tools**: SSH agents, PowerShell processes, Wireshark usage
- **System State**: Service states, available RPC interfaces, authentication requirements

**Example Information Patterns**:
```
Discovered Pipes → System Intelligence
\pipe\TSVCPIPE → RDP/Terminal Services active
\pipe\MsFteWds → Windows Search service running
\pipe\mojo.* → Chromium-based browser in use
\pipe\spoolss → Print services available
\pipe\sql\query → SQL Server installation detected
```

### 6.4 Integration Points

**1. SMB Connection Infrastructure**:
Slinger already has robust SMB connection management through:
- `smblib.py` - SMB client operations
- `dcetransport.py` - DCE/RPC transport over SMB
- `slingerclient.py` - High-level client coordination

**2. Authentication Context**:
- Existing credential management
- NTLM/Kerberos authentication support
- Session management

**3. RPC Infrastructure**:
- Impacket DCE/RPC bindings
- UUID endpoint management
- Error handling and recovery

### 5.3 Current Limitations

**Missing Capabilities**:
1. **Named Pipe Discovery**: No functionality to enumerate available named pipes
2. **Comprehensive Pipe Information**: Limited information gathering about pipe properties
3. **Dynamic Pipe Detection**: No runtime discovery of new or custom named pipes
4. **Pipe Security Analysis**: No capability to analyze pipe permissions or security

## 7. Practical Implementation Approaches for Slinger

### 7.1 Connection Management Strategy (Preserve Current Shares)

**Key Requirement**: Maintain existing share connections while adding IPC$ enumeration capability.

**Implementation Approach**:
```python
def enumerate_named_pipes_without_disconnect(self):
    """
    Enumerate named pipes while preserving existing share connections
    Uses Impacket's SMB connection to add IPC$ tree without disconnecting current shares
    """
    current_shares = self.get_current_tree_connections()  # Preserve existing state

    try:
        # Add IPC$ tree connection (doesn't disconnect existing shares)
        ipc_tree_id = self.conn.connectTree('IPC$')

        # Method 1: Attempt direct directory listing (may fail due to share type)
        pipes_direct = self._attempt_direct_pipe_listing(ipc_tree_id)

        # Method 2: Use SMB2_FIND_FULL_DIRECTORY_INFO bypass (Impacket approach)
        pipes_bypass = self._enumerate_pipes_via_smb_bypass(ipc_tree_id)

        # Method 3: RPC endpoint enumeration fallback
        pipes_rpc = self._enumerate_pipes_via_rpc_endpoints()

        # Combine and deduplicate results
        all_pipes = self._merge_pipe_results(pipes_direct, pipes_bypass, pipes_rpc)

        return all_pipes

    except Exception as e:
        print_debug(f"Named pipe enumeration failed: {e}")
        return []

    finally:
        # IPC$ tree connection remains active for potential future use
        # Original share connections remain untouched
        pass
```

**Connection State Management**:
```python
def get_current_tree_connections(self):
    """Track current share connections to preserve them"""
    return {
        'tree_connections': self.conn.getTreeConnections(),
        'current_share': getattr(self, 'current_share', None),
        'current_path': getattr(self, 'current_path', '\\')
    }
```

### 7.2 Impacket-Based SMB2_FIND_FULL_DIRECTORY_INFO Implementation

**Core Implementation Using Impacket's Bypass Approach**:
```python
def _enumerate_pipes_via_smb_bypass(self, ipc_tree_id):
    """
    Use Impacket's approach to call SMB2_FIND_FULL_DIRECTORY_INFO directly
    This bypasses the standard API restrictions for IPC$ share enumeration
    """
    try:
        # Impacket's smbclient.py approach - direct SMB protocol calls
        from impacket.smb3structs import *
        from impacket.nt_errors import *

        # Open the pipe directory for enumeration
        pipe_fid = self.conn.create(
            ipc_tree_id,
            '\\pipe\\',  # Target the pipe directory
            FILE_READ_DATA | FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            0
        )

        # Use FIND_FULL_DIRECTORY_INFO to enumerate
        files = self.conn.queryDirectory(
            ipc_tree_id,
            pipe_fid,
            '\\pipe\\*',  # Search pattern for all pipes
            maxBufferSize=65535
        )

        pipes = []
        for file_info in files:
            if file_info['FileName'] not in ['.', '..']:
                pipe_data = {
                    'name': file_info['FileName'],
                    'creation_time': file_info['CreationTime'],
                    'last_access_time': file_info['LastAccessTime'],
                    'attributes': file_info['FileAttributes'],
                    'method': 'smb_bypass'
                }
                pipes.append(pipe_data)

        self.conn.close(ipc_tree_id, pipe_fid)
        return pipes

    except Exception as e:
        print_debug(f"SMB bypass enumeration failed: {e}")
        return []
```

### 7.3 Fallback RPC Endpoint Enumeration

**RPC Endpoint Mapper Approach**:
```python
def _enumerate_pipes_via_rpc_endpoints(self):
    """
    Enumerate named pipes through RPC endpoint mapper
    Provides service context for discovered pipes
    """
    try:
        # Use existing DCETransport for epmapper
        self._connect("epmapper")

        from impacket.dcerpc.v5 import epm
        self._bind(epm.MSRPC_UUID_PORTMAP)

        # Query all endpoints
        resp = epm.hept_lookup(None, dce=self.dce)

        pipes = []
        for entry in resp:
            # Extract pipe name from tower floors
            pipe_name = self._extract_pipe_from_tower(entry['tower'])
            if pipe_name:
                pipe_data = {
                    'name': pipe_name,
                    'uuid': str(entry['tower']['Floors'][0]['ProtocolData']),
                    'annotation': entry.get('annotation', ''),
                    'method': 'rpc_endpoint'
                }
                pipes.append(pipe_data)

        self._disconnect()
        return pipes

    except Exception as e:
        print_debug(f"RPC endpoint enumeration failed: {e}")
        return []
```

## 8. Implementation Approaches

### 8.1 Impacket-Based Implementation

**Core Libraries Required**:
```python
from impacket.dcerpc.v5 import transport, srvs, epm
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SMBConnection
```

**Method 1: RPC Endpoint Mapper Enumeration**
```python
def enumerate_rpc_endpoints(self):
    """Enumerate RPC endpoints via epmapper"""
    try:
        # Connect to epmapper named pipe
        self._connect("epmapper")
        self._bind(epm.MSRPC_UUID_PORTMAP)

        # Query endpoint map
        resp = epm.hept_lookup(None, dce=self.dce)
        endpoints = []

        for entry in resp:
            endpoint_info = {
                'uuid': str(entry['tower']['Floors'][0]['ProtocolData']),
                'annotation': entry.get('annotation', ''),
                'protocol': self._parse_protocol_data(entry['tower']),
                'pipe_name': self._extract_pipe_name(entry['tower'])
            }
            endpoints.append(endpoint_info)

        return endpoints
    except Exception as e:
        print_debug(f"RPC endpoint enumeration failed: {e}")
        return []
```

**Method 2: Direct Named Pipe Enumeration**
```python
def enumerate_named_pipes(self):
    """Enumerate named pipes by attempting directory listing"""
    try:
        # Connect to IPC$ share
        tree_id = self.conn.connectTree('IPC$')

        # Attempt to list \pipe\ directory
        pipe_files = []
        try:
            files = self.conn.listPath('IPC$', '\\pipe\\*')
            for file_info in files:
                if file_info.get_longname() not in ['.', '..']:
                    pipe_info = {
                        'name': file_info.get_longname(),
                        'creation_time': file_info.get_creation_time(),
                        'last_access_time': file_info.get_last_access_time(),
                        'attributes': file_info.get_attributes()
                    }
                    pipe_files.append(pipe_info)
        except Exception as e:
            print_debug(f"Direct pipe listing failed: {e}")

        return pipe_files
    except Exception as e:
        print_debug(f"Named pipe enumeration failed: {e}")
        return []
```

**Method 3: Service-Based Discovery**
```python
def discover_pipes_via_services(self):
    """Discover named pipes through service enumeration"""
    discovered_pipes = {}

    # Service to pipe mappings
    service_pipes = {
        'svcctl': ['svcctl'],
        'srvsvc': ['srvsvc'],
        'winreg': ['winreg'],
        'eventlog': ['eventlog'],
        'samr': ['samr', 'lsass'],
        'lsarpc': ['lsarpc', 'lsass']
    }

    for service, pipes in service_pipes.items():
        try:
            self._connect(service)
            if self.is_connected:
                discovered_pipes[service] = {
                    'status': 'accessible',
                    'pipes': pipes,
                    'uuid': self.current_bind
                }
            self._disconnect()
        except Exception as e:
            discovered_pipes[service] = {
                'status': 'error',
                'error': str(e),
                'pipes': pipes
            }

    return discovered_pipes
```

### 6.2 Enhanced Information Gathering

**Pipe Capability Detection**:
```python
def analyze_pipe_capabilities(self, pipe_name):
    """Analyze what operations are available on a named pipe"""
    capabilities = {
        'pipe_name': pipe_name,
        'accessible': False,
        'operations': [],
        'security_info': {},
        'service_info': {}
    }

    try:
        # Attempt connection
        self._connect(pipe_name)
        capabilities['accessible'] = True

        # Detect available RPC interfaces
        uuid_map = {
            srvs.MSRPC_UUID_SRVS: 'Server Service',
            scmr.MSRPC_UUID_SCMR: 'Service Control Manager',
            rrp.MSRPC_UUID_RRP: 'Remote Registry',
            # Add more UUID mappings
        }

        for uuid, service_name in uuid_map.items():
            try:
                self._bind(uuid)
                capabilities['operations'].append(service_name)
            except:
                continue

        # Gather additional service information
        if pipe_name == 'srvsvc':
            capabilities['service_info'] = self._get_server_info()
        elif pipe_name == 'svcctl':
            capabilities['service_info'] = self._get_service_list()

    except Exception as e:
        capabilities['error'] = str(e)

    return capabilities
```

### 6.3 Security Information Gathering

**Pipe Permission Analysis**:
```python
def get_pipe_security_info(self, pipe_name):
    """Gather security information about a named pipe"""
    security_info = {
        'pipe_name': pipe_name,
        'access_allowed': False,
        'auth_required': True,
        'impersonation_level': 'unknown',
        'access_rights': []
    }

    try:
        # Test anonymous access
        if self._test_anonymous_access(pipe_name):
            security_info['auth_required'] = False
            security_info['access_allowed'] = True

        # Test with current credentials
        elif self._test_authenticated_access(pipe_name):
            security_info['access_allowed'] = True

        # Determine available access rights
        security_info['access_rights'] = self._enumerate_access_rights(pipe_name)

    except Exception as e:
        security_info['error'] = str(e)

    return security_info
```

## 7. DCE/RPC Interfaces and SMB Calls

### 7.1 Key RPC Interfaces for Named Pipe Enumeration

**Endpoint Mapper Interface**:
```python
# UUID: 4B324FC8-1670-01D3-1278-5A47BF6EE188
import impacket.dcerpc.v5.epm as epm

# Operations:
# - ept_lookup: Enumerate registered endpoints
# - ept_map: Map service UUID to endpoint
# - ept_lookup_handle_t: Handle-based enumeration
```

**Server Service Interface**:
```python
# UUID: 4B01A2C8-7D2B-11D2-B2F3-0060979AA2FB
import impacket.dcerpc.v5.srvs as srvs

# Key operations for named pipe discovery:
# - NetrShareEnum: Enumerate network shares
# - NetrServerGetInfo: Get server information
# - NetrSessionEnum: Enumerate active sessions
```

**Service Control Manager Interface**:
```python
# UUID: 367ABB81-9844-35F1-AD32-98F038001003
import impacket.dcerpc.v5.scmr as scmr

# Operations:
# - EnumServicesStatusW: Enumerate services (reveals pipe usage)
# - OpenSCManagerW: Open service control manager
# - QueryServiceConfigW: Get service configuration
```

### 7.2 SMB Operations for Named Pipe Access

**Tree Connect Operations**:
```python
# Connect to IPC$ share for named pipe access
tree_id = smb_connection.connectTree('IPC$')

# Create/Open named pipe file
file_id = smb_connection.create(
    tree_id,
    '\\pipe\\pipename',
    FILE_READ_DATA,
    FILE_SHARE_READ
)
```

**Named Pipe Specific SMB Calls**:
```python
# SMB_COM_OPEN_ANDX - Open named pipe
# SMB_COM_READ_ANDX - Read from named pipe
# SMB_COM_WRITE_ANDX - Write to named pipe
# SMB_COM_TRANSACTION - RPC over SMB transaction
# SMB_COM_CLOSE - Close named pipe handle
```

## 8. Implementation Plan for Slinger Integration

### 8.1 New Module: `named_pipes.py`

**Location**: `src/slingerpkg/lib/named_pipes.py`

**Class Structure**:
```python
class NamedPipeEnumerator:
    def __init__(self, smb_connection, dce_transport):
        self.conn = smb_connection
        self.dce = dce_transport
        self.discovered_pipes = {}

    def enumerate_all_pipes(self):
        """Comprehensive named pipe enumeration"""

    def enumerate_rpc_endpoints(self):
        """RPC endpoint mapper enumeration"""

    def enumerate_service_pipes(self):
        """Service-specific pipe discovery"""

    def analyze_pipe_capabilities(self, pipe_name):
        """Analyze pipe functionality"""

    def get_pipe_security_info(self, pipe_name):
        """Security information gathering"""

    def generate_pipe_report(self):
        """Generate comprehensive report"""
```

### 8.2 CLI Integration

**New Commands**:
```python
# In src/slingerpkg/utils/cli.py
parser_pipes = subparsers.add_parser('pipes', help='Named pipe operations')
pipes_subparsers = parser_pipes.add_subparsers(dest='pipes_action')

# pipes list - List available named pipes
parser_pipes_list = pipes_subparsers.add_parser('list', help='List named pipes')
parser_pipes_list.add_argument('--method', choices=['rpc', 'direct', 'service'],
                               default='all', help='Enumeration method')

# pipes info - Get detailed pipe information
parser_pipes_info = pipes_subparsers.add_parser('info', help='Pipe information')
parser_pipes_info.add_argument('pipe_name', help='Named pipe to analyze')

# pipes test - Test pipe accessibility
parser_pipes_test = pipes_subparsers.add_parser('test', help='Test pipe access')
parser_pipes_test.add_argument('pipe_name', help='Named pipe to test')
```

### 8.3 Integration with Existing DCETransport

**Enhanced DCETransport Class**:
```python
# In src/slingerpkg/lib/dcetransport.py
class DCETransport:
    def __init__(self, host, username, port, smb_connection):
        # ... existing initialization ...
        self.pipe_enumerator = None

    def init_pipe_enumeration(self):
        """Initialize named pipe enumeration capabilities"""
        from slingerpkg.lib.named_pipes import NamedPipeEnumerator
        self.pipe_enumerator = NamedPipeEnumerator(self.conn, self)

    def enumerate_named_pipes(self, method='all'):
        """Enumerate available named pipes"""
        if not self.pipe_enumerator:
            self.init_pipe_enumeration()
        return self.pipe_enumerator.enumerate_all_pipes()
```

### 8.4 Output Formatting

**Tabulated Output Example**:
```python
def format_pipe_list(pipes_data):
    """Format named pipe list for display"""
    headers = ['Pipe Name', 'Status', 'Service', 'Access Level', 'Description']
    rows = []

    for pipe in pipes_data:
        rows.append([
            pipe['name'],
            pipe['status'],
            pipe.get('service', 'Unknown'),
            pipe.get('access_level', 'Unknown'),
            pipe.get('description', '')
        ])

    return tabulate(rows, headers=headers, tablefmt='grid')
```

## 9. Testing and Validation

### 9.1 Test Scenarios

**Test 1: Basic Named Pipe Discovery**
```python
def test_basic_pipe_discovery():
    # Test against known Windows system
    # Verify common pipes are discovered
    # Validate pipe names and accessibility
```

**Test 2: RPC Endpoint Enumeration**
```python
def test_rpc_endpoint_enumeration():
    # Test epmapper functionality
    # Verify endpoint-to-pipe mapping
    # Validate UUID resolution
```

**Test 3: Security Context Testing**
```python
def test_security_contexts():
    # Test NULL session access
    # Test authenticated access
    # Verify permission detection
```

### 9.2 Integration Testing

**Test with Existing Slinger Commands**:
- Verify named pipe enumeration works with existing SMB connections
- Test interaction with service enumeration commands
- Validate DCE/RPC transport compatibility

### 9.3 Error Handling

**Common Error Scenarios**:
- Network connectivity issues
- Authentication failures
- Permission denied on specific pipes
- Malformed RPC responses
- SMB connection timeouts

## 10. Security Considerations

### 10.1 Operational Security

**Stealth Considerations**:
- Named pipe enumeration may trigger security alerts
- Excessive RPC calls may be logged and detected
- Failed authentication attempts create audit trails

**Mitigation Strategies**:
- Implement rate limiting for enumeration attempts
- Use existing authenticated sessions when possible
- Provide verbose logging for troubleshooting but quiet operation by default

### 10.2 Legal and Ethical Considerations

**Legitimate Use Cases**:
- System administration and inventory
- Security assessment with proper authorization
- Network troubleshooting and diagnostics

**Potential Misuse**:
- Unauthorized system reconnaissance
- Preparation for lateral movement attacks
- Information gathering for privilege escalation

## 11. Performance Considerations

### 11.1 Enumeration Efficiency

**Optimization Strategies**:
- Parallel enumeration of multiple pipes
- Caching of discovered pipe information
- Intelligent fallback between enumeration methods
- Timeout management for unresponsive pipes

### 11.2 Resource Management

**Memory Usage**:
- Efficient storage of pipe metadata
- Cleanup of temporary RPC connections
- Management of multiple SMB tree connections

**Network Usage**:
- Minimize redundant RPC calls
- Reuse existing SMB connections
- Batch operations where possible

## 12. Future Enhancements

### 12.1 Advanced Capabilities

**Real-time Monitoring**:
- Monitor for new named pipes
- Detect pipe creation/deletion events
- Track pipe usage patterns

**Interactive Pipe Communication**:
- Direct communication with custom named pipes
- Pipe-based command execution
- Data exfiltration through pipes

### 12.2 Integration Opportunities

**Plugin System Integration**:
- Named pipe enumeration plugins for specific services
- Custom analysis modules for discovered pipes
- Automated exploitation modules

**Reporting and Analytics**:
- Trend analysis of discovered pipes
- Comparison across multiple systems
- Risk assessment based on exposed pipes

## 13. Conclusion

Named pipe enumeration represents a valuable addition to the Slinger framework, providing comprehensive reconnaissance capabilities for Windows systems. The implementation leverages existing SMB connection infrastructure while adding sophisticated RPC endpoint discovery and analysis capabilities.

**Key Benefits**:
1. **Enhanced Reconnaissance**: Comprehensive service discovery through named pipe enumeration
2. **Security Assessment**: Identification of potentially vulnerable IPC mechanisms
3. **System Understanding**: Deep insight into Windows service architecture
4. **Attack Surface Mapping**: Identification of potential lateral movement paths

**Implementation Complexity**: **Medium to High**
- Requires deep understanding of Windows RPC and SMB protocols
- Complex error handling for various authentication and permission scenarios
- Integration with existing Slinger architecture requires careful planning

**Recommended Approach**:
1. Implement basic named pipe discovery functionality first
2. Add RPC endpoint enumeration capabilities
3. Enhance with security analysis features
4. Integrate comprehensive reporting and output formatting

This research provides the foundation for implementing robust named pipe enumeration capabilities in the Slinger framework, supporting both legitimate system administration tasks and authorized security assessments.

## 14. Practical Implementation Recommendations for `enumpipes` Command

### 14.1 Command Interface Design

**Proposed Command Syntax**:
```bash
# Basic enumeration
enumpipes

# Detailed enumeration with service information
enumpipes --detailed

# Specific enumeration method
enumpipes --method rpc          # RPC endpoint enumeration only
enumpipes --method smb          # SMB directory enumeration only
enumpipes --method all          # All methods (default)

# Output control
enumpipes --output pipes.txt    # Save to file
enumpipes --format json         # JSON output format
enumpipes --quiet              # Minimal output

# Filtering options
enumpipes --filter admin       # Administrative pipes only
enumpipes --filter service     # Service-related pipes only
enumpipes --accessible-only    # Only show accessible pipes
```

### 14.2 Integration with Existing Slinger Architecture

**File Location**: `src/slingerpkg/lib/named_pipes.py`

**Integration Points**:
1. **CLI Parser**: Add to `src/slingerpkg/utils/cli.py`
2. **Client Integration**: Extend `SlingerClient` class in `src/slingerpkg/lib/slingerclient.py`
3. **DCE Transport**: Enhance `src/slingerpkg/lib/dcetransport.py` for RPC enumeration
4. **Output Formatting**: Use existing `src/slingerpkg/utils/printlib.py` functions

**Class Integration**:
```python
# In src/slingerpkg/lib/slingerclient.py
class SlingerClient(SMBLib, WinReg, SchTasks, SCM, Secrets, AtExec, HasDump):
    def __init__(self, host, username, port, smb_connection):
        # ... existing initialization ...
        self.named_pipe_enumerator = None

    def enumerate_named_pipes(self, method='all', detailed=False):
        """
        Enumerate named pipes without disconnecting from current shares
        """
        if not self.named_pipe_enumerator:
            from slingerpkg.lib.named_pipes import NamedPipeEnumerator
            self.named_pipe_enumerator = NamedPipeEnumerator(self.conn, self.dce_transport)

        return self.named_pipe_enumerator.enumerate_all_pipes(method=method, detailed=detailed)
```

### 14.3 Expected Output Format

**Standard Output**:
```
[*] Enumerating named pipes on \\target\IPC$...
[*] Using method: all (smb + rpc + service detection)

[+] Administrative Pipes:
    ├── lsarpc          (LSA RPC Interface) [Accessible]
    ├── samr            (SAM Database Access) [Accessible]
    ├── svcctl          (Service Control Manager) [Accessible]
    └── winreg          (Remote Registry) [Access Denied]

[+] File & Print Services:
    ├── srvsvc          (Server Service) [Accessible]
    ├── wkssvc          (Workstation Service) [Accessible]
    └── spoolss         (Print Spooler) [Accessible]

[+] Application Pipes:
    ├── sql\query       (SQL Server Default) [Not Tested]
    ├── TSVCPIPE        (Terminal Services) [Accessible]
    └── MsFteWds        (Windows Search) [Accessible]

[+] Browser/Application:
    ├── mojo.1234.567   (Chrome/Chromium) [Not Tested]
    └── mojo.890.123    (Chrome/Chromium) [Not Tested]

[*] Total: 12 named pipes discovered
[*] Accessible: 8, Access Denied: 1, Not Tested: 3
[*] Methods used: SMB bypass (8), RPC endpoints (4), Service detection (12)
```

**Detailed Output (--detailed flag)**:
```
[+] Pipe: lsarpc
    ├── UUID: 12345678-1234-5678-9abc-123456789abc
    ├── Service: Local Security Authority RPC
    ├── Access: Read/Write
    ├── Authentication: Required
    ├── Creation Time: 2025-01-14 10:30:45
    ├── Last Access: 2025-01-14 15:42:12
    └── Method: SMB bypass enumeration
```

### 14.4 Error Handling and Graceful Degradation

**Connection Preservation**:
- Always maintain existing share connections
- Use separate IPC$ tree connection for enumeration
- Graceful fallback if primary enumeration method fails

**Error Scenarios**:
```python
def handle_enumeration_errors(self, error, method):
    """Graceful error handling with informative messages"""
    error_patterns = {
        'access_denied': "Insufficient privileges for {method} enumeration",
        'connection_failed': "Cannot connect to IPC$ share",
        'smb_version': "SMB version incompatible with {method} method",
        'timeout': "Enumeration timeout - target may be overloaded"
    }

    # Provide helpful guidance
    if 'access_denied' in str(error).lower():
        print_warning("Try alternative authentication methods or different user account")
    elif 'connection_failed' in str(error).lower():
        print_warning("IPC$ share may be disabled - try RPC endpoint enumeration only")
```

### 14.5 Security and Operational Considerations

**Stealth Options**:
```bash
enumpipes --stealth            # Rate-limited enumeration
enumpipes --timing paranoid    # Very slow, careful enumeration
enumpipes --known-only         # Test only well-known pipes
```

**Logging and Audit Trail**:
- Log all enumeration attempts for audit purposes
- Respect existing verbose/debug output settings
- Provide timing information for performance analysis

**Performance Optimization**:
- Parallel enumeration where safe
- Caching of results within session
- Intelligent retry logic for network issues

This comprehensive research provides all the technical foundation needed to implement a robust `enumpipes` command that integrates seamlessly with Slinger's existing architecture while providing valuable named pipe reconnaissance capabilities through multiple enumeration methods.
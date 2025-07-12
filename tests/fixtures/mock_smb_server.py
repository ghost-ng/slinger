"""
Mock SMB Server for testing Slinger without real Windows targets
"""
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import MagicMock
import struct


class MockFile:
    """Mock file object for SMB operations"""
    def __init__(self, name: str, content: bytes = b'', is_directory: bool = False):
        self.name = name
        self.content = content
        self.is_directory = is_directory
        self.size = len(content) if not is_directory else 0
        self.created_time = datetime.now()
        self.modified_time = datetime.now()
        self.attributes = 0x10 if is_directory else 0x20  # FILE_ATTRIBUTE_DIRECTORY or FILE_ATTRIBUTE_ARCHIVE


class MockShare:
    """Mock SMB share"""
    def __init__(self, name: str, remark: str = '', type_: int = 0x0):
        self.name = name
        self.remark = remark
        self.type = type_
        self.files: Dict[str, MockFile] = {}
        self.current_path = "\\"
        
        # Initialize with some default directories
        if name == "C$":
            self._init_c_drive()
    
    def _init_c_drive(self):
        """Initialize C$ share with typical Windows structure"""
        # Create directory structure
        self.files["\\"] = MockFile("\\", is_directory=True)
        self.files["\\Windows"] = MockFile("Windows", is_directory=True)
        self.files["\\Windows\\System32"] = MockFile("System32", is_directory=True)
        self.files["\\Program Files"] = MockFile("Program Files", is_directory=True)
        self.files["\\Users"] = MockFile("Users", is_directory=True)
        self.files["\\Users\\Administrator"] = MockFile("Administrator", is_directory=True)
        
        # Add some files
        self.files["\\Windows\\System32\\cmd.exe"] = MockFile("cmd.exe", b"MZ\x90\x00" + b"\x00" * 100)
        self.files["\\Users\\Administrator\\Desktop"] = MockFile("Desktop", is_directory=True)
        self.files["\\test.txt"] = MockFile("test.txt", b"Hello from mock SMB server!")


class MockSMBConnection:
    """Mock SMB connection that simulates impacket's SMBConnection"""
    
    def __init__(self):
        self.connected = False
        self.authenticated = False
        self.shares: Dict[str, MockShare] = {}
        self.current_share: Optional[str] = None
        self.tid: Optional[int] = None
        
        # Initialize default shares
        self._init_default_shares()
        
        # Error simulation flags
        self.simulate_auth_failure = False
        self.simulate_network_timeout = False
        self.simulate_access_denied = False
    
    def _init_default_shares(self):
        """Initialize default Windows shares"""
        self.shares["C$"] = MockShare("C$", "Default share")
        self.shares["ADMIN$"] = MockShare("ADMIN$", "Remote Admin")
        self.shares["IPC$"] = MockShare("IPC$", "Remote IPC", type_=0x3)
    
    def login(self, username: str, password: str, domain: str = '', lmhash: str = '', nthash: str = '', ntlm: bool = False) -> bool:
        """Simulate login"""
        if self.simulate_auth_failure:
            raise Exception("Authentication failed")
        
        self.authenticated = True
        self.username = username
        self.domain = domain
        return True
    
    def connectTree(self, share: str) -> int:
        """Connect to a share"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if self.simulate_access_denied:
            raise Exception("Access denied")
        
        if share in self.shares:
            self.current_share = share
            self.tid = hash(share) & 0xFFFF
            return self.tid
        else:
            raise Exception(f"Share {share} not found")
    
    def listShares(self) -> List[Dict[str, Any]]:
        """List available shares"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        return [
            {
                'shi1_netname': name.encode('utf-16le'),
                'shi1_type': share.type,
                'shi1_remark': share.remark.encode('utf-16le')
            }
            for name, share in self.shares.items()
        ]
    
    def listPath(self, shareName: str, path: str = '*') -> List[Tuple]:
        """List files in a path"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        # Normalize path
        if not path.startswith("\\"):
            path = "\\" + path
        
        if path == "*" or path == "\\*":
            path = "\\"
        
        # Remove wildcard if present
        if path.endswith("\\*"):
            path = path[:-2]
        
        results = []
        
        # Find all files in the requested directory
        for file_path, file_obj in share.files.items():
            # Get parent directory of file
            parent_dir = "\\".join(file_path.split("\\")[:-1])
            if not parent_dir:
                parent_dir = "\\"
            
            # Check if file is in the requested directory
            if parent_dir == path and file_path != path:
                # Create SMB directory entry tuple
                # Format: (filename, attributes, 0, 0, 0, 0, 0, 0, mtime, size, ?, ?, ?, shortname)
                entry = (
                    file_obj.name,  # Filename
                    file_obj.attributes,  # Attributes
                    0,  # Reserved
                    0,  # Creation time high
                    0,  # Creation time low
                    0,  # Last access time high
                    0,  # Last access time low
                    0,  # Last write time high
                    int(file_obj.modified_time.timestamp()),  # Last write time low
                    file_obj.size,  # File size
                    0,  # Reserved
                    0,  # Reserved
                    0,  # Reserved
                    file_obj.name[:8]  # Short name
                )
                results.append(entry)
        
        return results
    
    def getFile(self, shareName: str, pathName: str, callback: Any = None) -> bytes:
        """Download a file"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        if not pathName.startswith("\\"):
            pathName = "\\" + pathName
        
        if pathName in share.files and not share.files[pathName].is_directory:
            content = share.files[pathName].content
            if callback:
                callback(content)
            return content
        else:
            raise Exception(f"File {pathName} not found")
    
    def putFile(self, shareName: str, pathName: str, callback: Any = None) -> None:
        """Upload a file"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        if not pathName.startswith("\\"):
            pathName = "\\" + pathName
        
        # Read content from callback
        content = b""
        if callback:
            chunk = callback(8192)
            while chunk:
                content += chunk
                chunk = callback(8192)
        
        # Create file
        filename = pathName.split("\\")[-1]
        share.files[pathName] = MockFile(filename, content)
    
    def deleteFile(self, shareName: str, pathName: str) -> None:
        """Delete a file"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        if not pathName.startswith("\\"):
            pathName = "\\" + pathName
        
        if pathName in share.files:
            del share.files[pathName]
        else:
            raise Exception(f"File {pathName} not found")
    
    def createDirectory(self, shareName: str, pathName: str) -> None:
        """Create a directory"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        if not pathName.startswith("\\"):
            pathName = "\\" + pathName
        
        dirname = pathName.split("\\")[-1]
        share.files[pathName] = MockFile(dirname, is_directory=True)
    
    def deleteDirectory(self, shareName: str, pathName: str) -> None:
        """Delete a directory"""
        if not self.authenticated:
            raise Exception("Not authenticated")
        
        if shareName not in self.shares:
            raise Exception(f"Share {shareName} not found")
        
        share = self.shares[shareName]
        
        if not pathName.startswith("\\"):
            pathName = "\\" + pathName
        
        # Check if directory exists and is empty
        if pathName in share.files and share.files[pathName].is_directory:
            # Check if directory has any children
            has_children = any(
                fp.startswith(pathName + "\\") for fp in share.files.keys()
            )
            if has_children:
                raise Exception("Directory not empty")
            
            del share.files[pathName]
        else:
            raise Exception(f"Directory {pathName} not found")
    
    def close(self) -> None:
        """Close connection"""
        self.connected = False
        self.authenticated = False
        self.current_share = None
        self.tid = None


class MockDCERPCConnection:
    """Mock DCE/RPC connection for service and registry operations"""
    
    def __init__(self):
        self.services: Dict[str, Dict[str, Any]] = {}
        self.registry: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        
        # Initialize with some default services
        self._init_default_services()
        self._init_default_registry()
    
    def _init_default_services(self):
        """Initialize default Windows services"""
        self.services["Spooler"] = {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "status": "RUNNING",
            "type": "WIN32_OWN_PROCESS",
            "start_type": "AUTO_START",
            "binary_path": "C:\\Windows\\System32\\spoolsv.exe"
        }
        self.services["Themes"] = {
            "name": "Themes",
            "display_name": "Themes",
            "status": "RUNNING",
            "type": "WIN32_SHARE_PROCESS",
            "start_type": "AUTO_START",
            "binary_path": "C:\\Windows\\System32\\svchost.exe -k netsvcs"
        }
    
    def _init_default_registry(self):
        """Initialize default registry keys"""
        self.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"] = {
            "ProgramFilesDir": ("REG_SZ", "C:\\Program Files"),
            "SystemRoot": ("REG_SZ", "C:\\Windows"),
            "Version": ("REG_SZ", "10.0")
        }
        self.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler"] = {
            "DisplayName": ("REG_SZ", "Print Spooler"),
            "ImagePath": ("REG_EXPAND_SZ", "C:\\Windows\\System32\\spoolsv.exe"),
            "Start": ("REG_DWORD", 2)
        }


class MockSMBServer:
    """Main mock SMB server that combines all components"""
    
    def __init__(self, host: str = "192.168.1.100", port: int = 445):
        self.host = host
        self.port = port
        self.connection = MockSMBConnection()
        self.dce_connection = MockDCERPCConnection()
        
        # Track connections for testing
        self.connection_count = 0
        self.command_history: List[str] = []
    
    def get_connection(self) -> MockSMBConnection:
        """Get a mock SMB connection"""
        self.connection_count += 1
        return self.connection
    
    def get_dce_connection(self) -> MockDCERPCConnection:
        """Get a mock DCE/RPC connection"""
        return self.dce_connection
    
    def add_share(self, name: str, files: Optional[Dict[str, bytes]] = None) -> None:
        """Add a custom share with files"""
        share = MockShare(name)
        if files:
            for path, content in files.items():
                if not path.startswith("\\"):
                    path = "\\" + path
                filename = path.split("\\")[-1]
                is_dir = content is None
                share.files[path] = MockFile(
                    filename, 
                    content if not is_dir else b'', 
                    is_directory=is_dir
                )
        self.connection.shares[name] = share
    
    def add_service(self, name: str, **kwargs) -> None:
        """Add a service to the mock server"""
        self.dce_connection.services[name] = {
            "name": name,
            "display_name": kwargs.get("display_name", name),
            "status": kwargs.get("status", "STOPPED"),
            "type": kwargs.get("type", "WIN32_OWN_PROCESS"),
            "start_type": kwargs.get("start_type", "MANUAL"),
            "binary_path": kwargs.get("binary_path", f"C:\\Windows\\System32\\{name}.exe")
        }
    
    def add_registry_key(self, path: str, values: Dict[str, Tuple[str, Any]]) -> None:
        """Add a registry key with values"""
        self.dce_connection.registry[path] = values
    
    def add_task(self, name: str, **kwargs) -> None:
        """Add a scheduled task"""
        self.dce_connection.tasks[name] = {
            "name": name,
            "status": kwargs.get("status", "Ready"),
            "next_run": kwargs.get("next_run", "N/A"),
            "last_run": kwargs.get("last_run", "Never"),
            "command": kwargs.get("command", "")
        }
    
    def simulate_auth_failure(self) -> None:
        """Simulate authentication failure"""
        self.connection.simulate_auth_failure = True
    
    def simulate_network_timeout(self) -> None:
        """Simulate network timeout"""
        self.connection.simulate_network_timeout = True
    
    def simulate_access_denied(self) -> None:
        """Simulate access denied error"""
        self.connection.simulate_access_denied = True
    
    def reset_errors(self) -> None:
        """Reset all error simulations"""
        self.connection.simulate_auth_failure = False
        self.connection.simulate_network_timeout = False
        self.connection.simulate_access_denied = False
    
    def log_command(self, command: str) -> None:
        """Log a command for verification"""
        self.command_history.append(command)
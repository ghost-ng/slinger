#!/usr/bin/env python3
"""
Integration test with mock SMB server to test path validation in realistic scenario
"""
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, 'tests')

from unittest.mock import patch
from tests.fixtures.mock_smb_server import MockSMBServer
from tests.fixtures.cli_runner import SlingerTestRunner

def test_path_validation_with_mock_smb():
    """Test path issues with mock SMB server"""
    print("🔧 SETTING UP MOCK SMB SERVER")
    
    # Create mock server
    mock_server = MockSMBServer()
    
    # Add realistic file structure
    mock_server.add_share("C$", {
        "\\Windows\\System32\\cmd.exe": b"MZ\x90\x00",
        "\\Windows\\System32\\drivers": None,  # Directory
        "\\Users\\Administrator\\Documents": None,  # Directory
        "\\Users\\Administrator\\Documents\\report.pdf": b"PDF content",
        "\\temp\\upload.txt": b"Upload test"
    })
    
    print("✅ Mock SMB server configured")
    print("📁 File structure:")
    print("   C$\\Windows\\System32\\cmd.exe")
    print("   C$\\Users\\Administrator\\Documents\\report.pdf")
    print("   C$\\temp\\upload.txt")
    
    # Test with CLI runner
    with patch('impacket.smbconnection.SMBConnection') as mock_smb_class:
        mock_smb_class.return_value = mock_server.get_connection()
        
        runner = SlingerTestRunner(mock_server=mock_server)
        
        if runner.start(host="192.168.1.100", username="testuser", password="testpass"):
            print("✅ Mock session established")
            
            # Test 1: Path traversal via cd
            print("\n🧪 TEST 1: Path traversal")
            output = runner.send_command("use C$")
            print(f"Connected to C$: {output}")
            
            output = runner.send_command("cd Users\\Administrator")
            print(f"Changed to Users\\Administrator: {output}")
            
            # Attempt path traversal
            output = runner.send_command("cd ..\\..\\Windows\\System32")
            print(f"Path traversal attempt: {output}")
            
            # Test 2: PUT with path issues
            print("\n🧪 TEST 2: PUT command paths")
            output = runner.send_command("put /tmp/test.txt Documents\\uploaded.txt")
            print(f"PUT result: {output}")
            
            # Test 3: GET with absolute path
            print("\n🧪 TEST 3: GET with absolute path")
            output = runner.send_command("get \\Windows\\System32\\cmd.exe /tmp/cmd.exe")
            print(f"GET absolute path: {output}")
            
            runner.stop()
        else:
            print("❌ Failed to establish mock session")

if __name__ == "__main__":
    print("🧪 SMB INTEGRATION PATH TESTING")
    test_path_validation_with_mock_smb()
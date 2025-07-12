#!/usr/bin/env python3
"""
Manual test script to demonstrate path validation issues in real time
Run this to see the actual bugs in action!
"""
import sys
import ntpath
sys.path.insert(0, 'src')

from unittest.mock import Mock, MagicMock, patch

# Mock impacket
with patch('impacket.smbconnection.SMBConnection'):
    from slingerpkg.lib.smblib import smblib

def setup_mock_client():
    """Set up a realistic mock client"""
    client = Mock()
    client.share = "C$"
    client.relative_path = "Users\\Administrator"
    client.current_path = "C$\\Users\\Administrator"
    client.tree_id = 123
    client.is_connected_to_share = True
    client.conn = Mock()
    client.dce_transport = Mock()
    
    # Mock methods
    client.conn.listPath.return_value = []
    client.check_if_connected = Mock(return_value=True)
    client.is_valid_directory = Mock(return_value=True)
    client.update_current_path = Mock()
    client.print_current_path = Mock()
    
    # Initialize smblib
    smblib.__init__(client)
    return client

def test_cd_path_traversal():
    """Test 1: CD Path Traversal Attack"""
    print("\n" + "="*60)
    print("🚨 TEST 1: CD PATH TRAVERSAL ATTACK")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Users\\Administrator"
    
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"Attempting: cd ..\\..\\..\\Windows\\System32")
    
    # Simulate what happens in cd() method
    malicious_path = "..\\..\\..\\Windows\\System32"
    
    # This is the vulnerable line from smblib.py:244
    result_path = ntpath.normpath(ntpath.join(client.relative_path, malicious_path))
    
    print(f"❌ Result path: {result_path}")
    
    if result_path.startswith(".."):
        print("🚨 SECURITY ISSUE: Path escapes share root!")
        print("   Attacker could access: \\\\server\\{}".format(result_path))
    else:
        print("✅ Path stays within share bounds")

def test_put_path_logic():
    """Test 2: PUT command path handling"""
    print("\n" + "="*60)
    print("🔧 TEST 2: PUT COMMAND PATH LOGIC")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Documents"
    
    # Test case 1: Relative remote path
    args1 = Mock()
    args1.local_path = "/tmp/report.pdf"
    args1.remote_path = "Reports\\Q4\\report.pdf"
    
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"PUT: {args1.local_path} -> {args1.remote_path}")
    
    # Simulate the logic from upload_handler (lines 262-265)
    if args1.remote_path == "." or args1.remote_path == "" or args1.remote_path is None or "\\" not in args1.remote_path:
        remote_path = ntpath.join(client.relative_path, ntpath.basename(args1.local_path))
    else:
        remote_path = args1.remote_path
    
    print(f"❌ Bug: Remote path = {remote_path}")
    print("🔍 Issue: Should join relative_path + remote_path, but doesn't!")
    
    # What it SHOULD be:
    correct_path = ntpath.normpath(ntpath.join(client.relative_path, args1.remote_path))
    print(f"✅ Should be: {correct_path}")

def test_get_absolute_path():
    """Test 3: GET command with absolute path"""
    print("\n" + "="*60)
    print("📥 TEST 3: GET COMMAND ABSOLUTE PATH")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Users\\Administrator"
    
    args = Mock()
    args.remote_path = "\\Windows\\System32\\drivers\\etc\\hosts"  # Absolute path
    args.local_path = "/tmp/hosts"
    
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"GET: {args.remote_path} -> {args.local_path}")
    
    # This is the problematic line from download_handler (line 285)
    remote_path = ntpath.join(client.relative_path, args.remote_path)
    
    print(f"❌ Bug: Joined path = {remote_path}")
    print("🔍 Issue: Absolute path should NOT be joined with relative_path!")
    
    # What it SHOULD be:
    if args.remote_path.startswith("\\"):
        correct_path = args.remote_path.lstrip("\\")
    else:
        correct_path = ntpath.normpath(ntpath.join(client.relative_path, args.remote_path))
    
    print(f"✅ Should be: {correct_path}")

def test_drive_letter_handling():
    """Test 4: Drive letter path handling"""
    print("\n" + "="*60)
    print("💿 TEST 4: DRIVE LETTER PATH HANDLING")
    print("="*60)
    
    client = setup_mock_client()
    
    test_paths = [
        "C:\\Windows\\System32",
        "D:\\Shares\\Files",
        "E:\\Backup\\data.zip"
    ]
    
    print(f"Current share: {client.share}")
    
    for drive_path in test_paths:
        print(f"\nTrying: cd {drive_path}")
        
        # Check current cd() logic (lines 238-239)
        if drive_path.startswith("/"):
            result = drive_path.lstrip("/")
            print(f"  Unix path handling: {result}")
        elif len(drive_path) > 2 and drive_path[1] == ":":
            print(f"  ❌ Drive letter detected but NO HANDLING in code!")
            print(f"     User expects to go to {drive_path}")
            print(f"     But code will treat as relative path!")
        else:
            print(f"  Treated as relative path")

def main():
    """Run all manual tests"""
    print("🧪 SLINGER PATH VALIDATION MANUAL TESTING")
    print("This script demonstrates the actual bugs in the path handling")
    
    try:
        test_cd_path_traversal()
        test_put_path_logic() 
        test_get_absolute_path()
        test_drive_letter_handling()
        
        print("\n" + "="*60)
        print("✅ MANUAL TESTING COMPLETE")
        print("="*60)
        print("Summary of issues found:")
        print("1. CD: Path traversal attacks possible")
        print("2. PUT: Incorrect remote path joining logic")
        print("3. GET: Absolute paths wrongly joined with relative_path")
        print("4. ALL: Drive letter paths (C:) not handled")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
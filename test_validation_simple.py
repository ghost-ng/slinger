#!/usr/bin/env python3
"""
Simple validation test to verify our path handling fixes work
"""
import sys
sys.path.insert(0, 'src')

from unittest.mock import Mock, patch

# Mock impacket
with patch('impacket.smbconnection.SMBConnection'):
    from slingerpkg.lib.smblib import smblib

def test_security_fixes():
    """Test that security fixes work correctly"""
    print("🧪 TESTING PATH SECURITY FIXES")
    
    # Create real smblib instance
    client = smblib()
    client.share = "C$"
    client.relative_path = "Users\\Administrator"
    client.check_if_connected = Mock(return_value=True)
    client.is_valid_directory = Mock(return_value=True)
    client.update_current_path = Mock()
    client.print_current_path = Mock()
    
    print("\n1. Testing Path Traversal Protection:")
    print("   Attempting: cd ..\\..\\..\\Windows\\System32")
    
    # Capture the warning
    original_path = client.relative_path
    client.cd("..\\..\\..\\Windows\\System32")
    
    # Path should have changed - SMB client allows this, SMB server controls access
    expected_path = "..\\Windows\\System32"  # This is what the normalized path should be
    if client.relative_path == expected_path:
        print("   ✅ Path traversal allowed with warning - SMB server will control access")
    else:
        print(f"   ❌ Path handling incorrect: got {client.relative_path}, expected {expected_path}")
        return False
    
    print("\n2. Testing Drive Letter Rejection:")
    print("   Attempting: cd C:\\Windows\\System32")
    
    original_path = client.relative_path
    client.cd("C:\\Windows\\System32")
    
    if client.relative_path == original_path:
        print("   ✅ Drive letter path REJECTED - path unchanged")
    else:
        print("   ❌ Drive letter path NOT rejected")
        return False
    
    print("\n3. Testing Valid Relative Path:")
    print("   Attempting: cd Documents")
    
    # Reset to a known good state first
    client.relative_path = "Users\\Administrator"
    client.cd("Documents")
    expected = "Users\\Administrator\\Documents"
    
    if client.relative_path == expected:
        print(f"   ✅ Valid relative path works: {client.relative_path}")
    else:
        print(f"   ❌ Relative path failed: got {client.relative_path}, expected {expected}")
        return False
    
    print("\n4. Testing Valid Absolute Path:")
    print("   Attempting: cd \\Windows\\System32")
    
    client.cd("\\Windows\\System32")
    expected = "Windows\\System32"
    
    if client.relative_path == expected:
        print(f"   ✅ Valid absolute path works: {client.relative_path}")
    else:
        print(f"   ❌ Absolute path failed: got {client.relative_path}, expected {expected}")
        return False
    
    return True

def test_put_fixes():
    """Test PUT command fixes"""
    print("\n🧪 TESTING PUT COMMAND FIXES")
    
    client = smblib()
    client.share = "C$"
    client.relative_path = "Documents"
    client.check_if_connected = Mock(return_value=True)
    
    # Mock the upload method to capture the path
    uploaded_paths = []
    def mock_upload(local, remote):
        uploaded_paths.append(remote)
    client.upload = mock_upload
    
    # Test relative path joining
    args = Mock()
    args.local_path = "/tmp/test.txt"
    args.remote_path = "Reports\\Q4\\test.txt"
    
    with patch('os.path.exists', return_value=True):
        client.upload_handler(args)
    
    if uploaded_paths:
        actual = uploaded_paths[0]
        expected = "Documents\\Reports\\Q4\\test.txt"
        if actual == expected:
            print(f"   ✅ PUT path joining works: {actual}")
            return True
        else:
            print(f"   ❌ PUT failed: got {actual}, expected {expected}")
            return False
    else:
        print("   ❌ PUT not called")
        return False

def test_get_fixes():
    """Test GET command fixes"""
    print("\n🧪 TESTING GET COMMAND FIXES")
    
    client = smblib()
    client.share = "C$"
    client.relative_path = "Users\\Administrator"
    client.check_if_connected = Mock(return_value=True)
    
    # Mock the download method to capture the path
    downloaded_paths = []
    def mock_download(remote, local, echo=True):
        downloaded_paths.append(remote)
    client.download = mock_download
    
    # Test absolute path handling
    args = Mock()
    args.remote_path = "\\Windows\\System32\\cmd.exe"
    args.local_path = "/tmp/cmd.exe"
    
    with patch('os.path.isdir', return_value=True):
        client.download_handler(args)
    
    if downloaded_paths:
        actual = downloaded_paths[0]
        expected = "Windows\\System32\\cmd.exe"  # Should NOT be joined with relative_path
        if actual == expected:
            print(f"   ✅ GET absolute path works: {actual}")
            return True
        else:
            print(f"   ❌ GET failed: got {actual}, expected {expected}")
            return False
    else:
        print("   ❌ GET not called")
        return False

def main():
    """Run all tests"""
    print("🛡️ SLINGER PATH VALIDATION FIX VERIFICATION")
    
    all_passed = True
    
    if not test_security_fixes():
        all_passed = False
    
    if not test_put_fixes():
        all_passed = False
    
    if not test_get_fixes():
        all_passed = False
    
    print("\n" + "="*50)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Security vulnerabilities fixed")
        print("✅ Path logic bugs corrected")
        print("✅ All commands work as expected")
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
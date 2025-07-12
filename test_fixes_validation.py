#!/usr/bin/env python3
"""
Test script to validate the path handling fixes
This will verify that our security and logic improvements work correctly
"""
import sys
import ntpath
sys.path.insert(0, 'src')

from unittest.mock import Mock, MagicMock, patch

# Mock impacket
with patch('impacket.smbconnection.SMBConnection'):
    from slingerpkg.lib.smblib import smblib

def setup_mock_client():
    """Set up a realistic mock client with our fixes"""
    # Create a real smblib instance instead of a mock
    client = smblib()
    
    # Set required attributes
    client.share = "C$"
    client.relative_path = "Users\\Administrator"
    client.current_path = "C$\\Users\\Administrator"
    client.tree_id = 123
    client.is_connected_to_share = True
    client.conn = Mock()
    client.dce_transport = Mock()
    
    # Mock methods that make external calls
    client.conn.listPath.return_value = []
    client.check_if_connected = Mock(return_value=True)
    client.is_valid_directory = Mock(return_value=True)
    client.update_current_path = Mock()
    client.print_current_path = Mock()
    
    return client

def test_cd_security_improvements():
    """Test 1: Verify CD security fixes"""
    print("\n" + "="*60)
    print("🛡️  TEST 1: CD SECURITY IMPROVEMENTS")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Users\\Administrator"
    
    # Test 1a: Path traversal should be blocked
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"Attempting: cd ..\\..\\..\\Windows\\System32")
    
    with patch('slingerpkg.utils.printlib.print_warning') as mock_warning:
        smblib.cd(client, "..\\..\\..\\Windows\\System32")
        
        # Should have called print_warning with security message
        mock_warning.assert_called_once()
        warning_msg = mock_warning.call_args[0][0]
        print(f"✅ Security message: {warning_msg}")
        assert "escape share bounds" in warning_msg or "path traversal" in warning_msg.lower()
    
    # Test 1b: Drive letter paths should be rejected
    print(f"\nAttempting: cd C:\\Windows\\System32")
    
    with patch('slingerpkg.utils.printlib.print_warning') as mock_warning:
        smblib.cd(client, "C:\\Windows\\System32")
        
        mock_warning.assert_called_once()
        warning_msg = mock_warning.call_args[0][0]
        print(f"✅ Drive letter rejection: {warning_msg}")
        assert "drive letter" in warning_msg.lower()
    
    # Test 1c: Valid relative paths should work
    print(f"\nAttempting: cd Documents")
    original_relative_path = client.relative_path
    smblib.cd(client, "Documents")
    
    expected_path = ntpath.normpath(ntpath.join(original_relative_path, "Documents"))
    assert client.relative_path == expected_path
    print(f"✅ Valid relative path works: {client.relative_path}")
    
    # Test 1d: Absolute paths should work correctly
    client.relative_path = "Users\\Administrator"  # Reset
    print(f"\nAttempting: cd \\Windows\\System32")
    smblib.cd(client, "\\Windows\\System32")
    
    expected_path = "Windows\\System32"  # Should strip leading backslash
    assert client.relative_path == expected_path
    print(f"✅ Absolute path works: {client.relative_path}")

def test_put_path_improvements():
    """Test 2: Verify PUT path fixes"""
    print("\n" + "="*60)
    print("📤 TEST 2: PUT PATH IMPROVEMENTS")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Documents"
    
    # Test 2a: Relative remote path should join correctly
    args = Mock()
    args.local_path = "/tmp/report.pdf"
    args.remote_path = "Reports\\Q4\\report.pdf"
    
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"PUT: {args.local_path} -> {args.remote_path}")
    
    with patch('os.path.exists', return_value=True):
        with patch('slingerpkg.lib.smblib.smblib.upload') as mock_upload:
            smblib.upload_handler(client, args)
            
            mock_upload.assert_called_once()
            call_args = mock_upload.call_args[0]
            actual_remote_path = call_args[1]
            
            expected_path = ntpath.normpath(ntpath.join("Documents", "Reports\\Q4\\report.pdf"))
            assert actual_remote_path == expected_path
            print(f"✅ Relative path joined correctly: {actual_remote_path}")
    
    # Test 2b: Default filename should work
    args2 = Mock()
    args2.local_path = "/tmp/myfile.txt"
    args2.remote_path = "."
    
    print(f"\nPUT: {args2.local_path} -> {args2.remote_path} (default)")
    
    with patch('os.path.exists', return_value=True):
        with patch('slingerpkg.lib.smblib.smblib.upload') as mock_upload:
            smblib.upload_handler(client, args2)
            
            mock_upload.assert_called_once()
            call_args = mock_upload.call_args[0]
            actual_remote_path = call_args[1]
            
            # Should place file in current directory
            expected_path = ntpath.join("Documents", "myfile.txt")
            assert actual_remote_path == expected_path
            print(f"✅ Default filename works: {actual_remote_path}")

def test_get_path_improvements():
    """Test 3: Verify GET path fixes"""
    print("\n" + "="*60)
    print("📥 TEST 3: GET PATH IMPROVEMENTS")
    print("="*60)
    
    client = setup_mock_client()
    client.relative_path = "Users\\Administrator"
    
    # Test 3a: Absolute remote path should NOT be joined
    args = Mock()
    args.remote_path = "\\Windows\\System32\\drivers\\etc\\hosts"
    args.local_path = "/tmp/hosts"
    
    print(f"Current location: {client.share}\\{client.relative_path}")
    print(f"GET: {args.remote_path} -> {args.local_path}")
    
    with patch('os.path.isdir', return_value=True):
        with patch('slingerpkg.lib.smblib.smblib.download') as mock_download:
            smblib.download_handler(client, args)
            
            mock_download.assert_called_once()
            call_args = mock_download.call_args[0]
            actual_remote_path = call_args[0]
            
            # Should strip leading backslash but NOT join with relative_path
            expected_path = "Windows\\System32\\drivers\\etc\\hosts"
            assert actual_remote_path == expected_path
            print(f"✅ Absolute path handled correctly: {actual_remote_path}")
    
    # Test 3b: Relative remote path should be joined
    args2 = Mock()
    args2.remote_path = "Documents\\report.pdf"
    args2.local_path = "/tmp/report.pdf"
    
    print(f"\nGET: {args2.remote_path} -> {args2.local_path}")
    
    with patch('os.path.isdir', return_value=True):
        with patch('slingerpkg.lib.smblib.smblib.download') as mock_download:
            smblib.download_handler(client, args2)
            
            mock_download.assert_called_once()
            call_args = mock_download.call_args[0]
            actual_remote_path = call_args[0]
            
            # Should join with current relative_path
            expected_path = ntpath.normpath(ntpath.join("Users\\Administrator", "Documents\\report.pdf"))
            assert actual_remote_path == expected_path
            print(f"✅ Relative path joined correctly: {actual_remote_path}")

def test_helper_functions():
    """Test 4: Verify helper function behavior"""
    print("\n" + "="*60)
    print("🔧 TEST 4: HELPER FUNCTION VALIDATION")
    print("="*60)
    
    client = setup_mock_client()
    
    # Test path normalization
    test_cases = [
        ("Windows\\System32\\", "Windows\\System32"),
        ("Windows\\..\\Windows", "Windows"),
        (".\\System32", "System32"),
        ("", ""),
    ]
    
    print("Testing _normalize_path:")
    for input_path, expected in test_cases:
        result = client._normalize_path(input_path)
        assert result == expected
        print(f"  ✅ '{input_path}' -> '{result}'")
    
    # Test absolute path detection
    print("\nTesting _is_absolute_path:")
    absolute_tests = [
        ("\\Windows\\System32", True),
        ("C:\\Windows", True),
        ("D:\\Data", True),
        ("relative\\path", False),
        ("", False),
        (".", False),
    ]
    
    for path, expected in absolute_tests:
        result = client._is_absolute_path(path)
        assert result == expected
        print(f"  ✅ '{path}' -> {result}")
    
    # Test security validation
    print("\nTesting _validate_path_security:")
    security_tests = [
        ("Users", "Documents", True),  # Valid relative
        ("Users", "..\\..\\Windows", False),  # Path traversal
        ("Users", "\\Windows\\System32", True),  # Valid absolute
        ("Users", "C:\\Windows", False),  # Drive letter
    ]
    
    for base, target, should_be_safe in security_tests:
        is_safe, resolved, error = client._validate_path_security(base, target)
        assert is_safe == should_be_safe
        status = "✅ SAFE" if is_safe else "🚨 BLOCKED"
        print(f"  {status} '{base}' + '{target}' -> {resolved if is_safe else error}")

def main():
    """Run all validation tests"""
    print("🧪 SLINGER PATH HANDLING FIX VALIDATION")
    print("Testing all the security and logic improvements...")
    
    try:
        test_cd_security_improvements()
        test_put_path_improvements()
        test_get_path_improvements()
        test_helper_functions()
        
        print("\n" + "="*60)
        print("🎉 ALL TESTS PASSED!")
        print("="*60)
        print("✅ CD command: Path traversal blocked, drive letters rejected")
        print("✅ PUT command: Correct path joining logic")
        print("✅ GET command: Proper absolute/relative path handling")
        print("✅ Helper functions: Robust validation and normalization")
        print("\n🛡️ Security improvements successfully implemented!")
        
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
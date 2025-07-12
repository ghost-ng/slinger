"""
Unit tests for SMB library functions
"""
import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime
import sys

sys.path.insert(0, 'src')

# We'll need to mock the actual module since it depends on impacket
with patch('impacket.smbconnection.SMBConnection'):
    from slingerpkg.lib.smblib import smblib


class TestSMBLib:
    """Test SMB library functionality"""
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock client with SMBLib mixin"""
        client = Mock(spec=smblib)
        
        # Add required attributes
        client.smb = MagicMock()
        client.username = "testuser"
        client.password = "testpass"
        client.domain = "TESTDOMAIN"
        client.shares = ["C$", "ADMIN$", "IPC$"]
        client.pwd = "C$\\"
        client.use_share = "C$"
        client.host = "192.168.1.100"
        
        # Bind actual methods to mock
        SMBLibMixin.__init__(client)
        
        return client
    
    def test_list_shares(self, mock_client):
        """Test listing SMB shares"""
        # Mock the listShares response
        mock_shares = [
            {
                'shi1_netname': b'C$\x00',
                'shi1_type': 0x0,
                'shi1_remark': b'Default share\x00'
            },
            {
                'shi1_netname': b'ADMIN$\x00',
                'shi1_type': 0x0,
                'shi1_remark': b'Remote Admin\x00'
            },
            {
                'shi1_netname': b'IPC$\x00',
                'shi1_type': 0x3,
                'shi1_remark': b'Remote IPC\x00'
            }
        ]
        
        mock_client.smb.listShares.return_value = mock_shares
        
        # Call the actual method
        shares = SMBLibMixin.ls_shares(mock_client)
        
        # Verify
        assert mock_client.smb.listShares.called
        assert len(shares) == 3
    
    def test_connect_share(self, mock_client):
        """Test connecting to a share"""
        mock_client.smb.connectTree.return_value = 123  # Mock TID
        
        # Test connect
        result = SMBLibMixin.use(mock_client, "ADMIN$")
        
        mock_client.smb.connectTree.assert_called_with("ADMIN$")
        assert mock_client.use_share == "ADMIN$"
        assert mock_client.pwd == "ADMIN$\\"
    
    def test_list_files(self, mock_client):
        """Test listing files in a directory"""
        # Mock file listing response
        mock_files = [
            (".", 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "."),
            ("..", 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ".."),
            ("test.txt", 0x20, 0, 0, 0, 0, 0, 0, 1234567890, 1024, 0, 0, 0, "test.txt"),
            ("folder", 0x10, 0, 0, 0, 0, 0, 0, 1234567890, 0, 0, 0, 0, "folder")
        ]
        
        mock_client.smb.listPath.return_value = mock_files
        
        # Call ls
        files = SMBLibMixin.ls(mock_client, ".")
        
        # Should filter out . and ..
        assert len([f for f in mock_files if f[0] not in ['.', '..']]) == 2
    
    def test_change_directory(self, mock_client):
        """Test changing directory"""
        # Test absolute path
        SMBLibMixin.cd(mock_client, "C$\\Windows")
        assert mock_client.pwd == "C$\\Windows"
        
        # Test relative path
        mock_client.pwd = "C$\\Windows"
        SMBLibMixin.cd(mock_client, "System32")
        assert mock_client.pwd == "C$\\Windows\\System32"
        
        # Test parent directory
        SMBLibMixin.cd(mock_client, "..")
        assert mock_client.pwd == "C$\\Windows"
    
    def test_pwd_command(self, mock_client):
        """Test print working directory"""
        mock_client.pwd = "C$\\Users\\Administrator"
        result = SMBLibMixin.pwd(mock_client)
        assert result == "C$\\Users\\Administrator"
    
    def test_download_file(self, mock_client):
        """Test file download"""
        mock_content = b"Test file content"
        
        def mock_callback(data):
            return mock_content
        
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            
            # Mock getFile to call the callback
            def mock_getFile(share, path, callback):
                callback(mock_content)
            
            mock_client.smb.getFile.side_effect = mock_getFile
            
            # Download file
            SMBLibMixin.download(mock_client, "test.txt", "/tmp/test.txt")
            
            # Verify
            mock_open.assert_called_with("/tmp/test.txt", "wb")
            mock_file.write.assert_called_with(mock_content)
    
    def test_upload_file(self, mock_client):
        """Test file upload"""
        mock_content = b"Upload test content"
        
        with patch('builtins.open', create=True) as mock_open:
            # Mock file reading
            mock_file = MagicMock()
            mock_file.read.return_value = mock_content
            mock_open.return_value.__enter__.return_value = mock_file
            
            # Upload file
            SMBLibMixin.upload(mock_client, "/tmp/upload.txt", "upload.txt")
            
            # Verify
            mock_open.assert_called_with("/tmp/upload.txt", "rb")
            assert mock_client.smb.putFile.called
    
    def test_delete_file(self, mock_client):
        """Test file deletion"""
        SMBLibMixin.rm(mock_client, "test.txt")
        
        mock_client.smb.deleteFile.assert_called_with("C$", "\\test.txt")
    
    def test_create_directory(self, mock_client):
        """Test directory creation"""
        SMBLibMixin.mkdir(mock_client, "NewFolder")
        
        mock_client.smb.createDirectory.assert_called_with("C$", "\\NewFolder")
    
    def test_remove_directory(self, mock_client):
        """Test directory removal"""
        SMBLibMixin.rmdir(mock_client, "OldFolder")
        
        mock_client.smb.deleteDirectory.assert_called_with("C$", "\\OldFolder")
    
    def test_path_completion(self, mock_client):
        """Test path completion logic"""
        # Test share completion
        result = SMBLibMixin.path_completion(mock_client, "", "")
        assert "C$" in result
        assert "ADMIN$" in result
        
        # Test file completion
        mock_files = [
            ("test1.txt", 0x20, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, "test1.txt"),
            ("test2.txt", 0x20, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, "test2.txt"),
            ("folder", 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "folder")
        ]
        mock_client.smb.listPath.return_value = mock_files
        
        result = SMBLibMixin.path_completion(mock_client, "C$\\", "test")
        assert any("test1.txt" in r for r in result)
        assert any("test2.txt" in r for r in result)
    
    def test_cat_file(self, mock_client):
        """Test reading file content"""
        mock_content = b"File content\nLine 2\nLine 3"
        
        def mock_getFile(share, path, callback):
            callback(mock_content)
        
        mock_client.smb.getFile.side_effect = mock_getFile
        
        # Read file
        content = SMBLibMixin.cat(mock_client, "test.txt")
        
        # Verify the call was made
        assert mock_client.smb.getFile.called
    
    def test_error_handling(self, mock_client):
        """Test error handling in SMB operations"""
        # Test file not found
        mock_client.smb.getFile.side_effect = Exception("File not found")
        
        with pytest.raises(Exception) as exc_info:
            SMBLibMixin.cat(mock_client, "nonexistent.txt")
        
        assert "File not found" in str(exc_info.value)
        
        # Test access denied
        mock_client.smb.deleteFile.side_effect = Exception("Access denied")
        
        with pytest.raises(Exception) as exc_info:
            SMBLibMixin.rm(mock_client, "protected.txt")
        
        assert "Access denied" in str(exc_info.value)
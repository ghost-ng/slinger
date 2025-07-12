"""
Integration tests for Slinger commands using mock SMB server
"""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from tests.fixtures.mock_smb_server import MockSMBServer
from tests.fixtures.cli_runner import SlingerTestRunner, BatchCommandRunner


class TestCommandIntegration:
    """Test Slinger commands with mock SMB server"""

    @pytest.fixture
    def mock_server(self):
        """Create and configure mock SMB server"""
        server = MockSMBServer()

        # Add test files
        server.add_share(
            "TEST$",
            {
                "\\test.txt": b"Hello from mock server!",
                "\\folder": None,  # Directory
                "\\folder\\nested.txt": b"Nested file content",
                "\\data.bin": b"\x00\x01\x02\x03\x04\x05",
            },
        )

        # Add test service
        server.add_service(
            "TestService",
            display_name="Test Service",
            status="STOPPED",
            binary_path="C:\\Windows\\System32\\test.exe",
        )

        # Add test registry key
        server.add_registry_key(
            "HKLM\\SOFTWARE\\Test",
            {
                "Version": ("REG_SZ", "1.0"),
                "InstallPath": ("REG_SZ", "C:\\Program Files\\Test"),
                "Enabled": ("REG_DWORD", 1),
            },
        )

        return server

    @pytest.fixture
    def runner(self, mock_server, monkeypatch):
        """Create test runner with mock server"""
        # Patch the SMB connection to use our mock
        monkeypatch.setattr(
            "impacket.smbconnection.SMBConnection",
            lambda *args, **kwargs: mock_server.get_connection(),
        )

        runner = SlingerTestRunner(mock_server=mock_server, test_mode=False)

        # Start runner with test credentials
        if not runner.start(host="192.168.1.100", username="testuser", password="testpass"):
            pytest.skip("Failed to start test runner")

        yield runner

        runner.stop()

    @pytest.mark.requires_mock_server
    def test_shares_command(self, runner):
        """Test listing shares"""
        output = runner.send_command("shares")

        assert "C$" in output
        assert "ADMIN$" in output
        assert "IPC$" in output
        assert "TEST$" in output

    @pytest.mark.requires_mock_server
    def test_use_command(self, runner):
        """Test connecting to a share"""
        output = runner.send_command("use TEST$")

        assert "TEST$" in output or "Connected" in output
        assert runner.send_command("pwd") == "TEST$\\"

    @pytest.mark.requires_mock_server
    def test_ls_command(self, runner):
        """Test listing files"""
        # Connect to test share
        runner.send_command("use TEST$")

        # List root directory
        output = runner.send_command("ls")

        assert "test.txt" in output
        assert "folder" in output
        assert "data.bin" in output

    @pytest.mark.requires_mock_server
    def test_cd_command(self, runner):
        """Test changing directory"""
        runner.send_command("use TEST$")

        # Change to folder
        output = runner.send_command("cd folder")
        assert runner.send_command("pwd") == "TEST$\\folder"

        # List files in folder
        output = runner.send_command("ls")
        assert "nested.txt" in output

        # Go back to parent
        runner.send_command("cd ..")
        assert runner.send_command("pwd") == "TEST$\\"

    @pytest.mark.requires_mock_server
    def test_cat_command(self, runner):
        """Test reading file content"""
        runner.send_command("use TEST$")

        output = runner.send_command("cat test.txt")
        assert "Hello from mock server!" in output

    @pytest.mark.requires_mock_server
    def test_file_operations_workflow(self, runner):
        """Test complete file operation workflow"""
        batch = BatchCommandRunner(runner)

        commands = [
            "use TEST$",
            "ls",
            "cat test.txt",
            "cd folder",
            "ls",
            "cat nested.txt",
            "pwd",
            "cd ..",
            "pwd",
        ]

        results = batch.run_commands(commands)

        # Check all commands succeeded
        assert batch.all_successful()

        # Verify specific outputs
        outputs = {cmd: output for cmd, output, _ in results}
        assert "test.txt" in outputs["ls"]
        assert "Hello from mock server!" in outputs["cat test.txt"]
        assert "nested.txt" in outputs["cat nested.txt"]
        assert outputs["pwd"] == "TEST$\\"

    @pytest.mark.requires_mock_server
    def test_service_enumeration(self, runner):
        """Test service enumeration"""
        output = runner.send_command("enumservices")

        # Should list both default services and our test service
        assert "Spooler" in output
        assert "TestService" in output or "Test Service" in output

    @pytest.mark.requires_mock_server
    def test_registry_query(self, runner):
        """Test registry operations"""
        output = runner.send_command("regquery HKLM\\SOFTWARE\\Test")

        assert "Version" in output
        assert "1.0" in output
        assert "InstallPath" in output
        assert "C:\\Program Files\\Test" in output

    @pytest.mark.requires_mock_server
    def test_error_handling(self, runner):
        """Test error scenarios"""
        # Try to access non-existent share
        output = runner.send_command("use NONEXISTENT$")
        assert "error" in output.lower() or "failed" in output.lower()

        # Try to read non-existent file
        runner.send_command("use TEST$")
        output = runner.send_command("cat nonexistent.txt")
        assert "error" in output.lower() or "not found" in output.lower()

    @pytest.mark.requires_mock_server
    def test_help_command(self, runner):
        """Test help command"""
        output = runner.send_command("help")

        # Should list available commands
        assert "ls" in output
        assert "cat" in output
        assert "shares" in output
        assert "use" in output


class TestAuthenticationScenarios:
    """Test different authentication scenarios"""

    @pytest.fixture
    def mock_server(self):
        """Create mock server for auth testing"""
        return MockSMBServer()

    def test_successful_authentication(self, mock_server, monkeypatch):
        """Test successful authentication"""
        monkeypatch.setattr(
            "impacket.smbconnection.SMBConnection",
            lambda *args, **kwargs: mock_server.get_connection(),
        )

        runner = SlingerTestRunner(mock_server=mock_server, test_mode=False)

        assert runner.start(host="192.168.1.100", username="testuser", password="testpass")

        runner.stop()

    def test_failed_authentication(self, mock_server, monkeypatch):
        """Test failed authentication"""
        mock_server.simulate_auth_failure()

        monkeypatch.setattr(
            "impacket.smbconnection.SMBConnection",
            lambda *args, **kwargs: mock_server.get_connection(),
        )

        runner = SlingerTestRunner(mock_server=mock_server, test_mode=False)

        assert not runner.start(host="192.168.1.100", username="baduser", password="badpass")

    def test_ntlm_authentication(self, mock_server, monkeypatch):
        """Test NTLM hash authentication"""
        monkeypatch.setattr(
            "impacket.smbconnection.SMBConnection",
            lambda *args, **kwargs: mock_server.get_connection(),
        )

        runner = SlingerTestRunner(mock_server=mock_server, test_mode=False)

        assert runner.start(
            host="192.168.1.100", username="testuser", auth_type="ntlm", nthash="aabbccdd11223344"
        )

        runner.stop()


class TestComplexScenarios:
    """Test complex multi-command scenarios"""

    @pytest.fixture
    def configured_server(self):
        """Create a fully configured mock server"""
        server = MockSMBServer()

        # Create complex directory structure
        server.add_share(
            "C$",
            {
                "\\Windows": None,
                "\\Windows\\System32": None,
                "\\Windows\\System32\\config": None,
                "\\Windows\\System32\\config\\SAM": b"SAM DATABASE",
                "\\Users": None,
                "\\Users\\Administrator": None,
                "\\Users\\Administrator\\Desktop": None,
                "\\Users\\Administrator\\Desktop\\flag.txt": b"CTF{mock_flag_123}",
                "\\Program Files": None,
                "\\temp": None,
            },
        )

        # Add multiple services
        for i in range(5):
            server.add_service(
                f"Service{i}",
                display_name=f"Test Service {i}",
                status="RUNNING" if i % 2 == 0 else "STOPPED",
            )

        # Add scheduled tasks
        server.add_task(
            "\\Microsoft\\Windows\\Test\\TestTask",
            status="Ready",
            command="C:\\Windows\\System32\\calc.exe",
        )

        return server

    @pytest.mark.requires_mock_server
    @pytest.mark.slow
    def test_penetration_test_scenario(self, configured_server, monkeypatch):
        """Test a typical penetration testing workflow"""
        monkeypatch.setattr(
            "impacket.smbconnection.SMBConnection",
            lambda *args, **kwargs: configured_server.get_connection(),
        )

        with SlingerTestRunner(mock_server=configured_server, test_mode=False) as runner:
            if not runner.start(
                host="192.168.1.100", username="Administrator", password="Admin123"
            ):
                pytest.skip("Failed to start runner")

            batch = BatchCommandRunner(runner)

            # Typical pentest workflow
            commands = [
                # Initial enumeration
                "shares",
                "use C$",
                # Navigate to interesting locations
                "cd Windows\\System32\\config",
                "ls",
                # Check for sensitive files
                "cd \\Users\\Administrator\\Desktop",
                "ls",
                "cat flag.txt",
                # Service enumeration
                "enumservices",
                # Back to root
                "cd \\",
                "pwd",
            ]

            results = batch.run_commands(commands)

            # Verify the workflow completed
            assert batch.all_successful()

            # Check we found the flag
            flag_output = next(output for cmd, output, _ in results if cmd == "cat flag.txt")
            assert "CTF{mock_flag_123}" in flag_output

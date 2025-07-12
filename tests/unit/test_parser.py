"""
Unit tests for Slinger command parser
"""

import pytest
import sys
from unittest.mock import Mock, patch
from argparse import ArgumentParser, Namespace

# Import after adding to path
sys.path.insert(0, "src")
from slingerpkg.utils.cli import setup_cli_parser


class TestCliParser:
    """Test command-line argument parsing"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        return setup_cli_parser()

    def test_parser_creation(self, parser):
        """Test that parser is created successfully"""
        assert isinstance(parser, ArgumentParser)
        assert parser.prog == "slinger"

    def test_basic_connection_args(self, parser):
        """Test basic connection arguments"""
        args = parser.parse_args(
            ["-host", "192.168.1.100", "-user", "testuser", "-password", "testpass"]
        )

        assert args.host == "192.168.1.100"
        assert args.user == "testuser"
        assert args.password == "testpass"

    def test_ntlm_auth_args(self, parser):
        """Test NTLM hash authentication arguments"""
        args = parser.parse_args(
            ["-host", "192.168.1.100", "-user", "testuser", "-hashes", ":aabbccdd11223344"]
        )

        assert args.host == "192.168.1.100"
        assert args.user == "testuser"
        assert args.hashes == ":aabbccdd11223344"
        assert args.password == ""

    def test_kerberos_auth_args(self, parser):
        """Test Kerberos authentication arguments"""
        args = parser.parse_args(["-host", "server.domain.com", "-k"])

        assert args.host == "server.domain.com"
        assert args.k is True

    def test_optional_args(self, parser):
        """Test optional arguments"""
        args = parser.parse_args(
            [
                "-host",
                "192.168.1.100",
                "-user",
                "testuser",
                "-password",
                "testpass",
                "-domain",
                "TESTDOMAIN",
                "-port",
                "139",
                "-debug",
                "-no-color",
            ]
        )

        assert args.domain == "TESTDOMAIN"
        assert args.port == 139
        assert args.debug is True
        assert args.no_color is True

    def test_share_argument(self, parser):
        """Test share argument"""
        args = parser.parse_args(
            [
                "-host",
                "192.168.1.100",
                "-user",
                "testuser",
                "-password",
                "testpass",
                "-share",
                "ADMIN$",
            ]
        )

        assert args.share == "ADMIN$"

    def test_no_pass_argument(self, parser):
        """Test no password argument"""
        args = parser.parse_args(["-host", "192.168.1.100", "-user", "testuser", "-no-pass"])

        assert args.no_pass is True
        assert args.password == ""

    def test_required_args_missing(self, parser):
        """Test that missing required arguments raise error"""
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_conflicting_auth_methods(self, parser):
        """Test handling of conflicting authentication methods"""
        # Should not raise error - last one wins
        args = parser.parse_args(
            [
                "-host",
                "192.168.1.100",
                "-user",
                "testuser",
                "-password",
                "testpass",
                "-hashes",
                ":aabbccdd11223344",
            ]
        )

        assert args.password == "testpass"
        assert args.hashes == ":aabbccdd11223344"

    def test_dc_ip_argument(self, parser):
        """Test domain controller IP argument"""
        args = parser.parse_args(
            [
                "-host",
                "192.168.1.100",
                "-user",
                "testuser",
                "-password",
                "testpass",
                "-dc-ip",
                "192.168.1.10",
            ]
        )

        assert args.dc_ip == "192.168.1.10"

    def test_log_argument(self, parser):
        """Test log file argument"""
        args = parser.parse_args(
            [
                "-host",
                "192.168.1.100",
                "-user",
                "testuser",
                "-password",
                "testpass",
                "-log",
                "/tmp/slinger.log",
            ]
        )

        assert args.log == "/tmp/slinger.log"


class TestCommandParsers:
    """Test individual command parsers"""

    @pytest.fixture
    def mock_client(self):
        """Create mock Slinger client"""
        client = Mock()
        client.shares = ["C$", "ADMIN$", "IPC$"]
        client.pwd = "C$\\"
        return client

    def test_ls_command_parser(self):
        """Test ls command argument parsing"""
        from slingerpkg.lib.parser import CmdArgumentParser

        parser = CmdArgumentParser(prog="ls", description="List files")
        parser.add_argument("path", nargs="?", default=".")

        # Test default path
        args = parser.parse_args([])
        assert args.path == "."

        # Test specific path
        args = parser.parse_args(["C$\\Windows"])
        assert args.path == "C$\\Windows"

    def test_cat_command_parser(self):
        """Test cat command argument parsing"""
        from slingerpkg.lib.parser import CmdArgumentParser

        parser = CmdArgumentParser(prog="cat", description="Read file")
        parser.add_argument("filename")

        args = parser.parse_args(["test.txt"])
        assert args.filename == "test.txt"

    def test_upload_command_parser(self):
        """Test upload command argument parsing"""
        from slingerpkg.lib.parser import CmdArgumentParser

        parser = CmdArgumentParser(prog="upload", description="Upload file")
        parser.add_argument("local")
        parser.add_argument("remote")

        args = parser.parse_args(["/tmp/local.txt", "C$\\remote.txt"])
        assert args.local == "/tmp/local.txt"
        assert args.remote == "C$\\remote.txt"

    def test_service_command_parser(self):
        """Test service-related command parsers"""
        from slingerpkg.lib.parser import CmdArgumentParser

        # Service start command
        parser = CmdArgumentParser(prog="servicestart", description="Start service")
        parser.add_argument("service_name")

        args = parser.parse_args(["Spooler"])
        assert args.service_name == "Spooler"

        # Service create command
        parser = CmdArgumentParser(prog="servicecreate", description="Create service")
        parser.add_argument("service_name")
        parser.add_argument("display_name")
        parser.add_argument("binary_path")
        parser.add_argument("-start", choices=["auto", "manual", "disabled"])

        args = parser.parse_args(
            [
                "TestService",
                "Test Service Display",
                "C:\\Windows\\System32\\test.exe",
                "-start",
                "auto",
            ]
        )

        assert args.service_name == "TestService"
        assert args.display_name == "Test Service Display"
        assert args.binary_path == "C:\\Windows\\System32\\test.exe"
        assert args.start == "auto"

    def test_registry_command_parser(self):
        """Test registry command parsers"""
        from slingerpkg.lib.parser import CmdArgumentParser

        # Registry query command
        parser = CmdArgumentParser(prog="regquery", description="Query registry")
        parser.add_argument("key_path")
        parser.add_argument("-v", "--value", help="Specific value to query")

        args = parser.parse_args(["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"])
        assert args.key_path == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        assert args.value is None

        args = parser.parse_args(
            ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "-v", "ProgramFilesDir"]
        )
        assert args.value == "ProgramFilesDir"

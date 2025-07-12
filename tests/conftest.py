"""
Pytest configuration and shared fixtures for Slinger tests
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def mock_smb_connection():
    """Mock SMB connection for testing"""
    mock = MagicMock()
    mock.login.return_value = True
    mock.listShares.return_value = [
        {"shi1_netname": "C$", "shi1_type": 0x0, "shi1_remark": "Default share"},
        {"shi1_netname": "ADMIN$", "shi1_type": 0x0, "shi1_remark": "Remote Admin"},
        {"shi1_netname": "IPC$", "shi1_type": 0x3, "shi1_remark": "Remote IPC"},
    ]
    mock.connectTree.return_value = True
    mock.listPath.return_value = []
    return mock


@pytest.fixture
def mock_dce_connection():
    """Mock DCE/RPC connection for testing"""
    mock = MagicMock()
    mock.connect.return_value = True
    mock.bind.return_value = True
    return mock


@pytest.fixture
def mock_slinger_client():
    """Mock SlingerClient for testing"""
    from unittest.mock import Mock

    client = Mock()
    client.host = "192.168.1.100"
    client.username = "testuser"
    client.password = "testpass"
    client.domain = "TESTDOMAIN"
    client.shares = ["C$", "ADMIN$", "IPC$"]
    client.pwd = "C$\\"
    client.use_share = "C$"
    client.smb = Mock()
    client.is_connected.return_value = True

    return client


@pytest.fixture
def sample_registry_data():
    """Sample registry data for testing"""
    return {
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion": {
            "ProgramFilesDir": "C:\\Program Files",
            "SystemRoot": "C:\\Windows",
            "Version": "10.0",
        },
        "HKLM\\SYSTEM\\CurrentControlSet\\Services": {
            "Spooler": {
                "DisplayName": "Print Spooler",
                "ImagePath": "C:\\Windows\\System32\\spoolsv.exe",
                "Start": 2,
            }
        },
    }


@pytest.fixture
def sample_service_data():
    """Sample service data for testing"""
    return [
        {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "status": "RUNNING",
            "type": "WIN32_OWN_PROCESS",
            "start_type": "AUTO_START",
        },
        {
            "name": "Themes",
            "display_name": "Themes",
            "status": "RUNNING",
            "type": "WIN32_SHARE_PROCESS",
            "start_type": "AUTO_START",
        },
    ]


@pytest.fixture
def sample_task_data():
    """Sample scheduled task data for testing"""
    return [
        {
            "name": "\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update",
            "status": "Ready",
            "next_run": "2024-01-20 03:00:00",
            "last_run": "2024-01-19 03:00:00",
        },
        {"name": "\\TestTask", "status": "Disabled", "next_run": "N/A", "last_run": "Never"},
    ]


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file"""
    test_file = tmp_path / "test_file.txt"
    test_file.write_text("This is a test file for Slinger testing.")
    return test_file


@pytest.fixture
def cli_args():
    """Common CLI arguments for testing"""

    class Args:
        host = "192.168.1.100"
        user = "testuser"
        password = "testpass"
        domain = ""
        hashes = None
        no_pass = False
        port = 445
        debug = False
        no_color = True
        log = None

    return Args()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "slow: Tests that take a long time")
    config.addinivalue_line("markers", "requires_mock_server: Tests that require mock SMB server")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers"""
    for item in items:
        # Add markers based on test location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)

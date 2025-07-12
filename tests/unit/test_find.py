#!/usr/bin/env python3
"""
Unit tests for file search functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from datetime import datetime, timedelta

# Add the source directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from slingerpkg.lib.smblib import smblib


class TestFindFunctionality(unittest.TestCase):
    """Test cases for file search functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.smb_client = smblib()
        self.smb_client.conn = Mock()
        self.smb_client.share = "C$"
        self.smb_client.relative_path = "test"
        self.smb_client.is_connected_to_share = True

    def test_parse_size_filter_valid_formats(self):
        """Test size filter parsing with valid formats."""
        # Test various valid size formats
        test_cases = [
            ("+1MB", ("+", 1048576)),
            ("-100KB", ("-", 102400)),
            ("=5GB", ("=", 5368709120)),
            ("1024B", ("=", 1024)),
            ("2.5GB", ("=", 2684354560)),
        ]

        for size_filter, expected in test_cases:
            with self.subTest(size_filter=size_filter):
                result = self.smb_client._parse_size_filter(size_filter)
                self.assertEqual(result, expected)

    def test_parse_size_filter_invalid_formats(self):
        """Test size filter parsing with invalid formats."""
        invalid_filters = ["invalid", "++1MB", "1XB", "MB1", "", "abc"]

        for invalid_filter in invalid_filters:
            with self.subTest(invalid_filter=invalid_filter):
                with self.assertRaises(ValueError):
                    self.smb_client._parse_size_filter(invalid_filter)

    def test_matches_size_filter(self):
        """Test size filter matching logic."""
        # Test greater than
        self.assertTrue(self.smb_client._matches_size_filter(2000, "+", 1000))
        self.assertFalse(self.smb_client._matches_size_filter(500, "+", 1000))

        # Test less than
        self.assertTrue(self.smb_client._matches_size_filter(500, "-", 1000))
        self.assertFalse(self.smb_client._matches_size_filter(2000, "-", 1000))

        # Test equals
        self.assertTrue(self.smb_client._matches_size_filter(1000, "=", 1000))
        self.assertFalse(self.smb_client._matches_size_filter(1001, "=", 1000))

    def test_sort_find_results(self):
        """Test result sorting functionality."""
        # Create mock results
        results = [
            {"name": "file_b.txt", "size": 2000, "mtime": datetime(2023, 1, 2)},
            {"name": "file_a.txt", "size": 1000, "mtime": datetime(2023, 1, 1)},
            {"name": "file_c.txt", "size": 3000, "mtime": datetime(2023, 1, 3)},
        ]

        # Test sorting by name
        sorted_by_name = self.smb_client._sort_find_results(results, "name", False)
        self.assertEqual(
            [r["name"] for r in sorted_by_name], ["file_a.txt", "file_b.txt", "file_c.txt"]
        )

        # Test sorting by size (reverse)
        sorted_by_size = self.smb_client._sort_find_results(results, "size", True)
        self.assertEqual([r["size"] for r in sorted_by_size], [3000, 2000, 1000])

        # Test sorting by mtime
        sorted_by_mtime = self.smb_client._sort_find_results(results, "mtime", False)
        self.assertEqual(
            [r["mtime"] for r in sorted_by_mtime],
            [datetime(2023, 1, 1), datetime(2023, 1, 2), datetime(2023, 1, 3)],
        )

    def test_extract_file_info(self):
        """Test file information extraction."""
        # Mock SMB file object
        mock_file = Mock()
        mock_file.get_longname.return_value = "test.txt"
        mock_file.is_directory.return_value = False
        mock_file.get_filesize.return_value = 1024
        mock_file.get_mtime.return_value = 133000000000000000  # Mock Windows FILETIME
        mock_file.get_ctime.return_value = 133000000000000000
        mock_file.get_atime.return_value = 133000000000000000
        mock_file.is_hidden.return_value = False
        mock_file.is_readonly.return_value = False

        # Mock _get_file_attributes method
        self.smb_client._get_file_attributes = Mock(return_value="F,A")

        result = self.smb_client._extract_file_info(mock_file, "folder")

        self.assertEqual(result["name"], "test.txt")
        self.assertEqual(result["path"], "folder\\test.txt")
        self.assertEqual(result["size"], 1024)
        self.assertFalse(result["is_directory"])
        self.assertEqual(result["attributes"], "F,A")

    @patch("slingerpkg.lib.smblib.print_warning")
    def test_find_handler_not_connected(self, mock_print_warning):
        """Test find handler when not connected to share."""
        self.smb_client.check_if_connected = Mock(return_value=False)

        # Mock args
        args = Mock()

        self.smb_client.find_handler(args)

        mock_print_warning.assert_called_once_with("You are not connected to a share.")

    def test_find_handler_invalid_depth_parameters(self):
        """Test find handler with invalid depth parameters."""
        self.smb_client.check_if_connected = Mock(return_value=True)
        self.smb_client._normalize_path_for_smb = Mock(return_value=(True, "test", ""))

        # Test maxdepth <= 0
        args = Mock()
        args.path = "."
        args.pattern = "*.txt"
        args.maxdepth = 0
        args.mindepth = 0

        with patch("slingerpkg.lib.smblib.print_warning") as mock_warning:
            self.smb_client.find_handler(args)
            mock_warning.assert_called_with("Maximum depth must be greater than 0")

        # Test mindepth < 0
        args.maxdepth = 5
        args.mindepth = -1

        with patch("slingerpkg.lib.smblib.print_warning") as mock_warning:
            self.smb_client.find_handler(args)
            mock_warning.assert_called_with("Minimum depth cannot be negative")

        # Test mindepth >= maxdepth
        args.maxdepth = 5
        args.mindepth = 5

        with patch("slingerpkg.lib.smblib.print_warning") as mock_warning:
            self.smb_client.find_handler(args)
            mock_warning.assert_called_with("Minimum depth must be less than maximum depth")


class TestFindIntegration(unittest.TestCase):
    """Integration tests for find functionality."""

    def setUp(self):
        """Set up integration test fixtures."""
        self.smb_client = smblib()
        self.smb_client.share = "C$"
        self.smb_client.relative_path = ""

    def test_find_files_mock_integration(self):
        """Test _find_files method with mocked SMB responses."""
        # This would require more complex mocking of the SMB connection
        # For now, we'll just test that the method exists and can be called
        self.assertTrue(hasattr(self.smb_client, "_find_files"))
        self.assertTrue(callable(getattr(self.smb_client, "_find_files")))


if __name__ == "__main__":
    unittest.main()

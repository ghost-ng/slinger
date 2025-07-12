#!/usr/bin/env python3
"""
Download State Management for Resume Downloads

This module provides persistent state management for resumable downloads,
enabling interrupted file transfers to be resumed from the exact point
of interruption.
"""

import json
import os
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from slingerpkg.utils.printlib import print_debug, print_warning, print_info


class DownloadState:
    """
    Manages persistent state for resumable downloads.

    State is stored in JSON format with atomic updates to prevent corruption.
    Each download has a unique state file based on local path hash.
    """

    def __init__(self, remote_path: str, local_path: str, total_size: int = 0):
        self.remote_path = remote_path
        self.local_path = local_path
        self.total_size = total_size
        self.bytes_downloaded = 0
        self.chunk_size = 64 * 1024  # 64KB default
        self.checksum_type = "sha256"
        self.partial_checksum = ""
        self.last_modified = datetime.now(timezone.utc).isoformat()
        self.retry_count = 0
        self.max_retries = 5
        self.state_version = "1.0"

        # Calculate state file path
        self.state_file_path = self._get_state_file_path()

    def _get_state_file_path(self) -> str:
        """Generate unique state file path based on local path hash"""
        # Use SHA256 of local path for unique filename
        path_hash = hashlib.sha256(self.local_path.encode()).hexdigest()[:16]

        # Store in .slinger directory in user's home
        slinger_dir = Path.home() / ".slinger" / "downloads"
        slinger_dir.mkdir(parents=True, exist_ok=True)

        state_filename = f"download_{path_hash}.json"
        return str(slinger_dir / state_filename)

    def save_state(self) -> bool:
        """
        Atomically save download state to file.

        Uses temporary file + rename for atomic operation to prevent corruption.
        """
        try:
            state_data = {
                "version": self.state_version,
                "remote_path": self.remote_path,
                "local_path": self.local_path,
                "total_size": self.total_size,
                "bytes_downloaded": self.bytes_downloaded,
                "chunk_size": self.chunk_size,
                "checksum_type": self.checksum_type,
                "partial_checksum": self.partial_checksum,
                "last_modified": self.last_modified,
                "retry_count": self.retry_count,
                "max_retries": self.max_retries,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Atomic write: write to temp file then rename
            temp_path = self.state_file_path + ".tmp"

            with open(temp_path, "w") as f:
                json.dump(state_data, f, indent=2)

            # Atomic rename
            os.rename(temp_path, self.state_file_path)
            print_debug(f"Saved download state: {self.bytes_downloaded}/{self.total_size} bytes")
            return True

        except Exception as e:
            print_debug(f"Failed to save download state: {e}")
            return False

    @classmethod
    def load_state(cls, local_path: str) -> Optional["DownloadState"]:
        """
        Load existing download state from file.

        Returns None if no state file exists or if state is corrupted.
        """
        try:
            # Create temporary instance to get state file path
            temp_state = cls("", local_path)
            state_file_path = temp_state.state_file_path

            if not os.path.exists(state_file_path):
                print_debug(f"No existing state file found for: {local_path}")
                return None

            with open(state_file_path, "r") as f:
                state_data = json.load(f)

            # Validate state file version
            if state_data.get("version") != "1.0":
                print_warning(f"Unsupported state file version: {state_data.get('version')}")
                return None

            # Create state instance from loaded data
            state = cls(
                state_data["remote_path"], state_data["local_path"], state_data["total_size"]
            )

            state.bytes_downloaded = state_data["bytes_downloaded"]
            state.chunk_size = state_data["chunk_size"]
            state.checksum_type = state_data["checksum_type"]
            state.partial_checksum = state_data["partial_checksum"]
            state.last_modified = state_data["last_modified"]
            state.retry_count = state_data["retry_count"]
            state.max_retries = state_data["max_retries"]

            print_debug(f"Loaded download state: {state.bytes_downloaded}/{state.total_size} bytes")
            return state

        except Exception as e:
            print_debug(f"Failed to load download state: {e}")
            return None

    def validate_resume(self) -> Tuple[bool, str]:
        """
        Validate that resume is possible and safe.

        Returns:
            (is_valid, error_message)
        """
        try:
            # Check if local file exists
            if not os.path.exists(self.local_path):
                return False, "Local partial file does not exist"

            # Check local file size matches our state
            local_size = os.path.getsize(self.local_path)
            if local_size != self.bytes_downloaded:
                return (
                    False,
                    f"Local file size ({local_size}) doesn't match state ({self.bytes_downloaded})",
                )

            # Check if we've exceeded retry limits
            if self.retry_count >= self.max_retries:
                return False, f"Maximum retries ({self.max_retries}) exceeded"

            # Check if download is already complete
            if self.bytes_downloaded >= self.total_size and self.total_size > 0:
                return False, "Download already complete"

            return True, "Resume validation successful"

        except Exception as e:
            return False, f"Resume validation error: {e}"

    def update_progress(self, bytes_written: int) -> None:
        """Update download progress and save state"""
        self.bytes_downloaded += bytes_written
        self.last_modified = datetime.now(timezone.utc).isoformat()
        self.save_state()

    def increment_retry(self) -> bool:
        """
        Increment retry counter.

        Returns:
            True if retry is allowed, False if max retries exceeded
        """
        self.retry_count += 1
        self.save_state()
        return self.retry_count < self.max_retries

    def get_resume_offset(self) -> int:
        """Get the byte offset to resume download from"""
        return self.bytes_downloaded

    def get_remaining_bytes(self) -> int:
        """Get number of bytes remaining to download"""
        return max(0, self.total_size - self.bytes_downloaded)

    def get_progress_percentage(self) -> float:
        """Get download progress as percentage"""
        if self.total_size == 0:
            return 0.0
        return (self.bytes_downloaded / self.total_size) * 100

    def cleanup(self) -> bool:
        """Remove state file (called on successful completion)"""
        try:
            if os.path.exists(self.state_file_path):
                os.remove(self.state_file_path)
                print_debug(f"Cleaned up state file: {self.state_file_path}")
            return True
        except Exception as e:
            print_debug(f"Failed to cleanup state file: {e}")
            return False

    def __str__(self) -> str:
        """String representation for debugging"""
        return (
            f"DownloadState(remote='{self.remote_path}', "
            f"local='{self.local_path}', "
            f"progress={self.get_progress_percentage():.1f}%, "
            f"bytes={self.bytes_downloaded}/{self.total_size})"
        )


class DownloadStateManager:
    """
    High-level manager for download states.

    Provides utilities for listing, cleaning up, and managing multiple download states.
    """

    @staticmethod
    def list_active_downloads() -> list:
        """List all active download states"""
        try:
            downloads_dir = Path.home() / ".slinger" / "downloads"
            if not downloads_dir.exists():
                return []

            active_downloads = []
            for state_file in downloads_dir.glob("download_*.json"):
                try:
                    with open(state_file, "r") as f:
                        state_data = json.load(f)

                    progress = 0.0
                    if state_data["total_size"] > 0:
                        progress = (state_data["bytes_downloaded"] / state_data["total_size"]) * 100

                    active_downloads.append(
                        {
                            "local_path": state_data["local_path"],
                            "remote_path": state_data["remote_path"],
                            "progress": progress,
                            "bytes_downloaded": state_data["bytes_downloaded"],
                            "total_size": state_data["total_size"],
                            "last_modified": state_data.get(
                                "timestamp", state_data.get("last_modified", "")
                            ),
                        }
                    )
                except Exception as e:
                    print_debug(f"Skipping corrupted state file {state_file}: {e}")
                    continue

            return active_downloads

        except Exception as e:
            print_debug(f"Error listing active downloads: {e}")
            return []

    @staticmethod
    def cleanup_completed_downloads() -> int:
        """Remove state files for completed downloads"""
        try:
            downloads_dir = Path.home() / ".slinger" / "downloads"
            if not downloads_dir.exists():
                return 0

            cleaned_count = 0
            for state_file in downloads_dir.glob("download_*.json"):
                try:
                    with open(state_file, "r") as f:
                        state_data = json.load(f)

                    # Check if download is complete
                    local_path = state_data["local_path"]
                    if os.path.exists(local_path):
                        local_size = os.path.getsize(local_path)
                        total_size = state_data["total_size"]

                        if total_size > 0 and local_size >= total_size:
                            os.remove(state_file)
                            cleaned_count += 1
                            print_debug(f"Cleaned completed download state: {state_file}")
                    else:
                        # Local file doesn't exist, remove state
                        os.remove(state_file)
                        cleaned_count += 1
                        print_debug(f"Cleaned orphaned download state: {state_file}")

                except Exception as e:
                    print_debug(f"Error processing state file {state_file}: {e}")
                    continue

            return cleaned_count

        except Exception as e:
            print_debug(f"Error cleaning up downloads: {e}")
            return 0

    @staticmethod
    def cleanup_stale_downloads(max_age_days: int = 7) -> int:
        """Remove state files older than specified days"""
        try:
            downloads_dir = Path.home() / ".slinger" / "downloads"
            if not downloads_dir.exists():
                return 0

            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 60 * 60
            cleaned_count = 0

            for state_file in downloads_dir.glob("download_*.json"):
                try:
                    file_age = current_time - os.path.getmtime(state_file)
                    if file_age > max_age_seconds:
                        os.remove(state_file)
                        cleaned_count += 1
                        print_debug(f"Cleaned stale download state: {state_file}")
                except Exception as e:
                    print_debug(f"Error processing stale file {state_file}: {e}")
                    continue

            return cleaned_count

        except Exception as e:
            print_debug(f"Error cleaning up stale downloads: {e}")
            return 0


def parse_chunk_size(chunk_size_str: str) -> int:
    """
    Parse human-readable chunk size string to bytes.

    Examples: '64k', '1M', '512', '2MB'
    """
    if not chunk_size_str:
        return 64 * 1024  # Default 64KB

    chunk_size_str = chunk_size_str.strip().upper()

    # Default to bytes if no unit specified
    if chunk_size_str.isdigit():
        return int(chunk_size_str)

    # Parse size with unit
    try:
        if chunk_size_str.endswith("K") or chunk_size_str.endswith("KB"):
            number = chunk_size_str.rstrip("KB")
            return int(number) * 1024
        elif chunk_size_str.endswith("M") or chunk_size_str.endswith("MB"):
            number = chunk_size_str.rstrip("MB")
            return int(number) * 1024 * 1024
        elif chunk_size_str.endswith("G") or chunk_size_str.endswith("GB"):
            number = chunk_size_str.rstrip("GB")
            return int(number) * 1024 * 1024 * 1024
        else:
            # Unknown unit, default to bytes
            return int(chunk_size_str.rstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    except ValueError:
        print_warning(f"Invalid chunk size '{chunk_size_str}', using default 64KB")
        return 64 * 1024

#!/usr/bin/env python3
"""
Download State Management System Design

This module defines the state management system for resume downloads,
including file format, persistence, and recovery mechanisms.
"""

import json
import os
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple


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
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Atomic write: write to temp file then rename
            temp_path = self.state_file_path + ".tmp"
            
            with open(temp_path, 'w') as f:
                json.dump(state_data, f, indent=2)
            
            # Atomic rename
            os.rename(temp_path, self.state_file_path)
            return True
            
        except Exception as e:
            print(f"Failed to save download state: {e}")
            return False
    
    @classmethod
    def load_state(cls, local_path: str) -> Optional['DownloadState']:
        """
        Load existing download state from file.
        
        Returns None if no state file exists or if state is corrupted.
        """
        try:
            # Create temporary instance to get state file path
            temp_state = cls("", local_path)
            state_file_path = temp_state.state_file_path
            
            if not os.path.exists(state_file_path):
                return None
            
            with open(state_file_path, 'r') as f:
                state_data = json.load(f)
            
            # Validate state file version
            if state_data.get("version") != "1.0":
                print(f"Unsupported state file version: {state_data.get('version')}")
                return None
            
            # Create state instance from loaded data
            state = cls(
                state_data["remote_path"],
                state_data["local_path"],
                state_data["total_size"]
            )
            
            state.bytes_downloaded = state_data["bytes_downloaded"]
            state.chunk_size = state_data["chunk_size"]
            state.checksum_type = state_data["checksum_type"]
            state.partial_checksum = state_data["partial_checksum"]
            state.last_modified = state_data["last_modified"]
            state.retry_count = state_data["retry_count"]
            state.max_retries = state_data["max_retries"]
            
            return state
            
        except Exception as e:
            print(f"Failed to load download state: {e}")
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
                return False, f"Local file size ({local_size}) doesn't match state ({self.bytes_downloaded})"
            
            # Check if we've exceeded retry limits
            if self.retry_count >= self.max_retries:
                return False, f"Maximum retries ({self.max_retries}) exceeded"
            
            # Check if download is already complete
            if self.bytes_downloaded >= self.total_size:
                return False, "Download already complete"
            
            # TODO: Add checksum validation of partial file
            # if self.partial_checksum:
            #     if not self._validate_partial_checksum():
            #         return False, "Partial file checksum validation failed"
            
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
            return True
        except Exception as e:
            print(f"Failed to cleanup state file: {e}")
            return False
    
    def _calculate_partial_checksum(self) -> str:
        """Calculate checksum of partial file for integrity validation"""
        try:
            hasher = hashlib.sha256()
            with open(self.local_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return (f"DownloadState(remote='{self.remote_path}', "
                f"local='{self.local_path}', "
                f"progress={self.get_progress_percentage():.1f}%, "
                f"bytes={self.bytes_downloaded}/{self.total_size})")


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
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    
                    active_downloads.append({
                        "local_path": state_data["local_path"],
                        "remote_path": state_data["remote_path"],
                        "progress": (state_data["bytes_downloaded"] / state_data["total_size"]) * 100,
                        "bytes_downloaded": state_data["bytes_downloaded"],
                        "total_size": state_data["total_size"],
                        "last_modified": state_data["timestamp"]
                    })
                except Exception:
                    continue  # Skip corrupted state files
            
            return active_downloads
            
        except Exception as e:
            print(f"Error listing active downloads: {e}")
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
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    
                    # Check if download is complete
                    local_path = state_data["local_path"]
                    if os.path.exists(local_path):
                        local_size = os.path.getsize(local_path)
                        total_size = state_data["total_size"]
                        
                        if local_size >= total_size:
                            os.remove(state_file)
                            cleaned_count += 1
                    else:
                        # Local file doesn't exist, remove state
                        os.remove(state_file)
                        cleaned_count += 1
                        
                except Exception:
                    continue  # Skip problematic files
            
            return cleaned_count
            
        except Exception as e:
            print(f"Error cleaning up downloads: {e}")
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
                except Exception:
                    continue
            
            return cleaned_count
            
        except Exception as e:
            print(f"Error cleaning up stale downloads: {e}")
            return 0


# Example usage and testing
if __name__ == "__main__":
    print("Download State Management System Design")
    print("======================================")
    
    # Example: Create new download state
    state = DownloadState(
        remote_path="C:\\Windows\\System32\\cmd.exe",
        local_path="/tmp/cmd.exe",
        total_size=291328
    )
    
    print(f"Created state: {state}")
    print(f"State file path: {state.state_file_path}")
    
    # Example: Save and load state
    print("\nTesting state persistence...")
    if state.save_state():
        print("✓ State saved successfully")
        
        loaded_state = DownloadState.load_state("/tmp/cmd.exe")
        if loaded_state:
            print(f"✓ State loaded: {loaded_state}")
        else:
            print("✗ Failed to load state")
    else:
        print("✗ Failed to save state")
    
    # Example: Progress update
    print("\nTesting progress updates...")
    state.update_progress(65536)  # Downloaded 64KB
    print(f"Progress: {state.get_progress_percentage():.1f}%")
    print(f"Remaining: {state.get_remaining_bytes()} bytes")
    
    # Example: Resume validation
    print("\nTesting resume validation...")
    is_valid, message = state.validate_resume()
    print(f"Resume valid: {is_valid} - {message}")
    
    # Example: Manager functions
    print("\nTesting state manager...")
    active = DownloadStateManager.list_active_downloads()
    print(f"Active downloads: {len(active)}")
    
    # Cleanup example state
    state.cleanup()
    print("✓ Cleaned up test state")
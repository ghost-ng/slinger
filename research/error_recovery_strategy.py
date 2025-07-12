#!/usr/bin/env python3
"""
Error Categorization and Recovery Strategy for Resume Downloads

This module defines error types, recovery strategies, and retry logic
for robust resume download functionality.
"""

import time
import random
from enum import Enum
from typing import Dict, Tuple, Optional
from dataclasses import dataclass


class ErrorCategory(Enum):
    """Classification of errors for appropriate recovery strategies"""
    
    # Recoverable errors - retry with backoff
    NETWORK_TIMEOUT = "network_timeout"
    CONNECTION_LOST = "connection_lost"
    SMB_PROTOCOL_ERROR = "smb_protocol_error"
    TEMPORARY_ACCESS_DENIED = "temp_access_denied"
    SERVER_BUSY = "server_busy"
    
    # Fatal errors - require user intervention
    FILE_NOT_FOUND = "file_not_found"
    PERMANENT_ACCESS_DENIED = "perm_access_denied"
    DISK_FULL = "disk_full"
    PERMISSION_ERROR = "permission_error"
    FILE_CHANGED = "file_changed"
    INVALID_PATH = "invalid_path"
    
    # Special cases
    MAX_RETRIES_EXCEEDED = "max_retries_exceeded"
    USER_CANCELLED = "user_cancelled"
    UNKNOWN = "unknown"


@dataclass
class ErrorInfo:
    """Information about an error occurrence"""
    category: ErrorCategory
    message: str
    retry_count: int
    timestamp: float
    can_retry: bool
    suggested_action: str


class ErrorClassifier:
    """
    Classifies SMB and network errors into appropriate categories
    for recovery strategy determination.
    """
    
    # Error patterns mapped to categories
    ERROR_PATTERNS = {
        # Network/Connection errors (recoverable)
        ErrorCategory.NETWORK_TIMEOUT: [
            "timeout",
            "timed out",
            "connection timeout",
            "read timeout",
            "socket timeout"
        ],
        
        ErrorCategory.CONNECTION_LOST: [
            "connection lost",
            "connection reset",
            "connection aborted",
            "broken pipe",
            "network is unreachable",
            "no route to host"
        ],
        
        ErrorCategory.SMB_PROTOCOL_ERROR: [
            "STATUS_INVALID_SMB",
            "STATUS_SMB_BAD_TID",
            "STATUS_INVALID_HANDLE",
            "STATUS_NETWORK_NAME_DELETED"
        ],
        
        ErrorCategory.SERVER_BUSY: [
            "STATUS_TOO_MANY_CONNECTIONS",
            "STATUS_INSUFFICIENT_RESOURCES",
            "server busy",
            "too busy"
        ],
        
        # File/Access errors (potentially fatal)
        ErrorCategory.FILE_NOT_FOUND: [
            "STATUS_OBJECT_NAME_NOT_FOUND",
            "STATUS_NO_SUCH_FILE",
            "file not found",
            "path not found"
        ],
        
        ErrorCategory.PERMANENT_ACCESS_DENIED: [
            "STATUS_ACCESS_DENIED",
            "access denied",
            "permission denied",
            "forbidden"
        ],
        
        ErrorCategory.DISK_FULL: [
            "no space left",
            "disk full",
            "insufficient space",
            "STATUS_DISK_FULL"
        ],
        
        ErrorCategory.FILE_CHANGED: [
            "file size changed",
            "file modified",
            "checksum mismatch",
            "file timestamp changed"
        ]
    }
    
    @classmethod
    def classify_error(cls, error_message: str, retry_count: int = 0) -> ErrorInfo:
        """
        Classify an error and determine recovery strategy.
        
        Args:
            error_message: The error message to classify
            retry_count: Current retry attempt number
            
        Returns:
            ErrorInfo with classification and recovery suggestions
        """
        error_msg_lower = error_message.lower()
        
        # Check each category for matching patterns
        for category, patterns in cls.ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in error_msg_lower:
                    return cls._create_error_info(category, error_message, retry_count)
        
        # Default to unknown category
        return cls._create_error_info(ErrorCategory.UNKNOWN, error_message, retry_count)
    
    @classmethod
    def _create_error_info(cls, category: ErrorCategory, message: str, retry_count: int) -> ErrorInfo:
        """Create ErrorInfo object with appropriate recovery strategy"""
        
        # Determine if retry is possible
        can_retry = category in [
            ErrorCategory.NETWORK_TIMEOUT,
            ErrorCategory.CONNECTION_LOST,
            ErrorCategory.SMB_PROTOCOL_ERROR,
            ErrorCategory.SERVER_BUSY,
            ErrorCategory.UNKNOWN  # Be optimistic about unknown errors
        ]
        
        # Generate suggested action
        suggested_action = cls._get_suggested_action(category, retry_count)
        
        return ErrorInfo(
            category=category,
            message=message,
            retry_count=retry_count,
            timestamp=time.time(),
            can_retry=can_retry,
            suggested_action=suggested_action
        )
    
    @classmethod
    def _get_suggested_action(cls, category: ErrorCategory, retry_count: int) -> str:
        """Get human-readable suggested action for error category"""
        
        action_map = {
            ErrorCategory.NETWORK_TIMEOUT: f"Retrying with exponential backoff (attempt {retry_count + 1})",
            ErrorCategory.CONNECTION_LOST: f"Re-establishing connection and retrying (attempt {retry_count + 1})",
            ErrorCategory.SMB_PROTOCOL_ERROR: f"Retrying SMB operation (attempt {retry_count + 1})",
            ErrorCategory.SERVER_BUSY: f"Waiting for server resources (attempt {retry_count + 1})",
            ErrorCategory.FILE_NOT_FOUND: "Check remote file path and permissions",
            ErrorCategory.PERMANENT_ACCESS_DENIED: "Verify authentication credentials and file permissions",
            ErrorCategory.DISK_FULL: "Free up disk space on local system",
            ErrorCategory.FILE_CHANGED: "Remote file has changed - restart download",
            ErrorCategory.PERMISSION_ERROR: "Check local file permissions",
            ErrorCategory.INVALID_PATH: "Verify local and remote paths are valid",
            ErrorCategory.MAX_RETRIES_EXCEEDED: "Manual intervention required",
            ErrorCategory.USER_CANCELLED: "Download cancelled by user",
            ErrorCategory.UNKNOWN: f"Retrying unknown error (attempt {retry_count + 1})"
        }
        
        return action_map.get(category, "Unknown error - manual investigation required")


class ExponentialBackoff:
    """
    Implements exponential backoff with jitter for retry operations.
    """
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, 
                 backoff_factor: float = 2.0, jitter: bool = True):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
    
    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for given attempt number.
        
        Args:
            attempt: Retry attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        # Calculate exponential delay
        delay = self.base_delay * (self.backoff_factor ** attempt)
        delay = min(delay, self.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.jitter:
            jitter_amount = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        return max(0, delay)
    
    def wait(self, attempt: int) -> None:
        """Sleep for the calculated delay"""
        delay = self.get_delay(attempt)
        time.sleep(delay)


class RetryManager:
    """
    Manages retry logic and recovery strategies for download operations.
    """
    
    def __init__(self, max_retries: int = 5):
        self.max_retries = max_retries
        self.backoff = ExponentialBackoff()
        self.retry_counts = {}  # Track retries per error category
    
    def should_retry(self, error_info: ErrorInfo) -> Tuple[bool, str]:
        """
        Determine if an operation should be retried.
        
        Args:
            error_info: Classified error information
            
        Returns:
            (should_retry, reason)
        """
        # Check if error category is retryable
        if not error_info.can_retry:
            return False, f"Error category '{error_info.category.value}' is not retryable"
        
        # Check retry count limits
        if error_info.retry_count >= self.max_retries:
            return False, f"Maximum retries ({self.max_retries}) exceeded"
        
        return True, "Retry permitted"
    
    def execute_with_retry(self, operation, *args, **kwargs):
        """
        Execute operation with automatic retry and recovery.
        
        Args:
            operation: Function to execute
            *args, **kwargs: Arguments for the operation
            
        Returns:
            Operation result or raises final exception
        """
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return operation(*args, **kwargs)
                
            except Exception as e:
                last_error = e
                error_info = ErrorClassifier.classify_error(str(e), attempt)
                
                should_retry, reason = self.should_retry(error_info)
                
                if not should_retry:
                    print(f"Not retrying: {reason}")
                    break
                
                if attempt < self.max_retries:
                    delay = self.backoff.get_delay(attempt)
                    print(f"Retry {attempt + 1}/{self.max_retries} after {delay:.1f}s: {error_info.suggested_action}")
                    time.sleep(delay)
        
        # All retries exhausted
        raise last_error


class ConnectionRecovery:
    """
    Handles SMB connection recovery for network interruptions.
    """
    
    def __init__(self, connection_factory):
        """
        Args:
            connection_factory: Function that returns a new SMB connection
        """
        self.connection_factory = connection_factory
        self.current_connection = None
    
    def ensure_connection(self) -> bool:
        """
        Ensure we have a valid SMB connection, reconnecting if necessary.
        
        Returns:
            True if connection is available, False otherwise
        """
        try:
            # Test current connection if it exists
            if self.current_connection is not None:
                # Try a simple operation to test connection
                self.current_connection.listShares()
                return True
                
        except Exception:
            # Connection is broken, need to reconnect
            self.current_connection = None
        
        # Attempt to create new connection
        try:
            self.current_connection = self.connection_factory()
            return self.current_connection is not None
            
        except Exception as e:
            print(f"Failed to establish connection: {e}")
            return False
    
    def get_connection(self):
        """Get current connection, ensuring it's valid"""
        if self.ensure_connection():
            return self.current_connection
        return None


# Integration example for slinger
class ResumeDownloadRecovery:
    """
    High-level recovery manager for resume download operations.
    """
    
    def __init__(self, smb_client, max_retries: int = 5):
        self.smb_client = smb_client
        self.retry_manager = RetryManager(max_retries)
        self.connection_recovery = ConnectionRecovery(
            lambda: self._reconnect_smb()
        )
    
    def _reconnect_smb(self):
        """Reconnect SMB using existing client credentials"""
        # This would use the existing slinger connection parameters
        # to re-establish the SMB connection
        try:
            # Implementation would depend on slinger's connection architecture
            return self.smb_client.reconnect()
        except Exception as e:
            print(f"SMB reconnection failed: {e}")
            return None
    
    def download_chunk_with_recovery(self, remote_path: str, offset: int, 
                                   chunk_size: int, max_retries: int = 3):
        """
        Download a single chunk with full error recovery.
        
        Args:
            remote_path: Remote file path
            offset: Byte offset to start reading
            chunk_size: Number of bytes to read
            max_retries: Maximum retry attempts
            
        Returns:
            Chunk data or None on failure
        """
        def download_operation():
            # Ensure we have a valid connection
            connection = self.connection_recovery.get_connection()
            if not connection:
                raise Exception("Unable to establish SMB connection")
            
            # Perform the actual chunk download
            return self._download_chunk_internal(remote_path, offset, chunk_size)
        
        try:
            return self.retry_manager.execute_with_retry(download_operation)
        except Exception as e:
            error_info = ErrorClassifier.classify_error(str(e))
            print(f"Final error after retries: {error_info.suggested_action}")
            return None
    
    def _download_chunk_internal(self, remote_path: str, offset: int, chunk_size: int):
        """Internal method that performs the actual chunk download"""
        # This would implement the actual SMB chunk download
        # using the byte-range operations researched earlier
        pass


# Error recovery configuration
ERROR_RECOVERY_CONFIG = {
    "max_retries": 5,
    "base_delay": 1.0,
    "max_delay": 60.0,
    "backoff_factor": 2.0,
    "enable_jitter": True,
    "connection_timeout": 30.0,
    "chunk_timeout": 120.0
}


if __name__ == "__main__":
    print("Error Recovery Strategy for Resume Downloads")
    print("===========================================")
    
    # Test error classification
    print("\nTesting error classification:")
    
    test_errors = [
        "Network timeout occurred",
        "STATUS_ACCESS_DENIED",
        "Connection reset by peer",
        "No space left on device",
        "STATUS_OBJECT_NAME_NOT_FOUND",
        "Unknown protocol error"
    ]
    
    for error in test_errors:
        error_info = ErrorClassifier.classify_error(error, retry_count=2)
        print(f"Error: {error}")
        print(f"  Category: {error_info.category.value}")
        print(f"  Can retry: {error_info.can_retry}")
        print(f"  Action: {error_info.suggested_action}")
        print()
    
    # Test exponential backoff
    print("Testing exponential backoff:")
    backoff = ExponentialBackoff()
    for i in range(6):
        delay = backoff.get_delay(i)
        print(f"  Attempt {i}: {delay:.2f}s delay")
    
    print("\n✓ Error recovery strategy design complete")
    print("✓ Ready for integration into resume download system")
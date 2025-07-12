#!/usr/bin/env python3
"""
Basic Error Recovery for Resume Downloads

This module provides basic error recovery and retry logic for download operations.
"""

import time
import random
from enum import Enum
from typing import Optional

from slingerpkg.utils.printlib import print_debug, print_warning, print_info


class RetryableError(Exception):
    """Exception for errors that can be retried"""

    def __init__(self, message, retry_delay=1.0):
        super().__init__(message)
        self.retry_delay = retry_delay


class FatalError(Exception):
    """Exception for errors that cannot be retried"""

    pass


def classify_smb_error(error_message: str) -> bool:
    """
    Classify SMB error to determine if it's retryable.

    Args:
        error_message: The error message to classify

    Returns:
        True if retryable, False if fatal
    """
    error_msg_lower = error_message.lower()

    # Retryable errors
    retryable_patterns = [
        "timeout",
        "timed out",
        "connection timeout",
        "connection reset",
        "connection lost",
        "broken pipe",
        "network is unreachable",
        "no route to host",
        "status_invalid_smb",
        "status_smb_bad_tid",
        "status_invalid_handle",
        "status_network_name_deleted",
        "too busy",
        "server busy",
        "status_too_many_connections",
    ]

    # Fatal errors
    fatal_patterns = [
        "status_object_name_not_found",
        "file not found",
        "status_access_denied",
        "access denied",
        "permission denied",
        "no space left",
        "disk full",
        "status_disk_full",
        "file size changed",
        "file modified",
        "checksum mismatch",
    ]

    # Check for fatal errors first
    for pattern in fatal_patterns:
        if pattern in error_msg_lower:
            return False

    # Check for retryable errors
    for pattern in retryable_patterns:
        if pattern in error_msg_lower:
            return True

    # Unknown errors are treated as retryable (optimistic approach)
    return True


class SimpleRetryManager:
    """
    Simple retry manager with exponential backoff for download operations.
    """

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 30.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    def get_retry_delay(self, attempt: int) -> float:
        """Calculate retry delay with exponential backoff and jitter"""
        if attempt <= 0:
            return 0

        # Exponential backoff: 1s, 2s, 4s, 8s, etc.
        delay = self.base_delay * (2 ** (attempt - 1))
        delay = min(delay, self.max_delay)

        # Add 10% jitter to prevent thundering herd
        jitter = delay * 0.1 * random.uniform(-1, 1)
        return max(0, delay + jitter)

    def should_retry(self, error_message: str, attempt: int) -> bool:
        """Determine if operation should be retried"""
        if attempt >= self.max_retries:
            return False

        return classify_smb_error(error_message)

    def execute_with_retry(self, operation, *args, **kwargs):
        """
        Execute operation with retry logic.

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
                error_msg = str(e)

                if not self.should_retry(error_msg, attempt):
                    print_debug(f"Error not retryable: {error_msg}")
                    break

                if attempt < self.max_retries:
                    delay = self.get_retry_delay(attempt + 1)
                    print_warning(
                        f"Operation failed (attempt {attempt + 1}/{self.max_retries + 1}): {error_msg}"
                    )
                    print_info(f"Retrying in {delay:.1f} seconds...")
                    time.sleep(delay)
                else:
                    print_warning(f"Final attempt failed: {error_msg}")

        # All retries exhausted
        raise last_error


def with_basic_retry(max_retries: int = 3):
    """
    Decorator for adding basic retry logic to methods.

    Usage:
        @with_basic_retry(max_retries=3)
        def download_chunk(self, remote_path, offset, chunk_size):
            # Method implementation
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            retry_manager = SimpleRetryManager(max_retries=max_retries)
            return retry_manager.execute_with_retry(func, *args, **kwargs)

        return wrapper

    return decorator


# Utility functions for connection recovery
def reconnect_smb_with_retry(connection_factory, max_attempts: int = 3):
    """
    Attempt to reconnect SMB connection with retry logic.

    Args:
        connection_factory: Function that creates a new SMB connection
        max_attempts: Maximum reconnection attempts

    Returns:
        New connection or None if failed
    """
    for attempt in range(max_attempts):
        try:
            print_info(f"Attempting SMB reconnection (attempt {attempt + 1}/{max_attempts})...")
            connection = connection_factory()
            if connection:
                print_info("SMB connection re-established successfully")
                return connection
        except Exception as e:
            error_msg = str(e)
            print_warning(f"Reconnection attempt {attempt + 1} failed: {error_msg}")

            if attempt < max_attempts - 1:
                delay = 2**attempt  # 1s, 2s, 4s
                print_info(f"Waiting {delay}s before next attempt...")
                time.sleep(delay)

    print_warning("Failed to re-establish SMB connection after all attempts")
    return None


def validate_chunk_integrity(chunk_data: bytes, expected_size: int) -> bool:
    """
    Basic validation of downloaded chunk data.

    Args:
        chunk_data: Downloaded chunk bytes
        expected_size: Expected chunk size

    Returns:
        True if chunk appears valid
    """
    if chunk_data is None:
        return False

    if len(chunk_data) > expected_size:
        print_warning(f"Chunk size larger than expected: {len(chunk_data)} > {expected_size}")
        return False

    # Basic validation passed
    return True

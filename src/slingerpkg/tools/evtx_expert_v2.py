#!/usr/bin/env python3
"""
EVTX Expert v2 - Windows EventLog Binary XML Format Manipulation Tool
Based on Microsoft EVTX specifications and forensics research

Author: Claude Code
Purpose: Professional-grade EVTX file manipulation for security research
Format: EVTX (Windows Vista+ Event Log) with Binary XML
"""

import struct
import os
import sys
import json
import zlib
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, BinaryIO
import argparse


class EVTXError(Exception):
    """Base exception for EVTX operations"""

    pass


class EVTXStructureError(EVTXError):
    """EVTX file structure corruption or format error"""

    pass


class EVTXManipulationError(EVTXError):
    """Error during EVTX file manipulation"""

    pass


class EVTXFileHeader:
    """
    EVTX File Header Structure (4096 bytes total, 128 bytes used)

    Based on Microsoft EVTX specification:
    - Magic: "ElfFile\x00" (8 bytes)
    - FirstChunkNumber: Number of first chunk (8 bytes)
    - LastChunkNumber: Number of last chunk (8 bytes)
    - NextRecordIdentifier: Next record ID to assign (8 bytes)
    - HeaderSize: Size of header (128 bytes) (4 bytes)
    - MinorVersion: EVTX format minor version (2 bytes)
    - MajorVersion: EVTX format major version (2 bytes)
    - HeaderBlockSize: Size of header block (2 bytes)
    - NumberOfChunks: Total chunks in file (2 bytes)
    - Unknown1: Reserved (76 bytes)
    - FileFlags: File status flags (4 bytes)
    - Checksum: CRC32 header checksum (4 bytes)
    - Padding: Zero padding to 4096 bytes
    """

    FORMAT = "<8sQQQIHHHH76sII"
    HEADER_SIZE = 128
    TOTAL_SIZE = 4096
    MAGIC = b"ElfFile\x00"

    def __init__(self, data: bytes = None):
        if data:
            self.parse(data)
        else:
            # Create new header
            self.magic = self.MAGIC
            self.first_chunk_number = 0
            self.last_chunk_number = 0
            self.next_record_identifier = 1
            self.header_size = self.HEADER_SIZE
            self.minor_version = 1
            self.major_version = 3
            self.header_block_size = self.HEADER_SIZE
            self.number_of_chunks = 0
            self.unknown1 = b"\x00" * 76
            self.file_flags = 0
            self.checksum = 0

    def parse(self, data: bytes):
        """Parse EVTX file header from binary data"""
        if len(data) < self.TOTAL_SIZE:
            raise EVTXStructureError(f"File header too short: {len(data)} < {self.TOTAL_SIZE}")

        # Parse the structured header portion (128 bytes)
        header_data = data[: self.HEADER_SIZE]
        fields = struct.unpack(self.FORMAT, header_data)

        self.magic = fields[0]
        if self.magic != self.MAGIC:
            raise EVTXStructureError(f"Invalid EVTX magic: {self.magic!r}")

        self.first_chunk_number = fields[1]
        self.last_chunk_number = fields[2]
        self.next_record_identifier = fields[3]
        self.header_size = fields[4]
        self.minor_version = fields[5]
        self.major_version = fields[6]
        self.header_block_size = fields[7]
        self.number_of_chunks = fields[8]
        self.unknown1 = fields[9]
        self.file_flags = fields[10]
        self.checksum = fields[11]

        # Note: Header checksum verification is handled in the file loading process

    def pack(self) -> bytes:
        """Pack header back to binary format"""
        # Calculate checksum before packing
        temp_data = struct.pack(
            self.FORMAT[:-1] + "I",
            self.magic,
            self.first_chunk_number,
            self.last_chunk_number,
            self.next_record_identifier,
            self.header_size,
            self.minor_version,
            self.major_version,
            self.header_block_size,
            self.number_of_chunks,
            self.unknown1,
            self.file_flags,
            0,
        )

        self.checksum = self._calculate_checksum(temp_data[:-4])

        header_data = struct.pack(
            self.FORMAT,
            self.magic,
            self.first_chunk_number,
            self.last_chunk_number,
            self.next_record_identifier,
            self.header_size,
            self.minor_version,
            self.major_version,
            self.header_block_size,
            self.number_of_chunks,
            self.unknown1,
            self.file_flags,
            self.checksum,
        )

        # Pad to full 4096 bytes
        return header_data + b"\x00" * (self.TOTAL_SIZE - len(header_data))

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate CRC32 checksum for header"""
        return zlib.crc32(data) & 0xFFFFFFFF

    def __repr__(self):
        return (
            f"EVTXFileHeader(chunks={self.number_of_chunks}, "
            f"next_record={self.next_record_identifier}, "
            f"version={self.major_version}.{self.minor_version})"
        )


class EVTXChunkHeader:
    """
    EVTX Chunk Header Structure (512 bytes)

    Based on Microsoft specification:
    - Magic: "ElfChnk\x00" (8 bytes)
    - FirstEventRecordNumber: First record number in chunk (8 bytes)
    - LastEventRecordNumber: Last record number in chunk (8 bytes)
    - FirstEventRecordIdentifier: Identifier of first record (8 bytes)
    - LastEventRecordIdentifier: Identifier of last record (8 bytes)
    - HeaderSize: Size of this header (4 bytes)
    - LastEventRecordDataOffset: Offset to last event record (4 bytes)
    - FreeSpaceOffset: Offset to free space (4 bytes)
    - EventRecordsChecksum: CRC32 of event records (4 bytes)
    - Unknown: Reserved (68 bytes)
    - Checksum: CRC32 of chunk header (4 bytes)
    - Padding: Zero padding to 512 bytes (384 bytes)
    """

    FORMAT = "<8sQQQQIIII68sI"
    SIZE = 512
    MAGIC = b"ElfChnk\x00"

    def __init__(self, data: bytes = None, chunk_number: int = 0):
        self.chunk_number = chunk_number
        if data:
            self.parse(data)
        else:
            # Create new chunk header
            self.magic = self.MAGIC
            self.first_event_record_number = 0
            self.last_event_record_number = 0
            self.first_event_record_identifier = 0
            self.last_event_record_identifier = 0
            self.header_size = 128  # Actual structured header size
            self.last_event_record_data_offset = 512
            self.free_space_offset = 512
            self.event_records_checksum = 0
            self.unknown = b"\x00" * 68
            self.checksum = 0

    def parse(self, data: bytes):
        """Parse chunk header from binary data"""
        if len(data) < self.SIZE:
            raise EVTXStructureError(f"Chunk header too short: {len(data)} < {self.SIZE}")

        # Parse structured portion (128 bytes)
        header_data = data[:128]
        fields = struct.unpack(self.FORMAT, header_data)

        self.magic = fields[0]
        if self.magic != self.MAGIC:
            raise EVTXStructureError(f"Invalid chunk magic: {self.magic!r}")

        self.first_event_record_number = fields[1]
        self.last_event_record_number = fields[2]
        self.first_event_record_identifier = fields[3]
        self.last_event_record_identifier = fields[4]
        self.header_size = fields[5]
        self.last_event_record_data_offset = fields[6]
        self.free_space_offset = fields[7]
        self.event_records_checksum = fields[8]
        self.unknown = fields[9]
        self.checksum = fields[10]

        # Verify chunk header checksum
        checksum_data = data[:120] + data[128:512]  # Exclude checksum field
        calculated_checksum = zlib.crc32(checksum_data) & 0xFFFFFFFF
        if calculated_checksum != self.checksum:
            print(f"[!] Chunk {self.chunk_number} header checksum mismatch")

    def pack(self) -> bytes:
        """Pack chunk header back to binary format"""
        # Calculate checksum
        temp_header = struct.pack(
            self.FORMAT[:-1] + "I",
            self.magic,
            self.first_event_record_number,
            self.last_event_record_number,
            self.first_event_record_identifier,
            self.last_event_record_identifier,
            self.header_size,
            self.last_event_record_data_offset,
            self.free_space_offset,
            self.event_records_checksum,
            self.unknown,
            0,
        )

        # Add padding for checksum calculation
        temp_data = temp_header[:120] + b"\x00" * 384 + temp_header[120:]
        self.checksum = zlib.crc32(temp_data[:-4]) & 0xFFFFFFFF

        # Pack final header
        header_data = struct.pack(
            self.FORMAT,
            self.magic,
            self.first_event_record_number,
            self.last_event_record_number,
            self.first_event_record_identifier,
            self.last_event_record_identifier,
            self.header_size,
            self.last_event_record_data_offset,
            self.free_space_offset,
            self.event_records_checksum,
            self.unknown,
            self.checksum,
        )

        # Pad to full 512 bytes
        return header_data + b"\x00" * (self.SIZE - len(header_data))

    def __repr__(self):
        return (
            f"EVTXChunkHeader(chunk={self.chunk_number}, "
            f"records={self.first_event_record_number}-{self.last_event_record_number}, "
            f"free_space={65536 - self.free_space_offset})"
        )


class EVTXEventRecord:
    """
    EVTX Event Record Structure

    Based on Microsoft specification:
    - Magic: "\x2a\x2a\x00\x00" (4 bytes)
    - Size: Total record size including header and trailing size (4 bytes)
    - EventRecordIdentifier: Unique record identifier (8 bytes)
    - TimeCreated: Event timestamp in FILETIME format (8 bytes)
    - BinaryXMLData: Variable-length binary XML content
    - Size2: Duplicate of size field at end (4 bytes)
    """

    MAGIC = b"\x2a\x2a\x00\x00"
    HEADER_SIZE = 24  # Magic + Size + RecordID + TimeCreated

    def __init__(self, data: bytes = None, record_id: int = None):
        if data:
            self.parse(data)
        else:
            # Create new record
            self.magic = self.MAGIC
            self.size = self.HEADER_SIZE + 4  # Minimum size with trailing size
            self.record_identifier = record_id or 1
            self.time_created = self._current_filetime()
            self.binary_xml_data = b""

    def parse(self, data: bytes):
        """Parse event record from binary data"""
        if len(data) < self.HEADER_SIZE:
            raise EVTXStructureError(f"Record header too short: {len(data)} < {self.HEADER_SIZE}")

        # Parse header
        self.magic, self.size, self.record_identifier, self.time_created = struct.unpack(
            "<4sIQQ", data[: self.HEADER_SIZE]
        )

        if self.magic != self.MAGIC:
            raise EVTXStructureError(f"Invalid record magic: {self.magic!r}")

        if self.size < self.HEADER_SIZE + 4:
            raise EVTXStructureError(f"Invalid record size: {self.size}")

        if len(data) < self.size:
            raise EVTXStructureError(f"Record data truncated: {len(data)} < {self.size}")

        # Extract binary XML data (between header and trailing size)
        xml_size = self.size - self.HEADER_SIZE - 4
        self.binary_xml_data = data[self.HEADER_SIZE : self.HEADER_SIZE + xml_size]

        # Verify trailing size field
        trailing_size = struct.unpack("<I", data[self.size - 4 : self.size])[0]
        if trailing_size != self.size:
            raise EVTXStructureError(f"Size mismatch: {self.size} != {trailing_size}")

    def pack(self) -> bytes:
        """Pack record back to binary format"""
        self.size = self.HEADER_SIZE + len(self.binary_xml_data) + 4

        return (
            struct.pack("<4sIQQ", self.magic, self.size, self.record_identifier, self.time_created)
            + self.binary_xml_data
            + struct.pack("<I", self.size)
        )

    def _current_filetime(self) -> int:
        """Convert current time to Windows FILETIME format"""
        # FILETIME: 100-nanosecond intervals since January 1, 1601 UTC
        epoch_diff = 11644473600  # Seconds between 1601 and 1970
        timestamp = datetime.now(timezone.utc).timestamp()
        return int((timestamp + epoch_diff) * 10000000)

    def get_timestamp(self) -> datetime:
        """Convert FILETIME to Python datetime"""
        epoch_diff = 11644473600
        timestamp = (self.time_created / 10000000) - epoch_diff
        return datetime.fromtimestamp(timestamp, timezone.utc)

    def extract_strings(self) -> List[str]:
        """Extract meaningful readable strings from binary XML data"""
        meaningful_strings = []

        try:
            # Look for UTF-16 encoded strings in the binary data
            i = 0
            while i < len(self.binary_xml_data) - 6:  # Need at least 6 bytes for meaningful UTF-16
                # Look for potential UTF-16 strings (even-length, null-terminated)
                if (
                    self.binary_xml_data[i] != 0
                    and self.binary_xml_data[i + 1] == 0
                    and i + 2 < len(self.binary_xml_data)
                ):
                    # Find end of string
                    start = i
                    end = start
                    while end < len(self.binary_xml_data) - 1:
                        if self.binary_xml_data[end] == 0 and self.binary_xml_data[end + 1] == 0:
                            break
                        end += 2

                    if end > start + 6:  # At least 3 characters
                        try:
                            text = self.binary_xml_data[start:end].decode("utf-16le")
                            # Filter for meaningful strings
                            if self._is_meaningful_string(text):
                                meaningful_strings.append(text)
                        except UnicodeDecodeError:
                            pass

                    i = end + 2
                else:
                    i += 1

            # Look for ASCII strings (longer minimum length for quality)
            i = 0
            while i < len(self.binary_xml_data) - 6:
                if (
                    32 <= self.binary_xml_data[i] <= 126  # Printable ASCII
                    and self.binary_xml_data[i + 1] != 0  # Not UTF-16
                ):
                    start = i
                    while i < len(self.binary_xml_data) and 32 <= self.binary_xml_data[i] <= 126:
                        i += 1

                    if i - start >= 6:  # Minimum 6 character strings
                        try:
                            text = self.binary_xml_data[start:i].decode("ascii")
                            if self._is_meaningful_string(text):
                                meaningful_strings.append(text)
                        except UnicodeDecodeError:
                            pass
                else:
                    i += 1

        except Exception:
            # If string extraction fails, return basic info
            meaningful_strings = [f"<Binary XML: {len(self.binary_xml_data)} bytes>"]

        # Remove duplicates while preserving order
        seen = set()
        unique_strings = []
        for s in meaningful_strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)

        return unique_strings[:5]  # Return top 5 meaningful strings

    def _is_meaningful_string(self, text: str) -> bool:
        """Determine if a string is meaningful (not just binary noise)"""
        if len(text) < 3:
            return False

        # Filter out strings that are just control characters or single repeated chars
        if (
            len(set(text)) < 2
            and text[0] in "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        ):
            return False

        # Skip strings with excessive non-ASCII characters (garbled Unicode)
        non_ascii_count = sum(1 for c in text if ord(c) > 127)
        if non_ascii_count > len(text) * 0.1:  # More than 10% non-ASCII likely garbled
            return False

        # Skip strings that contain obvious garbled Unicode patterns
        if any(ord(c) > 255 for c in text):  # Extended Unicode characters
            return False

        # Filter out strings with too many non-printable characters
        printable_ratio = sum(1 for c in text if c.isprintable() and ord(c) >= 32) / len(text)
        if printable_ratio < 0.8:  # Raised threshold for cleaner output
            return False

        # Skip obvious binary patterns and garbled Unicode
        bad_patterns = [
            "\x00",
            "\\u00",
            "\\x",
            "阥",
            "咄",
            "呸",
            "䦔",
            "몥",
            "㬾",
            "⠃",
            "ස",
            "Č",
            "矙",
            "䈢",
            "℣",
            "洀",
            "椀",
            "最",
            "甀",
            "攀",
            "氀",
        ]
        if any(pattern in text for pattern in bad_patterns):
            return False

        # Skip strings that look like corrupted provider names
        if "Microsoft-Windows" in text and any(ord(c) > 127 for c in text):
            return False

        # Prefer strings with common EventLog keywords
        keywords = [
            "Event",
            "System",
            "Application",
            "Security",
            "Provider",
            "EventID",
            "Level",
            "Task",
            "Keywords",
            "TimeCreated",
            "EventRecordID",
            "Computer",
            "Channel",
            "Message",
            "Data",
            "UserID",
            "ProcessID",
            "ThreadID",
            "ActivityID",
            "RelatedActivityID",
            "Correlation",
            "Execution",
            "Version",
            "Qualifiers",
            "Opcode",
            "Microsoft",
            "Windows",
            "Auditing",
            "DESKTOP",
            "WORKGROUP",
            "Administrator",
            "Guest",
            "Users",
            "Logon",
            "Logoff",
            "Account",
            "Domain",
        ]

        # Check for EventLog-related terms
        text_lower = text.lower()
        has_eventlog_terms = any(keyword.lower() in text_lower for keyword in keywords)

        # Accept if it has EventLog terms
        if has_eventlog_terms:
            return True

        # For non-EventLog terms, be extremely selective
        # Must be 100% clean ASCII
        if not all(32 <= ord(c) <= 126 for c in text):
            return False

        # Must contain letters (not just numbers/symbols)
        has_letters = any(c.isalpha() for c in text)
        if not has_letters:
            return False

        # Must look like real words/identifiers
        if len(text) < 4:
            return False

        # Skip if it looks like hex or other encoded data
        if all(c in "0123456789ABCDEFabcdef" for c in text):
            return False

        return True

    def get_summary(self) -> str:
        """Get a summary representation of the record"""
        strings = self.extract_strings()
        timestamp = self.get_timestamp()

        # Create a more informative summary
        if strings and any(strings):
            # If we have meaningful strings, use them
            content = " | ".join(strings[:3])
        else:
            # Fallback to basic info
            content = f"Binary Event Data ({self.size} bytes)"

        return (
            f"Record {self.record_identifier} "
            f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}]: "
            f"{content}"
        )

    def __repr__(self):
        return (
            f"EVTXEventRecord(id={self.record_identifier}, "
            f"time={self.get_timestamp().isoformat()}, "
            f"size={self.size})"
        )


class EVTXFile:
    """
    Comprehensive EVTX file parser and manipulator

    Provides deep knowledge of EVTX format based on Microsoft specifications:
    - Parsing complete file structure with proper chunk alignment
    - Extracting and analyzing records with binary XML processing
    - Manipulating and removing records with checksum recalculation
    - Reconstructing valid EVTX files with proper formatting
    """

    CHUNK_SIZE = 65536  # 64KB chunks (Microsoft specification)

    def __init__(self, filepath: str = None, verbose: bool = False):
        self.filepath = filepath
        self.file_header: Optional[EVTXFileHeader] = None
        self.chunks: List[Tuple[EVTXChunkHeader, List[EVTXEventRecord]]] = []
        self.total_records = 0
        self.verbose = verbose

        if filepath:
            self.load()

    def load(self):
        """Load and parse EVTX file according to Microsoft specifications"""
        if not os.path.exists(self.filepath):
            raise EVTXError(f"File not found: {self.filepath}")

        if self.verbose:
            print(f"[*] Loading EVTX file: {self.filepath}")

        with open(self.filepath, "rb") as f:
            self._parse_file(f)

        if self.verbose:
            print(f"[+] Loaded {len(self.chunks)} chunks with {self.total_records} total records")

    def _validate_and_fix_header_checksum(self, file_header_data: bytes):
        """Validate and fix header checksum if needed"""
        # Calculate expected checksum for header data (excluding the checksum field)
        header_without_checksum = file_header_data[: EVTXFileHeader.HEADER_SIZE - 4]
        calculated_checksum = self.file_header._calculate_checksum(header_without_checksum)

        if calculated_checksum != self.file_header.checksum:
            if self.verbose:
                print(
                    f"[*] Fixed header checksum: {self.file_header.checksum:08x} -> {calculated_checksum:08x}"
                )
            # Update the header object with correct checksum
            self.file_header.checksum = calculated_checksum

    def _parse_file(self, f: BinaryIO):
        """Parse complete EVTX file structure per Microsoft specification"""
        # Parse file header (4096 bytes)
        file_header_data = f.read(EVTXFileHeader.TOTAL_SIZE)
        self.file_header = EVTXFileHeader(file_header_data)

        # Check and fix header checksum if needed
        self._validate_and_fix_header_checksum(file_header_data)

        if self.verbose:
            print(f"[*] {self.file_header}")

        # Parse chunks starting at offset 4096
        # Each chunk is exactly 65536 bytes
        chunk_number = 0
        file_size = os.path.getsize(self.filepath)
        expected_chunks = (file_size - 4096) // self.CHUNK_SIZE

        if self.verbose:
            print(f"[*] Expected {expected_chunks} chunks based on file size")

        current_offset = 4096  # First chunk starts after file header

        while current_offset + self.CHUNK_SIZE <= file_size and chunk_number < expected_chunks:
            f.seek(current_offset)

            # Read chunk header
            chunk_header_data = f.read(EVTXChunkHeader.SIZE)

            if len(chunk_header_data) < EVTXChunkHeader.SIZE:
                print(f"[!] Incomplete chunk header at offset {current_offset}")
                break

            # Check for chunk magic
            if not chunk_header_data.startswith(EVTXChunkHeader.MAGIC):
                print(f"[!] No chunk magic at offset {current_offset}, skipping")
                current_offset += self.CHUNK_SIZE
                chunk_number += 1
                continue

            try:
                chunk_header = EVTXChunkHeader(chunk_header_data, chunk_number)

                # Read chunk data
                chunk_data_size = self.CHUNK_SIZE - EVTXChunkHeader.SIZE
                chunk_data = f.read(chunk_data_size)

                if len(chunk_data) != chunk_data_size:
                    print(f"[!] Incomplete chunk data at offset {current_offset}")
                    break

                # Parse records in this chunk
                records = self._parse_chunk_records(chunk_data, chunk_header)

                if records:
                    if self.verbose:
                        print(f"[*] Chunk {chunk_number}: {len(records)} records")
                    self.chunks.append((chunk_header, records))
                    self.total_records += len(records)
                else:
                    if self.verbose:
                        print(f"[*] Chunk {chunk_number}: empty or no valid records")

                chunk_number += 1
                current_offset += self.CHUNK_SIZE

            except EVTXStructureError as e:
                print(f"[!] Chunk {chunk_number} parsing error: {e}")
                current_offset += self.CHUNK_SIZE
                chunk_number += 1
                continue

    def _parse_chunk_records(
        self, chunk_data: bytes, chunk_header: EVTXChunkHeader
    ) -> List[EVTXEventRecord]:
        """Parse all event records within a chunk"""
        records = []
        offset = 0

        # Records start immediately after chunk header
        while offset < len(chunk_data) - 24:  # Minimum record size
            try:
                # Look for record magic
                if (
                    offset + 4 <= len(chunk_data)
                    and chunk_data[offset : offset + 4] == EVTXEventRecord.MAGIC
                ):
                    # Get record size
                    if offset + 8 > len(chunk_data):
                        break

                    size = struct.unpack("<I", chunk_data[offset + 4 : offset + 8])[0]

                    # Validate size
                    if size < 24 or size > len(chunk_data) - offset:
                        print(f"[!] Invalid record size {size} at chunk offset {offset}")
                        offset += 4
                        continue

                    # Parse complete record
                    record_data = chunk_data[offset : offset + size]
                    try:
                        record = EVTXEventRecord(record_data)
                        records.append(record)
                        offset += size
                    except EVTXStructureError as e:
                        print(f"[!] Record parsing error at chunk offset {offset}: {e}")
                        offset += 4
                        continue
                else:
                    offset += 4  # Skip to next potential record

            except Exception as e:
                print(f"[!] Unexpected error at chunk offset {offset}: {e}")
                offset += 4
                continue

        return records

    def get_all_records(self) -> List[EVTXEventRecord]:
        """Get all records from all chunks"""
        all_records = []
        for chunk_header, records in self.chunks:
            all_records.extend(records)
        return sorted(all_records, key=lambda r: r.record_identifier)

    def analyze(self) -> Dict[str, Any]:
        """Comprehensive analysis of EVTX file"""
        all_records = self.get_all_records()

        if not all_records:
            return {"error": "No records found"}

        # Time analysis
        timestamps = [r.get_timestamp() for r in all_records]
        earliest = min(timestamps)
        latest = max(timestamps)

        # Record ID analysis
        record_ids = [r.record_identifier for r in all_records]
        min_id = min(record_ids)
        max_id = max(record_ids)

        return {
            "file_info": {
                "path": self.filepath,
                "file_size_mb": (
                    round(os.path.getsize(self.filepath) / (1024 * 1024), 2) if self.filepath else 0
                ),
                "total_chunks": len(self.chunks),
                "total_records": self.total_records,
                "format_version": (
                    f"{self.file_header.major_version}.{self.file_header.minor_version}"
                ),
            },
            "time_range": {
                "earliest": earliest.isoformat(),
                "latest": latest.isoformat(),
                "span_hours": round((latest - earliest).total_seconds() / 3600, 2),
            },
            "record_ids": {
                "min_id": min_id,
                "max_id": max_id,
                "total_records": len(record_ids),
                "id_gaps": self._find_id_gaps(record_ids),
            },
        }

    def _find_id_gaps(self, record_ids: List[int]) -> List[Tuple[int, int]]:
        """Find gaps in record ID sequence"""
        sorted_ids = sorted(record_ids)
        gaps = []

        for i in range(len(sorted_ids) - 1):
            if sorted_ids[i + 1] - sorted_ids[i] > 1:
                gaps.append((sorted_ids[i] + 1, sorted_ids[i + 1] - 1))

        return gaps[:10]  # Return first 10 gaps

    def remove_records_by_ids(self, record_ids: List[int], test_mode: bool = False) -> int:
        """Remove records with specific IDs"""
        removed_count = 0
        record_ids_set = set(record_ids)

        for i, (chunk_header, records) in enumerate(self.chunks):
            new_records = []
            for record in records:
                if record.record_identifier not in record_ids_set:
                    new_records.append(record)
                else:
                    removed_count += 1
                    if test_mode:
                        print(
                            f"[TEST] Would remove record {record.record_identifier}: {record.get_summary()}"
                        )
                    else:
                        print(f"[*] Removing record {record.record_identifier}")

            if not test_mode:
                self.chunks[i] = (chunk_header, new_records)

        if not test_mode:
            self.total_records -= removed_count
            self._update_headers()

        action = "Would remove" if test_mode else "Removed"
        print(f"[+] {action} {removed_count} records")
        return removed_count

    def remove_records_by_time_range(
        self, start_time: datetime, end_time: datetime, test_mode: bool = False
    ) -> int:
        """Remove records within a specific time range"""
        removed_count = 0

        for i, (chunk_header, records) in enumerate(self.chunks):
            new_records = []
            for record in records:
                record_time = record.get_timestamp()
                if not (start_time <= record_time <= end_time):
                    new_records.append(record)
                else:
                    removed_count += 1
                    if test_mode:
                        print(
                            f"[TEST] Would remove record {record.record_identifier} from {record_time}: {record.get_summary()}"
                        )
                    else:
                        print(f"[*] Removing record {record.record_identifier} from {record_time}")

            if not test_mode:
                self.chunks[i] = (chunk_header, new_records)

        if not test_mode:
            self.total_records -= removed_count
            self._update_headers()

        action = "Would remove" if test_mode else "Removed"
        print(f"[+] {action} {removed_count} records in time range")
        return removed_count

    def remove_records_by_content(
        self, pattern: str, test_mode: bool = False, use_regex: bool = False
    ) -> int:
        """Remove records matching specific content pattern (supports regex)"""
        removed_count = 0

        # Compile regex pattern if requested
        if use_regex:
            try:
                regex_pattern = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                raise EVTXError(f"Invalid regex pattern '{pattern}': {e}")
        else:
            pattern_lower = pattern.lower()

        for i, (chunk_header, records) in enumerate(self.chunks):
            new_records = []
            for record in records:
                content = " ".join(record.extract_strings())

                # Check if content matches pattern
                if use_regex:
                    matches = bool(regex_pattern.search(content))
                else:
                    matches = pattern_lower in content.lower()

                if not matches:
                    new_records.append(record)
                else:
                    removed_count += 1
                    if test_mode:
                        match_type = "regex" if use_regex else "contains"
                        print(
                            f"[TEST] Would remove record {record.record_identifier} "
                            f"({match_type} '{pattern}'): {record.get_summary()}"
                        )
                    else:
                        print(
                            f"[*] Removing record {record.record_identifier} "
                            f"(matches '{pattern}')"
                        )

            if not test_mode:
                self.chunks[i] = (chunk_header, new_records)

        if not test_mode:
            self.total_records -= removed_count
            self._update_headers()

        match_type = "regex" if use_regex else "containing"
        action = "Would remove" if test_mode else "Removed"
        print(f"[+] {action} {removed_count} records {match_type} '{pattern}'")
        return removed_count

    def count_matching_records(
        self,
        pattern: str = None,
        record_ids: List[int] = None,
        time_range: Tuple[datetime, datetime] = None,
        use_regex: bool = False,
    ) -> Dict[str, Any]:
        """Count records matching specified criteria"""
        matching_records = []
        total_count = 0

        # Get all records
        all_records = self.get_all_records()

        for record in all_records:
            matches = True

            # Check pattern match
            if pattern:
                content = " ".join(record.extract_strings())
                if use_regex:
                    try:
                        regex_pattern = re.compile(pattern, re.IGNORECASE)
                        matches = bool(regex_pattern.search(content))
                    except re.error as e:
                        raise EVTXError(f"Invalid regex pattern '{pattern}': {e}")
                else:
                    matches = pattern.lower() in content.lower()

            # Check record ID match
            if record_ids and matches:
                matches = record.record_identifier in record_ids

            # Check time range match
            if time_range and matches:
                start_time, end_time = time_range
                record_time = record.get_timestamp()
                # Ensure timezone consistency
                if record_time.tzinfo is None:
                    record_time = record_time.replace(tzinfo=timezone.utc)
                matches = start_time <= record_time <= end_time

            if matches:
                matching_records.append(
                    {
                        "record_id": record.record_identifier,
                        "timestamp": record.get_timestamp().isoformat(),
                        "summary": record.get_summary(),
                    }
                )
                total_count += 1

        return {
            "total_matching": total_count,
            "total_records": len(all_records),
            "match_percentage": (
                round((total_count / len(all_records)) * 100, 2) if all_records else 0
            ),
            "criteria": {
                "pattern": pattern,
                "use_regex": use_regex,
                "record_ids": record_ids,
                "time_range": (
                    [time_range[0].isoformat(), time_range[1].isoformat()] if time_range else None
                ),
            },
            "matching_records": matching_records[:50],  # Show first 50 matches
        }

    def _update_headers(self):
        """Update file and chunk headers after modifications"""
        if not self.file_header:
            return

        # Update file header
        all_records = self.get_all_records()
        if all_records:
            self.file_header.next_record_identifier = (
                max(r.record_identifier for r in all_records) + 1
            )
            self.file_header.last_chunk_number = len(self.chunks) - 1
        else:
            self.file_header.next_record_identifier = 1
            self.file_header.last_chunk_number = 0

        self.file_header.number_of_chunks = len(self.chunks)

        # Update chunk headers and recalculate checksums
        for i, (chunk_header, records) in enumerate(self.chunks):
            if records:
                chunk_header.first_event_record_number = min(r.record_identifier for r in records)
                chunk_header.last_event_record_number = max(r.record_identifier for r in records)
                chunk_header.first_event_record_identifier = chunk_header.first_event_record_number
                chunk_header.last_event_record_identifier = chunk_header.last_event_record_number
            else:
                chunk_header.first_event_record_number = 0
                chunk_header.last_event_record_number = 0
                chunk_header.first_event_record_identifier = 0
                chunk_header.last_event_record_identifier = 0

            # Calculate free space offset based on record sizes
            total_record_size = sum(record.size for record in records)
            chunk_header.free_space_offset = EVTXChunkHeader.SIZE + total_record_size

            # Recalculate event records checksum
            if records:
                records_data = b"".join(record.pack() for record in records)
                chunk_header.event_records_checksum = zlib.crc32(records_data) & 0xFFFFFFFF
            else:
                chunk_header.event_records_checksum = 0

    def save(self, output_path: str):
        """Save modified EVTX file with proper structure and checksums"""
        print(f"[*] Saving modified EVTX to: {output_path}")

        # Update all headers before saving
        self._update_headers()

        with open(output_path, "wb") as f:
            # Write file header (4096 bytes)
            f.write(self.file_header.pack())

            # Write chunks
            for chunk_header, records in self.chunks:
                # Pack all records in chunk
                chunk_data = b""
                for record in records:
                    chunk_data += record.pack()

                # Pad chunk data to full size (65536 - 512 = 65024 bytes)
                chunk_data_size = self.CHUNK_SIZE - EVTXChunkHeader.SIZE
                if len(chunk_data) > chunk_data_size:
                    print("[!] Warning: Chunk data exceeds maximum size")
                    chunk_data = chunk_data[:chunk_data_size]

                # Pad with zeros
                chunk_data += b"\x00" * (chunk_data_size - len(chunk_data))

                # Write chunk
                f.write(chunk_header.pack())
                f.write(chunk_data)

        print(f"[+] Saved {len(self.chunks)} chunks with {self.total_records} records")

        # Verify saved file
        try:
            verify_file = EVTXFile(output_path)
            print(f"[+] Verification: {verify_file.total_records} records loaded successfully")
        except Exception as e:
            print(f"[!] Verification failed: {e}")

    def dump_records_json(self, output_path: str, max_records: int = None):
        """Dump records to JSON format with detailed information"""
        all_records = self.get_all_records()

        if max_records:
            all_records = all_records[:max_records]

        records_data = []
        for record in all_records:
            records_data.append(
                {
                    "record_id": record.record_identifier,
                    "timestamp": record.get_timestamp().isoformat(),
                    "size": record.size,
                    "strings": record.extract_strings(),
                    "summary": record.get_summary(),
                }
            )

        with open(output_path, "w") as f:
            json.dump(records_data, f, indent=2)

        print(f"[+] Dumped {len(records_data)} records to {output_path}")


def main():
    """Main function with comprehensive EVTX manipulation capabilities"""
    parser = argparse.ArgumentParser(
        description="EVTX Expert v2 - Microsoft Specification Compliant Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Count records containing "DESKTOP"
  python evtx_expert_v2.py -i Security.evtx --count --match "DESKTOP"

  # Test removal with regex pattern (verbose output)
  python evtx_expert_v2.py -i Security.evtx --test --match "user=.*@outlook\\.com" --regex -v

  # Remove records in time range
  python evtx_expert_v2.py -i Security.evtx --match-time-range "2025-07-15T00:00:00" "2025-07-15T23:59:59" --output cleaned.evtx

  # Count records in specific time window
  python evtx_expert_v2.py -i Security.evtx --count --match-time-range "2025-07-15T18:49:00" "2025-07-15T19:00:00"
        """,
    )

    # Input/Output
    parser.add_argument(
        "-i", "--input", dest="input_file", required=True, help="Input EVTX file path"
    )
    parser.add_argument("--output", help="Output file path for modified EVTX")

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output (show chunk loading details)",
    )
    parser.add_argument(
        "--count", action="store_true", help="Count records matching specified criteria"
    )
    parser.add_argument("--dump-json", help="Dump records to JSON file")

    # Matching/Filtering
    parser.add_argument(
        "--match", help="Match records by content pattern (supports regex with --regex)"
    )
    parser.add_argument(
        "--regex", action="store_true", help="Treat --match pattern as regular expression"
    )
    parser.add_argument("--remove-ids", help="Remove records by IDs (comma-separated)")
    parser.add_argument(
        "--match-time-range",
        nargs=2,
        metavar=("START", "END"),
        help="Match records in time range (ISO format: 2025-07-15T18:49:55.015663+00:00)",
    )

    # Options
    parser.add_argument("--max-records", type=int, help="Limit number of records to process")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Preview mode - show what would be changed without making changes",
    )

    args = parser.parse_args()

    try:
        # Load EVTX file
        print("=" * 70)
        print("EVTX EXPERT v2 - Microsoft Specification Compliant Tool")
        print("=" * 70)

        evtx = EVTXFile(args.input_file, verbose=args.verbose)

        # Count matching records
        if args.count:
            print("\n[*] Counting matching records...")

            # Prepare criteria
            time_range = None
            if args.match_time_range:
                start_time = datetime.fromisoformat(args.match_time_range[0])
                end_time = datetime.fromisoformat(args.match_time_range[1])
                # Ensure timezone awareness for comparison
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=timezone.utc)
                if end_time.tzinfo is None:
                    end_time = end_time.replace(tzinfo=timezone.utc)
                time_range = (start_time, end_time)

            record_ids = None
            if args.remove_ids:
                record_ids = [int(x.strip()) for x in args.remove_ids.split(",")]

            count_result = evtx.count_matching_records(
                pattern=args.match,
                record_ids=record_ids,
                time_range=time_range,
                use_regex=args.regex,
            )
            print(json.dumps(count_result, indent=2))

        # JSON dump
        if args.dump_json:
            print("\n[*] Dumping records to JSON...")
            evtx.dump_records_json(args.dump_json, args.max_records)

        # Record removal operations
        modified = False
        test_mode = args.test

        if test_mode:
            print("\n[TEST MODE] - Showing what would be removed without making changes")

        if args.remove_ids:
            action = "Testing removal" if test_mode else "Removing records"
            print(f"\n[*] {action} by IDs...")
            ids = [int(x.strip()) for x in args.remove_ids.split(",")]
            evtx.remove_records_by_ids(ids, test_mode=test_mode)
            if not test_mode:
                modified = True

        if args.match:
            action = "Testing removal" if test_mode else "Removing records"
            match_type = "regex" if args.regex else "pattern"
            print(f"\n[*] {action} matching {match_type} '{args.match}'...")
            evtx.remove_records_by_content(args.match, test_mode=test_mode, use_regex=args.regex)
            if not test_mode:
                modified = True

        if args.match_time_range:
            action = "Testing removal" if test_mode else "Removing records"
            print(f"\n[*] {action} in time range...")
            start_time = datetime.fromisoformat(args.match_time_range[0])
            end_time = datetime.fromisoformat(args.match_time_range[1])
            # Ensure timezone awareness for comparison
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            if end_time.tzinfo is None:
                end_time = end_time.replace(tzinfo=timezone.utc)
            evtx.remove_records_by_time_range(start_time, end_time, test_mode=test_mode)
            if not test_mode:
                modified = True

        # Save modified file
        if test_mode:
            print("\n[TEST] No changes made - test mode active")
        elif modified and args.output:
            print("\n[*] Saving modified EVTX file...")
            evtx.save(args.output)
        elif modified and not args.output:
            print("\n[!] Records were removed but no output file specified (use --output)")

        print("\n[+] EVTX processing complete!")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


# =============================================================================
# Callable API Functions for Integration
# =============================================================================


def analyze_evtx_file(filepath: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze an EVTX file and return comprehensive metadata.

    Args:
        filepath: Path to the EVTX file
        verbose: Enable verbose output

    Returns:
        Dictionary with file analysis including record counts, time ranges, etc.
    """
    try:
        evtx = EVTXFile(filepath, verbose=verbose)
        return evtx.analyze()
    except Exception as e:
        return {"error": str(e)}


def list_evtx_records(filepath: str, max_records: int = None) -> List[Dict[str, Any]]:
    """
    List records from an EVTX file with detailed information.

    Args:
        filepath: Path to the EVTX file
        max_records: Maximum number of records to return

    Returns:
        List of record dictionaries with metadata
    """
    try:
        evtx = EVTXFile(filepath)
        all_records = evtx.get_all_records()

        if max_records:
            all_records = all_records[:max_records]

        return [
            {
                "record_id": record.record_identifier,
                "timestamp": record.get_timestamp().isoformat(),
                "size": record.size,
                "strings": record.extract_strings(),
                "summary": record.get_summary(),
            }
            for record in all_records
        ]
    except Exception as e:
        return [{"error": str(e)}]


def test_evtx_removal(
    filepath: str,
    record_ids: List[int] = None,
    content_filter: str = None,
    time_range: Tuple[str, str] = None,
    use_regex: bool = False,
) -> Dict[str, Any]:
    """
    Test what records would be removed without actually removing them.

    Args:
        filepath: Path to the EVTX file
        record_ids: List of record IDs to remove
        content_filter: Pattern to match in record content (supports regex)
        time_range: Tuple of (start_time, end_time) in ISO format
        use_regex: Whether to treat content_filter as regex pattern

    Returns:
        Dictionary with removal statistics and affected records
    """
    try:
        evtx = EVTXFile(filepath, verbose=False)  # Silent for API calls
        results = {
            "original_record_count": evtx.total_records,
            "removal_operations": [],
            "total_would_remove": 0,
        }

        if record_ids:
            count = evtx.remove_records_by_ids(record_ids, test_mode=True)
            results["removal_operations"].append(
                {"type": "by_ids", "criteria": record_ids, "would_remove": count}
            )
            results["total_would_remove"] += count

        if content_filter:
            count = evtx.remove_records_by_content(
                content_filter, test_mode=True, use_regex=use_regex
            )
            results["removal_operations"].append(
                {
                    "type": "by_content",
                    "criteria": content_filter,
                    "use_regex": use_regex,
                    "would_remove": count,
                }
            )
            results["total_would_remove"] += count

        if time_range:
            start_time = datetime.fromisoformat(time_range[0])
            end_time = datetime.fromisoformat(time_range[1])
            count = evtx.remove_records_by_time_range(start_time, end_time, test_mode=True)
            results["removal_operations"].append(
                {"type": "by_time_range", "criteria": time_range, "would_remove": count}
            )
            results["total_would_remove"] += count

        results["final_record_count"] = evtx.total_records - results["total_would_remove"]
        return results

    except Exception as e:
        return {"error": str(e)}


def clean_evtx_file(
    filepath: str,
    output_path: str,
    record_ids: List[int] = None,
    content_filter: str = None,
    time_range: Tuple[str, str] = None,
) -> Dict[str, Any]:
    """
    Clean an EVTX file by removing specified records and save to new file.

    Args:
        filepath: Path to the source EVTX file
        output_path: Path for the cleaned EVTX file
        record_ids: List of record IDs to remove
        content_filter: String to search for in record content
        time_range: Tuple of (start_time, end_time) in ISO format

    Returns:
        Dictionary with operation results and statistics
    """
    try:
        evtx = EVTXFile(filepath)
        original_count = evtx.total_records
        total_removed = 0

        operations = []

        if record_ids:
            removed = evtx.remove_records_by_ids(record_ids)
            total_removed += removed
            operations.append({"type": "by_ids", "removed": removed})

        if content_filter:
            removed = evtx.remove_records_by_content(content_filter)
            total_removed += removed
            operations.append({"type": "by_content", "removed": removed})

        if time_range:
            start_time = datetime.fromisoformat(time_range[0])
            end_time = datetime.fromisoformat(time_range[1])
            removed = evtx.remove_records_by_time_range(start_time, end_time)
            total_removed += removed
            operations.append({"type": "by_time_range", "removed": removed})

        # Save cleaned file
        evtx.save(output_path)

        return {
            "success": True,
            "original_records": original_count,
            "final_records": evtx.total_records,
            "total_removed": total_removed,
            "operations": operations,
            "output_file": output_path,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


def export_evtx_to_json(filepath: str, output_path: str, max_records: int = None) -> Dict[str, Any]:
    """
    Export EVTX records to JSON format.

    Args:
        filepath: Path to the EVTX file
        output_path: Path for the JSON output file
        max_records: Maximum number of records to export

    Returns:
        Dictionary with export results
    """
    try:
        evtx = EVTXFile(filepath)
        evtx.dump_records_json(output_path, max_records)

        return {
            "success": True,
            "total_records": evtx.total_records,
            "exported_records": min(max_records or evtx.total_records, evtx.total_records),
            "output_file": output_path,
        }

    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    sys.exit(main())

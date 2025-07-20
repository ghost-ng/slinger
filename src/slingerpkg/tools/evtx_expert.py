#!/usr/bin/env python3
"""
EVTX Expert - Windows EventLog Binary XML Format Manipulation Tool
Deep knowledge implementation for parsing, dumping, and manipulating EVTX files

Author: Claude Code
Purpose: Professional-grade EVTX file manipulation for security research
"""

import struct
import os
import sys
import json
from datetime import datetime, timezone
import zlib
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


class EVTXHeader:
    """
    EVTX File Header Structure (128 bytes)

    Format based on Microsoft documentation:
    - Magic: "ElfFile\x00" (8 bytes)
    - OldestChunk: First chunk number (8 bytes)
    - CurrentChunkNumber: Last chunk number (8 bytes)
    - NextRecordNumber: Next record ID to assign (8 bytes)
    - HeaderSize: Size of header (4 bytes)
    - MinorVersion: EVTX format minor version (2 bytes)
    - MajorVersion: EVTX format major version (2 bytes)
    - HeaderBlockSize: Size of header block (2 bytes)
    - NumberOfChunks: Total chunks in file (2 bytes)
    - Unknown1: Reserved (76 bytes)
    - FileFlags: File status flags (4 bytes)
    - Checksum: Header checksum (4 bytes)
    """

    FORMAT = "<8sQQQIHHHH76sII"
    SIZE = 128
    MAGIC = b"ElfFile\x00"

    def __init__(self, data: bytes = None):
        if data:
            self.parse(data)
        else:
            # Create new header
            self.magic = self.MAGIC
            self.oldest_chunk = 0
            self.current_chunk_number = 0
            self.next_record_number = 1
            self.header_size = 128
            self.minor_version = 1
            self.major_version = 3
            self.header_block_size = 128
            self.number_of_chunks = 0
            self.unknown1 = b"\x00" * 76
            self.file_flags = 0
            self.checksum = 0

    def parse(self, data: bytes):
        """Parse EVTX header from binary data"""
        if len(data) < self.SIZE:
            raise EVTXStructureError(f"Header too short: {len(data)} < {self.SIZE}")

        fields = struct.unpack(self.FORMAT, data[: self.SIZE])

        self.magic = fields[0]
        if self.magic != self.MAGIC:
            raise EVTXStructureError(f"Invalid EVTX magic: {self.magic!r}")

        self.oldest_chunk = fields[1]
        self.current_chunk_number = fields[2]
        self.next_record_number = fields[3]
        self.header_size = fields[4]
        self.minor_version = fields[5]
        self.major_version = fields[6]
        self.header_block_size = fields[7]
        self.number_of_chunks = fields[8]
        self.unknown1 = fields[9]
        self.file_flags = fields[10]
        self.checksum = fields[11]

    def pack(self) -> bytes:
        """Pack header back to binary format"""
        # Calculate checksum before packing
        temp_data = struct.pack(
            self.FORMAT[:-1] + "I",
            self.magic,
            self.oldest_chunk,
            self.current_chunk_number,
            self.next_record_number,
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

        return struct.pack(
            self.FORMAT,
            self.magic,
            self.oldest_chunk,
            self.current_chunk_number,
            self.next_record_number,
            self.header_size,
            self.minor_version,
            self.major_version,
            self.header_block_size,
            self.number_of_chunks,
            self.unknown1,
            self.file_flags,
            self.checksum,
        )

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate CRC32 checksum for header"""
        return zlib.crc32(data) & 0xFFFFFFFF

    def __repr__(self):
        return (
            f"EVTXHeader(chunks={self.number_of_chunks}, "
            f"next_record={self.next_record_number}, "
            f"version={self.major_version}.{self.minor_version})"
        )


class EVTXChunkHeader:
    """
    EVTX Chunk Header Structure (512 bytes)

    Each chunk contains multiple event records and has its own header:
    - Magic: "ElfChnk\x00" (8 bytes)
    - FirstEventRecordNumber: First record number in chunk (8 bytes)
    - LastEventRecordNumber: Last record number in chunk (8 bytes)
    - FirstEventRecordID: File offset of first record (8 bytes)
    - LastEventRecordID: File offset of last record (8 bytes)
    - HeaderSize: Size of this header (4 bytes)
    - LastEventRecordDataOffset: Offset within chunk (4 bytes)
    - FreeSpaceOffset: Offset to free space (4 bytes)
    - EventRecordsChecksum: Checksum of all records (4 bytes)
    - Padding: Reserved space (456 bytes to make total 512)
    """

    FORMAT = "<8sQQQQIIII456s"
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
            self.first_event_record_id = 0
            self.last_event_record_id = 0
            self.header_size = 512
            self.last_event_record_data_offset = 512
            self.free_space_offset = 512
            self.event_records_checksum = 0
            self.padding = b"\x00" * 456

    def parse(self, data: bytes):
        """Parse chunk header from binary data"""
        if len(data) < self.SIZE:
            raise EVTXStructureError(f"Chunk header too short: {len(data)} < {self.SIZE}")

        fields = struct.unpack(self.FORMAT, data[: self.SIZE])

        self.magic = fields[0]
        if self.magic != self.MAGIC:
            raise EVTXStructureError(f"Invalid chunk magic: {self.magic!r}")

        self.first_event_record_number = fields[1]
        self.last_event_record_number = fields[2]
        self.first_event_record_id = fields[3]
        self.last_event_record_id = fields[4]
        self.header_size = fields[5]
        self.last_event_record_data_offset = fields[6]
        self.free_space_offset = fields[7]
        self.event_records_checksum = fields[8]
        self.padding = fields[9]

    def pack(self) -> bytes:
        """Pack chunk header back to binary format"""
        return struct.pack(
            self.FORMAT,
            self.magic,
            self.first_event_record_number,
            self.last_event_record_number,
            self.first_event_record_id,
            self.last_event_record_id,
            self.header_size,
            self.last_event_record_data_offset,
            self.free_space_offset,
            self.event_records_checksum,
            self.padding,
        )

    def __repr__(self):
        return (
            f"EVTXChunkHeader(chunk={self.chunk_number}, "
            f"records={self.first_event_record_number}-{self.last_event_record_number})"
        )


class EVTXRecord:
    """
    EVTX Event Record Structure

    Each event record contains:
    - Magic: "\x2a\x2a\x00\x00" (4 bytes)
    - Size: Total record size (4 bytes)
    - EventRecordID: Unique record identifier (8 bytes)
    - TimeCreated: Event timestamp (8 bytes - FILETIME)
    - BinaryXMLData: Variable-length binary XML content
    - Size2: Duplicate of size field (4 bytes)
    """

    MAGIC = b"\x2a\x2a\x00\x00"
    HEADER_SIZE = 24  # Magic + Size + RecordID + TimeCreated

    def __init__(self, data: bytes = None, record_id: int = None):
        if data:
            self.parse(data)
        else:
            # Create new record
            self.magic = self.MAGIC
            self.size = self.HEADER_SIZE + 8  # Minimum size with Size2
            self.record_id = record_id or 1
            self.time_created = self._current_filetime()
            self.binary_xml_data = b""

    def parse(self, data: bytes):
        """Parse event record from binary data"""
        if len(data) < self.HEADER_SIZE:
            raise EVTXStructureError(f"Record header too short: {len(data)} < {self.HEADER_SIZE}")

        # Parse header
        self.magic, self.size, self.record_id, self.time_created = struct.unpack(
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
            struct.pack("<4sIQQ", self.magic, self.size, self.record_id, self.time_created)
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

    def extract_xml_content(self) -> str:
        """Extract readable XML from binary XML data (simplified)"""
        # This is a simplified implementation - real binary XML is complex
        try:
            # Look for UTF-16 encoded strings in the binary data
            text_parts = []
            i = 0
            while i < len(self.binary_xml_data) - 1:
                if self.binary_xml_data[i] == 0 and self.binary_xml_data[i + 1] != 0:
                    # Potential start of UTF-16 string
                    start = i + 1
                    end = start
                    while end < len(self.binary_xml_data) - 1:
                        if self.binary_xml_data[end] == 0 and self.binary_xml_data[end + 1] == 0:
                            # End of string
                            try:
                                text = self.binary_xml_data[start:end].decode("utf-16le")
                                if len(text) > 3 and text.isprintable():
                                    text_parts.append(text)
                            except UnicodeDecodeError:
                                pass
                            break
                        end += 2
                    i = end
                else:
                    i += 1

            return " | ".join(text_parts[:10])  # Return first 10 text parts
        except Exception:
            return f"<Binary XML Data: {len(self.binary_xml_data)} bytes>"

    def __repr__(self):
        return (
            f"EVTXRecord(id={self.record_id}, "
            f"time={self.get_timestamp().isoformat()}, "
            f"size={self.size})"
        )


class EVTXFile:
    """
    Comprehensive EVTX file parser and manipulator

    Provides deep knowledge of EVTX format for:
    - Parsing complete file structure
    - Extracting and analyzing records
    - Manipulating and removing records
    - Reconstructing valid EVTX files
    """

    CHUNK_SIZE = 65536  # 64KB chunks

    def __init__(self, filepath: str = None):
        self.filepath = filepath
        self.header: Optional[EVTXHeader] = None
        self.chunks: List[Tuple[EVTXChunkHeader, List[EVTXRecord]]] = []
        self.total_records = 0

        if filepath:
            self.load()

    def load(self):
        """Load and parse EVTX file"""
        if not os.path.exists(self.filepath):
            raise EVTXError(f"File not found: {self.filepath}")

        print(f"[*] Loading EVTX file: {self.filepath}")

        with open(self.filepath, "rb") as f:
            self._parse_file(f)

        print(f"[+] Loaded {len(self.chunks)} chunks with {self.total_records} total records")

    def _parse_file(self, f: BinaryIO):
        """Parse complete EVTX file structure"""
        # Parse file header
        header_data = f.read(EVTXHeader.SIZE)
        self.header = EVTXHeader(header_data)

        print(f"[*] EVTX Header: {self.header}")

        # EVTX files have chunks starting at specific offsets
        # First chunk typically starts at offset 4096 (0x1000)
        chunk_number = 0
        file_size = os.path.getsize(self.filepath)

        # Start at first chunk offset (after file header padding)
        f.seek(4096)  # 0x1000 - standard EVTX chunk alignment

        while f.tell() < file_size:
            chunk_pos = f.tell()

            # Look for chunk magic
            chunk_header_data = f.read(EVTXChunkHeader.SIZE)

            if len(chunk_header_data) < EVTXChunkHeader.SIZE:
                break  # End of file

            # Check if this looks like a chunk header
            if not chunk_header_data.startswith(EVTXChunkHeader.MAGIC):
                # Skip to next potential chunk boundary
                f.seek(chunk_pos + self.CHUNK_SIZE)
                continue

            try:
                chunk_header = EVTXChunkHeader(chunk_header_data, chunk_number)
                print(f"[*] Parsing {chunk_header}")

                # Read chunk data
                chunk_data_size = self.CHUNK_SIZE - EVTXChunkHeader.SIZE
                chunk_data = f.read(chunk_data_size)

                # Parse records in this chunk
                records = self._parse_chunk_records(chunk_data, chunk_header)
                self.chunks.append((chunk_header, records))
                self.total_records += len(records)

                chunk_number += 1

                # Move to next chunk boundary
                next_chunk_pos = chunk_pos + self.CHUNK_SIZE
                f.seek(next_chunk_pos)

            except EVTXStructureError as e:
                print(f"[!] Chunk parsing error at offset {chunk_pos}: {e}")
                # Skip to next chunk boundary
                f.seek(chunk_pos + self.CHUNK_SIZE)
                continue

    def _parse_chunk_records(
        self, chunk_data: bytes, chunk_header: EVTXChunkHeader
    ) -> List[EVTXRecord]:
        """Parse all event records within a chunk"""
        records = []
        offset = 0

        while offset < len(chunk_data) - 8:  # Minimum record size
            try:
                # Check for record magic
                if chunk_data[offset : offset + 4] == EVTXRecord.MAGIC:
                    # Get record size
                    if offset + 8 > len(chunk_data):
                        break

                    size = struct.unpack("<I", chunk_data[offset + 4 : offset + 8])[0]

                    if offset + size > len(chunk_data):
                        print(f"[!] Record extends beyond chunk: offset={offset}, size={size}")
                        break

                    # Parse complete record
                    record_data = chunk_data[offset : offset + size]
                    record = EVTXRecord(record_data)
                    records.append(record)

                    offset += size
                else:
                    offset += 4  # Skip to next potential record

            except EVTXStructureError as e:
                print(f"[!] Record parsing error at chunk offset {offset}: {e}")
                offset += 4
                continue

        return records

    def get_all_records(self) -> List[EVTXRecord]:
        """Get all records from all chunks"""
        all_records = []
        for chunk_header, records in self.chunks:
            all_records.extend(records)
        return all_records

    def get_records_by_id_range(self, start_id: int, end_id: int) -> List[EVTXRecord]:
        """Get records within a specific ID range"""
        matching_records = []
        for record in self.get_all_records():
            if start_id <= record.record_id <= end_id:
                matching_records.append(record)
        return matching_records

    def get_records_by_time_range(
        self, start_time: datetime, end_time: datetime
    ) -> List[EVTXRecord]:
        """Get records within a specific time range"""
        matching_records = []
        for record in self.get_all_records():
            record_time = record.get_timestamp()
            if start_time <= record_time <= end_time:
                matching_records.append(record)
        return matching_records

    def remove_records_by_ids(self, record_ids: List[int]) -> int:
        """Remove records with specific IDs"""
        removed_count = 0
        record_ids_set = set(record_ids)

        for i, (chunk_header, records) in enumerate(self.chunks):
            new_records = []
            for record in records:
                if record.record_id not in record_ids_set:
                    new_records.append(record)
                else:
                    removed_count += 1

            self.chunks[i] = (chunk_header, new_records)

        self.total_records -= removed_count
        self._update_headers()

        print(f"[+] Removed {removed_count} records")
        return removed_count

    def remove_records_by_time_range(self, start_time: datetime, end_time: datetime) -> int:
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

            self.chunks[i] = (chunk_header, new_records)

        self.total_records -= removed_count
        self._update_headers()

        print(f"[+] Removed {removed_count} records in time range")
        return removed_count

    def remove_records_by_content(self, search_string: str) -> int:
        """Remove records containing specific content"""
        removed_count = 0
        search_string_lower = search_string.lower()

        for i, (chunk_header, records) in enumerate(self.chunks):
            new_records = []
            for record in records:
                content = record.extract_xml_content().lower()
                if search_string_lower not in content:
                    new_records.append(record)
                else:
                    removed_count += 1

            self.chunks[i] = (chunk_header, new_records)

        self.total_records -= removed_count
        self._update_headers()

        print(f"[+] Removed {removed_count} records containing '{search_string}'")
        return removed_count

    def _update_headers(self):
        """Update file and chunk headers after modifications"""
        if not self.header:
            return

        # Update file header
        all_records = self.get_all_records()
        if all_records:
            self.header.next_record_number = max(r.record_id for r in all_records) + 1
        else:
            self.header.next_record_number = 1

        self.header.number_of_chunks = len(self.chunks)

        # Update chunk headers
        for i, (chunk_header, records) in enumerate(self.chunks):
            if records:
                chunk_header.first_event_record_number = min(r.record_id for r in records)
                chunk_header.last_event_record_number = max(r.record_id for r in records)
            else:
                chunk_header.first_event_record_number = 0
                chunk_header.last_event_record_number = 0

    def save(self, output_path: str):
        """Save modified EVTX file"""
        print(f"[*] Saving modified EVTX to: {output_path}")

        with open(output_path, "wb") as f:
            # Write file header
            f.write(self.header.pack())

            # Write chunks
            for chunk_header, records in self.chunks:
                # Pack all records in chunk
                chunk_data = b""
                for record in records:
                    chunk_data += record.pack()

                # Pad chunk to full size
                while len(chunk_data) < self.CHUNK_SIZE - EVTXChunkHeader.SIZE:
                    chunk_data += b"\x00"

                chunk_data = chunk_data[: self.CHUNK_SIZE - EVTXChunkHeader.SIZE]

                # Update chunk header
                chunk_header.free_space_offset = EVTXChunkHeader.SIZE + len(chunk_data)

                # Write chunk
                f.write(chunk_header.pack())
                f.write(chunk_data)

        print(f"[+] Saved {len(self.chunks)} chunks with {self.total_records} records")

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
        record_ids = [r.record_id for r in all_records]
        min_id = min(record_ids)
        max_id = max(record_ids)

        # Content analysis
        content_samples = []
        for record in all_records[:10]:  # Sample first 10 records
            content_samples.append(
                {
                    "record_id": record.record_id,
                    "timestamp": record.get_timestamp().isoformat(),
                    "content_preview": record.extract_xml_content()[:200],
                }
            )

        return {
            "file_info": {
                "path": self.filepath,
                "total_chunks": len(self.chunks),
                "total_records": self.total_records,
                "file_size_mb": (
                    round(os.path.getsize(self.filepath) / (1024 * 1024), 2) if self.filepath else 0
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
                "id_gaps": self._find_id_gaps(record_ids),
            },
            "content_samples": content_samples,
        }

    def _find_id_gaps(self, record_ids: List[int]) -> List[Tuple[int, int]]:
        """Find gaps in record ID sequence"""
        sorted_ids = sorted(record_ids)
        gaps = []

        for i in range(len(sorted_ids) - 1):
            if sorted_ids[i + 1] - sorted_ids[i] > 1:
                gaps.append((sorted_ids[i] + 1, sorted_ids[i + 1] - 1))

        return gaps[:10]  # Return first 10 gaps

    def dump_records_json(self, output_path: str, max_records: int = None):
        """Dump records to JSON format"""
        all_records = self.get_all_records()

        if max_records:
            all_records = all_records[:max_records]

        records_data = []
        for record in all_records:
            records_data.append(
                {
                    "record_id": record.record_id,
                    "timestamp": record.get_timestamp().isoformat(),
                    "size": record.size,
                    "content_preview": record.extract_xml_content(),
                }
            )

        with open(output_path, "w") as f:
            json.dump(records_data, f, indent=2)

        print(f"[+] Dumped {len(records_data)} records to {output_path}")


def main():
    """Main function with comprehensive EVTX manipulation capabilities"""
    parser = argparse.ArgumentParser(description="EVTX Expert - Windows EventLog Manipulation Tool")
    parser.add_argument("input_file", help="Input EVTX file path")
    parser.add_argument("--analyze", action="store_true", help="Analyze EVTX file structure")
    parser.add_argument("--dump-json", help="Dump records to JSON file")
    parser.add_argument("--remove-ids", help="Remove records by IDs (comma-separated)")
    parser.add_argument("--remove-content", help="Remove records containing string")
    parser.add_argument(
        "--remove-time-range",
        nargs=2,
        metavar=("START", "END"),
        help="Remove records in time range (ISO format)",
    )
    parser.add_argument("--output", help="Output file path for modified EVTX")
    parser.add_argument("--max-records", type=int, help="Limit number of records to process")

    args = parser.parse_args()

    try:
        # Load EVTX file
        print("=" * 60)
        print("EVTX EXPERT - Windows EventLog Manipulation Tool")
        print("=" * 60)

        evtx = EVTXFile(args.input_file)

        # Analysis
        if args.analyze:
            print("\n[*] Performing comprehensive analysis...")
            analysis = evtx.analyze()
            print(json.dumps(analysis, indent=2))

        # JSON dump
        if args.dump_json:
            print("\n[*] Dumping records to JSON...")
            evtx.dump_records_json(args.dump_json, args.max_records)

        # Record removal operations
        modified = False

        if args.remove_ids:
            print("\n[*] Removing records by IDs...")
            ids = [int(x.strip()) for x in args.remove_ids.split(",")]
            evtx.remove_records_by_ids(ids)
            modified = True

        if args.remove_content:
            print(f"\n[*] Removing records containing '{args.remove_content}'...")
            evtx.remove_records_by_content(args.remove_content)
            modified = True

        if args.remove_time_range:
            print("\n[*] Removing records in time range...")
            start_time = datetime.fromisoformat(args.remove_time_range[0])
            end_time = datetime.fromisoformat(args.remove_time_range[1])
            evtx.remove_records_by_time_range(start_time, end_time)
            modified = True

        # Save modified file
        if modified and args.output:
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


if __name__ == "__main__":
    sys.exit(main())

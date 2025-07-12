# Resume Downloads Technical Specification

## Executive Summary

This document provides the complete technical specification for implementing resume downloads functionality in the Slinger SMB client. The feature enables interrupted file transfers to be resumed from the exact point of interruption, dramatically improving reliability for large file operations in unstable network environments.

**Status**: Phase 1 Complete - Research and Foundation  
**Implementation Timeline**: 3 weeks (Phase 1: 1 week, Phase 2: 1 week, Phase 3: 1 week)  
**Risk Level**: Low (Defensive enhancement with no security implications)

## Research Findings Summary

### SMB Protocol Capabilities ✅

**Key Discovery**: Impacket supports byte-range operations required for resume functionality.

#### Current Implementation Limitations
- **getFile() Method**: Does NOT support offset/byte-range parameters
- **Current Usage**: `self.conn.getFile(self.share, remote_path, file_obj.write)`
- **Behavior**: Always downloads entire file from start to finish

#### Available Low-Level Methods
```python
# Required method combination for resume downloads:
file_id = self.conn.openFile(tree_id, path, desiredAccess=FILE_READ_DATA)
data = self.conn.readFile(tree_id, file_id, offset=resume_offset, bytesToRead=chunk_size)
self.conn.closeFile(tree_id, file_id)
```

**Critical Parameters:**
- `offset`: Starting byte position (enables resume from any position)
- `bytesToRead`: Number of bytes to read (enables chunked transfers)
- `singleCall`: Controls multiple read attempts

### State Management Design ✅

**State File Format**: JSON-based with atomic updates
**Storage Location**: `~/.slinger/downloads/download_<hash>.json`
**Concurrency Safety**: Atomic write via temp file + rename

#### State Schema (v1.0)
```json
{
    "version": "1.0",
    "remote_path": "C:\\\\path\\\\to\\\\file.zip",
    "local_path": "/tmp/file.zip", 
    "total_size": 104857600,
    "bytes_downloaded": 52428800,
    "chunk_size": 65536,
    "checksum_type": "sha256",
    "partial_checksum": "a1b2c3d4e5f6...",
    "last_modified": "2025-07-12T13:15:00Z",
    "retry_count": 2,
    "max_retries": 5,
    "timestamp": "2025-07-12T13:20:00Z"
}
```

### Error Recovery Strategy ✅

**Error Categories Identified:**

| Category | Examples | Recovery Strategy | Max Retries |
|----------|----------|-------------------|-------------|
| **Recoverable** | Network timeout, Connection lost, SMB protocol errors | Exponential backoff | 5 |
| **Fatal** | File not found, Access denied, Disk full | User intervention required | 0 |
| **Special** | File changed remotely | Restart download | 0 |

**Exponential Backoff Pattern**: 1s, 2s, 4s, 8s, 16s (max 60s with 10% jitter)

## Technical Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  Resume Download System                     │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface                                              │
│  ├── --resume flag                                          │
│  ├── --no-resume flag                                       │
│  ├── --chunk-size parameter                                 │
│  └── downloads list/cleanup commands                        │
├─────────────────────────────────────────────────────────────┤
│  Enhanced Download Handler                                  │
│  ├── Resume detection and validation                        │
│  ├── State management integration                           │
│  ├── Progress reporting with ETA                            │
│  └── Error recovery coordination                            │
├─────────────────────────────────────────────────────────────┤
│  SMB Byte-Range Operations                                  │
│  ├── openFile() + readFile() + closeFile()                 │
│  ├── Chunked transfer with offset control                   │
│  ├── Connection recovery and retry logic                    │
│  └── Integrity validation (checksums)                       │
├─────────────────────────────────────────────────────────────┤
│  State Management System                                    │
│  ├── DownloadState class with persistence                   │
│  ├── Atomic state file updates                              │
│  ├── Resume validation and safety checks                    │
│  └── State cleanup and management utilities                 │
├─────────────────────────────────────────────────────────────┤
│  Error Recovery Framework                                   │
│  ├── Error classification and categorization                │
│  ├── Exponential backoff with jitter                        │
│  ├── Connection recovery and re-establishment               │
│  └── Retry limits and failure handling                      │
└─────────────────────────────────────────────────────────────┘
```

### Integration Points

#### 1. CLI Parser Extension (`src/slingerpkg/utils/cli.py`)
```python
# Add to existing 'get' command parser:
parser_get.add_argument('--resume', action='store_true', 
                       help='Resume interrupted download if possible')
parser_get.add_argument('--no-resume', action='store_true',
                       help='Force fresh download, ignore existing partial file')
parser_get.add_argument('--chunk-size', type=str, default='64k',
                       help='Chunk size for download (e.g., 64k, 1M)')

# New 'downloads' command for state management:
parser_downloads = subparsers.add_parser('downloads', help='Manage download states')
downloads_subparsers = parser_downloads.add_subparsers()
downloads_subparsers.add_parser('list', help='List active downloads')
downloads_subparsers.add_parser('cleanup', help='Clean up completed downloads')
```

#### 2. Enhanced Download Handler (`src/slingerpkg/lib/smblib.py`)
```python
def download_handler(self, args, echo=True):
    """Enhanced download handler with resume capability"""
    if not self.check_if_connected():
        return
    
    # Resolve paths (existing logic)
    is_valid, remote_path, error = self._normalize_path_for_smb(...)
    if not is_valid:
        return
    
    # Determine local path (existing logic with custom filename support)
    local_path = self._resolve_local_path(args.remote_path, args.local_path)
    
    # Resume logic
    if args.resume and not args.no_resume:
        return self._download_resumable(remote_path, local_path, args.chunk_size)
    else:
        return self._download_standard(remote_path, local_path)

def _download_resumable(self, remote_path, local_path, chunk_size_str):
    """Core resume download implementation"""
    # Implementation details in Phase 2
    pass
```

#### 3. State Integration
```python
# In download_resumable method:
state = DownloadState.load_state(local_path)
if state:
    is_valid, message = state.validate_resume()
    if is_valid:
        return self._resume_existing_download(state)
    else:
        print_warning(f"Cannot resume: {message}")

# Create new download state
state = DownloadState(remote_path, local_path, remote_file_size)
return self._perform_chunked_download(state)
```

## Implementation Plan

### Phase 1: Research and Foundation ✅ COMPLETED

**Duration**: Week 1  
**Status**: COMPLETE

#### Deliverables ✅
- [x] SMB byte-range research and proof-of-concept (`research/smb_byte_range_poc.py`)
- [x] State management design (`research/download_state_design.py`)
- [x] Error recovery strategy (`research/error_recovery_strategy.py`)
- [x] Technical specification document (this document)

#### Key Findings ✅
- Impacket supports required byte-range operations via `readFile()`
- State persistence design with atomic updates and resume validation
- Comprehensive error categorization with appropriate recovery strategies
- Integration points identified in existing slinger architecture

### Phase 2: Core Implementation

**Duration**: Week 2  
**Goals**: Implement core resume download functionality

#### Tasks
1. **Enhanced Download Handler** (2 days)
   ```python
   def _download_resumable(self, remote_path, local_path, chunk_size):
       # Check for existing state
       # Validate resume possibility
       # Implement chunked download loop
       # Update state after each chunk
       # Handle completion and cleanup
   ```

2. **SMB Byte-Range Operations** (2 days)
   ```python
   def _download_chunk(self, remote_path, offset, chunk_size):
       # Open remote file
       # Read chunk at offset
       # Close file handle
       # Return chunk data with error handling
   ```

3. **State Management Integration** (1 day)
   - Integrate DownloadState class into smblib.py
   - Add state save/load/cleanup calls
   - Implement resume validation logic

4. **CLI Integration** (1 day)
   - Add resume flags to existing 'get' command
   - Add 'downloads' command for state management
   - Integrate chunk size parsing

#### Success Criteria
- [ ] Resume existing partial downloads
- [ ] Create new resumable downloads
- [ ] Handle basic network interruptions
- [ ] Save/load state correctly
- [ ] Integrate with existing CLI interface

### Phase 3: Advanced Features and Testing

**Duration**: Week 3  
**Goals**: Add advanced features, comprehensive testing, and HTB validation

#### Tasks
1. **Advanced Error Recovery** (2 days)
   - Implement exponential backoff with jitter
   - Add connection recovery after network drops
   - Smart chunk size adjustment based on performance
   - Maximum retry limits with user feedback

2. **Performance Optimization** (1 day)
   - Dynamic chunk size based on network conditions
   - Bandwidth throttling options
   - Memory usage optimization for large files
   - Progress visualization improvements

3. **Comprehensive Testing** (2 days)
   - Unit tests for state management
   - Integration tests with mock SMB failures
   - HTB testing with intentional network interruptions
   - Large file transfer validation (>100MB)

4. **User Experience Enhancements** (2 days)
   - Resume prompts for interrupted downloads
   - Clear progress indicators with ETA calculation
   - Detailed error messages and recovery suggestions
   - Cleanup commands for corrupted partial downloads

#### Success Criteria
- [ ] >95% success rate for large transfers in unstable networks
- [ ] <5% overhead for resume-enabled downloads
- [ ] Resume from interruption within 10 seconds
- [ ] Intuitive CLI requiring minimal additional flags
- [ ] HTB validation with real Windows SMB shares

## Technical Specifications

### Performance Requirements

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Resume Overhead** | <5% | Time comparison vs standard download |
| **Success Rate** | >95% | Large file transfers in unstable networks |
| **Resume Time** | <10s | Time from interruption to resume |
| **Memory Usage** | <1MB | Overhead per concurrent download |
| **Chunk Processing** | 64KB-1MB | Optimal chunk size range |

### CLI Command Reference

```bash
# Resume existing download (auto-detect partial file)
get large_file.zip /tmp/large_file.zip --resume

# Force fresh download (ignore existing partial)
get large_file.zip /tmp/large_file.zip --no-resume

# Custom chunk size for network optimization
get large_file.zip /tmp/large_file.zip --resume --chunk-size 128k

# List all resumable downloads
downloads list

# Clean up completed/stale downloads
downloads cleanup

# Clean up downloads older than 7 days
downloads cleanup --max-age 7
```

### State File Management

**Storage Locations:**
- State files: `~/.slinger/downloads/download_<hash>.json`
- Hash based on local file path for uniqueness
- Automatic cleanup on successful completion

**Concurrency Safety:**
- Atomic writes via temporary file + rename
- File locking prevents concurrent access
- State validation prevents corruption recovery

**Cleanup Policies:**
- Automatic cleanup on successful download completion
- Manual cleanup commands for failed/stale downloads
- Configurable maximum age for automatic cleanup

### Error Handling Matrix

| Error Type | SMB Status Codes | Recovery Action | Max Retries |
|------------|------------------|-----------------|-------------|
| **Network Timeout** | Connection timeout, Socket timeout | Exponential backoff | 5 |
| **Connection Lost** | Connection reset, Network unreachable | Reconnect + resume | 3 |
| **Protocol Error** | STATUS_INVALID_SMB, STATUS_SMB_BAD_TID | Immediate retry | 2 |
| **Server Busy** | STATUS_TOO_MANY_CONNECTIONS | Wait + retry | 5 |
| **File Not Found** | STATUS_OBJECT_NAME_NOT_FOUND | Fatal - user action | 0 |
| **Access Denied** | STATUS_ACCESS_DENIED | Fatal - check permissions | 0 |
| **Disk Full** | No space left on device | Fatal - free space | 0 |
| **File Changed** | Size/timestamp mismatch | Fatal - restart download | 0 |

### Security Considerations

**Data Integrity:**
- SHA256 checksums for partial file validation
- File size verification before resume
- Timestamp checks to detect remote file changes

**State File Security:**
- State files stored in user home directory
- No sensitive credentials stored in state
- Atomic operations prevent corruption

**Error Information:**
- Detailed error logging for debugging
- No credential exposure in error messages
- Safe cleanup of temporary files

## Testing Strategy

### Unit Testing
```python
# Test state management
test_download_state_creation()
test_state_persistence()
test_resume_validation()
test_state_cleanup()

# Test error recovery
test_error_classification()
test_exponential_backoff()
test_retry_limits()
test_connection_recovery()

# Test chunk operations
test_chunk_size_calculation()
test_offset_validation()
test_partial_checksum()
```

### Integration Testing
```python
# Test with mock SMB failures
test_network_interruption_recovery()
test_connection_loss_recovery()
test_large_file_transfers()
test_concurrent_downloads()

# Test CLI integration
test_resume_flag_behavior()
test_chunk_size_parsing()
test_downloads_command()
```

### HTB Integration Testing
- Test against real Windows SMB shares (10.10.11.69)
- Intentional network interruptions during transfers
- Multi-gigabyte file transfer validation
- Performance benchmarking vs current implementation

### Performance Validation
- Transfer reliability comparison
- Memory usage profiling
- Chunk size optimization testing
- Network condition adaptation

## Risk Assessment

### Low Risk Factors ✅
- **Defensive Feature**: Only improves existing functionality
- **No New Attack Surface**: Uses existing SMB connection methods
- **Backward Compatible**: Optional feature, doesn't break existing downloads
- **Well-Defined Scope**: Clear boundaries and requirements

### Potential Challenges

| Challenge | Mitigation Strategy |
|-----------|-------------------|
| **SMB Version Compatibility** | Comprehensive testing across SMB 1/2/3 |
| **State File Corruption** | Atomic operations + validation checks |
| **Network Edge Cases** | Extensive error recovery testing |
| **Memory Usage** | Streaming approach + configurable chunk sizes |
| **Concurrent Access** | File locking + unique state files |

### Mitigation Strategies
1. **Progressive Rollout**: Feature flags for gradual deployment
2. **Fallback Mechanism**: Auto-fallback to standard download on errors
3. **Comprehensive Testing**: Unit + integration + HTB validation
4. **Clear Documentation**: User guides and troubleshooting

## Success Metrics

### Functional Requirements ✅
- [x] **Technical Foundation**: SMB byte-range research complete
- [x] **State Design**: Persistence and recovery mechanisms designed
- [x] **Error Strategy**: Comprehensive error recovery framework
- [ ] **Resume Capability**: Resume interrupted downloads from exact position
- [ ] **Integrity Validation**: Maintain file integrity through checksums
- [ ] **Error Recovery**: Handle network errors with exponential backoff
- [ ] **CLI Integration**: Seamless integration with existing interface
- [ ] **Progress Reporting**: Clear indicators and error messages

### Performance Requirements
- [ ] **Overhead**: <5% performance overhead for resume-enabled downloads
- [ ] **Reliability**: >95% success rate for large file transfers
- [ ] **Memory**: <1MB memory overhead per concurrent download
- [ ] **Resume Speed**: Resume from interruption within 10 seconds

### User Experience Requirements
- [ ] **Intuitive Interface**: Minimal additional CLI flags required
- [ ] **Clear Feedback**: Progress reporting with ETA and percentage
- [ ] **Helpful Errors**: Error messages with recovery suggestions
- [ ] **Automatic Cleanup**: Transparent state file management

## Future Enhancements

**Phase 4 Possibilities** (Post-MVP):
1. **Parallel Chunk Downloads**: Multiple simultaneous chunks for faster transfers
2. **Bandwidth Throttling**: Rate limiting for controlled network usage
3. **Mirror Downloads**: Download from multiple sources simultaneously
4. **Smart Retry**: Machine learning-based retry strategies
5. **Cloud Integration**: Resume downloads interrupted across different sessions

## Conclusion

Phase 1 research has successfully validated the feasibility and designed the architecture for resume downloads functionality. Key findings:

✅ **Technical Feasibility Confirmed**: Impacket supports required byte-range operations  
✅ **Architecture Designed**: Comprehensive state management and error recovery  
✅ **Integration Planned**: Clear integration points with existing slinger codebase  
✅ **Risk Mitigation**: Low-risk implementation with defensive enhancements only  

**Ready for Phase 2**: Core implementation can proceed with confidence based on solid research foundation. The resume downloads feature will establish slinger as a professional-grade SMB client capable of handling enterprise-scale file operations reliably.

---

**Document Version**: 1.0  
**Last Updated**: 2025-07-12  
**Status**: Phase 1 Complete - Ready for Implementation
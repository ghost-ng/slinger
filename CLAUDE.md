# Slinger Project: Comprehensive Roadmap & Structure Guide

## Table of Contents
1. [Project Overview](#project-overview)
2. [Project Structure and Organization](#project-structure-and-organization)
3. [Core Architecture](#core-architecture)
4. [Development Roadmap](#development-roadmap)
5. [File Organization Guide](#file-organization-guide)
6. [Documentation Navigation](#documentation-navigation)
7. [Development Workflow](#development-workflow)

---

## Project Overview

Slinger is a Python-based SMB (Server Message Block) client framework designed as a comprehensive "Swiss Army knife" for Windows system administration and security operations. Built on the Impacket library, it provides an interactive command-line interface for advanced SMB operations, remote Windows administration, and security testing.

### Key Capabilities
- **Interactive SMB Client**: Shell-like interface with command history and auto-completion
- **Multi-Protocol Authentication**: Support for NTLM, Kerberos, and password authentication
- **Advanced File Operations**: Bi-directional transfers, recursive operations, custom naming
- **Windows Administration**: Remote service, task, registry, and process management
- **Extensible Plugin System**: Modular architecture for custom functionality
- **Security Features**: Path traversal protection, verbose logging, session management

---

## Project Structure and Organization

### Root Directory Structure
```
/home/unknown/Documents/Github/slinger/
├── Documentation Files
│   ├── CLAUDE.md              # This comprehensive guide
│   ├── README.md              # Project introduction and setup
│   ├── TODO.md                # Current tasks and enhancements
│   ├── RESEARCH.md            # Technical research findings
│   ├── TECHNICAL_SPEC.md      # Detailed technical specifications
│   ├── IMPLEMENTATION_PLANS.md # Advanced feature implementation plans
│   └── cli_menu.md            # CLI command reference
├── Configuration Files
│   ├── pyproject.toml         # Project metadata and dependencies
│   ├── requirements.txt       # Python dependencies
│   ├── pytest.ini           # Test configuration
│   ├── MANIFEST.in           # Package manifest
│   └── LICENSE               # Project license
├── Build and Deployment
│   ├── build/                # Build artifacts
│   ├── build_script.py       # Build automation
│   └── .github/              # GitHub Actions CI/CD
├── Source Code
│   └── src/                  # Main source directory
├── Testing Infrastructure
│   └── tests/                # Comprehensive test suite
├── Development Tools
│   └── scripts/              # Development utilities
└── Assets and Reports
    ├── assets/               # Documentation images
    ├── htmlcov/             # Coverage reports
    └── coverage.xml         # Coverage data
```

### Source Code Structure (`src/slingerpkg/`)

#### Core Application Files
- **`slinger.py`**: Main entry point and interactive session manager
  - Handles command-line argument parsing
  - Manages interactive prompt with history and completion
  - Coordinates plugin loading and initialization
  - Provides session state management

- **`lib/slingerclient.py`**: High-level client wrapper and orchestrator
  - Inherits from all functional modules (smblib, winreg, schtasks, etc.)
  - Manages SMB connection lifecycle
  - Provides unified interface for all operations
  - Handles authentication and session state

- **`lib/smblib.py`**: Core SMB protocol operations
  - File system navigation (cd, ls, pwd)
  - File transfer operations (get, put)
  - Share enumeration and connection
  - Directory and file management
  - Path validation and security

#### Specialized Libraries (`lib/`)
- **`atexec.py`**: Remote command execution via AT service
- **`dcetransport.py`**: DCE/RPC transport management
- **`hashdump.py`**: Password hash extraction utilities
- **`msrpcperformance.py`**: RPC performance monitoring
- **`plugin_base.py`**: Plugin system foundation
- **`process_tree.py`**: Process enumeration and management
- **`schtasks.py`**: Windows Task Scheduler operations
- **`scm.py`**: Service Control Manager operations
- **`secrets.py`**: Credential and secret extraction
- **`secretsdump.py`**: Advanced credential dumping
- **`winreg.py`**: Windows Registry operations

#### Utility Framework (`utils/`)
- **`cli.py`**: Command-line interface system
  - Argparse-based command parsing
  - Auto-completion implementation
  - Command help system
  - Parser merging for plugins

- **`printlib.py`**: Standardized output formatting
  - Colored output functions (success, error, warning, debug)
  - Verbose output control
  - Logging integration

- **`common.py`**: Shared utilities and helpers
  - Configuration management
  - File operations
  - Path utilities
  - Output redirection (TeeOutput)

- **`logger.py`**: Logging infrastructure

#### Configuration (`var/`)
- **`config.py`**: Application configuration management
  - Version information
  - Default settings
  - Runtime configuration

#### Plugin System (`plugins/`)
- **`system_audit.py`**: Example system audit plugin
- Plugin framework supports extensible functionality

#### Automation Framework (`automation/`)
- **`utils.py`**: Automation utilities
- **`vars.py`**: Automation variables

### Testing Infrastructure (`tests/`)

#### Test Categories
- **`unit/`**: Component-level tests
  - `test_parser.py`: CLI parser validation
  - `test_smblib.py`: SMB library testing
  - `test_path_validation.py`: Security testing

- **`integration/`**: Cross-component tests
  - `test_commands.py`: Command integration

- **`e2e/`**: End-to-end scenarios
  - Real-world workflow testing

#### Test Support (`fixtures/`)
- **`mock_smb_server.py`**: SMB server simulation
- **`cli_runner.py`**: CLI testing framework
- **`sample_files/`**: Test data
- **`test_configs/`**: Test configurations

#### Test Utilities
- **`conftest.py`**: Pytest configuration
- **`test_coverage_validator.py`**: Coverage validation
- **`README.md`**: Comprehensive testing documentation

### Development Tools (`scripts/`)
- **`generate_test_stub.py`**: Automated test creation

---

## Core Architecture

### System Design Principles

1. **Modular Architecture**: Clear separation between SMB operations, Windows administration, and CLI management
2. **Plugin Extensibility**: Dynamic loading of additional functionality modules
3. **Security First**: Path validation, traversal protection, and secure credential handling
4. **Interactive Experience**: Shell-like interface with context awareness and command completion
5. **Comprehensive Testing**: Unit, integration, and end-to-end test coverage

### Data Flow

```
CLI Input → Parser → Command Router → SMB/Admin Operations → Output Formatter
    ↓              ↓                        ↓                      ↓
History File   Plugin System         Connection Manager      Log Files
```

### Key Design Patterns

- **Inheritance Chain**: SlingerClient inherits from all operational modules
- **Plugin Architecture**: Dynamic loading with standardized interfaces
- **Command Pattern**: Argparse-based command routing with function callbacks
- **Observer Pattern**: Output redirection and logging
- **Factory Pattern**: Connection and transport management

### Recent Enhancements (Preserved from Original)

#### 1. Enhanced Verbose Output Control
- Added `-verbose` command-line flag for enabling verbose output
- Verbose mode shows detailed remote path transformations during file operations
- Configurable via both CLI flag and runtime `set` command
- Displays statements like "[*] Remote Path (Before)" and "[*] Remote Path (After)"

#### 2. Improved File Transfer Capabilities
- **Custom Download Filenames**: Users can now specify custom filenames when downloading
  - Example: `get KeePass-2.58.zip /tmp/custom_name.zip`
  - Automatically creates necessary parent directories
- **Fixed Relative Path Uploads**: Resolved issue with relative path handling in put operations
  - Example: `put strap.sh ../` now works correctly
  - Proper path resolution for parent directory references

#### 3. Enhanced Path Navigation Security
- Navigation attempts above share root are automatically redirected to root
- Provides user-friendly warning messages while maintaining security
- Prevents directory traversal attacks while being user-friendly

#### 4. Advanced Directory Listing
- ls command supports saving output to files with `-o` flag
- `--show` option displays previously saved listing files
- Works with recursive listings (`-r` flag) for comprehensive directory trees
- Integrates with existing tee_output system for reliable file operations

---

## Development Roadmap

### Current Project State (v1.7)

#### ✅ Completed Features
- **Core SMB Operations**: Full file system navigation and transfer capabilities
- **Windows Administration**: Service, task, registry, and process management
- **Security Enhancements**: Path traversal protection, verbose output control
- **Advanced File Transfers**: Custom download filenames, improved upload handling
- **Resume Downloads**: Complete resumable download functionality with MD5 integrity
- **Testing Infrastructure**: Comprehensive test suite with mock infrastructure and pexpect
- **Plugin System**: Extensible architecture with example implementations

#### 🔧 Recent Enhancements (Phase 2: Resume Downloads)
- **Resume Download System**: Complete implementation with state persistence
  - `--resume` flag to resume interrupted downloads
  - `--restart` flag to force fresh downloads (replaces `--no-resume`)
  - Automatic partial file detection with user warnings
  - JSON-based state management with atomic operations
- **SMB Byte-Range Operations**: Efficient chunked downloads with retry logic
  - `openFile()`, `readFile()`, `closeFile()` methods for precise file access
  - Configurable chunk sizes (`--chunk-size 64k`, `1M`, etc.)
  - Error classification and exponential backoff retry
- **Downloads Management**: Complete state management system
  - `downloads list` command to show active downloads with progress
  - `downloads cleanup` command to manage state files
  - Integration with existing CLI architecture
- **Enhanced Error Recovery**: Intelligent error handling and classification
  - Distinction between retryable network errors and fatal file errors
  - Automatic retry with exponential backoff and jitter
  - Connection recovery mechanisms
- **Comprehensive Testing**: Pexpect-based test suite with MD5 verification
  - Full end-to-end testing with HTB instance (10.10.11.69)
  - MD5 integrity verification for resumed downloads
  - Automated test interruption and resume validation

### Immediate Next Steps (Next 2-4 weeks)

#### High Priority Tasks
1. **File Search Functionality** (`find` command)
   - Recursive directory traversal with pattern matching
   - Multiple search criteria (name, size, date, attributes)
   - Regular expression and wildcard support
   - Integration with existing CLI system

2. **Enhanced Error Handling**
   - Comprehensive exception management
   - User-friendly error messages
   - Recovery mechanisms for connection issues
   - Detailed debug information

3. **Performance Optimizations**
   - Large file transfer improvements
   - Directory listing optimization
   - Memory usage reduction
   - Connection pooling for multiple operations

4. **Documentation Improvements**
   - Command reference completion
   - Video tutorials and examples
   - API documentation generation
   - Plugin development guide

### Medium-term Goals (1-3 months)

#### Advanced Features
1. **Multi-target Operations**
   - Concurrent connections to multiple hosts
   - Batch operations across targets
   - Result aggregation and reporting

2. **Advanced Authentication**
   - Certificate-based authentication
   - Token-based authentication
   - Credential management system
   - SSO integration

3. **Reporting and Analytics**
   - Operation reporting framework
   - Performance metrics collection
   - Security audit reports
   - Compliance checking

4. **GUI Interface**
   - Web-based dashboard
   - Visual file browser
   - Configuration management interface
   - Real-time operation monitoring

### Long-term Vision (3-12 months)

#### Strategic Initiatives
1. **Cloud Integration**
   - Azure AD authentication
   - Cloud storage backends
   - Hybrid environment support
   - Container deployment options

2. **Enterprise Features**
   - Role-based access control
   - Audit logging and compliance
   - Integration with SIEM systems
   - Enterprise deployment tools

3. **Advanced Security**
   - Threat detection capabilities
   - Behavioral analysis
   - Compliance frameworks
   - Security automation

4. **Ecosystem Expansion**
   - Additional protocol support (FTP, SFTP, etc.)
   - Integration with other security tools
   - Marketplace for community plugins
   - API for external integrations

---

## File Organization Guide

### Where to Implement New Features

#### Core SMB Operations
- **File Operations**: Add to `src/slingerpkg/lib/smblib.py`
- **Connection Management**: Enhance `src/slingerpkg/lib/slingerclient.py`
- **Protocol Extensions**: Create new files in `src/slingerpkg/lib/`

#### Windows Administration
- **Service Operations**: Extend `src/slingerpkg/lib/scm.py`
- **Registry Operations**: Enhance `src/slingerpkg/lib/winreg.py`
- **Task Scheduling**: Add to `src/slingerpkg/lib/schtasks.py`
- **Process Management**: Extend `src/slingerpkg/lib/process_tree.py`

#### CLI and User Interface
- **New Commands**: Add parsers to `src/slingerpkg/utils/cli.py`
- **Output Formatting**: Extend `src/slingerpkg/utils/printlib.py`
- **Configuration**: Modify `src/slingerpkg/var/config.py`
- **Interactive Features**: Enhance `src/slingerpkg/slinger.py`

#### Plugin Development
- **New Plugins**: Create in `src/slingerpkg/plugins/`
- **Plugin Base**: Extend `src/slingerpkg/lib/plugin_base.py`
- **Plugin Utilities**: Add to plugin-specific directories

#### Testing
- **Unit Tests**: Add to `tests/unit/test_<module>.py`
- **Integration Tests**: Create in `tests/integration/`
- **Test Fixtures**: Add to `tests/fixtures/`
- **Mock Infrastructure**: Enhance `tests/fixtures/mock_smb_server.py`

#### Documentation
- **Technical Specs**: Update `TECHNICAL_SPEC.md`
- **Implementation Plans**: Add to `IMPLEMENTATION_PLANS.md`
- **User Documentation**: Enhance `README.md` and `cli_menu.md`
- **Research Notes**: Document in `RESEARCH.md`

### Naming Conventions

#### File Naming
- **Core Libraries**: `<functionality>.py` (e.g., `smblib.py`, `winreg.py`)
- **Plugins**: `<plugin_name>.py` (e.g., `system_audit.py`)
- **Tests**: `test_<module>.py` (e.g., `test_smblib.py`)
- **Utilities**: `<purpose>.py` (e.g., `cli.py`, `common.py`)

#### Class and Function Naming
- **Classes**: PascalCase (e.g., `SlingerClient`, `MockSMBServer`)
- **Functions**: snake_case (e.g., `connect_share`, `list_files`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `FILE_SHARE_READ`)

#### Documentation Files
- **User Docs**: ALL_CAPS.md (e.g., `README.md`, `TODO.md`)
- **Technical Docs**: Descriptive names (e.g., `cli_menu.md`)

---

## Documentation Navigation

### Primary Documentation Files

#### **CLAUDE.md** (This File)
- **Purpose**: Comprehensive project roadmap and structure guide
- **Audience**: Developers, contributors, project maintainers
- **Content**: Architecture, roadmap, organization guide
- **Update Frequency**: Major releases and structural changes

#### **README.md**
- **Purpose**: Project introduction and quick start guide
- **Audience**: New users, general public
- **Content**: Installation, basic usage, key features
- **Update Frequency**: Each release

#### **TECHNICAL_SPEC.md**
- **Purpose**: Detailed technical specifications
- **Audience**: Developers, security professionals
- **Content**: Architecture details, capabilities, operational flow
- **Update Frequency**: Significant feature additions

#### **TODO.md**
- **Purpose**: Current tasks and enhancement tracking
- **Audience**: Active developers
- **Content**: Priority tasks, implementation status
- **Update Frequency**: Continuous during development

#### **RESEARCH.md**
- **Purpose**: Technical research and investigation findings
- **Audience**: Developers, researchers
- **Content**: Architecture analysis, security considerations, performance characteristics
- **Update Frequency**: During research phases

#### **IMPLEMENTATION_PLANS.md**
- **Purpose**: Detailed implementation plans for advanced features
- **Audience**: Feature developers
- **Content**: Implementation strategies, timelines, technical approaches
- **Update Frequency**: When planning new features

#### **cli_menu.md**
- **Purpose**: Command reference and usage examples
- **Audience**: End users, administrators
- **Content**: Command syntax, examples, troubleshooting
- **Update Frequency**: When commands are added or modified

### Documentation Workflow

1. **Feature Planning**: Document in `IMPLEMENTATION_PLANS.md`
2. **Research Phase**: Record findings in `RESEARCH.md`
3. **Development Tasks**: Track in `TODO.md`
4. **Implementation**: Update relevant technical docs
5. **Testing**: Document in test files and `tests/README.md`
6. **Release**: Update `README.md` and user-facing docs
7. **Roadmap Updates**: Revise this `CLAUDE.md` file

---

## Development Workflow

### Getting Started

1. **Environment Setup**
   ```bash
   git clone <repository>
   cd slinger
   pip install -e ".[dev]"
   ```

2. **Development Dependencies**
   ```bash
   pip install pytest pytest-cov black flake8 mypy pre-commit
   ```

3. **Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

### Development Process

#### New Feature Development Workflow
The standard workflow for implementing new features follows this comprehensive cycle:

1. **Research Phase**
   - Investigate technical requirements and feasibility
   - Document findings in `RESEARCH.md`
   - Identify potential challenges and dependencies
   - Research existing solutions and best practices

2. **Planning and Design**
   - Present clear action plan and implementation strategy
   - Document in `IMPLEMENTATION_PLANS.md`
   - Explain technical specifics and architectural decisions
   - Identify and document potential risks and mitigation strategies
   - Clearly explain the purpose and value proposition

3. **Branch Creation**
   - Create new feature branch from main
   - Use descriptive branch naming (e.g., `feature/resume-downloads`)
   - Ensure clean starting point for development

4. **Implementation Cycle**
   - Implement feature following file organization guide
   - Create comprehensive tests on the branch
   - Run all tests (unit, integration, e2e)
   - **If tests fail**: Debug, fix issues, and repeat cycle
   - **If tests pass**: Proceed to completion

5. **Completion and Review**
   - Ensure all tests pass and coverage meets standards
   - Update documentation and examples
   - Report completion status
   - **Wait for explicit instructions** before merging

#### Legacy Feature Development (Reference)
1. **Planning**: Document in `IMPLEMENTATION_PLANS.md`
2. **Research**: Record findings in `RESEARCH.md`
3. **Task Creation**: Add to `TODO.md`
4. **Test-Driven Development**: Write tests first
5. **Implementation**: Follow file organization guide
6. **Testing**: Ensure all tests pass
7. **Documentation**: Update relevant docs
8. **Code Review**: Submit pull request

#### Code Quality Standards
- **Test Coverage**: Minimum 80%
- **Code Style**: Black formatting, flake8 compliance
- **Type Hints**: MyPy validation
- **Documentation**: Comprehensive docstrings
- **Security**: Security-focused code review

#### Testing Strategy
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=slingerpkg --cov-report=html

# Run specific test categories
pytest tests/unit
pytest tests/integration
pytest tests/e2e

# Generate test stubs for new features
python scripts/generate_test_stub.py <feature_name>
```

### Configuration System
The tool uses a configuration system with the following key settings:
- Debug mode toggle
- Verbose output control
- Log file locations
- Plugin directories
- Codec settings for output encoding

### Release Process

1. **Version Update**: Modify `pyproject.toml` and `src/slingerpkg/var/config.py`
2. **Documentation Review**: Update all relevant docs
3. **Testing**: Full test suite execution
4. **Build**: Generate distribution packages
5. **Release Notes**: Document changes and improvements
6. **Roadmap Update**: Revise this guide as needed

### Contribution Guidelines

#### Code Contributions
- Follow established architecture patterns
- Maintain comprehensive test coverage
- Update documentation for new features
- Follow security best practices
- Ensure backward compatibility

#### Documentation Contributions
- Keep documentation current and accurate
- Follow established formatting standards
- Include practical examples
- Consider multiple audience levels

#### Bug Reports and Feature Requests
- Use GitHub issues with appropriate labels
- Provide detailed reproduction steps
- Include environment information
- Suggest implementation approaches when possible

---

## Resume Downloads Testing Workflow

### Phase 2 Implementation Testing

The resume downloads functionality includes comprehensive testing workflows to ensure reliability and integrity. The following test suite validates all aspects of the implementation:

#### Test Files and Structure

```
/home/unknown/Documents/slinger/
├── test_resume_pexpect.py      # Comprehensive pexpect-based test suite
├── test_quick_verify.py        # Quick verification test
├── test_resume_demo.py         # Feature demonstration script
├── test_simple_resume.py       # Core component unit tests
└── test_htb_direct_fixed.py    # Direct HTB integration tests
```

#### Comprehensive Test Workflow (test_resume_pexpect.py)

**Purpose**: Full end-to-end testing with MD5 integrity verification as requested.

**Test Sequence**:
1. **Complete Download**: Download large file (ntoskrnl.exe) completely and calculate reference MD5
2. **Interrupted Download**: Start same download and interrupt after 6 seconds using pexpect
3. **Resume Download**: Resume with `--resume` flag and complete download
4. **Integrity Verification**: Compare MD5 hashes to verify file integrity is maintained

**Usage**:
```bash
source test_env/bin/activate
python test_resume_pexpect.py
```

**Key Features Tested**:
- MD5 hash integrity verification
- Partial file detection and resume
- `--restart` flag functionality
- CLI flag integration
- Downloads management commands
- Error handling and recovery

#### Quick Verification Test (test_quick_verify.py)

**Purpose**: Fast validation of core functionality without full MD5 workflow.

**Test Coverage**:
- HTB connection (10.10.11.69 with NTLM authentication)
- CLI flags (`--resume`, `--restart`) integration
- Help system verification
- Basic download operations
- Downloads management commands

**Usage**:
```bash
source test_env/bin/activate
python test_quick_verify.py
```

#### Core Component Tests (test_simple_resume.py)

**Purpose**: Unit testing of individual components without network dependencies.

**Components Tested**:
- DownloadState class functionality
- Error recovery and classification
- Chunk size parsing
- State persistence and cleanup
- DownloadStateManager operations

#### HTB Integration Tests (test_htb_direct_fixed.py)

**Purpose**: Direct library-level testing against HTB instance.

**Test Coverage**:
- SlingerClient instantiation and login
- Share connection and enumeration
- File operations and size retrieval
- Downloads management integration
- Method availability verification

### Test Environment Setup

#### Virtual Environment
```bash
python -m venv test_env
source test_env/bin/activate
pip install -e .
```

#### HTB Target Configuration
- **Host**: 10.10.11.69
- **User**: administrator
- **Authentication**: NTLM hash (:8da83a3fa618b6e3a00e93f676c92a6e)
- **Primary Share**: C$
- **Test Files**:
  - Windows/System32/ntoskrnl.exe (large file for resume testing)
  - Windows/System32/cmd.exe (small file for quick tests)

### Test Automation with Pexpect

The test suite uses pexpect for interactive testing because:

1. **Interactive Nature**: Slinger requires terminal interaction for proper operation
2. **Realistic Testing**: Simulates actual user interaction patterns
3. **Interruption Testing**: Can send Ctrl+C to interrupt downloads mid-stream
4. **Output Validation**: Can verify CLI output and prompts in real-time

#### Pexpect Pattern Examples

```python
# Connection and login
child = pexpect.spawn(cmd, timeout=60)
child.expect(r'>', timeout=30)

# Command execution
child.sendline("use C$")
child.expect(r'>', timeout=15)

# Download interruption
child.sendline(f"get {large_file} {local_path}")
time.sleep(6)  # Let download start
child.sendintr()  # Send Ctrl+C
```

### Verification Criteria

#### MD5 Integrity Test
- ✅ Complete download MD5 hash calculated
- ✅ Interrupted download creates partial file
- ✅ Resume download completes successfully
- ✅ Final MD5 hash matches original
- ✅ File sizes match exactly

#### Functionality Tests
- ✅ `--resume` flag enables resume mode
- ✅ `--restart` flag forces fresh download
- ✅ Partial file warnings displayed appropriately
- ✅ Downloads management commands functional
- ✅ Error recovery and retry logic operational

### Test Results Documentation

Test results are documented with:
- **Pass/Fail Status**: Clear success/failure indicators
- **Performance Metrics**: File sizes, transfer times, retry counts
- **Error Analysis**: Detailed error classification and recovery
- **Integrity Verification**: MD5 hash comparisons
- **Feature Coverage**: Comprehensive functionality validation

### Continuous Integration Considerations

The test suite is designed for:
- **Automated Execution**: Can run in CI/CD pipelines
- **Timeout Management**: Appropriate timeouts for network operations
- **Error Isolation**: Individual test failures don't block other tests
- **Resource Cleanup**: Automatic cleanup of test files and directories
- **Detailed Reporting**: Comprehensive pass/fail reporting with metrics

---

This comprehensive guide serves as the primary navigation resource for the Slinger project. It should be updated regularly to reflect the current state of development and future planning. For specific technical details, refer to the individual documentation files referenced throughout this guide.

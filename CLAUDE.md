# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Slinger is a Python-based SMB client framework for Windows system administration and security operations. Built on Impacket, it provides an interactive CLI for SMB operations, remote Windows administration, and security testing.

## Architecture

The codebase uses a complex multiple inheritance pattern where `SlingerClient` inherits from ~10 operational modules:

```
CLI Entry (slinger.py) → SlingerClient → Multiple Inheritance Chain:
├── smblib (SMB operations)
├── winreg (Registry management)
├── schtasks (Task scheduling)
├── scm (Service control)
├── secrets (Credential operations)
├── atexec (AT command execution)
├── wmiexec (WMI execution)
├── EventLog (Event log analysis)
└── DCETransport (RPC transport)
```

**Key architectural points:**
- Interactive shell with prompt_toolkit
- Plugin system with dynamic loading (`plugins/`)
- Resumable downloads with state persistence (`lib/download_state.py`)
- Complex inheritance chain may create method resolution complexity

## Development Commands

### Environment Setup
```bash
# Create and activate virtual environment (REQUIRED)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy pre-commit pexpect
```

### Build and Test Commands
```bash
# Build the project
python scripts/build_script.py

# Run all tests (requires virtual environment)
pytest

# Run tests with coverage
pytest --cov=slingerpkg --cov-report=html

# Run specific test categories
pytest tests/unit
pytest tests/integration
pytest tests/e2e

# Generate test stubs for new features
python scripts/generate_test_stub.py <feature_name>

# CLI testing (example HTB target)
python src/slingerpkg/slinger.py --user administrator --host 10.10.11.69 --ntlm :8da83a3fa618b6e3a00e93f676c92a6e
```

### Quality Commands
```bash
# Format code
black src/ tests/

# Lint
flake8 src/ tests/

# Type checking
mypy src/
```

## Key Development Practices

### Virtual Environment Requirement
**CRITICAL**: All development, testing, and CLI execution MUST use an active virtual environment. The tool relies on package installation and dependencies that won't work without proper environment isolation.

### CLI Command Development
When adding new CLI commands, you MUST:
1. Add the command parser to `src/slingerpkg/utils/cli.py`
2. Add the command to the help categorization system in the `categories` dictionary within `print_all_commands_verbose()`
3. Choose appropriate emoji category (📁 File Operations, 🔍 System Enumeration, etc.)
4. Test both `help` and `help --verbose` to ensure the command appears

### Plugin Development
New plugins go in `src/slingerpkg/plugins/` and must inherit from `PluginBase` (`lib/plugin_base.py`). See `plugins/system_audit.py` for example.

## File Structure for New Features

### Core SMB Operations
- **File Operations**: Add to `src/slingerpkg/lib/smblib.py`
- **Connection Management**: Enhance `src/slingerpkg/lib/slingerclient.py`

### Windows Administration
- **Service Operations**: `src/slingerpkg/lib/scm.py`
- **Registry Operations**: `src/slingerpkg/lib/winreg.py`
- **Task Scheduling**: `src/slingerpkg/lib/schtasks.py`
- **Process Management**: `src/slingerpkg/lib/process_tree.py`

### CLI and User Interface
- **New Commands**: Add parsers to `src/slingerpkg/utils/cli.py`
- **Output Formatting**: `src/slingerpkg/utils/printlib.py`
- **Configuration**: `src/slingerpkg/var/config.py`

### Testing
- **Unit Tests**: `tests/unit/test_<module>.py`
- **Integration Tests**: `tests/integration/`
- **Test Fixtures**: `tests/fixtures/`

## Important Notes

### Resume Downloads Feature
The project includes comprehensive resumable download functionality with:
- `--resume` flag for resuming interrupted downloads
- `--restart` flag for forcing fresh downloads
- JSON-based state management
- MD5 integrity verification
- Chunked download with retry logic

### Testing Requirements
- Use pexpect for interactive CLI testing
- HTB integration tests use target 10.10.11.69
- Always activate virtual environment before testing
- MD5 verification required for download integrity tests

### Dependencies
Key dependencies from pyproject.toml:
- impacket==0.11.0 (core SMB functionality)
- prompt_toolkit==3.0.41 (interactive CLI)
- pycryptodome==3.20.0 (cryptographic operations)
- tabulate==0.8.9 (output formatting)
- pexpect (testing framework)

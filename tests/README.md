# Slinger Test Suite Documentation

## Overview

The Slinger test suite provides comprehensive testing infrastructure for ensuring code quality, reliability, and maintainability. The test framework includes unit tests, integration tests, and end-to-end tests, all designed to work with Slinger's embedded CLI architecture.

## Table of Contents

1. [Test Structure](#test-structure)
2. [Running Tests](#running-tests)
3. [Writing Tests](#writing-tests)
4. [Mock Infrastructure](#mock-infrastructure)
5. [Test Coverage](#test-coverage)
6. [CI/CD Integration](#cicd-integration)
7. [Best Practices](#best-practices)

## Test Structure

```
tests/
├── unit/                     # Unit tests for individual components
│   ├── test_parser.py       # CLI parser tests
│   ├── test_smblib.py       # SMB library tests
│   └── test_*.py            # Other unit tests
├── integration/             # Integration tests
│   ├── test_commands.py     # Command integration tests
│   └── test_*.py            # Other integration tests
├── e2e/                     # End-to-end tests
│   └── test_scenarios.py    # Real-world scenarios
├── fixtures/                # Test fixtures and utilities
│   ├── mock_smb_server.py   # Mock SMB server
│   ├── cli_runner.py        # CLI test runner
│   └── sample_files/        # Test data files
├── conftest.py              # Pytest configuration
└── test_coverage_validator.py # Coverage validation tool
```

## Running Tests

### Prerequisites

Install development dependencies:
```bash
pip install -e ".[dev]"
```

### Running All Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=slingerpkg --cov-report=html

# Run specific test category
pytest tests/unit
pytest tests/integration
pytest tests/e2e
```

### Running Specific Tests

```bash
# Run a specific test file
pytest tests/unit/test_parser.py

# Run a specific test function
pytest tests/unit/test_parser.py::TestCliParser::test_basic_connection_args

# Run tests matching a pattern
pytest -k "test_authentication"
```

### Test Markers

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"

# Run tests requiring mock server
pytest -m requires_mock_server
```

## Writing Tests

### Unit Tests

Unit tests focus on testing individual components in isolation:

```python
# tests/unit/test_example.py
import pytest
from unittest.mock import Mock

class TestExample:
    @pytest.fixture
    def mock_client(self):
        """Create mock client for testing"""
        client = Mock()
        client.host = "192.168.1.100"
        return client
    
    def test_example_function(self, mock_client):
        """Test example functionality"""
        result = example_function(mock_client)
        assert result == expected_value
```

### Integration Tests

Integration tests verify command execution with mock infrastructure:

```python
# tests/integration/test_command.py
import pytest
from tests.fixtures.mock_smb_server import MockSMBServer
from tests.fixtures.cli_runner import SlingerTestRunner

class TestCommandIntegration:
    @pytest.fixture
    def runner(self, mock_server):
        """Create test runner with mock server"""
        runner = SlingerTestRunner(mock_server=mock_server)
        runner.start(host="192.168.1.100", username="test", password="test")
        yield runner
        runner.stop()
    
    def test_command_execution(self, runner):
        """Test command execution"""
        output = runner.send_command("ls")
        assert "file.txt" in output
```

### Adding New Tests

1. **For new commands**: Use the test stub generator
   ```bash
   python scripts/generate_test_stub.py new_command
   ```

2. **Manual test creation**: Follow the naming convention
   - Unit test: `tests/unit/test_<module>.py`
   - Integration test: `tests/integration/test_<feature>.py`

## Mock Infrastructure

### Mock SMB Server

The mock SMB server simulates Windows SMB responses without requiring actual targets:

```python
from tests.fixtures.mock_smb_server import MockSMBServer

# Create mock server
server = MockSMBServer()

# Add custom share with files
server.add_share("TEST$", {
    "\\file.txt": b"Content",
    "\\folder": None  # Directory
})

# Add services
server.add_service("TestService", status="RUNNING")

# Add registry keys
server.add_registry_key("HKLM\\SOFTWARE\\Test", {
    "Value": ("REG_SZ", "Data")
})

# Simulate errors
server.simulate_auth_failure()
server.simulate_access_denied()
```

### CLI Test Runner

The CLI runner handles interaction with Slinger's embedded CLI:

```python
from tests.fixtures.cli_runner import SlingerTestRunner

# Create runner
runner = SlingerTestRunner()

# Start with authentication
runner.start(
    host="192.168.1.100",
    username="admin",
    password="pass123"
)

# Send commands
output = runner.send_command("shares")
output = runner.send_command("use C$")

# Batch commands
batch = BatchCommandRunner(runner)
results = batch.run_commands([
    "shares",
    "use C$",
    "ls",
    "pwd"
])
```

## Test Coverage

### Checking Coverage

```bash
# Generate coverage report
pytest --cov=slingerpkg --cov-report=html

# View HTML report
open htmlcov/index.html

# Check coverage requirements (80% minimum)
pytest --cov=slingerpkg --cov-fail-under=80
```

### Coverage Validation

```bash
# Validate all commands have tests
python tests/test_coverage_validator.py

# Generate coverage matrix
python -c "from tests.test_coverage_validator import TestCoverageValidator; \
          v = TestCoverageValidator(); \
          print(v.generate_markdown_report())"
```

## CI/CD Integration

### GitHub Actions

Tests run automatically on:
- Every push to main/develop branches
- All pull requests
- Daily schedule (2 AM UTC)

### Test Matrix

Tests run across:
- **OS**: Ubuntu, Windows, macOS
- **Python**: 3.10, 3.11, 3.12

### PR Requirements

Pull requests must:
1. Pass all tests
2. Maintain 80%+ coverage
3. Include tests for new features
4. Update tests for modified features

## Best Practices

### 1. Test Naming

- Use descriptive test names
- Follow pattern: `test_<feature>_<scenario>`
- Example: `test_ls_command_with_hidden_files`

### 2. Test Independence

- Tests should not depend on each other
- Clean up resources in teardown
- Use fresh fixtures for each test

### 3. Mock Usage

- Mock external dependencies
- Use mock server for SMB operations
- Avoid real network connections

### 4. Assertions

- Use specific assertions
- Include helpful error messages
- Test both success and failure cases

### 5. Performance

- Mark slow tests with `@pytest.mark.slow`
- Keep unit tests fast (<0.1s)
- Use fixtures efficiently

### 6. Documentation

- Document complex test logic
- Explain test scenarios
- Include examples in docstrings

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure src is in path
   export PYTHONPATH=$PYTHONPATH:$(pwd)/src
   ```

2. **Mock Server Issues**
   - Check mock server configuration
   - Verify authentication parameters
   - Review mock data setup

3. **CLI Runner Timeouts**
   - Increase timeout in runner configuration
   - Check for blocking commands
   - Verify prompt patterns

### Debug Mode

```bash
# Run tests with verbose output
pytest -vv

# Show print statements
pytest -s

# Debug specific test
pytest --pdb tests/unit/test_parser.py::test_name
```

## Contributing

When adding new features:

1. Write tests first (TDD)
2. Ensure all tests pass
3. Maintain coverage above 80%
4. Update test documentation

For questions or issues, please open a GitHub issue with the `testing` label.
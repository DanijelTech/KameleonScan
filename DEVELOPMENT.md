# w3af Development Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Project Structure](#project-structure)
3. [Development Setup](#development-setup)
4. [Running Tests](#running-tests)
5. [Code Style](#code-style)
6. [Plugin Development](#plugin-development)
7. [API Reference](#api-reference)
8. [Debugging](#debugging)
9. [Common Issues](#common-issues)

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- 4GB RAM (8GB recommended)
- Linux/macOS or Windows with WSL

### Quick Start
```bash
# Clone the repository
git clone https://github.com/DanijelTech/KameleonScan.git
cd KameleonScan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest w3af/ -v
```

---

## Project Structure

```
KameleonScan/
├── w3af/                    # Main package
│   ├── core/               # Core functionality
│   │   ├── controllers/    # Scan controllers
│   │   ├── data/          # Data structures
│   │   └── ui/            # User interfaces
│   ├── plugins/           # Plugin system
│   │   ├── audit/         # Vulnerability detection
│   │   ├── crawl/         # Web crawling
│   │   ├── grep/          # Content analysis
│   │   ├── attack/        # Exploitation
│   │   ├── output/        # Report generation
│   │   └── mangle/        # Request/response modification
│   └── tests/              # Test suite
├── doc/                    # Documentation
├── profiles/               # Scan profiles
├── scripts/                # Automation scripts
├── tools/                 # Utility tools
├── w3af_console           # CLI executable
├── w3af_gui              # GUI executable
└── w3af_api              # API server executable
```

---

## Development Setup

### Full Development Environment
```bash
# Install all dependencies
pip install -r requirements.txt
pip install -r w3af/tests/requirements.txt

# Install development tools
pip install black flake8 isort mypy pylint pytest pytest-cov

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Docker Development
```bash
# Build Docker image
docker build -t w3af-dev .

# Run with volume mount for development
docker run -it -v $(pwd):/app w3af-dev /bin/bash
```

---

## Running Tests

### Run All Tests
```bash
pytest w3af/ -v
```

### Run Specific Test Category
```bash
# Unit tests only
pytest w3af/ -v -m unit

# Integration tests
pytest w3af/ -v -m integration

# Skip slow tests
pytest w3af/ -v -m "not slow"
```

### Run with Coverage
```bash
pytest w3af/ --cov=w3af --cov-report=html --cov-report=term-missing
```

### Run Specific Test File
```bash
pytest w3af/core/data/misc/tests/test_encoding.py -v
```

---

## Code Style

### Format Code
```bash
# Format with Black
black w3af/

# Sort imports
isort w3af/
```

### Lint Code
```bash
# Run flake8
flake8 w3af/ --count --show-source --statistics

# Run mypy type checking
mypy w3af/ --ignore-missing-imports

# Run pylint
pylint w3af/
```

### Pre-commit Hooks
```bash
# Run all hooks manually
pre-commit run --all-files

# Skip hooks (not recommended)
git commit --no-verify
```

---

## Plugin Development

### Creating a New Audit Plugin

```python
"""
Example audit plugin template
"""

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin


class MyCustomPlugin(AuditPlugin):
    """
    Plugin description here.
    """
    
    def __init__(self):
        AuditPlugin.__init__(self)
        
    def audit(self, freq, response):
        """
        Main plugin logic
        """
        # Your vulnerability detection logic here
        
        if vulnerability_found:
            self._add_vulnerability(
                freq.get_url(),
                'Vulnerability description',
                response.id,
                'high'  # severity
            )
    
    def get_plugin_by_name(self, plugin_name, plugin_type):
        """Get other plugins if needed."""
        return self.w3af_core.plugins.get_plugin_by_name(plugin_name, plugin_type)
```

### Plugin Types
- **audit** - Vulnerability detection
- **crawl** - Web spidering
- **grep** - Content analysis
- **attack** - Exploitation
- **output** - Report formats
- **mangle** - Request/response modification

---

## API Reference

### Starting the API Server
```bash
./w3af_api
# Server starts at http://localhost:44444
```

### Using the REST API
```bash
# Start a scan
curl -X POST http://localhost:44444/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com", "profile": "fast_scan"}'

# Get scan status
curl http://localhost:44444/scan/{scan_id}

# Get vulnerabilities
curl http://localhost:44444/kb
```

### OpenAPI Documentation
See `doc/api/openapi.yaml` for the complete API specification.

---

## Debugging

### Enable Debug Logging
```python
# In your code
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Visual Debugging
```bash
# Use the GUI with debug mode
./w3af_gui --debug
```

### Profiling
```bash
# Profile scan performance
python -m cProfile -o output.pstats w3af_console
# Analyze: python -m pstats output.pstats
```

### Memory Profiling
```bash
python -m memory_profiler w3af_console
```

---

## Common Issues

### Import Errors
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Set PYTHONPATH: `export PYTHONPATH=/path/to/KameleonScan`

### Test Failures
- Run tests with verbose output: `pytest -v --tb=short`
- Check if network-dependent tests fail: use `-m "not requires_network"`

### Performance Issues
- Reduce scan scope with profiles
- Use `-j` flag for parallel processing
- Limit crawling depth

---

## Useful Commands

```bash
# Quick scan with fast_scan profile
./w3af_console -p profiles/fast_scan

# List all profiles
./w3af_console -l profiles

# List all plugins by type
./w3af_console -i audit

# Export results to JSON
./w3af_console -o output.json

# Enable verbose output
./w3af_console -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

---

## Resources

- [Official Documentation](http://docs.w3af.org/)
- [Wiki](https://github.com/DanijelTech/KameleonScan/wiki)
- [Issue Tracker](https://github.com/DanijelTech/KameleonScan/issues)
- [Discussions](https://github.com/DanijelTech/KameleonScan/discussions)
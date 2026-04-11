# KameleonScan - Web Application Security Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/DanijelTech/KameleonScan/update-readme-image/doc/sphinx/images/Kameleon.png" alt="KameleonScan logo" width="200"/>
</p>

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](https://www.gnu.org/licenses/gpl-2.0.txt)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![codecov](https://codecov.io/gh/DanijelTech/KameleonScan/branch/main/graph/badge.svg)](https://codecov.io/gh/DanijelTech/KameleonScan)
[![Security](https://img.shields.io/badge/security-bandit-orange.svg)](https://github.com/PyCQA/bandit)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/w3af/w3af)

## About

[w3af](http://w3af.org/) is an open source web application security scanner which helps developers and penetration testers identify and exploit vulnerabilities in their web applications.

The scanner is able to identify **200+ vulnerabilities**, including:
- Cross-Site Scripting (XSS)
- SQL Injection
- OS Commanding
- LDAP Injection
- XML External Entity (XXE)
- And many more...

## Requirements

- Python 3.8 or higher
- Linux/macOS/Windows (via WSL or Docker)
- 4GB RAM minimum (8GB recommended)
- Network connectivity for scanning

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/DanijelTech/KameleonScan.git
cd KameleonScan

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running w3af

```bash
# Command-line interface
./w3af_console

# Graphical User Interface
./w3af_gui

# REST API server
./w3af_api
```

### Using Docker

```bash
# Build the Docker image
docker build -t w3af .

# Run the container
docker run -it w3af ./w3af_console
```

## Features

- **Comprehensive Scanning**: 200+ vulnerability checks
- **Multiple Interfaces**: CLI, GUI, and REST API
- **Plugin System**: Extensible architecture for custom plugins
- **Authentication Handling**: Support for various auth mechanisms
- **Reporting**: Multiple output formats (HTML, JSON, XML, CSV)
- **Proxy Support**: Transparent proxy for manual testing
- **Fuzzing**: Advanced fuzzing capabilities

## Documentation

For detailed documentation, visit:
- [w3af Documentation](http://docs.w3af.org/en/latest/)
- [Installation Guide](https://github.com/DanijelTech/KameleonScan/wiki/Installation)
- [User Guide](https://github.com/DanijelTech/KameleonScan/wiki/User-Guide)

## Development

### Setting up Development Environment

```bash
# Install development dependencies
pip install -r requirements.txt
pip install -r w3af/tests/requirements.txt
pip install black flake8 isort mypy pylint pytest

# Run tests
pytest w3af/ -v

# Code formatting
black w3af/
isort w3af/

# Type checking
mypy w3af/ --ignore-missing-imports

# Linting
pylint w3af/
```

### CI/CD

The project uses GitHub Actions for continuous integration. See `.github/workflows/ci.yml` for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Ways to Contribute

- Report bugs and suggest features
- Improve documentation
- Add new vulnerability checks
- Fix issues and improve code quality
- Share the project with others

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please contact: info@w3af.org

## Support

- [Issue Tracker](https://github.com/DanijelTech/KameleonScan/issues)
- [Discussion Forum](#)
- [Wiki](https://github.com/DanijelTech/KameleonScan/wiki)

---

<p align="center">
  Made with ❤️ by the w3af team
</p>

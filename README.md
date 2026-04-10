# KameleonScan - Professional Web Application Security Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/DanijelTech/KameleonScan/main/doc/sphinx/images/w3af-logo.png" alt="KameleonScan logo" width="200"/>
</p>

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](https://www.gnu.org/licenses/gpl-2.0.txt)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![codecov](https://codecov.io/gh/DanijelTech/KameleonScan/branch/main/graph/badge.svg)](https://codecov.io/gh/DanijelTech/KameleonScan)
[![Security](https://img.shields.io/badge/security-bandit-orange.svg)](https://github.com/PyCQA/bandit)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/kameleonscan/kameleonscan)

## About

**KameleonScan** is a professional-grade web application security scanner with AI-powered capabilities. It helps developers and penetration testers identify and exploit vulnerabilities in their web applications.

The scanner includes **200+ vulnerability checks** and features:
- AI-powered adaptive scanning
- Modern async architecture
- Full DevSecOps integration
- Kubernetes security scanning
- Auto-compliance reporting
- SBOM generation

## Version History

This repository contains two versions:

| Version | Directory | Status | Description |
|---------|-----------|--------|-------------|
| **v2.0 Phoenix** | `kameleon/` | Active Development | New modern KameleonScan with AI, async, K8s security |
| **v1.0 Legacy** | `w3af/` | Maintenance Only | Classic scanner - still functional |

## Requirements

- Python 3.11 or higher (v2.0)
- Python 3.8 or higher (v1.0)
- Linux/macOS/Windows (via WSL or Docker)
- 4GB RAM minimum (8GB recommended)
- Network connectivity for scanning

## Quick Start

### KameleonScan v2.0 (Recommended)

```bash
# Clone and install
git clone https://github.com/DanijelTech/KameleonScan.git
cd KameleonScan
pip install -r kameleon/requirements.txt

# Using Python API
python -c "
from kameleon import quick_scan
import asyncio

async def main():
    result = await quick_scan('https://example.com')
    print(f'Found {len(result.vulnerabilities)} vulnerabilities')

asyncio.run(main())
"

# Or install as CLI
pip install -e kameleon/
kameleon scan https://example.com --ai
```

### Legacy w3af v1.0

```bash
# Install dependencies
pip install -r requirements.txt

# Run legacy scanner
./w3af_console    # CLI
./w3af_gui       # GUI
./w3af_api       # REST API
```

### Using Docker

```bash
docker build -t kameleonscan .
docker run -it kameleonscan
```

## Features

### KameleonScan v2.0 (Phoenix) ✨

| Feature | Description |
|---------|-------------|
| **AI-Powered** | Adaptive scanning with ML-based false positive reduction |
| **Async Architecture** | Modern asyncio/httpx based networking |
| **Kubernetes Security** | Pod security, RBAC, network policies, secrets |
| **IDE Integration** | VS Code and JetBrains plugins for real-time scanning |
| **CI/CD Integration** | GitHub Actions, GitLab CI, Jenkins, Azure DevOps |
| **Auto-Compliance** | PCI-DSS, GDPR, HIPAA, SOC2 auto-reporting |
| **SBOM Generation** | SPDX, CycloneDX formats for supply chain security |
| **Cloud Security** | AWS S3, Azure Blob, GCP Storage enumeration |

### Legacy w3af v1.0

| Feature | Description |
|---------|-------------|
| **200+ Vuln Checks** | SQLi, XSS, CSRF, XXE, LFI, RFI, RCE, etc. |
| **Multiple Interfaces** | CLI, GUI, REST API |
| **Plugin System** | Extensible architecture |
| **Authentication** | HTTP Basic, Form, Cookie, NTLM |
| **Reporting** | HTML, JSON, XML, CSV formats |
| **Proxy** | Transparent proxy for manual testing |

## Documentation

- [KameleonScan v2.0 Docs](https://kameleonscan.io/docs)
- [Installation Guide](https://github.com/DanijelTech/KameleonScan/wiki/Installation)
- [API Reference](https://kameleonscan.io/api)
- [Migration Guide](https://kameleonscan.io/migrate)

## Development

### v2.0 Development

```bash
pip install -r kameleon/requirements.txt
pip install -e kameleon/

# Run tests
pytest kameleon/ -v

# Code quality
black kameleon/
mypy kameleon/
```

### v1.0 Development

```bash
pip install -r requirements.txt
pip install -r w3af/tests/requirements.txt

pytest w3af/ -v
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

Areas where help is needed:
- AI/ML integration for v2.0
- New vulnerability detection plugins
- IDE plugin development
- Kubernetes security scanning
- Documentation improvements

## License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

## Security

For security vulnerabilities, please contact: **security@kameleonscan.io**

## Support

- [Issue Tracker](https://github.com/DanijelTech/KameleonScan/issues)
- [Discussions](https://github.com/DanijelTech/KameleonScan/discussions)
- [Wiki](https://github.com/DanijelTech/KameleonScan/wiki)

---

<p align="center">
  Made with ❤️ by the KameleonScan team
</p>
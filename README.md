# KameleonScan - Professional Web Application Security Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/DanijelTech/KameleonScan/main/doc/sphinx/images/logo.png" alt="KameleonScan" width="200"/>
</p>

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](https://www.gnu.org/licenses/gpl-2.0.txt)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/kameleonscan/kameleonscan)

## About

**KameleonScan** is a professional-grade web application security scanner built for modern DevSecOps workflows.

### Features

- **AI-Powered Scanning** - Adaptive vulnerability detection
- **Async Architecture** - Modern asyncio/httpx performance
- **Kubernetes Security** - Pod, RBAC, Network policies
- **IDE Integration** - VS Code, JetBrains plugins
- **CI/CD Integration** - GitHub Actions, GitLab, Jenkins
- **Auto-Compliance** - PCI-DSS, GDPR, HIPAA
- **SBOM Generation** - Supply chain security

## Quick Start

```bash
pip install -r kameleon/requirements.txt
pip install -e kameleon/
kameleon scan https://example.com --ai
```

## Python API

```python
from kameleon import quick_scan
import asyncio

async def main():
    result = await quick_scan('https://example.com')
    print(f'Found {len(result.vulnerabilities)} vulnerabilities')

asyncio.run(main())
```

## Docker

```bash
docker build -t kameleonscan .
docker run -it kameleonscan kameleon scan https://example.com
```

## License

GPL-2.0

## Security

security@kameleonscan.io
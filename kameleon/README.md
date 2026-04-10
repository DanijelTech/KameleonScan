# KameleonScan v2.0 "Phoenix" - Professional Security Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/DanijelTech/KameleonScan/main/doc/sphinx/images/w3af-logo.png" alt="KameleonScan" width="200"/>
</p>

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](https://www.gnu.org/licenses/gpl-2.0.txt)

## 🚀 Professional Security Scanner for 2026

**KameleonScan v2.0 Phoenix** is a complete rebuild of the classic w3af scanner, designed for modern security challenges.

### Key Features

#### 🤖 AI-Powered Security
- **Adaptive scanning** - AI that learns your application
- **False positive reduction** - ML-based analysis
- **Smart vulnerability classification** - Context-aware detection
- **Anomaly detection** - Behavioral analysis

#### ⚡ Modern Async Architecture
- **asyncio-first** - Built on modern async/await patterns
- **httpx** - Modern HTTP client with connection pooling
- **Distributed scanning** - Scale horizontally
- **Real-time processing** - Async event-driven

#### 🔌 Full DevSecOps Integration
- **GitHub Actions** - Native SARIF integration
- **GitLab CI** - Security scanning in merge requests
- **Jenkins** - Pipeline security automation
- **Azure DevOps** - Enterprise integration
- **IDE Plugins** - VS Code & JetBrains real-time scanning

#### ☁️ Cloud-Native Security
- **Kubernetes scanner** - Pod security, RBAC, network policies
- **Container security** - Image vulnerability scanning
- **Cloud enumeration** - AWS S3, Azure, GCP
- **Serverless scanning** - Lambda, Functions

#### 📊 Auto-Compliance
- **PCI-DSS 4.0** - Automated compliance checking
- **GDPR** - Privacy compliance validation
- **HIPAA** - Healthcare security
- **SOC 2** - Security compliance
- **SBOM Generation** - SPDX, CycloneDX

### Architecture

```
kameleon/
├── core.py              # Main orchestrator
├── http/
│   └── client.py        # Async HTTP with httpx
├── ai/
│   └── engine.py        # AI scanning engine
├── plugin/
│   └── manager.py       # Modern plugin system
├── scanner/
│   └── engine.py        # Scan orchestration
├── compliance/          # Auto-compliance reports
├── supply_chain/        # SBOM generation
├── k8s/                 # Kubernetes security
├── ide/                 # IDE integration plugins
└── ci/                  # CI/CD pipeline integration
```

### Quick Start

```python
# Quick scan
from kameleon import quick_scan

result = await quick_scan("https://example.com")
print(f"Found {len(result.vulnerabilities)} vulnerabilities")

# AI-powered scan
from kameleon import ai_scan

result = await ai_scan("https://example.com", ai_adaptive=True)
print(f"AI insights: {result.ai_insights}")

# Full audit with compliance
from kameleon import full_audit

result = await full_audit(
    "https://example.com",
    compliance_standard="pci-dss",
    generate_sbom=True
)
print(f"Compliance score: {result.compliance_results['score']}")
```

### CLI Usage

```bash
# Quick scan
kameleon scan https://example.com

# AI adaptive scan
kameleon scan https://example.com --ai

# Full audit with compliance
kameleon scan https://example.com --full --compliance pcid --generate-sbom

# CI/CD integration (GitHub Actions)
kameleon scan $TARGET_URL --output-format sarif --fail-on critical
```

### Installation

```bash
pip install kameleonscan

# Or from source
git clone https://github.com/DanijelTech/KameleonScan.git
cd KameleonScan
pip install -e .
```

### Requirements

- Python 3.11+
- asyncio
- httpx
- aioredis (optional, for Redis storage)

### Comparison: v1 vs v2

| Feature | v1 (w3af) | v2 (Phoenix) |
|---------|-----------|--------------|
| Architecture | Threading | Async-first |
| HTTP | urllib3 | httpx |
| AI/ML | None | Full AI engine |
| K8s Security | ❌ | ✅ Full |
| IDE Plugins | ❌ | ✅ VS Code/JetBrains |
| CI/CD | Basic | Native integrations |
| Compliance | Manual | Auto-reports |
| SBOM | ❌ | ✅ SPDX/CycloneDX |

### Professional Features

- [x] Proof-based vulnerability verification
- [x] False positive reduction with ML
- [x] Runtime security (IDE, K8s)
- [x] Auto-generated compliance reports
- [x] SBOM for supply chain security
- [x] Zero-trust architecture testing

### License

GNU General Public License v2.0 - See [LICENSE](LICENSE) file.

---

**Note:** This is v2.0 "Phoenix" - a complete rebuild from the ground up for modern security requirements.
"""
KameleonScan - Professional Security Scanner
============================================

Version 2.0 - Phoenix Build

Modern async security scanner with:
- AI-powered adaptive scanning
- Full DevSecOps integration
- Kubernetes security
- IDE plugins
- Auto-compliance reporting
"""

__version__ = "2.0.0"
__author__ = "KameleonScan Team"
__license__ = "GPL-2.0"

# Core imports
from .core import KameleonScan, ScanConfig, ScanResult
from .core import quick_scan, ai_scan, full_audit

__all__ = [
    'KameleonScan',
    'ScanConfig',
    'ScanResult',
    'quick_scan',
    'ai_scan',
    'full_audit',
]
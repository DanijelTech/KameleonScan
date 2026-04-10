"""
KameleonScan Core - Async-First Modern Security Scanner
=========================================================

Modern architecture built from ground up for 2026 professional requirements:
- Async-first with asyncio/httpx
- AI-powered adaptive scanning
- Distributed scanning support
- Plugin-based extensible architecture
- Runtime integration (IDE, CI/CD, K8s)

Version: 2.0.0 - "Phoenix"
Author: KameleonScan Team
"""

import asyncio
import logging
from typing import Optional, Dict, List, Any, Callable, Type
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import time
import uuid

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a security scan."""
    target_url: str
    scan_type: str = "full"  # quick, full, custom, ai Adaptive
    max_concurrent_requests: int = 100
    timeout: int = 30
    max_depth: int = 10
    follow_redirects: bool = True
    verify_ssl: bool = True
    user_agent: str = "KameleonScan/2.0 (Professional Security Scanner)"
    
    # AI Options
    ai_adaptive: bool = True
    ai_false_positive_reduction: bool = True
    
    # Authentication
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_token: Optional[str] = None
    
    # Headers
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Performance
    rate_limit: int = 100
    retry_count: int = 3
    
    # Output
    output_format: str = "json"
    output_path: Optional[str] = None
    
    # Compliance
    compliance_standard: Optional[str] = None


@dataclass 
class ScanResult:
    """Result of a security scan."""
    scan_id: str
    target_url: str
    start_time: float
    end_time: Optional[float] = None
    
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    # AI-generated insights
    ai_insights: Optional[Dict[str, Any]] = None
    
    # Compliance results
    compliance_results: Optional[Dict[str, Any]] = None
    
    # SBOM if requested
    sbom: Optional[Dict[str, Any]] = None
    
    def add_vulnerability(self, vuln: Dict[str, Any]) -> None:
        vuln['id'] = str(uuid.uuid4())[:8]
        vuln['timestamp'] = time.time()
        self.vulnerabilities.append(vuln)
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in self.vulnerabilities:
            sev = v.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts


class KameleonScan:
    """
    Main KameleonScan orchestrator - Professional-grade async security scanner.
    """
    
    VERSION = "2.0.0"
    BUILD = "Phoenix-2026.1"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._initialized = False
        
        self._http_client = None
        self._plugin_manager = None
        self._ai_engine = None
        self._reporting_engine = None
        self._storage = None
        self._active_scans: Dict[str, ScanResult] = {}
        self._scan_queue = None
        
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    async def initialize(self) -> None:
        if self._initialized:
            return
            
        logger.info(f"Initializing KameleonScan v{self.VERSION} ({self.BUILD})")
        
        # Initialize HTTP client
        from .http.client import AsyncHTTPClient
        self._http_client = AsyncHTTPClient(
            max_connections=self.config.get('max_connections', 1000),
            timeout=self.config.get('timeout', 30)
        )
        await self._http_client.initialize()
        
        # Initialize plugin system
        from .plugin.manager import PluginManager
        self._plugin_manager = PluginManager(self._http_client)
        await self._plugin_manager.load_plugins()
        
        # Initialize AI scanning engine
        from .ai.engine import AIScanningEngine
        self._ai_engine = AIScanningEngine(
            self._http_client,
            self._plugin_manager,
            adaptive=self.config.get('ai_adaptive', True)
        )
        
        # Initialize reporting engine
        from .reporting.engine import ReportingEngine
        self._reporting_engine = ReportingEngine(
            storage=None,
            output_format=self.config.get('output_format', 'json')
        )
        
        self._initialized = True
        logger.info("KameleonScan initialized successfully")
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        if not self._initialized:
            await self.initialize()
        
        scan_id = str(uuid.uuid4())[:8]
        logger.info(f"Starting scan {scan_id} for {config.target_url}")
        
        result = ScanResult(
            scan_id=scan_id,
            target_url=config.target_url,
            start_time=time.time()
        )
        
        try:
            # Import and run scan engine
            from .scanner.engine import ScanEngine
            
            if config.scan_type == "ai" or config.ai_adaptive:
                engine = self._ai_engine
            else:
                engine = ScanEngine(self._http_client, self._plugin_manager, config)
            
            vulnerabilities = await engine.scan(config)
            
            for vuln in vulnerabilities:
                result.add_vulnerability(vuln)
            
            if config.compliance_standard:
                from .compliance import ComplianceEngine
                engine = ComplianceEngine(config.compliance_standard)
                result.compliance_results = engine.check_compliance(result.vulnerabilities)
            
            if config.ai_false_positive_reduction and self._ai_engine:
                result.ai_insights = await self._ai_engine.analyze_results(
                    result.vulnerabilities, config.target_url
                )
            
            result.end_time = time.time()
            logger.info(f"Scan {scan_id} completed: {len(result.vulnerabilities)} vulns")
            
            return result
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            result.errors.append(str(e))
            result.end_time = time.time()
            raise
    
    async def shutdown(self) -> None:
        logger.info("Shutting down KameleonScan...")
        if self._http_client:
            await self._http_client.close()
        logger.info("KameleonScan shutdown complete")
    
    @asynccontextmanager
    async def session(self):
        await self.initialize()
        try:
            yield self
        finally:
            await self.shutdown()


# Convenience functions
async def quick_scan(url: str, **kwargs) -> ScanResult:
    config = ScanConfig(target_url=url, scan_type="quick", **kwargs)
    async with KameleonScan() as scanner:
        return await scanner.scan(config)


async def ai_scan(url: str, **kwargs) -> ScanResult:
    config = ScanConfig(target_url=url, scan_type="ai", ai_adaptive=True, **kwargs)
    async with KameleonScan() as scanner:
        return await scanner.scan(config)


async def full_audit(url: str, **kwargs) -> ScanResult:
    config = ScanConfig(
        target_url=url, scan_type="full", ai_adaptive=True,
        compliance_standard="auto", **kwargs
    )
    async with KameleonScan() as scanner:
        return await scanner.scan(config)


__all__ = ['KameleonScan', 'ScanConfig', 'ScanResult', 'quick_scan', 'ai_scan', 'full_audit']
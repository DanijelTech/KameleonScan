"""
Scanner Engine - Main scanning orchestration
=============================================

"""

import asyncio
import logging
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ScanEngine:
    """Standard async scan engine."""
    
    def __init__(self, http_client, plugin_manager, config):
        self._http = http_client
        self._plugins = plugin_manager
        self._config = config
        
    async def scan(self, config) -> List[Dict[str, Any]]:
        """Execute standard scan."""
        logger.info(f"Running standard scan on {config.target_url}")
        
        # Discovery phase
        endpoints = await self._discover_endpoints(config.target_url)
        
        # Audit phase  
        vulnerabilities = []
        for plugin_name in self._get_enabled_plugins():
            vulns = await self._plugins.execute_plugin(
                plugin_name,
                config.target_url,
                {'endpoints': endpoints}
            )
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _discover_endpoints(self, url: str) -> List[str]:
        """Discover available endpoints."""
        # Quick discovery
        endpoints = ['/', '/api', '/admin', '/login', '/graphql']
        
        discovered = []
        for ep in endpoints:
            try:
                result = await self._http.get(f"{url}{ep}")
                if result.status_code < 500:
                    discovered.append(ep)
            except:
                pass
        
        return discovered
    
    def _get_enabled_plugins(self) -> List[str]:
        return [
            'sql_injection', 'xss', 'ssrf', 'ssti', 'jwt', 
            'graphql', 'nosql', 'idor', 'csrf', 'xxe'
        ]


__all__ = ['ScanEngine']
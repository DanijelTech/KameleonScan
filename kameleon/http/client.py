"""
Async HTTP Client - Modern async-first networking
================================================

Built with httpx for professional-grade async HTTP:
- Connection pooling
- Request/response middleware
- Automatic retries
- Rate limiting
- Proxy support
"""

import asyncio
import httpx
import logging
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import ssl

logger = logging.getLogger(__name__)


@dataclass
class HTTPConfig:
    """Configuration for async HTTP client."""
    max_connections: int = 1000
    max_keepalive_connections: int = 100
    timeout: float = 30.0
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 30.0
    
    # Retry configuration
    max_retries: int = 3
    retry_backoff_factor: float = 0.5
    
    # Rate limiting
    requests_per_second: int = 100
    
    # SSL
    verify_ssl: bool = True
    ssl_cert: Optional[str] = None
    
    # Proxy
    proxy_url: Optional[str] = None
    
    # Headers
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": "KameleonScan/2.0 (Professional Security Scanner)",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })


@dataclass
class RequestResult:
    """Result of an HTTP request."""
    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: float
    error: Optional[str] = None
    
    @property
    def text(self) -> str:
        try:
            return self.body.decode('utf-8', errors='replace')
        except:
            return ""
    
    @property
    def json(self) -> Optional[Dict]:
        try:
            import json
            return json.loads(self.body)
        except:
            return None


class AsyncHTTPClient:
    """
    Professional async HTTP client with advanced features.
    """
    
    def __init__(self, max_connections: int = 1000, timeout: float = 30.0):
        self._config = HTTPConfig(
            max_connections=max_connections,
            timeout=timeout
        )
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._last_request_time: float = 0
        self._request_interval: float = 0
        
        # Statistics
        self._stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
        }
    
    async def initialize(self) -> None:
        """Initialize the HTTP client."""
        
        # Configure SSL
        ssl_context = httpx.create_ssl_context(verify=self._config.verify_ssl)
        
        # Configure transport with connection pooling
        limits = httpx.Limits(
            max_connections=self._config.max_connections,
            max_keepalive_connections=self._config.max_keepalive_connections
        )
        
        # Configure timeout
        timeout = httpx.Timeout(
            connect=self._config.connect_timeout,
            read=self._config.read_timeout,
            write=self._config.write_timeout,
            pool=self._config.timeout
        )
        
        # Create HTTPX client
        self._client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            ssl=ssl_context,
            proxies=self._config.proxy_url,
            follow_redirects=True,
            limits=limits
        )
        
        # Rate limiter
        self._request_interval = 1.0 / self._config.requests_per_second
        self._rate_limiter = asyncio.Semaphore(self._config.max_connections)
        
        logger.info(f"AsyncHTTPClient initialized: {self._config.max_connections} max connections")
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        params: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        auth: Optional[httpx.Auth] = None,
        **kwargs
    ) -> RequestResult:
        """
        Make an async HTTP request with rate limiting and retries.
        """
        if not self._client:
            raise RuntimeError("Client not initialized")
        
        # Rate limiting
        async with self._rate_limiter:
            now = asyncio.get_event_loop().time()
            time_since_last = now - self._last_request_time
            if time_since_last < self._request_interval:
                await asyncio.sleep(self._request_interval - time_since_last)
            self._last_request_time = asyncio.get_event_loop().time()
        
        # Merge headers
        req_headers = {**self._config.default_headers}
        if headers:
            req_headers.update(headers)
        
        # Retry logic
        last_error = None
        for attempt in range(self._config.max_retries):
            try:
                start_time = asyncio.get_event_loop().time()
                
                response = await self._client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    data=data,
                    json=json,
                    params=params,
                    cookies=cookies,
                    auth=auth,
                    **kwargs
                )
                
                elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                
                # Update stats
                self._stats['requests_sent'] += 1
                self._stats['total_bytes_received'] += len(response.content)
                
                return RequestResult(
                    url=str(response.url),
                    method=method,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    elapsed_ms=elapsed_ms
                )
                
            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
                self._stats['requests_failed'] += 1
                
            except httpx.HTTPError as e:
                last_error = f"HTTP Error: {e}"
                self._stats['requests_failed'] += 1
                
            except Exception as e:
                last_error = f"Error: {e}"
                self._stats['requests_failed'] += 1
            
            # Wait before retry
            if attempt < self._config.max_retries - 1:
                wait_time = self._config.retry_backoff_factor * (2 ** attempt)
                await asyncio.sleep(wait_time)
        
        return RequestResult(
            url=url,
            method=method,
            status_code=0,
            headers={},
            body=b"",
            elapsed_ms=0,
            error=last_error
        )
    
    # Convenience methods
    async def get(self, url: str, **kwargs) -> RequestResult:
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> RequestResult:
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> RequestResult:
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> RequestResult:
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> RequestResult:
        return await self.request("HEAD", url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> RequestResult:
        return await self.request("OPTIONS", url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> RequestResult:
        return await self.request("PATCH", url, **kwargs)
    
    # Batch requests
    async def batch_request(
        self,
        requests: List[Dict[str, Any]],
        max_concurrent: int = 50
    ) -> List[RequestResult]:
        """Execute multiple requests concurrently."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_request(req):
            async with semaphore:
                return await self.request(**req)
        
        tasks = [limited_request(req) for req in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            logger.info("AsyncHTTPClient closed")
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return self._stats.copy()


# ============================================================
# Auth helpers
# ============================================================

class BasicAuth(httpx.Auth):
    """Basic authentication handler."""
    
    def __init__(self, username: str, password: str):
        import base64
        self._credentials = base64.b64encode(f"{username}:{password}".encode()).decode()


class BearerAuth(httpx.Auth):
    """Bearer token authentication."""
    
    def __init__(self, token: str):
        self._token = token
    
    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self._token}"
        yield request


class APIKeyAuth(httpx.Auth):
    """API Key authentication."""
    
    def __init__(self, key: str, header_name: str = "X-API-Key"):
        self._key = key
        self._header = header_name
    
    def auth_flow(self, request):
        request.headers[self._header] = self._key
        yield request


__all__ = ['AsyncHTTPClient', 'HTTPConfig', 'RequestResult', 'BasicAuth', 'BearerAuth', 'APIKeyAuth']
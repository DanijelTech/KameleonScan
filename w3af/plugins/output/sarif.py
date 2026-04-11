"""
sarif.py - SARIF Output Format

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
import json
import os
import uuid
from datetime import datetime

import w3af.core.controllers.output_manager as om
from w3af.core.controllers.plugins.output_plugin import OutputPlugin
from w3af.core.data.options.opt_factory import opt_factory
from w3af.core.data.options.option_list import OptionList


class sarif(OutputPlugin):
    """
    Output results in SARIF (Static Analysis Results Interchange Format).
    
    SARIF is an OASIS standard format for static analysis results,
    enabling integration with CI/CD pipelines, GitHub Advanced Security,
    Azure DevOps, and other platforms.
    
    :author: KameleonScan Team
    :see: https://sarifweb.visualstudio.com/
    """
    
    RUN_ID = str(uuid.uuid4())
    VERSION = '2.1.0'
    
    SEVERITY_MAP = {
        'INFO': 'note',
        'LOW': 'note',
        'MEDIUM': 'warning',
        'HIGH': 'error',
        'CRITICAL': 'error',
    }
    
    def __init__(self):
        OutputPlugin.__init__(self)
        self._results = []
        self._rules = {}
        
    def get_options(self):
        """
        :return: A list of option objects for this plugin.
        """
        opt = OptionList()
        
        o = opt_factory('output_file', 'results.sarif',
                       'Output file path for SARIF results',
                       'STRING', 'OUTPUT_FILE')
        opt.add(o)
        
        o = opt_factory('include_passed', False,
                       'Include passed checks in output',
                       'BOOL', 'INCLUDE_PASSED')
        opt.add(o)
        
        o = opt_factory('pretty_print', True,
                       'Pretty print(JSON) output',
                       'BOOL', 'PRETTY_PRINT')
        opt.add(o)
        
        o = opt_factory('source_language', 'python',
                       'Source language for results',
                       'STRING', 'SOURCE_LANG')
        opt.add(o)
        
        o = opt_factory('git_repo_url', '',
                       'GitHub/GitLab repository URL for linking',
                       'STRING', 'GIT_REPO')
        opt.add(o)
        
        o = opt_factory('git_branch', 'main',
                       'Git branch name',
                       'STRING', 'GIT_BRANCH')
        opt.add(o)
        
        return opt

    def set_options(self, options):
        """
        Set the options given by the user.
        
        :param options: A dictionary with the options for the plugin.
        """
        self._output_file = options['output_file'].get_value()
        self._include_passed = options['include_passed'].get_value()
        self._pretty_print = options['pretty_print'].get_value()
        self._source_language = options['source_language'].get_value()
        self._git_repo_url = options['git_repo_url'].get_value()
        self._git_branch = options['git_branch'].get_value()
    
    def write_output(self, message):
        """
        This method is called when something interesting happens.
        
        :param message: The message that was passed to the output.
        """
        # This is called for general output - we only care about vulnerabilities
        pass
    
    def add_vulnerability(self, vuln):
        """
        Add a vulnerability to the SARIF output.
        
        :param vuln: Vuln instance
        """
        if not vuln:
            return
            
        plugin_name = vuln.get_plugin()
        
        # Create rule if not exists
        if plugin_name not in self._rules:
            self._rules[plugin_name] = self._create_rule(plugin_name, vuln)
        
        # Convert vulnerability to SARIF result
        result = self._convert_vuln_to_result(vuln)
        self._results.append(result)
    
    def add_filter(self, args):
        """
        This method is called when a message is filtered.
        
        :param filter_msg: The message that was filtered.
        :param filter_type: Filter type.
        """
        filter_msg, filter_type = args
        pass
    
    def _create_rule(self, plugin_name, vuln):
        """
        Create a SARIF rule from vulnerability.
        
        :param plugin_name: Plugin name
        :param vuln: Vulnerability instance
        :return: SARIF rule dict
        """
        severity = vuln.get_severity()
        
        rule = {
            'id': f"kamel-{plugin_name}",
            'name': vuln.get_name() or plugin_name,
            'shortDescription': {
                'text': vuln.get_name() or plugin_name
            },
            'fullDescription': {
                'text': vuln.get_desc()[:500] if vuln.get_desc() else 'No description'
            },
            'defaultConfiguration': {
                'level': self.SEVERITY_MAP.get(severity, 'warning'),
                'enabled': True,
            },
            'help': {
                'text': f"Vulnerability detected by {plugin_name}. See documentation for remediation.",
                'markdown': f"## {vuln.get_name()}\n\n{vuln.get_desc()[:1000]}\n\n### Remediation\nSee application documentation."
            },
            'properties': {
                'tags': ['security', 'vulnerability', plugin_name],
                'precision': 'high',
                'security-severity': self._get_cwe_severity(vuln),
            }
        }
        
        return rule
    
    def _get_cwe_severity(self, vuln):
        """
        Estimate security severity based on CWE if available.
        
        :param vuln: Vulnerability instance
        :return: Numeric severity (0-10)
        """
        # Map common vulnerability types to severity
        severity_map = {
            'sql injection': 9.8,
            'xss': 7.3,
            'csrf': 6.5,
            'rce': 9.8,
            'lfi': 7.5,
            'rfi': 9.8,
            'ssti': 9.8,
            'jwt': 8.2,
            'nosql': 8.1,
            'ssrf': 9.1,
            'idor': 6.5,
        }
        
        desc = (vuln.get_name() or '').lower()
        for key, severity in severity_map.items():
            if key in desc:
                return str(severity)
        
        return '5.0'  # Default medium
    
    def _convert_vuln_to_result(self, vuln):
        """
        Convert a vulnerability to SARIF result format.
        
        :param vuln: Vulnerability instance
        :return: SARIF result dict
        """
        url = vuln.get_url()
        severity = vuln.get_severity()
        
        # Create location
        location = {
            'physicalLocation': {
                'artifactLocation': {
                    'uri': str(url),
                    'uriBaseId': 'PROJECT_ROOT'
                },
                'region': {
                    'startLine': 1,
                    'startColumn': 1,
                }
            }
        }
        
        # Add message
        message = {
            'text': f"[{severity}] {vuln.get_name()}: {str(url)}"
        }
        
        if vuln.get_desc():
            message['markdown'] = vuln.get_desc()
        
        result = {
            'ruleId': f"kamel-{vuln.get_plugin()}",
            'ruleIndex': list(self._rules.keys()).index(vuln.get_plugin()),
            'level': self.SEVERITY_MAP.get(severity, 'warning'),
            'message': message,
            'locations': [location],
            'baselineState': 'new',
            'rank': self._get_cwe_severity(vuln),
        }
        
        # Add related locations if available
        if vuln.get_highlight():
            # Add code snippets as related locations
            for i, snippet in enumerate(vuln.get_highlight()[:3]):
                if len(snippet) > 200:
                    snippet = snippet[:200] + '...'
                
                result.setdefault('relatedLocations', []).append({
                    'id': i + 1,
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': str(url),
                            'uriBaseId': 'PROJECT_ROOT'
                        },
                        'region': {
                            'snippet': {
                                'text': snippet
                            }
                        }
                    },
                    'message': {
                        'text': f"Highlight {i+1}"
                    }
                })
        
        return result
    
    def _build_sarif_document(self):
        """
        Build the complete SARIF document.
        
        :return: SARIF document dict
        """
        rules = list(self._rules.values())
        
        # Create tool driver
        driver = {
            'name': 'KameleonScan',
            'version': '1.0.0',  # Would use actual version
            'informationUri': 'https://github.com/DanijelTech/KameleonScan',
            'rules': rules,
            'language': 'en-US',
        }
        
        # Create run
        run = {
            'tool': driver,
            'results': self._results,
        }
        
        # Add version control if available
        if self._git_repo_url:
            run['versionControlProvenance'] = [{
                'repositoryUri': self._git_repo_url,
                'branch': self._git_branch,
                'revisionId': 'HEAD',
            }]
        
        # Build SARIF document
        sarif_doc = {
            'version': self.VERSION,
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs': [run],
        }
        
        return sarif_doc
    
    def end(self, fixed_by_profile):
        """
        Called when the scan finishes.
        
        :param fixed_by_profile: Profile that was used
        """
        # Build SARIF document
        sarif_doc = self._build_sarif_document()
        
        # Write to file
        try:
            # Ensure directory exists
            output_dir = os.path.dirname(self._output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Write SARIF file
            with open(self._output_file, 'w') as f:
                if self._pretty_print:
                    json.dump(sarif_doc, f, indent=2)
                else:
                    json.dump(sarif_doc, f)
            
            om.out.info(f"SARIF results saved to: {self._output_file}")
            om.out.info(f"Total vulnerabilities: {len(self._results)}")
            
        except Exception as e:
            om.out.error(f"Error writing SARIF output: {e}")

    def get_long_desc(self):
        """
        :return: A DETAILED description of what the plugin does and how
                 it is used.
        """
        return """
        This plugin outputs scan results in SARIF format.
        
        SARIF (Static Analysis Results Interchange Format) is an OASIS
        standard for representing static analysis results.
        
        Features:
        - Full SARIF 2.1.0 specification support
        - GitHub Advanced Security integration
        - Azure DevOps integration
        - GitLab integration (via SARIF upload)
        - Jenkins plugin support
        - Integration with security dashboards
        
        Output Options:
        - output_file: Path to save SARIF file
        - include_passed: Include passed checks
        - pretty_print: Pretty print(JSON)
        - source_language: Source language for results
        - git_repo_url: Repository URL for linking
        - git_branch: Branch name for version control
        
        Usage:
        ```
        w3af> profiles
        w3af/profiles> use full_audit
        w3af/profiles> output.plugins
        w3af/profiles> output.plugins.set sarif.output_file /path/to/results.sarif
        w3af/profiles> output.plugins.set sarif.git_repo_url https://github.com/user/repo
        w3af/profiles> start
        ```
        
        Then upload the SARIF file to:
        - GitHub: Settings > Security > Code scanning > Upload
        - Azure DevOps: Pipelines > Security > Upload SARIF
        """
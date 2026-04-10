"""
IDE Integration - Security in the IDE
=====================================

VS Code and JetBrains plugin support for real-time security.
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class IDEScanResult:
    """Result of IDE security scan."""
    file_path: str
    line_number: int
    severity: str
    message: str
    rule_id: str
    suggestion: str


class IDEPlugin:
    """
    IDE Plugin for real-time security scanning.
    
    Supports:
    - VS Code
    - JetBrains (IntelliJ, WebStorm, etc.)
    - Vim/Neovim
    """
    
    def __init__(self, ide_type: str = "vscode"):
        self._ide_type = ide_type
        self._enabled_rules = set()
        self._scan_on_save = True
        self._scan_on_type = False
        
    def initialize(self, config: Dict) -> None:
        """Initialize IDE plugin."""
        
        self._enabled_rules = set(config.get('enabled_rules', [
            'hardcoded_credentials',
            'sql_injection',
            'xss_vulnerable',
            'insecure_random',
            'weak_crypto',
            'ssrf_pattern',
            'ssti_pattern',
            'jwt_hardcoded',
            'exposed_secrets',
            'insecure_deserialization'
        ]))
        
        self._scan_on_save = config.get('scan_on_save', True)
        self._scan_on_type = config.get('scan_on_type', False)
        
        logger.info(f"IDE Plugin initialized for {self._ide_type}")
    
    async def analyze_file(self, file_path: str, content: str) -> List[IDEScanResult]:
        """Analyze file content for security issues."""
        
        findings = []
        
        # Pattern-based detection
        patterns = {
            'hardcoded_credentials': [
                (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password detected'),
                (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key detected'),
                (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret detected'),
                (r'token\s*=\s*["\'][A-Za-z0-9]{20,}["\']', 'Hardcoded token detected'),
            ],
            'sql_injection': [
                (r'execute\s*\([^)]*\+[^)]*\)', 'Potential SQL injection - use parameterized queries'),
                (r'cursor\.execute\s*\([^)]*%s[^)]*\)', 'Potential SQL injection'),
                (r'SELECT\s+.*\+.*FROM', 'Potential SQL injection'),
            ],
            'xss_vulnerable': [
                (r'innerHTML\s*=', 'Potential XSS - use textContent or sanitize'),
                (r'dangerouslySetInnerHTML', 'React XSS risk - sanitize HTML'),
                (r'eval\s*\(', 'Dangerous eval usage'),
            ],
            'insecure_random': [
                (r'random\.random\(\)', 'Insecure random - use secrets module'),
                (r'Math\.random\(\)', 'Insecure random in JavaScript'),
            ],
            'weak_crypto': [
                (r'md5\s*\(', 'Weak hash algorithm - use SHA-256+'),
                (r'sha1\s*\(', 'Weak hash algorithm - use SHA-256+'),
                (r'hashlib\.md5', 'Weak hash - use SHA-256+'),
            ],
            'ssrf_pattern': [
                (r'requests\.get\s*\([^)]*input', 'Potential SSRF - validate URL'),
                (r'urllib\.request\s*\([^)]*input', 'Potential SSRF'),
            ],
            'ssti_pattern': [
                (r'render_template_string', 'Dangerous SSTI - use render_template'),
                (r'Template\s*\(\s*["\']', 'Potential SSTI - sanitize input'),
            ],
            'jwt_hardcoded': [
                (r'jwt\.decode\s*\([^,]+,\s*["\'][^"\']+["\']', 'JWT with hardcoded secret'),
            ],
            'exposed_secrets': [
                (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'Exposed JWT token'),
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
                (r'sk-[A-Za-z0-9]{48}', 'OpenAI API Key'),
                (r'sg-live-[A-Za-z0-9]{32}', 'Stripe API Key'),
            ]
        }
        
        for rule_id, pattern_list in patterns.items():
            if rule_id not in self._enabled_rules:
                continue
                
            for pattern, message in pattern_list:
                import re
                matches = re.finditer(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    # Calculate line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    findings.append(IDEScanResult(
                        file_path=file_path,
                        line_number=line_num,
                        severity=self._get_severity(rule_id),
                        message=message,
                        rule_id=rule_id,
                        suggestion=self._get_fix_suggestion(rule_id)
                    ))
        
        return findings
    
    def _get_severity(self, rule_id: str) -> str:
        """Map rule to severity."""
        
        severity_map = {
            'hardcoded_credentials': 'critical',
            'exposed_secrets': 'critical',
            'sql_injection': 'high',
            'xss_vulnerable': 'high',
            'ssrf_pattern': 'high',
            'ssti_pattern': 'high',
            'insecure_random': 'medium',
            'weak_crypto': 'medium',
            'jwt_hardcoded': 'high'
        }
        
        return severity_map.get(rule_id, 'medium')
    
    def _get_fix_suggestion(self, rule_id: str) -> str:
        """Get fix suggestion for rule."""
        
        suggestions = {
            'hardcoded_credentials': 'Use environment variables or secrets manager instead',
            'exposed_secrets': 'Move secrets to environment variables or secret management system',
            'sql_injection': 'Use parameterized queries or ORM: cursor.execute("SELECT * FROM users WHERE id = ?", (id,))',
            'xss_vulnerable': 'Use textContent instead of innerHTML, or sanitize with DOMPurify',
            'ssrf_pattern': 'Validate and sanitize URL input, use allowlists',
            'ssti_pattern': 'Use render_template() with context instead of render_template_string()',
            'insecure_random': 'Use secrets module: secrets.token_urlsafe(32)',
            'weak_crypto': 'Use hashlib.sha256() or stronger algorithms',
            'jwt_hardcoded': 'Store secrets in environment variables, verify signature properly'
        }
        
        return suggestions.get(rule_id, 'Review and fix security issue')
    
    def get_lsp_diagnostics(self, findings: List[IDEScanResult]) -> Dict:
        """Format findings as LSP diagnostics."""
        
        diagnostics = []
        
        for finding in findings:
            # VS Code format
            diagnostic = {
                'severity': self._lsp_severity(finding.severity),
                'message': f"[{finding.rule_id}] {finding.message}",
                'source': 'KameleonScan',
                'range': {
                    'start': {'line': finding.line_number - 1, 'character': 0},
                    'end': {'line': finding.line_number - 1, 'character': 100}
                }
            }
            
            if finding.suggestion:
                diagnostic['code'] = finding.rule_id
                diagnostic['codeDescription'] = {
                    'href': f"https://kameleonscan.io/rules/{finding.rule_id}"
                }
            
            diagnostics.append(diagnostic)
        
        return diagnostics
    
    def _lsp_severity(self, severity: str) -> int:
        """Convert severity to LSP diagnostic severity."""
        
        severity_map = {
            'critical': 1,  # Error
            'high': 1,
            'medium': 2,   # Warning
            'low': 3,      # Information
            'info': 3
        }
        
        return severity_map.get(severity, 2)


# ============================================================
# VS Code Extension manifest
# ============================================================

VSCODE_PACKAGE_JSON = {
    "name": "kameleonscan-security",
    "displayName": "KameleonScan Security",
    "description": "AI-powered security scanning in VS Code",
    "version": "1.0.0",
    "publisher": "kameleonscan",
    "engines": {
        "vscode": "^1.70.0"
    },
    "categories": ["Security", "Linters"],
    "activationEvents": ["onLanguage:javascript", "onLanguage:typescript", "onLanguage:python", "onLanguage:java"],
    "contributes": {
        "commands": [
            {
                "command": "kameleonscan.scan",
                "title": "Run Security Scan"
            },
            {
                "command": "kameleonscan.scanWorkspace",
                "title": "Scan Entire Workspace"
            }
        ],
        "configuration": {
            "title": "KameleonScan",
            "properties": {
                "kameleonscan.enable": {
                    "type": "boolean",
                    "default": true,
                    "description": "Enable security scanning"
                },
                "kameleonscan.scanOnSave": {
                    "type": "boolean",
                    "default": true,
                    "description": "Scan on file save"
                },
                "kameleonscan.severityLevel": {
                    "type": "string",
                    "default": "medium",
                    "enum": ["low", "medium", "high", "critical"]
                }
            }
        }
    }
}


# ============================================================
# JetBrains plugin
# ============================================================

JETBRAINS_BUILD_XML = """<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin version="2" xmlns:xi="http://www.w3.org/2001/XInclude">
    <id>io.kameleonscan.plugin</id>
    <name>KameleonScan Security</name>
    <version>1.0.0</version>
    <vendor>KameleonScan</vendor>
    <description>AI-powered security scanning for JetBrains IDEs</description>
    <depends>com.intellij.modules.platform</depends>
    <actions>
        <action id="KameleonScan.RunScan" class="io.kameleonscan.actions.RunScanAction" text="Run Security Scan">
            <add-to-group group-id="RunActions" anchor="first"/>
        </action>
    </actions>
</idea-plugin>
"""


__all__ = ['IDEPlugin', 'IDEScanResult', 'VSCODE_PACKAGE_JSON']
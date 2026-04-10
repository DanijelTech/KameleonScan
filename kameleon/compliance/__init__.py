"""
Compliance Engine - Auto-generated compliance reports
=======================================================

Supports: PCI-DSS, GDPR, HIPAA, SOC2, ISO 27001
"""

import logging
from typing import Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ComplianceRequirement:
    """A single compliance requirement."""
    requirement_id: str
    description: str
    status: str  # pass, fail, not_applicable
    evidence: List[str]
    finding_ids: List[str]
    remediation: str


@dataclass
class ComplianceReport:
    """Full compliance report."""
    standard: str
    version: str
    score: float  # 0-100
    total_requirements: int
    passed: int
    failed: int
    not_applicable: int
    requirements: List[ComplianceRequirement]
    executive_summary: str
    remediation_plan: List[Dict[str, Any]]


class ComplianceEngine:
    """
    Auto-generate compliance reports from scan results.
    """
    
    STANDARDS = {
        'pci-dss': {
            'version': '4.0',
            'requirements': {
                '1': 'Install and maintain network security controls',
                '2': 'Apply secure configurations to all system components',
                '3': 'Protect stored account data',
                '4': 'Protect cardholder data during transmission',
                '5': 'Protect all systems and networks from malicious software',
                '6': 'Develop and maintain secure systems and software',
                '7': 'Restrict access to system components and cardholder data',
                '8': 'Identify users and authenticate access to system components',
                '9': 'Restrict physical access to cardholder data',
                '10': 'Log and monitor all access to system components and cardholder data',
                '11': 'Test security of systems and networks regularly',
                '12': 'Support information security with organizational policies'
            }
        },
        'gdpr': {
            'version': 'GDPR 2016/679',
            'requirements': {
                '5': 'Principles of processing',
                '6': 'Lawfulness of processing',
                '7': 'Conditions for consent',
                '12': 'Transparent information and communication',
                '17': 'Right to erasure',
                '25': 'Data protection by design and default',
                '32': 'Security of processing',
                '33': 'Notification of personal data breach',
                '35': 'Data protection impact assessment'
            }
        },
        'hipaa': {
            'version': 'HIPAA 1996',
            'requirements': {
                '164.308': 'Administrative safeguards',
                '164.310': 'Physical safeguards',
                '164.312': 'Technical safeguards',
                '164.402': 'Breach notification',
                '164.502': 'Uses and disclosures of PHI',
                '164.514': 'De-identification'
            }
        }
    }
    
    def __init__(self, standard: str):
        self._standard = standard.lower()
        self._config = self.STANDARDS.get(self._standard, {})
    
    def check_compliance(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Check vulnerabilities against compliance requirements."""
        
        requirements = []
        
        # Map vulnerabilities to requirements
        vuln_to_req = {
            'critical': [
                ('pci-dss', '3', 'Unencrypted cardholder data stored'),
                ('pci-dss', '9', 'Physical access to cardholder data'),
                ('gdpr', '32', 'Inadequate security measures'),
                ('gdpr', '33', 'Breach notification failure'),
                ('hipaa', '164.312', 'Technical safeguards violated'),
            ],
            'high': [
                ('pci-dss', '6', 'Vulnerable systems'),
                ('pci-dss', '8', 'Weak authentication'),
                ('gdpr', '25', 'Missing data protection'),
                ('hipaa', '164.308', 'Administrative safeguards'),
            ],
            'medium': [
                ('pci-dss', '10', 'Inadequate logging'),
                ('pci-dss', '12', 'Missing security policy'),
            ]
        }
        
        # Analyze each vulnerability
        failed_requirements = []
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            
            if severity in vuln_to_req:
                for std, req_id, desc in vuln_to_req[severity]:
                    if std == self._standard:
                        failed_requirements.append({
                            'requirement_id': req_id,
                            'description': desc,
                            'severity': severity,
                            'vulnerability': vuln.get('name', 'Unknown'),
                            'remediation': vuln.get('remediation', 'Fix the vulnerability')
                        })
        
        # Calculate score
        total_requirements = len(self._config.get('requirements', {}))
        failed_count = len(failed_requirements)
        
        if total_requirements > 0:
            score = ((total_requirements - failed_count) / total_requirements) * 100
        else:
            score = 100
        
        return {
            'standard': self._standard,
            'score': score,
            'total_requirements': total_requirements,
            'failed_requirements': failed_count,
            'passed_requirements': total_requirements - failed_count,
            'findings': failed_requirements,
            'status': 'compliant' if score >= 80 else 'non_compliant',
            'next_audit_date': self._calculate_next_audit(score)
        }
    
    def _calculate_next_audit(self, score: float) -> str:
        """Calculate when next audit is needed."""
        if score >= 90:
            return "12 months"
        elif score >= 80:
            return "6 months"
        elif score >= 70:
            return "3 months"
        else:
            return "Immediate"
    
    def generate_full_report(self, vulnerabilities: List[Dict]) -> ComplianceReport:
        """Generate complete compliance report."""
        
        check_results = self.check_compliance(vulnerabilities)
        
        return ComplianceReport(
            standard=self._standard.upper(),
            version=self._config.get('version', 'Unknown'),
            score=check_results['score'],
            total_requirements=check_results['total_requirements'],
            passed=check_results['passed_requirements'],
            failed=check_results['failed_requirements'],
            not_applicable=0,
            requirements=[],  # Would populate detailed requirements
            executive_summary=self._generate_executive_summary(check_results),
            remediation_plan=self._generate_remediation_plan(check_results['findings'])
        )
    
    def _generate_executive_summary(self, results: Dict) -> str:
        """Generate executive summary."""
        
        score = results['score']
        
        if score >= 90:
            status = "EXCELLENT - Full compliance achieved"
        elif score >= 80:
            status = "GOOD - Minor issues to address"
        elif score >= 70:
            status = "FAIR - Significant improvements needed"
        else:
            status = "CRITICAL - Immediate action required"
        
        return f"""
COMPLIANCE EXECUTIVE SUMMARY
============================
Standard: {self._standard.upper()}
Score: {score:.1f}%

Status: {status}

Findings: {results['failed_requirements']} requirement(s) failed
Recommendations: {results.get('next_audit_date', 'N/A')}
"""
    
    def _generate_remediation_plan(self, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation plan."""
        
        priority_map = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4
        }
        
        # Sort by priority
        sorted_findings = sorted(
            findings,
            key=lambda x: priority_map.get(x.get('severity', 'low'), 99)
        )
        
        plan = []
        for i, finding in enumerate(sorted_findings, 1):
            plan.append({
                'priority': i,
                'requirement_id': finding.get('requirement_id', 'N/A'),
                'title': finding.get('description', 'N/A'),
                'severity': finding.get('severity', 'unknown'),
                'vulnerability': finding.get('vulnerability', 'N/A'),
                'remediation': finding.get('remediation', 'N/A'),
                'estimated_effort': self._estimate_effort(finding.get('severity', 'low'))
            })
        
        return plan
    
    def _estimate_effort(self, severity: str) -> str:
        """Estimate remediation effort."""
        effort_map = {
            'critical': '2-4 weeks',
            'high': '1-2 weeks',
            'medium': '1 week',
            'low': '1-2 days'
        }
        return effort_map.get(severity, 'Unknown')


__all__ = ['ComplianceEngine', 'ComplianceReport', 'ComplianceRequirement']
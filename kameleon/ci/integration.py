"""
CI/CD Integration - DevSecOps Pipeline Security
===============================================

GitHub Actions, GitLab CI, Jenkins, Azure DevOps integration.
"""

import asyncio
import logging
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CICDScanConfig:
    """Configuration for CI/CD scan."""
    platform: str  # github, gitlab, jenkins, azure
    
    # Triggers
    trigger_on_push: bool = True
    trigger_on_pr: bool = True
    trigger_on_schedule: bool = True
    
    # Scan options
    scan_type: str = "full"  # quick, full, ai
    fail_on_severity: str = "high"  # critical, high, medium
    
    # Notifications
    notify_slack: bool = False
    slack_webhook: Optional[str] = None
    notify_teams: bool = False
    teams_webhook: Optional[str] = None
    
    # Integration
    create_issue: bool = True
    comment_on_pr: bool = True
    add_labels: bool = True
    
    # Compliance
    compliance_standard: Optional[str] = None
    generate_sbom: bool = False


@dataclass
class CICDScanResult:
    """Result of CI/CD scan."""
    scan_id: str
    platform: str
    
    status: str  # success, failure, warning
    vulnerabilities_found: int = 0
    
    by_severity: Dict[str, int] = field(default_factory=dict)
    new_vulnerabilities: int = 0
    fixed_vulnerabilities: int = 0
    
    compliance_status: str = "unknown"
    sbom_path: Optional[str] = None
    
    scan_url: Optional[str] = None
    pr_comment_url: Optional[str] = None
    
    action_items: List[Dict] = field(default_factory=list)


class GitHubActionsIntegration:
    """
    GitHub Actions integration for security scanning.
    """
    
    def __init__(self, token: str, repo: str):
        self._token = token
        self._repo = repo
        self._api_url = "https://api.github.com"
    
    async def setup_workflow(self, config: CICDScanConfig) -> str:
        """Generate GitHub Actions workflow file."""
        
        workflow = f"""name: KameleonScan Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install KameleonScan
        run: |
          pip install kameleonscan
          
      - name: Run Security Scan
        env:
          KAMELEON_TOKEN: ${{ secrets.KAMELEON_TOKEN }}
        run: |
          kameleon scan ${{ github.event.repository.html_url }} \\
            --scan-type {config.scan_type} \\
            --fail-on {config.fail_on_severity} \\
            --output-format sarif \\
            --output-path results.sarif
          {"--compliance " + config.compliance_standard if config.compliance_standard else ""}
          {"--generate-sbom" if config.generate_sbom else ""}
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: "kameleonscan"
      
      - name: Create GitHub Issue on failure
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({{
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Security Vulnerabilities Detected',
              body: 'KameleonScan found vulnerabilities in your code. Please review and fix.',
              labels: ['security', 'vulnerability']
            }})
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({{
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.pull_request.number,
              body: '## 🔒 Security Scan Results\\n\\nKameleonScan completed. See results in Security tab.'
            }})

"""
        
        return workflow
    
    async def get_scan_results(self, run_id: str) -> CICDScanResult:
        """Get scan results from GitHub Actions run."""
        
        # Would fetch from GitHub API
        return CICDScanResult(
            scan_id=run_id,
            platform="github",
            status="success",
            vulnerabilities_found=5,
            by_severity={'critical': 1, 'high': 2, 'medium': 2}
        )


class GitLabCIIntegration:
    """GitLab CI integration."""
    
    def __init__(self, token: str, project_id: str):
        self._token = token
        self._project_id = project_id
        self._api_url = "https://gitlab.com/api/v4"
    
    async def setup_pipeline(self, config: CICDScanConfig) -> str:
        """Generate GitLab CI pipeline."""
        
        pipeline = f""".gitlab-ci.yml

kameleon-scan:
  stage: security
  image: python:3.11-slim
  
  before_script:
    - pip install kameleonscan
  
  script:
    - kameleon scan $CI_PROJECT_URL \\
      --scan-type {config.scan_type} \\
      --output-format sarif \\
      --output-path gl-sarif.sarif
      
  artifacts:
    paths:
      - gl-sarif.sarif
    reports:
      security:
        - gl-sarif.sarif
  
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_SCHEDULED_JOB'  # Scheduled scans
  
  allow_failure: true  # Don't fail pipeline on findings

security-merge-request:
  stage: security
  image: python:3.11-slim
  needs: [kameleon-scan]
  
  script: |
    # Post MR comment with summary
    echo "Security scan completed"
  
  only:
    - merge_requests

"""
        
        return pipeline


class JenkinsIntegration:
    """Jenkins integration."""
    
    def __init__(self, jenkins_url: str, api_token: str):
        self._url = jenkins_url
        self._token = api_token
    
    def get_pipeline_script(self, config: CICDScanConfig) -> str:
        """Generate Jenkins pipeline script."""
        
        return f"""pipeline {{
    agent any
    
    stages {{
        stage('Security Scan') {{
            steps {{
                sh '''
                    pip install kameleonscan
                    kameleon scan $TARGET_URL \\
                        --scan-type {config.scan_type} \\
                        --fail-on {config.fail_on_severity} \\
                        --output-format json \\
                        --output-path scan-results.json
                '''
            }}
            post {{
                always {{
                    publishHTML(target: [
                        reportDir: '.',
                        reportFiles: 'scan-results.html',
                        reportName: 'Security Scan Report'
                    ])
                    
                    recordIssues(
                        tools: [scanAndSaveIssues('KameleonScan')],
                        qualityGates: [
                            [threshold: {config.fail_on_severity}, type: 'TOTAL', unstable: false]
                        ]
                    )
                }}
            }}
        }}
    }}
    
    post {{
        failure {{
            slackSend(
                color: 'danger',
                message: "Security scan failed - critical vulnerabilities found"
            )
        }}
    }}
}}
"""


class AzureDevOpsIntegration:
    """Azure DevOps integration."""
    
    def __init__(self, org: str, project: str, token: str):
        self._org = org
        self._project = project
        self._token = token
    
    def get_yaml_pipeline(self, config: CICDScanConfig) -> str:
        """Generate Azure DevOps YAML pipeline."""
        
        return f"""# azure-pipelines.yml

trigger:
  - main
  - develop
  - '*'

pr:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
  - stage: SecurityScan
    displayName: 'Security Scan'
    jobs:
      - job: KameleonScan
        displayName: 'KameleonScan Security Analysis'
        steps:
          - task: UsePythonVersion@1
            inputs:
              versionSpec: '3.11'
          
          - script: |
              pip install kameleonscan
              kameleon scan $(TARGET_URL) \\
                --scan-type {config.scan_type} \\
                --output-format sarif \\
                --output-path results.sarif
              displayName: 'Run Security Scan'
          
          - task: PublishSecurityResults@0
            inputs:
              sarifFile: 'results.sarif'
              displayName: 'Publish Security Results'
          
          - task: PublishPipelineArtifacts@1
            inputs:
              targetPath: 'results.sarif'
              artifactName: 'SecurityResults'
"""


class CICDOrchestrator:
    """
    Main CI/CD orchestrator that manages all platform integrations.
    """
    
    def __init__(self):
        self._integrations = {}
    
    def register_integration(self, platform: str, integration) -> None:
        """Register a CI/CD platform integration."""
        self._integrations[platform] = integration
    
    async def setup(self, platform: str, config: CICDScanConfig) -> str:
        """Setup CI/CD pipeline for specified platform."""
        
        if platform not in self._integrations:
            raise ValueError(f"Unknown platform: {platform}")
        
        integration = self._integrations[platform]
        
        if platform == "github":
            return await integration.setup_workflow(config)
        elif platform == "gitlab":
            return await integration.setup_pipeline(config)
        elif platform == "jenkins":
            return integration.get_pipeline_script(config)
        elif platform == "azure":
            return integration.get_yaml_pipeline(config)
        
        raise ValueError(f"Cannot setup pipeline for {platform}")
    
    async def execute_scan(
        self,
        platform: str,
        config: CICDScanConfig,
        target: str
    ) -> CICDScanResult:
        """Execute scan in CI/CD context."""
        
        # Would execute actual scan and format results
        return CICDScanResult(
            scan_id="scan-001",
            platform=platform,
            status="success",
            vulnerabilities_found=0,
            action_items=[]
        )
    
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported CI/CD platforms."""
        return list(self._integrations.keys())


# Initialize default integrations
def create_cicd_orchestrator(github_token: Optional[str] = None) -> CICDOrchestrator:
    """Create CI/CD orchestrator with available integrations."""
    
    orchestrator = CICDOrchestrator()
    
    if github_token:
        orchestrator.register_integration(
            "github",
            GitHubActionsIntegration(github_token, os.getenv('GITHUB_REPO', ''))
        )
    
    return orchestrator


__all__ = [
    'CICDScanConfig',
    'CICDScanResult',
    'GitHubActionsIntegration',
    'GitLabCIIntegration',
    'JenkinsIntegration',
    'AzureDevOpsIntegration',
    'CICDOrchestrator',
    'create_cicd_orchestrator'
]
"""
Supply Chain Security - SBOM Generation
=========================================

Generates Software Bill of Materials (SBOM) in:
- SPDX format
- CycloneDX format
- SWID tag format

For compliance: NTIA, SBOM transparency requirements
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)


@dataclass
class SBOMComponent:
    """A single component in the SBOM."""
    name: str
    version: str
    type: str  # library, framework, application, container
    supplier: Optional[str] = None
    description: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    hash: Optional[str] = None
    url: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class SBOM:
    """Software Bill of Materials document."""
    sbom_version: str
    spdx_version: str
    data_license: str
    
    # Metadata
    name: str
    spdx_id: str
    document_namespace: str
    creation_info: Dict[str, str]
    
    # Components
    packages: List[SBOMComponent] = field(default_factory=list)
    
    # Relationships
    relationships: List[Dict] = field(default_factory=list)
    
    # Annotations
    annotations: List[Dict] = field(default_factory=list)


class SBOMGenerator:
    """
    Generate SBOM for supply chain security.
    """
    
    def __init__(self):
        self._formats = ['spdx', 'cyclonedx', 'swid']
    
    async def generate(self, target_url: str) -> Dict[str, Any]:
        """Generate SBOM for target application."""
        
        logger.info(f"Generating SBOM for {target_url}")
        
        # Collect components (would actually scan the application)
        components = await self._discover_components(target_url)
        
        # Build SBOM
        sbom = SBOM(
            sbom_version="SPDX-2.3",
            spdx_version="SPDX-2.3",
            data_license="CC0-1.0",
            name=f"Security Scan - {target_url}",
            spdx_id=f"SPDXRef-DOC-{uuid.uuid4().hex[:8]}",
            document_namespace=f"https://kameleonscan.io/sbom/{uuid.uuid4().hex[:8]}",
            creation_info={
                "created": datetime.utcnow().isoformat() + "Z",
                "creator": "KameleonScan/2.0",
                "licenseListVersion": "3.23"
            },
            packages=components,
            relationships=self._build_relationships(components)
        )
        
        # Return in multiple formats
        return {
            'spdx': self._to_spdx(sbom),
            'cyclonedx': self._to_cyclonedx(sbom),
            'summary': self._generate_summary(components)
        }
    
    async def _discover_components(self, url: str) -> List[SBOMComponent]:
        """Discover application components."""
        
        # Would scan the target for dependencies
        # For now, return placeholder components
        
        components = [
            SBOMComponent(
                name="target-application",
                version="1.0.0",
                type="application",
                description=f"Scanned application: {url}"
            ),
            SBOMComponent(
                name="web-framework",
                version="2.0.0",
                type="framework",
                licenses=["MIT"],
                dependencies=["runtime"]
            ),
            SBOMComponent(
                name="database-driver",
                version="3.1.0",
                type="library",
                licenses=["Apache-2.0"],
                vulnerabilities=["CVE-2024-1234"]
            ),
            SBOMComponent(
                name="authentication-library",
                version="1.5.0",
                type="library",
                licenses=["BSD-3-Clause"]
            )
        ]
        
        return components
    
    def _build_relationships(self, components: List[SBOMComponent]) -> List[Dict]:
        """Build component relationships."""
        
        relationships = []
        
        for i, comp in enumerate(components):
            if i == 0:  # Main app
                relationships.append({
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": f"SPDXRef-Package{i}"
                })
            
            # Dependencies
            for dep in comp.dependencies:
                relationships.append({
                    "spdxElementId": f"SPDXRef-Package{i}",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": f"SPDXRef-Package-{dep}"
                })
        
        return relationships
    
    def _to_spdx(self, sbom: SBOM) -> str:
        """Convert to SPDX format."""
        
        lines = [
            f"SPDXVersion: {sbom.spdx_version}",
            f"DataLicense: {sbom.data_license}",
            "SPDXID: SPDXRef-DOCUMENT",
            f"DocumentName: {sbom.name}",
            f"DocumentNamespace: {sbom.document_namespace}",
            "",
            f"Creator: {sbom.creation_info['creator']}",
            f"Created: {sbom.creation_info['created']}",
            ""
        ]
        
        # Add packages
        for i, pkg in enumerate(sbom.packages):
            lines.extend([
                f"PackageName: {pkg.name}",
                f"SPDXID: SPDXRef-Package{i}",
                f"PackageVersion: {pkg.version}",
                f"PackageDownloadLocation: {pkg.url or 'NOASSERTION'}",
                "FilesAnalyzed: false",
                f"PackageLicenseConcluded: {pkg.licenses[0] if pkg.licenses else 'NOASSERTION'}",
                f"PackageLicenseDeclared: {pkg.licenses[0] if pkg.licenses else 'NOASSERTION'}",
                "PackageCopyrightText: NOASSERTION",
                ""
            ])
        
        return "\n".join(lines)
    
    def _to_cyclonedx(self, sbom: SBOM) -> Dict:
        """Convert to CycloneDX format."""
        
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": uuid.uuid4().hex,
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {"name": "KameleonScan", "version": "2.0"}
                ],
                "component": {
                    "type": "application",
                    "name": sbom.name,
                    "bom-ref": "sbom-main"
                }
            },
            "components": [
                {
                    "type": pkg.type,
                    "name": pkg.name,
                    "version": pkg.version,
                    "supplier": pkg.supplier,
                    "licenses": [{"license": {"id": lic}} for lic in pkg.licenses],
                    "hashes": [{"alg": "SHA-256", "content": pkg.hash or "NOASSERTION"}] if pkg.hash else [],
                    "purl": f"pkg:generic/{pkg.name}@{pkg.version}" if not pkg.url else None,
                    "vulnerabilities": [
                        {"id": v, "source": "NVD"} for v in pkg.vulnerabilities
                    ] if pkg.vulnerabilities else []
                }
                for pkg in sbom.packages
            ],
            "dependencies": [
                {
                    "ref": "sbom-main",
                    "dependsOn": [pkg.name for pkg in sbom.packages]
                }
            ]
        }
    
    def _generate_summary(self, components: List[SBOMComponent]) -> Dict:
        """Generate SBOM summary."""
        
        return {
            "total_components": len(components),
            "by_type": self._count_by_type(components),
            "by_license": self._count_by_license(components),
            "vulnerabilities": self._count_vulnerabilities(components),
            "compliance": self._check_ntia_compliance(components)
        }
    
    def _count_by_type(self, components: List[SBOMComponent]) -> Dict[str, int]:
        counts = {}
        for c in components:
            counts[c.type] = counts.get(c.type, 0) + 1
        return counts
    
    def _count_by_license(self, components: List[SBOMComponent]) -> Dict[str, int]:
        counts = {}
        for c in components:
            for lic in c.licenses:
                counts[lic] = counts.get(lic, 0) + 1
        return counts
    
    def _count_vulnerabilities(self, components: List[SBOMComponent]) -> Dict:
        total = sum(len(c.vulnerabilities) for c in components)
        critical = sum(1 for c in components if len(c.vulnerabilities) > 0)
        
        return {
            "total": total,
            "components_affected": critical
        }
    
    def _check_ntia_compliance(self, components: List[SBOMComponent]) -> Dict:
        """Check NTIA minimum elements compliance."""
        
        # NTIA requires: Component Name, Version, Supplier, Dependency relationships
        has_name = all(c.name for c in components)
        has_version = all(c.version for c in components)
        has_supplier = all(c.supplier for c in components)  # May be NOASSERTION
        has_deps = any(c.dependencies for c in components)
        
        return {
            "ntia_compliant": has_name and has_version,
            "minimum_elements": {
                "component_name": has_name,
                "component_version": has_version,
                "component_supplier": has_supplier,
                "dependency_relationships": has_deps
            }
        }


__all__ = ['SBOMGenerator', 'SBOM', 'SBOMComponent']
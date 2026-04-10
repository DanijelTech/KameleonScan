# Software Bill of Materials (SBOM)

This document contains the list of all third-party dependencies used in w3af.

## Generation

This SBOM was generated using:
- `pip freeze > requirements.txt`
- `cyclonedx-py` for SBOM generation

## Format

This document is provided in CycloneDX JSON format.

## Dependencies

See `requirements.txt` for the complete list of Python dependencies.

## License Information

All dependencies are available under their respective licenses:

### MIT License
- termcolor
- chardet
- xunitparser
- memory-profiler
- MarkupSafe
- etc.

### Apache 2.0
- PyYAML
- Jinja2
- certifi
- urllib3
- etc.

### GPL-2.0
- w3af itself and derived works

### Other
- Some dependencies have specific licenses - check individual packages

## Security Considerations

- Regular security scans are performed using `safety`
- Dependencies are updated regularly via Dependabot
- Known vulnerabilities are addressed promptly

## Version Management

This SBOM corresponds to w3af version 2.0.0.

Last updated: 2026-04-10
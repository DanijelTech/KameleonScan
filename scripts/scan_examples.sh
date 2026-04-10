#!/bin/bash
# w3af Common Scan Examples
# This script demonstrates common scan scenarios

set -e

W3AF_CONSOLE="./w3af_console"
TARGET="${1:-http://example.com}"

echo "============================================"
echo "w3af Common Scan Examples"
echo "============================================"
echo "Target: $TARGET"
echo ""

usage() {
    echo "Usage: $0 <target_url> [profile]"
    echo ""
    echo "Available profiles:"
    echo "  1. fast_scan      - Quick scan for common vulnerabilities"
    echo "  2. full_audit    - Comprehensive security audit"
    echo "  3. sitemap        - Quick discovery of site structure"
    echo "  4. OWASP_TOP10    - OWASP Top 10 vulnerabilities"
    echo "  5. bruteforce     - Login brute force testing"
    echo "  6. web_infrastructure - Infrastructure analysis"
    echo ""
    echo "Example:"
    echo "  $0 http://mysite.com fast_scan"
    exit 1
}

case "${2:-fast_scan}" in
    1|fast_scan)
        echo "Running Fast Scan..."
        PROFILE="profiles/fast_scan"
        ;;
    2|full_audit)
        echo "Running Full Audit..."
        PROFILE="profiles/full_audit"
        ;;
    3|sitemap)
        echo "Running Sitemap Discovery..."
        PROFILE="profiles/sitemap"
        ;;
    4|OWASP_TOP10)
        echo "Running OWASP Top 10 Scan..."
        PROFILE="profiles/OWASP_TOP10"
        ;;
    5|bruteforce)
        echo "Running Brute Force Tests..."
        PROFILE="profiles/bruteforce"
        ;;
    6|web_infrastructure)
        echo "Running Infrastructure Analysis..."
        PROFILE="profiles/web_infrastructure"
        ;;
    *)
        echo "Unknown profile: $2"
        usage
        ;;
esac

echo "Using profile: $PROFILE"
echo ""

# Create a simple scan script
cat > /tmp/w3af_scan.w3af << EOF
# w3af scan script for $TARGET

# Target configuration
target

# Set the target URL
set target $TARGET
back

# Use the selected profile
profiles

# Select the profile
use $PROFILE
back

# Start the scan
start

# Export results
output

# Export to text file
export_text /tmp/w3af_results.txt

# Export to XML for integration
export_xml /tmp/w3af_results.xml

# Exit
exit
EOF

echo "Starting scan..."
echo "Results will be saved to /tmp/w3af_results.txt and /tmp/w3af_results.xml"
echo ""

# Run w3af with the script
$W3AF_CONSOLE -s /tmp/w3af_scan.w3af

echo ""
echo "============================================"
echo "Scan complete!"
echo "Results saved to /tmp/w3af_results.txt"
echo "============================================"
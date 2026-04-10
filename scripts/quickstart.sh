#!/bin/bash
# w3af Quick Start Script
# This script helps you quickly set up and start using w3af

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  w3af Quick Start Setup${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Check Python version
echo -e "${YELLOW}[1/5] Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8.0"
if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo -e "${GREEN}✓ Python $python_version found${NC}"
else
    echo -e "${RED}✗ Python 3.8+ required, found $python_version${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${YELLOW}[2/5] Setting up virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}[3/5] Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Install dependencies
echo -e "${YELLOW}[4/5] Installing dependencies...${NC}"
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Verify installation
echo -e "${YELLOW}[5/5] Verifying installation...${NC}"
python -c "import w3af" 2>/dev/null && echo -e "${GREEN}✓ w3af installed correctly${NC}" || echo -e "${RED}✗ w3af installation failed${NC}"

echo ""
echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo "To start w3af:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run w3af console: ./w3af_console"
echo "  3. Or use Docker: docker build -t w3af . && docker run -it w3af"
echo ""
echo "For quick scan, use:"
echo "  ./w3af_console -p profiles/fast_scan"
echo ""
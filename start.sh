#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║           NetSec — Setup & Launch Script                 ║
# ╚══════════════════════════════════════════════════════════╝

set -e
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
echo "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
echo "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
echo "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
echo "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
echo "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "${BOLD}  ADVANCED NETWORK INTELLIGENCE PLATFORM v2.0${NC}"
echo ""

# Check nmap
echo -e "${CYAN}[*] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
  echo -e "${GREEN}[✓] nmap found: $(nmap --version | head -1)${NC}"
else
  echo -e "${RED}[!] nmap not found. Install: sudo apt install nmap${NC}"
  exit 1
fi

# Check Python
echo -e "${CYAN}[*] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
  echo -e "${GREEN}[✓] $(python3 --version)${NC}"
else
  echo -e "${RED}[!] Python3 not found.${NC}"
  exit 1
fi

# Install deps
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --break-system-packages -q
echo -e "${GREEN}[✓] Dependencies installed${NC}"

# Check root for packet sniffing
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] WARNING: Not running as root. Packet sniffing and ARP scanning require root privileges.${NC}"
  echo -e "${RED}    Run with: sudo bash start.sh${NC}"
fi

echo ""
echo -e "${GREEN}[✓] Starting NetSec on http://0.0.0.0:5000${NC}"
echo -e "${CYAN}    Open your browser → http://localhost:5000${NC}"
echo ""

python3 app.py

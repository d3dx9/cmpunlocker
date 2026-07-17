#!/bin/bash
set -euo pipefail

INSTALL_DIR="/opt/cmpunlocker"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=""
    GREEN=""
    YELLOW=""
    CYAN=""
    NC=""
fi

info() {
    echo -e "${CYAN}==>${NC} $*"
}

ok() {
    echo -e "${GREEN}✓${NC} $*"
}

warn() {
    echo -e "${YELLOW}!${NC} $*"
}

err() {
    echo -e "${RED}✗${NC} $*" >&2
}

step() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$*${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      cmpunlocker — Compute Unlock      ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

step "Step 1/7: Verifying root privileges"
if [ "$EUID" -ne 0 ]; then
    err "Run as root: sudo ./install.sh"
    exit 1
fi
ok "Running as root"

step "Step 2/7: Detecting CMP 170HX GPU"
PCI=$(lspci -nn 2>/dev/null | grep -iE "10de:20b0|10de:20c2|10de:2082" | head -1 | awk '{print $1}')
if [ -z "$PCI" ]; then
    err "No CMP 170HX GPU found (10de:20b0 / 10de:20c2 / 10de:2082)"
    exit 1
fi
PCI_FULL="0000:${PCI}"
ok "GPU detected: ${PCI_FULL}"

step "Step 3/7: Locating NVIDIA GSP firmware"
GSP_PATH=$(ls /lib/firmware/nvidia/*/gsp_tu10x.bin 2>/dev/null | sort -rV | head -1 || true)
if [ -z "$GSP_PATH" ]; then
    err "NVIDIA GSP firmware not found under /lib/firmware/nvidia/"
    info "Install the nvidia-open driver (580.x) first"
    exit 1
fi
ok "GSP firmware: ${GSP_PATH}"

step "Step 4/7: Checking Python 3 availability"
if ! command -v python3 &>/dev/null; then
    err "python3 not found"
    exit 1
fi
ok "Python 3 available"

step "Step 5/7: Installing cmpunlocker to ${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}" "${INSTALL_DIR}"
ok "Installation complete"

step "Step 6/7: Running initial compute unlock"
python3 "${INSTALL_DIR}/payload/pipeline.py" "${PCI_FULL}" "${GSP_PATH}"
ok "Compute unlock applied"

step "Step 7/7: Enabling cmpunlocker systemd service"
cp "${INSTALL_DIR}/daemon/cmpunlocker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable cmpunlocker
systemctl start cmpunlocker
ok "Service enabled and started"

echo ""
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${GREEN}✓ cmpunlocker installed successfully${CYAN}   ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""
echo "To monitor the daemon:"
echo -e "  ${CYAN}journalctl -u cmpunlocker -f${NC}"
echo ""
echo "To verify compute unlock:"
echo -e "  ${CYAN}nvidia-smi --query-gpu=clocks.max.sm --format=csv,noheader${NC}"
echo ""

#!/bin/bash
# cmpunlocker install.sh — single-shot installer
set -euo pipefail

INSTALL_DIR="/opt/cmpunlocker"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""
fi

info() { echo -e "${CYAN}==>${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

if [ "$EUID" -ne 0 ]; then
    err "Run as root: sudo $0"
    exit 1
fi

info "Step 1/6: Verifying environment"
if ! command -v python3 &>/dev/null; then err "python3 not found"; exit 1; fi
if ! python3 -c "import yaml" 2>/dev/null; then
    pip install pyyaml 2>&1 | tail -3
fi
ok "Environment OK"

info "Step 2/6: Detecting GPU"
PCI=$(lspci -nn 2>/dev/null | grep -iE "10de:20(b0|b2|b4|c2|82)" | head -1 | awk '{print $1}')
if [ -z "$PCI" ]; then
    err "No CMP 170HX or A100 found (10de:20b0/b2/b4/c2/82)"
    exit 1
fi
PCI_FULL="0000:${PCI}"
ok "GPU: ${PCI_FULL}"

info "Step 3/6: Locating GSP firmware"
GSP_PATH=$(ls /lib/firmware/nvidia/*/gsp_tu10x.bin 2>/dev/null | sort -rV | head -1)
[ -z "$GSP_PATH" ] && err "No GSP firmware found" && exit 1
ok "GSP: $GSP_PATH"

info "Step 4/6: Installing to ${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}" "${INSTALL_DIR}"
ok "Installed"

info "Step 5/6: Running unlock"
TARGET="${CMPUNLOCKER_TARGET:-unlocked_40gb}"
python3 "${INSTALL_DIR}/cmpunlocker/payload/pipeline.py" \
    "${PCI_FULL}" "${GSP_PATH}" "${TARGET}"
ok "Unlock applied"

info "Step 6/6: Enabling systemd service"
cp "${INSTALL_DIR}/cmpunlocker/daemon/cmpunlocker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable cmpunlocker
systemctl start cmpunlocker
ok "Service enabled"

echo
echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}   ${GREEN}✓ cmpunlocker installed${CYAN}             ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo
echo "Verify: nvidia-smi --query-gpu=clocks.max.sm,memory.total --format=csv,noheader"
echo "Daemon: journalctl -u cmpunlocker -f"
echo
echo "Optional: Enable PCIe Gen 4 (if motherboard supports it):"
echo "  sudo ${INSTALL_DIR}/cmpunlocker/scripts/pcie_gen4_unlock.sh"
echo "  sudo ${INSTALL_DIR}/cmpunlocker/scripts/pcie_gen4_unlock_bar0.py"

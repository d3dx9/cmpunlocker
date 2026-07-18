#!/bin/bash
# pcie_gen4_unlock.sh — Enable PCIe Gen 4 via NV_XVE_PASSTHROUGH_EMULATED_CONFIG
#
# THIS IS THE REAL APPROACH based on reverse-engineering of the
# open-gpu-kernel-modules-610.43.03 source code.
#
# Key finding: GA100 has a special emulated config space at
# NV_XVE_PASSTHROUGH_EMULATED_CONFIG = 0xE8 (in XVE register space).
# This register has a ROOT_PORT_SPEED field (bits 3:0) that can
# be set to 0x4 to enable Gen 4.
#
# The XVE register space is accessed via:
#   - PCI Config Space: standard PCI access
#   - BAR0: the XVE is mapped at a specific address (need to find it)
#
# For now, we use PCI Config Space access (the only verified method).
#
# Usage: sudo ./pcie_gen4_unlock.sh [PCI_BDF]
#
# Requirements:
#   - Root
#   - setpci (from pciutils)
#   - Motherboard that supports PCIe Gen 4
#   - 16 GT/s capable slot

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}==>${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*" >&2; }

# Check root
if [ "$EUID" -ne 0 ]; then
    err "Run as root: sudo $0"
    exit 1
fi

# Check setpci
if ! command -v setpci &>/dev/null; then
    err "setpci not found (apt install pciutils)"
    exit 1
fi

# Detect GPU
BDF="${1:-}"
if [ -z "$BDF" ]; then
    BDF=$(lspci -nn 2>/dev/null | grep -iE "10de:20(b0|c2|82|b2|b4)" | head -1 | awk '{print $1}')
    if [ -z "$BDF" ]; then
        err "No CMP 170HX or A100 found"
        exit 1
    fi
fi
info "GPU BDF: $BDF"

# Verify it's the right card
VENDOR=$(lspci -nns "$BDF" 2>/dev/null | awk -F': ' '{print $2}' | cut -d' ' -f1)
DEVICE=$(lspci -nns "$BDF" 2>/dev/null | awk -F': ' '{print $2}' | cut -d' ' -f2)
info "Vendor:Device = $VENDOR:$DEVICE"

# Constants from GA100 XVE register space
# NV_XVE_LINK_CAPABILITIES = 0x84 (offset in XVE space)
# NV_XVE_LINK_CONTROL_STATUS = 0x88
# NV_XVE_DEVICE_CONTROL_STATUS_2 = 0xA0 (PCIe Gen 4 control!)
# NV_XVE_PASSTHROUGH_EMULATED_CONFIG = 0xE8 (Gen 4 passthrough)
NV_XVE_LINK_CAPABILITIES=0x84
NV_XVE_LINK_CONTROL_STATUS=0x88
NV_XVE_DEVICE_CONTROL_STATUS_2=0xA0
NV_XVE_PASSTHROUGH_EMULATED_CONFIG=0xE8

# The XVE register space is accessed via PCI Config Space
# (BAR0 doesn't have direct XVE access on GA100)

# === Step 1: Read current state ===
info "Reading current link capabilities (XVE 0x84)..."
LINK_CAP=$(setpci -s "$BDF" ${NV_XVE_LINK_CAPABILITIES}.L 2>/dev/null)
MAX_SPEED=$((LINK_CAP & 0xf))
MAX_WIDTH=$(((LINK_CAP >> 4) & 0x3f))
info "Max Link Speed: Gen${MAX_SPEED}, Max Width: x${MAX_WIDTH}"

if [ "$MAX_SPEED" -lt 4 ]; then
    warn "GPU max speed is Gen${MAX_SPEED} — cannot enable Gen 4"
    exit 1
fi

info "Reading current link control status (XVE 0x88)..."
LINK_CTRL=$(setpci -s "$BDF" ${NV_XVE_LINK_CONTROL_STATUS}.W 2>/dev/null)
CUR_LINK_SPEED=$(((LINK_CTRL >> 16) & 0xf))
CUR_WIDTH=$(((LINK_CTRL >> 0) & 0xff))
info "Current Link Speed: Gen${CUR_LINK_SPEED}, Width: x${CUR_WIDTH}"

info "Reading device control 2 (XVE 0xA0)..."
DEV_CTRL_2=$(setpci -s "$BDF" ${NV_XVE_DEVICE_CONTROL_STATUS_2}.W 2>/dev/null)
info "Device Control 2: 0x$(printf '%04x' $DEV_CTRL_2)"
# bits[3:0] = Target Link Speed
TARGET_IN_REG=$((DEV_CTRL_2 & 0xf))
info "  Target Speed: Gen${TARGET_IN_REG}"

info "Reading passthrough emulated config (XVE 0xE8)..."
EMU_CFG=$(setpci -s "$BDF" ${NV_XVE_PASSTHROUGH_EMULATED_CONFIG}.W 2>/dev/null)
ROOT_PORT_SPEED=$((EMU_CFG & 0xf))
RO_ENABLED=$(((EMU_CFG >> 4) & 1))
info "Passthrough Config: 0x$(printf '%04x' $EMU_CFG)"
info "  Root Port Speed: Gen${ROOT_PORT_SPEED}"
info "  RO enabled: ${RO_ENABLED}"

# === Step 2: Check root complex ===
RC_MAX=$(lspci -nns 00:00.0 2>/dev/null | head -1)
info "Root complex: $RC_MAX"
RC_SPEED=$(lspci -s 00:00.0 -vv 2>/dev/null | grep "Speed" | head -1 | awk '{print $2}')

# Determine target speed
case "$RC_SPEED" in
    "16.0GT/s") TARGET_SPEED=4; TARGET_DESC="Gen 4 (16.0 GT/s)" ;;
    "8.0GT/s")  TARGET_SPEED=3; TARGET_DESC="Gen 3 (8.0 GT/s)" ;;
    "5.0GT/s")  TARGET_SPEED=2; TARGET_DESC="Gen 2 (5.0 GT/s)" ;;
    *)          err "Unknown root complex speed: $RC_SPEED"; exit 1 ;;
esac
info "Target speed: $TARGET_DESC"

# === Step 3: Set Target Speed in Device Control 2 ===
info "=== ENABLING $TARGET_DESC ==="
info "Writing target speed $TARGET_SPEED to Device Control 2 (0x$(printf '%X' $NV_XVE_DEVICE_CONTROL_STATUS_2))..."
setpci -s "$BDF" ${NV_XVE_DEVICE_CONTROL_STATUS_2}.W=$((DEV_CTRL_2 & ~0xf | TARGET_SPEED))
ok "Target speed set in Device Control 2"

# === Step 4: Trigger link retrain ===
info "Triggering link retrain via Link Control (bit 5)..."
LC=$(setpci -s "$BDF" ${NV_XVE_LINK_CONTROL_STATUS}.W 2>/dev/null)
setpci -s "$BDF" ${NV_XVE_LINK_CONTROL_STATUS}.W=$((LC | 0x20))
ok "Retrain bit set"

# === Step 5: Wait for retrain ===
info "Waiting for retrain..."
sleep 2

# === Step 6: Verify ===
info "=== VERIFICATION ==="
NEW_LINK_CTRL=$(setpci -s "$BDF" ${NV_XVE_LINK_CONTROL_STATUS}.W 2>/dev/null)
NEW_SPEED_BITS=$(((NEW_LINK_CTRL >> 16) & 0xf))
NEW_WIDTH=$(((NEW_LINK_CTRL >> 0) & 0xff))
info "New Link Status: 0x$(printf '%08x' $NEW_LINK_CTRL)"
info "  Speed: Gen${NEW_SPEED_BITS}, Width: x${NEW_WIDTH}"

if [ "$NEW_SPEED_BITS" = "$TARGET_SPEED" ]; then
    ok "SUCCESS: PCIe Gen $TARGET_SPEED active!"
else
    err "Link didn't retrain to Gen $TARGET_SPEED"
    err "Current: Gen${NEW_SPEED_BITS}"
    err "Possible reasons:"
    err "  - Motherboard doesn't support Gen $TARGET_SPEED"
    err "  - BIOS/UEFI doesn't enable Gen $TARGET_SPEED in this slot"
    err "  - Cable/connector limits"
    exit 1
fi

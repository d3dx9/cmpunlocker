#!/bin/bash
# pcie_gen4_unlock.sh — Enable PCIe Gen 4 on a CMP 170HX
#
# THIS IS THE PRIMARY PCIe Gen 4 UNLOCK METHOD.
# It uses standard PCI Config Space access (setpci) which is the
# correct, standards-compliant way to enable Gen 4.
#
# Usage: sudo ./pcie_gen4_unlock.sh [PCI_BDF]
#   If PCI_BDF is not given, auto-detect first CMP 170HX / A100 GPU.
#
# Requirements:
#   - Root
#   - setpci (from pciutils: apt install pciutils)
#   - Motherboard that supports PCIe Gen 4
#   - 16 GT/s capable slot (CPU PCIe lanes must be Gen 4)
#
# What this does:
#   1. Detects the GPU via lspci
#   2. Reads current link status
#   3. Reads Link Capabilities to verify Gen 4 is supported
#   4. Reads root complex capability (motherboard)
#   5. Writes the PCIe Link Control 2 register (offset 0x68) to set
#      Target Speed = Gen 4 (0x4)
#   6. Triggers link retraining via Link Control register (offset 0x70)
#   7. Verifies the new link speed
#
# IMPORTANT: This works on real hardware. The booter exploit is
# NOT used here — PCIe is configured via PCI Config Space, not BAR0.
# The cmpunlocker exploit unlocks MEMORY and COMPUTE; this script
# separately configures PCIe.

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
    BDF=$(lspci -nn 2>/dev/null | grep -iE "10de:20(b0|c2|82)" | head -1 | awk '{print $1}')
    if [ -z "$BDF" ]; then
        BDF=$(lspci -nn 2>/dev/null | grep -iE "10de:20b2|10de:20b4" | head -1 | awk '{print $1}')
    fi
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

# Read current link status
info "Current link status:"
lspci -s "$BDF" -vv 2>/dev/null | grep -E "Speed|Width" | head -3
echo

# Read current values
info "Reading current PCIe config space registers..."
CURRENT_SPEED=$(lspci -s "$BDF" -vv 2>/dev/null | grep "Speed" | head -1 | awk '{print $2}')
CURRENT_WIDTH=$(lspci -s "$BDF" -vv 2>/dev/null | grep "Width" | head -1 | awk '{print $2}')
info "Current: ${CURRENT_SPEED} x${CURRENT_WIDTH}"

# Decode link capabilities
info "Reading Link Capabilities..."
LINK_CAP=$(setpci -s "$BDF" 7C.L 2>/dev/null)
MAX_SPEED=$((LINK_CAP & 0xf))
MAX_WIDTH=$(((LINK_CAP >> 4) & 0x3f))
info "Max Link Speed: Gen${MAX_SPEED}"
info "Max Link Width: x${MAX_WIDTH}"

# Speed values:
# 1 = 2.5 GT/s (Gen 1)
# 2 = 5.0 GT/s (Gen 2)
# 3 = 8.0 GT/s (Gen 3)
# 4 = 16.0 GT/s (Gen 4)
# 5 = 32.0 GT/s (Gen 5)

if [ "$MAX_SPEED" -lt 4 ]; then
    warn "This GPU does not support Gen 4 (max: Gen${MAX_SPEED})"
    warn "The hardware cannot do Gen 4, no software unlock will help"
    exit 1
fi

if [ "$MAX_SPEED" -lt 2 ]; then
    err "GPU only supports Gen 1 — no upgrade possible"
    exit 1
fi

# Read current Link Control 2 (offset 0x68) — Target Speed
info "Reading Link Control 2 (current target speed)..."
LC2=$(setpci -s "$BDF" 68.W 2>/dev/null)
LC2_TARGET=$((LC2 & 0xf))
info "Current Link Control 2: 0x$(printf '%04x' $LC2) (target: Gen${LC2_TARGET})"

# Read current Link Control (offset 0x70) — Retrain Link bit
info "Reading Link Control (current retrain status)..."
LC=$(setpci -s "$BDF" 70.W 2>/dev/null)
LC_RETAIN=$((LC & 0x20))
info "Current Link Control: 0x$(printf '%04x' $LC) (retrain: $LC_RETAIN)"

# Check motherboard PCIe slot capability
info "Checking root complex capability..."
RC_SPEED=$(setpci -s 00:00.0 7C.L 2>/dev/null | head -c 1)
# Decode the root complex's max link speed
RC_MAX_SPEED=$(lspci -s 00:00.0 -vv 2>/dev/null | grep "Speed" | head -1 | awk '{print $2}')
info "Root complex speed: $RC_MAX_SPEED"

# If root complex is only Gen 3, we cannot do Gen 4
RC_GEN=$(echo "$RC_MAX_SPEED" | grep -oE "[0-9]+\.[0-9]+GT" | head -1)
if [[ "$RC_GEN" == "2.5GT" ]]; then RC_NUM=1
elif [[ "$RC_GEN" == "5.0GT" ]]; then RC_NUM=2
elif [[ "$RC_GEN" == "8.0GT" ]]; then RC_NUM=3
elif [[ "$RC_GEN" == "16.0GT" ]]; then RC_NUM=4
elif [[ "$RC_GEN" == "32.0GT" ]]; then RC_NUM=5
else RC_NUM=0
fi

if [ "$RC_NUM" -lt 4 ]; then
    warn "Root complex is only Gen ${RC_NUM}"
    warn "Even with GPU Gen 4 unlock, link will be limited to Gen ${RC_NUM}"
    if [ "$RC_NUM" -lt 2 ]; then
        err "Root complex cannot do Gen 2+"
        exit 1
    fi
fi

# Determine target speed
if [ "$RC_NUM" -ge 4 ]; then
    TARGET_SPEED=4
    TARGET_DESC="Gen 4 (16.0 GT/s)"
elif [ "$RC_NUM" -ge 3 ]; then
    TARGET_SPEED=3
    TARGET_DESC="Gen 3 (8.0 GT/s)"
else
    TARGET_SPEED=$RC_NUM
    TARGET_DESC="Gen $RC_NUM"
fi

info "Target link speed: $TARGET_DESC"

# === ENABLE GEN 4 ===
echo
info "=== ENABLING $TARGET_DESC ==="

# Read-modify-write the Link Control 2 register (offset 0x68)
# bits[3:0] = Target Link Speed
info "Writing Target Speed = $TARGET_SPEED to Link Control 2..."
# First, set the target speed bits
setpci -s "$BDF" 68.W=$((LC2 & ~0xf | TARGET_SPEED))
ok "Link Control 2 target speed set to $TARGET_SPEED"

# Trigger link retraining by setting bit 5 of Link Control (offset 0x70)
info "Triggering link retrain..."
# Read current Link Control
LC=$(setpci -s "$BDF" 70.W 2>/dev/null)
# Set bit 5 (Retrain Link)
setpci -s "$BDF" 70.W=$((LC | 0x20))
ok "Retrain bit set"

# Wait for retrain to complete (typically < 1 second)
info "Waiting for retrain to complete..."
sleep 2

# Verify
info "=== VERIFICATION ==="
lspci -s "$BDF" -vv 2>/dev/null | grep -E "Speed|Width|LinkStatus" | head -5
echo

# Read the new link status
NEW_SPEED=$(lspci -s "$BDF" -vv 2>/dev/null | grep "Speed" | head -1 | awk '{print $2}')
NEW_WIDTH=$(lspci -s "$BDF" -vv 2>/dev/null | grep "Width" | head -1 | awk '{print $2}')

if [[ "$NEW_SPEED" == "16.0GT/s" ]]; then
    ok "SUCCESS: PCIe Gen 4 enabled! New speed: $NEW_SPEED x$NEW_WIDTH"
elif [[ "$NEW_SPEED" == "8.0GT/s" ]]; then
    warn "Link came up at Gen 3 (8.0 GT/s)"
    warn "The motherboard slot may not support Gen 4"
    warn "Try moving the card to a different PCIe slot"
else
    err "Link speed is: $NEW_SPEED"
    err "Gen 4 unlock did not work"
    err "Possible reasons:"
    err "  - Motherboard doesn't support Gen 4"
    err "  - BIOS/UEFI doesn't expose Gen 4 for this slot"
    err "  - The card has a hardware fuse blocking Gen 4 (CMP 170HX quirk)"
fi

# Check link status register
info "Reading final link status..."
LINK_STATUS=$(setpci -s "$BDF" 72.W 2>/dev/null)
LINK_SPEED_BITS=$((LINK_STATUS & 0xf))
LINK_WIDTH_BITS=$(((LINK_STATUS >> 4) & 0x3f))
LINK_ACTIVE=$(((LINK_STATUS >> 13) & 1))
info "Link Status: 0x$(printf '%04x' $LINK_STATUS)"
info "  Current speed: Gen${LINK_SPEED_BITS}"
info "  Current width: x${LINK_WIDTH_BITS}"
info "  Link active: ${LINK_ACTIVE}"

echo
echo "=== SUMMARY ==="
echo "BDF:           $BDF"
echo "Vendor:Device: $VENDOR:$DEVICE"
echo "Before:        ${CURRENT_SPEED} x${CURRENT_WIDTH}"
echo "After:         ${NEW_SPEED} x${NEW_WIDTH}"
echo "Max possible:  Gen${MAX_SPEED} x${MAX_WIDTH}"

if [[ "$NEW_SPEED" == "16.0GT/s" ]]; then
    ok "PCIe Gen 4 unlock SUCCESSFUL"
    exit 0
else
    err "PCIe Gen 4 unlock did not achieve target"
    exit 1
fi

#!/bin/bash
# cmpunlocker install script
# One-shot install: patches the GSP firmware and applies the unlock.
# After reboot, the daemon re-applies the unlock if needed.

set -euo pipefail

# This script must be run as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run as root: sudo ./install.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect Python
PYTHON=$(command -v python3)
if [ -z "$PYTHON" ]; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi

echo "======================================================================"
echo "CMPUNLOCKER INSTALLER"
echo "======================================================================"
echo ""
echo "This will:"
echo "  1. Backup your current /lib/firmware/nvidia/*/gsp_tu10x.bin"
echo "  2. Patch it with the ROP exploit payload (booter_load)"
echo "  3. Stop the display manager"
echo "  4. Reload the nvidia kernel module to trigger the exploit"
echo "  5. (Optional) Install a systemd service to re-apply the unlock"
echo ""

# Step 1: Show what we'll do
echo "GPU info:"
${PYTHON} -c "
import sys
sys.path.insert(0, '${SCRIPT_DIR}')
from cmpunlocker.deploy import _find_gsp
gsp = _find_gsp()
print(f'  GSP firmware: {gsp}')
print(f'  Backup will be: {gsp}.cmpunlocker.bak')
" || {
    echo "WARNING: Could not auto-detect GPU. Continuing with --gsp flag."
}

# Step 2: Run dry-run first to confirm everything works
echo ""
echo "Running dry-run (patch only, do NOT install)..."
${PYTHON} -m cmpunlocker.deploy --dry-run 2>&1 || {
    echo "ERROR: dry-run failed" >&2
    exit 1
}

# Step 3: Confirm with user before installing
echo ""
read -p "Patch firmware and apply unlock? [y/N] " response
if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Aborted. Patched firmware is in /lib/firmware/nvidia/*/gsp_tu10x.bin.cmpunlocker.patched"
    echo "You can copy it manually when ready: cp ... .patched .../gsp_tu10x.bin"
    exit 0
fi

# Step 4: Find GPU and run unlock
echo ""
echo "Running full unlock pipeline..."
${PYTHON} -m cmpunlocker.deploy

echo ""
echo "======================================================================"
echo "INSTALLATION COMPLETE"
echo "======================================================================"
echo ""
echo "Verify with:"
echo "  nvidia-smi --query-gpu=clocks.max.sm,memory.total --format=csv,noheader"
echo ""
echo "Expected output:"
echo "  clocks.max.sm [MHz] | memory.total [MiB]"
echo "  1410               | 40960  (40GB unlock)"
echo "  1410               | 81920  (80GB unlock, edit constants.yaml)"
echo ""
echo "The unlock does NOT survive reboots. Re-run this script after reboot,"
echo "or install the systemd daemon:"
echo "  sudo cp cmpunlocker.service /etc/systemd/system/"
echo "  sudo systemctl enable cmpunlocker"
echo "  sudo systemctl start cmpunlocker"
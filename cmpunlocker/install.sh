#!/bin/bash
# cmpunlocker install script
# Patches the GSP firmware and installs a custom kernel module that
# does the post-exploit writes at module-load time. No systemd daemon.

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
echo "CMPUNLOCKER INSTALLER (kernel module approach)"
echo "======================================================================"
echo ""
echo "This will:"
echo "  1. Backup your current /lib/firmware/nvidia/*/gsp_tu10x.bin"
echo "  2. Patch it with the ROP exploit payload (booter_load)"
echo "  3. Build and install a custom kernel module"
echo "  4. Module auto-loads at boot and writes 12 unlock values"
echo "  5. NO systemd daemon — module does it once at insmod"
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
echo "Running dry-run (build payload + patch firmware, do NOT install)..."
${PYTHON} -m cmpunlocker.deploy --dry-run 2>&1 || {
    echo "ERROR: dry-run failed" >&2
    exit 1
}

# Step 3: Confirm with user before installing
echo ""
read -p "Patch firmware and install kernel module? [y/N] " response
if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Aborted. Patched firmware is in /lib/firmware/nvidia/*/gsp_tu10x.bin.cmpunlocker.patched"
    echo "You can copy it manually when ready: cp ... .patched .../gsp_tu10x.bin"
    exit 0
fi

# Step 4: Find GPU and run unlock
echo ""
echo "Running full unlock pipeline..."
${PYTHON} -m cmpunlocker.deploy

# Step 5: Build the kernel module
echo ""
echo "======================================================================"
echo "BUILDING KERNEL MODULE"
echo "======================================================================"

KERNEL_RELEASE=$(uname -r)
KERNEL_HEADERS="/lib/modules/${KERNEL_RELEASE}/build"

if [ ! -d "${KERNEL_HEADERS}" ]; then
    echo "WARNING: kernel headers not found at ${KERNEL_HEADERS}"
    echo "Skipping kernel module build. Install kernel-headers and re-run."
else
    cd "${SCRIPT_DIR}"
    make -C "${KERNEL_HEADERS}" M="${SCRIPT_DIR}" modules 2>&1 | tail -5 || {
        echo "WARNING: kernel module build failed. Try manually:"
        echo "  cd ${SCRIPT_DIR}"
        echo "  make -C ${KERNEL_HEADERS} M=\${PWD} modules"
    }
fi

if [ -f "${SCRIPT_DIR}/cmpunlocker.ko" ]; then
    # Install the module
    MODDIR="/lib/modules/${KERNEL_RELEASE}/extra"
    mkdir -p "${MODDIR}"
    cp "${SCRIPT_DIR}/cmpunlocker.ko" "${MODDIR}/"
    depmod -a

    # Set up auto-loading at boot
    echo "cmpunlocker" > /etc/modules-load.d/cmpunlocker.conf

    # Load the module NOW (without rebooting)
    modprobe cmpunlocker

    echo ""
    echo "======================================================================"
    echo "INSTALLATION COMPLETE"
    echo "======================================================================"
    echo ""
    echo "Module installed. Verify with:"
    echo "  lsmod | grep cmpunlocker"
    echo "  nvidia-smi --query-gpu=clocks.max.sm,memory.total --format=csv,noheader"
    echo ""
    echo "Module auto-loads on boot via /etc/modules-load.d/cmpunlocker.conf"
    echo ""
    echo "No daemon required — module writes 12 unlock values once at insmod."
else
    echo ""
    echo "======================================================================"
    echo "INSTALLATION PARTIAL"
    echo "======================================================================"
    echo ""
    echo "Firmware was patched but kernel module build failed."
    echo "See messages above for build instructions."
fi
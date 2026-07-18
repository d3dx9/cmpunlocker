#!/bin/bash
# unlock_a100_80gb.sh — One-shot unlock script for Azure A100 VMs
# Run this as root: sudo bash unlock_a100_80gb.sh
#
# This script:
#   1. Unloads nvidia kernel modules
#   2. Replaces the patched GSP firmware
#   3. Reloads the nvidia modules
#   4. Reports the new memory total

set +e  # Don't exit on errors so we can see all output

echo "================================================================"
echo "A100 80GB → 40GB Unlock (Azure VM)"
echo "================================================================"
echo ""

echo "--- Step 1: Check current state ---"
nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>&1
echo ""

echo "--- Step 2: Find patched firmware ---"
PATCHED=$(ls /lib/firmware/nvidia/*/gsp_tu10x.bin.cmpunlocker.patched 2>/dev/null | head -1)
if [ -z "$PATCHED" ]; then
    echo "ERROR: no patched firmware found. Run cmpunlocker.deploy first."
    exit 1
fi
echo "Patched firmware: $PATCHED"
TARGET_DIR=$(dirname "$PATCHED")
TARGET="${TARGET_DIR}/gsp_tu10x.bin"
echo "Target: $TARGET"
ls -la "$TARGET"
echo ""

echo "--- Step 3: Stop services ---"
systemctl stop nvidia-persistenced 2>&1
echo ""

echo "--- Step 4: Unload nvidia modules ---"
for mod in nvidia_uvm nvidia_drm nvidia_modeset nvidia; do
    rmmod $mod 2>&1
done
echo ""

echo "--- Step 5: Kill GPU users ---"
fuser -k /dev/nvidia* 2>&1
sleep 2
echo ""

echo "--- Step 6: Try to remove target file ---"
rm -f "$TARGET" 2>&1
ls -la "$TARGET" 2>&1
echo ""

echo "--- Step 7: If file still exists, check why ---"
if [ -f "$TARGET" ]; then
    echo "File still exists. Checking..."
    lsof "$TARGET" 2>&1
    fuser -v "$TARGET" 2>&1
    stat "$TARGET"
    echo ""
    echo "If file is busy, you need to fully unload the nvidia modules."
    echo "Try: sudo systemctl isolate multi-user.target"
    echo "Then re-run this script from the new shell."
    exit 1
fi

echo "--- Step 8: Copy patched firmware ---"
cp "$PATCHED" "$TARGET" 2>&1
ls -la "$TARGET" 2>&1
echo ""

echo "--- Step 9: Reload nvidia modules ---"
modprobe nvidia 2>&1
modprobe nvidia_modeset 2>&1
modprobe nvidia_drm 2>&1
modprobe nvidia_uvm 2>&1
sleep 3
echo ""

echo "--- Step 10: Verify ---"
nvidia-smi --query-gpu=memory.total,clocks.max.sm --format=csv,noheader 2>&1
echo ""
echo "Expected: 40960 MiB, ~1410 MHz (if 40GB unlock worked)"
echo "Or: 81920 MiB, ~1410 MHz (if unlock was a no-op)"
echo "Or: error (if HBM controller refused the change)"
echo ""
echo "================================================================"
echo "Done"
echo "================================================================"

#!/bin/bash
# run_manual_mount.sh — Wraps the manual bind-mount with full diagnostics

set +e

echo "=== Step 1: Check override file ==="
ls -la /var/lib/cmpunlocker/firmware/nvidia/580.159.04/ 2>&1
echo ""

echo "=== Step 2: Check system firmware ==="
ls -la /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin 2>&1
ls -la /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin.cmpunlocker.patched 2>&1
echo ""

echo "=== Step 3: Check /lib/firmware mount type ==="
findmnt /lib/firmware 2>&1
mount | grep -E "firmware|lib/firmware" 2>&1
df -h /lib/firmware 2>&1
echo ""

echo "=== Step 4: Attempt bind-mount ==="
mount --bind \
  /var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin \
  /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin 2>&1
MOUNT_RC=$?
echo "mount exit code: $MOUNT_RC"
echo ""

echo "=== Step 5: Verify mount ==="
mount | grep gsp_tu10x 2>&1
ls -la /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin 2>&1
echo ""

echo "=== Step 6: If bind-mount failed, try with strace ==="
if [ $MOUNT_RC -ne 0 ]; then
    echo "Trying strace to see why mount failed:"
    strace -e mount,mount_entry mount --bind \
        /var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin \
        /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin 2>&1 | tail -20
fi
echo ""

echo "=== Done ==="

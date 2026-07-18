#!/bin/bash
# diagnose_a100_vm.sh — Comprehensive VM environment check
# Run this on the new A100 VM as the user (not root)

echo "============================================================"
echo "A100 VM Environment Diagnostic"
echo "============================================================"
echo ""

echo "=== 1. User & permissions ==="
whoami
id
echo ""

echo "=== 2. sudo availability ==="
sudo -n true 2>&1 && echo "  sudo: OK (passwordless)" || echo "  sudo: requires password or unavailable"
echo ""

echo "=== 3. GPU detection ==="
which lspci && lspci -nn -D | grep -i nvidia || echo "  lspci not available or no NVIDIA device"
echo ""

echo "=== 4. nvidia-smi ==="
which nvidia-smi && nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv 2>&1 || echo "  nvidia-smi not working"
echo ""

echo "=== 5. /dev/mem and /dev/kmem ==="
ls -la /dev/mem /dev/kmem 2>&1 | head -5
echo ""

echo "=== 6. /lib/firmware (writable?) ==="
ls -ld /lib/firmware
ls -ld /lib/firmware/nvidia 2>/dev/null
find /lib/firmware/nvidia -name "gsp_tu10x.bin" 2>/dev/null | head -3
ls -la /lib/firmware/nvidia/580*/gsp_tu10x.bin 2>/dev/null | head -3
echo ""

echo "=== 7. Mount info for /lib/firmware ==="
findmnt /lib/firmware 2>/dev/null || mount | grep firmware
df -h /lib/firmware 2>/dev/null
echo ""

echo "=== 8. Container/VM detection ==="
cat /sys/class/dmi/id/sys_vendor 2>/dev/null && echo ""
cat /sys/class/dmi/id/product_name 2>/dev/null && echo ""
cat /proc/1/cgroup 2>/dev/null | head -3
test -f /.dockerenv && echo "  In Docker container" || echo "  Not in Docker"
test -f /run/.containerenv && echo "  In podman/container" || echo "  Not in podman"
echo ""

echo "=== 9. Kernel version & driver ==="
uname -r
lsmod 2>/dev/null | grep -i nvidia | head -3
echo ""

echo "=== 10. udev ==="
which udevadm && udevadm --version 2>&1 | head -1 || echo "  udevadm not available"
test -d /etc/udev/rules.d && echo "  /etc/udev/rules.d exists" || echo "  /etc/udev/rules.d missing"
echo ""

echo "============================================================"
echo "Summary for Discord"
echo "============================================================"
echo "GPU: $(lspci -nn -D 2>/dev/null | grep -i nvidia | head -1)"
echo "Driver: $(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null)"
echo "Current VRAM: $(nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null)"
echo "Firmware path: $(find /lib/firmware -name gsp_tu10x.bin 2>/dev/null | head -1)"
echo "Firmware writable: $(test -w /lib/firmware && echo yes || echo no)"
echo "Sudo: $(sudo -n true 2>/dev/null && echo yes || echo no)"

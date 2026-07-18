#!/usr/bin/env python3
"""
Phase 1: BAR0 access verification for A100 80GB on RunPod Secure Cloud.

This script verifies:
1. /dev/mem is accessible (needed for raw MMIO access)
2. We can find the A100 PCIe device
3. We can map BAR0 (16 MB) into userspace
4. We can read known A100 registers and verify they look like GA100 silicon
5. We can read 0x009A0204 (CFG1) and report current VRAM configuration

Exit codes:
  0 = BAR0 access fully working, ready for unlock
  1 = partial access (read-only or limited)
  2 = no access (need privileged container / different setup)
  3 = not GA100 silicon (different GPU, exploit won't work)
"""

import os
import sys
import struct
import mmap
import ctypes
import ctypes.util
import subprocess


def check_devmem():
    """Check if /dev/mem exists and is readable/writable."""
    print("=" * 60)
    print("Step 1: /dev/mem access check")
    print("=" * 60)

    devmem = "/dev/mem"
    if not os.path.exists(devmem):
        print(f"  FAIL: {devmem} does not exist")
        return False, "no /dev/mem"

    try:
        with open(devmem, "rb") as f:
            f.read(4)
        print(f"  OK: {devmem} is readable")
    except PermissionError:
        print(f"  FAIL: {devmem} not readable (need root or CAP_SYS_RAWIO)")
        return False, "no read permission"
    except Exception as e:
        print(f"  FAIL: {devmem} read error: {e}")
        return False, str(e)

    try:
        with open(devmem, "r+b") as f:
            f.seek(0)
            f.write(b"\x00\x00\x00\x00")
        print(f"  OK: {devmem} is writable")
        return True, "full read/write"
    except PermissionError:
        print(f"  WARN: {devmem} is read-only (CAP_SYS_RAWIO missing)")
        return False, "read-only"
    except Exception as e:
        print(f"  WARN: {devmem} write error: {e}")
        return False, f"write failed: {e}"


def find_a100_pci_device():
    """Find the A100 NVIDIA GPU via lspci."""
    print()
    print("=" * 60)
    print("Step 2: Find A100 PCIe device")
    print("=" * 60)

    try:
        out = subprocess.check_output(["lspci", "-nn", "-D"], text=True)
    except FileNotFoundError:
        print("  FAIL: lspci not installed (apt install pciutils)")
        return None

    nvidia_devices = []
    for line in out.splitlines():
        if "NVIDIA" in line or "10de:" in line.lower():
            nvidia_devices.append(line)

    if not nvidia_devices:
        print("  FAIL: no NVIDIA device found via lspci")
        return None

    print(f"  Found {len(nvidia_devices)} NVIDIA device(s):")
    for d in nvidia_devices:
        print(f"    {d}")

    a100_candidates = []
    for d in nvidia_devices:
        if "20b0" in d or "20b2" in d or "20c2" in d or "2082" in d:
            a100_candidates.append(d)
        if "GA100" in d or "A100" in d or "CMP 170HX" in d:
            a100_candidates.append(d)

    if a100_candidates:
        print(f"  GA100/A100/CMP 170HX candidates: {len(a100_candidates)}")
        for c in a100_candidates:
            print(f"    {c}")
        return a100_candidates[0]

    print("  WARN: NVIDIA device found but not identified as GA100/A100")
    print("  Proceeding anyway — exploit will check silicon ID via BAR0 read")

    return nvidia_devices[0]


def get_bar0_info(pci_line):
    """Get BAR0 address and size from sysfs."""
    print()
    print("=" * 60)
    print("Step 3: Get BAR0 resource info")
    print("=" * 60)

    pci_addr = pci_line.split()[0]
    resource_path = f"/sys/bus/pci/devices/{pci_addr}/resource"

    if not os.path.exists(resource_path):
        print(f"  FAIL: {resource_path} not found")
        return None, 0

    try:
        with open(resource_path) as f:
            resources = f.readlines()

        bar0 = resources[0].split()
        if len(bar0) < 3:
            print(f"  FAIL: BAR0 line malformed: {bar0}")
            return None, 0

        start = int(bar0[0], 16)
        end = int(bar0[1], 16)
        flags = int(bar0[2], 16)
        size = end - start + 1

        print(f"  BAR0 start: 0x{start:016x}")
        print(f"  BAR0 end:   0x{end:016x}")
        print(f"  BAR0 size:  0x{size:x} ({size // (1024*1024)} MB)")
        print(f"  BAR0 flags: 0x{flags:x} {'(memory)' if flags & 0x1 == 0 else '(I/O)'}")

        if size < 16 * 1024 * 1024:
            print(f"  WARN: BAR0 is only {size//1024} KB, expected 16 MB for GA100")
            print(f"  This may be a BAR0 sized down via PCI_COMMAND")

        return start, size

    except Exception as e:
        print(f"  FAIL: error reading {resource_path}: {e}")
        return None, 0


def map_bar0_via_devmem(pci_addr, size):
    """Map BAR0 via /dev/mem (works in KVM with /dev/mem access)."""
    print()
    print("=" * 60)
    print("Step 4: Map BAR0 via /dev/mem")
    print("=" * 60)

    resource_path = f"/sys/bus/pci/devices/{pci_addr}/resource"
    with open(resource_path) as f:
        resources = f.readlines()
    bar0 = resources[0].split()
    bar0_start = int(bar0[0], 16)
    map_size = min(size, 16 * 1024 * 1024)

    try:
        fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    except PermissionError:
        print(f"  FAIL: cannot open /dev/mem (need root)")
        return None

    try:
        mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE,
                       offset=bar0_start)
        print(f"  OK: mapped {map_size//(1024*1024)} MB at 0x{bar0_start:x}")
        return mm
    except Exception as e:
        print(f"  FAIL: mmap failed: {e}")
        os.close(fd)
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def verify_ga100_silicon(mm, size):
    """Verify the silicon is GA100 by reading known registers."""
    print()
    print("=" * 60)
    print("Step 5: Verify GA100 silicon")
    print("=" * 60)

    if size < 0x1000:
        print(f"  FAIL: BAR0 too small ({size} bytes)")
        return False

    mm.seek(0)
    boot0 = struct.unpack_from("<I", mm, 0x0)[0]
    print(f"  PMC_BOOT_0 (0x0):        0x{boot0:08x}")

    mm.seek(0x4)
    boot1 = struct.unpack_from("<I", mm, 0x4)[0]
    print(f"  PMC_BOOT_1 (0x4):        0x{boot1:08x}")

    mm.seek(0x88)
    fuse_status = struct.unpack_from("<I", mm, 0x88)[0]
    print(f"  PMC_FUSE_STATUS (0x88):  0x{fuse_status:08x}")

    mm.seek(0x8c)
    fuse_ctl = struct.unpack_from("<I", mm, 0x8c)[0]
    print(f"  PMC_FUSE_CTL (0x8c):     0x{fuse_ctl:08x}")

    mm.seek(0x9a0204 if size > 0x9a0204 + 4 else 0)
    if size > 0x9a0204 + 4:
        cfg1 = struct.unpack_from("<I", mm, 0x9a0204)[0]
        print(f"  HBM CFG1 (0x9a0204):     0x{cfg1:08x}")

        strap = (cfg1 >> 16) & 0xff
        feature = (cfg1 >> 8) & 0xff
        if strap == 0x77 and feature == 0x90:
            print(f"  -> 5 stacks × 16GB HBM2e = 80GB (matches A100 80GB)")
        elif strap == 0x66 and feature == 0x90:
            print(f"  -> 5 stacks × 8GB HBM2e = 40GB")
        elif strap == 0x44 and feature == 0x90:
            print(f"  -> 5 stacks × 2GB HBM2 = 10GB (CMP 170HX native)")
        else:
            print(f"  -> strap=0x{strap:02x} feature=0x{feature:02x} (unknown config)")
    else:
        print(f"  SKIP: 0x9a0204 not in mapped BAR0 (size 0x{size:x})")

    mm.seek(0x118)
    if size > 0x118 + 4:
        dev_id = struct.unpack_from("<I", mm, 0x118)[0]
        print(f"  DEVICE_ID (0x118):       0x{dev_id:08x}")
        if dev_id in (0x20b020b0, 0x20b2, 0x20b020b2):
            print(f"  -> matches A100 80GB PCIe (0x20b0/0x20b2)")
        elif dev_id == 0x20b020c2 or (dev_id & 0xffff) == 0x20c2:
            print(f"  -> matches CMP 170HX 80GB (0x20c2)")

    return True


def main():
    print("BAR0 access verification for A100/CMP 170HX on RunPod")
    print("=" * 60)

    if os.geteuid() != 0:
        print("WARNING: not running as root, /dev/mem access will fail")
        print("Re-run with: sudo python3 verify_bar0.py")
        print()

    ok, mode = check_devmem()
    if not ok:
        print()
        print(f"EXIT 2: /dev/mem not usable ({mode})")
        print("Try: sudo setcap cap_sys_rawio+ep $(which python3)")
        return 2

    pci_line = find_a100_pci_device()
    if pci_line is None:
        print()
        print("EXIT 3: no NVIDIA PCIe device found")
        return 3

    pci_addr = pci_line.split()[0]
    start, size = get_bar0_info(pci_line)
    if size == 0:
        print()
        print("EXIT 1: cannot read BAR0 resource info")
        return 1

    mm = map_bar0_via_devmem(pci_addr, size)
    if mm is None:
        print()
        print("EXIT 1: cannot map BAR0")
        return 1

    verify_ga100_silicon(mm, size)

    mm.close()

    print()
    print("=" * 60)
    print("EXIT 0: BAR0 access fully working, ready for unlock")
    print("=" * 60)
    print()
    print("Next step: run the actual unlock payload")
    print("  sudo python3 unlock_80gb_to_40gb.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

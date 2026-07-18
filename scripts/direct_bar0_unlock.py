#!/usr/bin/env python3
"""
direct_bar0_unlock.py — Apply unlock writes directly via BAR0 MMIO.

This bypasses the firmware-patching path entirely. We:
  1. Find the GA100/A100 PCI device
  2. Map BAR0 (16 MB) into userspace via /dev/mem
  3. Write the unlock values directly to the relevant MMIO offsets
  4. Optionally trigger a function-level reset (FLR) to apply

The unlock writes are derived from our Falcon emulator analysis and
the 5 community-verified values from kinako404/cmpunlocker.

This works in environments where /lib/firmware is read-only (snap,
container, immutable root) because it doesn't touch firmware at all.

Usage:
    sudo python3 direct_bar0_unlock.py --target unlocked_40gb
    sudo python3 direct_bar0_unlock.py --target unlocked_80gb --read-cfg1
    sudo python3 direct_bar0_unlock.py --target unlocked_40gb --no-flr
"""

import argparse
import mmap
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

# Community-verified unlock writes from kinako404 + our emulator validation.
# Each entry: (BAR0_offset, value, label)
UNLOCK_WRITES = [
    (0x9A0204, 0x02669000, "CFG1 (40GB geometry: 5x8GB HBM2e)"),
    (0x100CE0, 0x0000028a, "LMR (memory rank configuration)"),
    (0x1FA824, 0x1FFFFE00, "WPR2 lo (write protection register 2 low)"),
    (0x1FA828, 0x00000000, "WPR2 hi (write protection register 2 high)"),
    (0x8403C4, 0x000000FF, "resetPLM (open platform lock manager)"),
    # Compute unlock (SM clock cap removal)
    (0x82381C, 0x88888888, "SS0 (FEAT_OVR_SM_SPD — all SMs max)"),
    (0x823820, 0x00000008, "SS1 (FEAT_OVR_SM_SPD_1 — IMLA4 override)"),
]

# CFG1 target values from our strap_info table
CFG1_TARGETS = {
    "nativ_8gb":     0x01540000,  # 4 × 2GB HBM2 (8GB native)
    "nativ_10gb":    0x02449000,  # 5 × 2GB HBM2 (10GB native)
    "unlocked_32gb": 0x02700000,  # 4 × 8GB HBM2e
    "unlocked_40gb": 0x02669000,  # 5 × 8GB HBM2e (kinako404 default)
    "unlocked_64gb": 0x02770000,  # 4 × 16GB HBM2e (hypothesized)
    "unlocked_80gb": 0x02779000,  # 5 × 16GB HBM2e
}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def find_ga100_pci():
    """Find GA100/A100 PCI device, return (bdf, vendor_id, device_id)."""
    try:
        out = subprocess.check_output(["lspci", "-nn", "-D"], text=True)
    except FileNotFoundError:
        log("ERROR: lspci not found (apt install pciutils)")
        sys.exit(1)

    candidates = []
    for line in out.splitlines():
        if "10de:" not in line:
            continue
        # Extract BDF
        bdf = line.split()[0]
        # Extract vendor:device
        ids = ""
        if "[" in line and "]" in line:
            ids = line.split("[")[-1].split("]")[0]
        vid, did = ids.split(":") if ":" in ids else ("", "")
        # Check for GA100/A100/CMP
        is_ga100 = any(x in line for x in ["GA100", "A100", "20b0", "20b2",
                                            "20b4", "20c2", "20c8", "2082"])
        if is_ga100:
            candidates.append((bdf, int(vid, 16), int(did, 16), line))
        else:
            candidates.append((bdf, int(vid, 16), int(did, 16), line))

    # Prefer confirmed GA100 IDs
    ga100_ids = {0x20b0, 0x20b2, 0x20b4, 0x20c2, 0x20c8, 0x2082}
    for c in candidates:
        if c[2] in ga100_ids:
            return c[0], c[1], c[2]
    if candidates:
        return candidates[0][0], candidates[0][1], candidates[0][2]
    return None, None, None


def map_bar0(bdf, size_mb=16):
    """Map BAR0 of the given PCI device via /dev/mem."""
    resource_path = f"/sys/bus/pci/devices/{bdf}/resource"
    with open(resource_path) as f:
        bar0 = f.readline().split()
    bar0_start = int(bar0[0], 16)
    bar0_end = int(bar0[1], 16)
    actual_size = bar0_end - bar0_start + 1
    map_size = min(size_mb * 1024 * 1024, actual_size)

    fd = os.open("/dev/mem", os.O_RDWR | os.O_SYNC)
    try:
        mm = mmap.mmap(fd, map_size, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE,
                       offset=bar0_start)
    finally:
        os.close(fd)
    return mm, bar0_start, map_size


def read_reg(mm, offset):
    mm.seek(offset)
    return struct.unpack_from("<I", mm, offset)[0]


def write_reg(mm, offset, value):
    struct.pack_into("<I", mm, offset, value & 0xFFFFFFFF)


def decode_cfg1(val):
    strap = (val >> 16) & 0xff
    feature = (val >> 8) & 0xff
    return f"strap=0x{strap:02x} feature=0x{feature:02x}"


def flr_reset(bdf):
    """Trigger PCI function-level reset."""
    reset_path = f"/sys/bus/pci/devices/{bdf}/reset"
    try:
        with open(reset_path, "w") as f:
            f.write("1")
        time.sleep(0.5)
        return True
    except (OSError, PermissionError) as e:
        log(f"  FLR via sysfs failed: {e}")
    return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="unlocked_40gb",
                   choices=list(CFG1_TARGETS.keys()),
                   help="CFG1 target (default: unlocked_40gb)")
    p.add_argument("--read-cfg1", action="store_true",
                   help="Only read current CFG1, don't write")
    p.add_argument("--no-flr", action="store_true",
                   help="Skip function-level reset after writes")
    p.add_argument("--bdf", default=None,
                   help="PCI BDF (auto-detect if not given)")
    args = p.parse_args()

    if os.geteuid() != 0:
        log("ERROR: must run as root (sudo)")
        sys.exit(1)

    log("=" * 70)
    log("Direct BAR0 Unlock (bypasses firmware patching)")
    log("=" * 70)

    bdf = args.bdf
    if bdf is None:
        bdf, vid, did = find_ga100_pci()
        if bdf is None:
            log("ERROR: no NVIDIA GPU found")
            sys.exit(1)
        log(f"GPU found: {bdf} (vendor:device = {vid:04x}:{did:04x})")

    log(f"Mapping BAR0 for {bdf}...")
    try:
        mm, bar0_base, map_size = map_bar0(bdf)
    except (OSError, PermissionError) as e:
        log(f"ERROR: cannot map BAR0: {e}")
        log("Check that /dev/mem is accessible and you have CAP_SYS_RAWIO")
        sys.exit(1)
    log(f"  BAR0 mapped: 0x{bar0_base:x} ({map_size // (1024*1024)} MB)")

    current_cfg1 = read_reg(mm, 0x9A0204)
    log(f"Current CFG1 (0x9a0204): 0x{current_cfg1:08x} ({decode_cfg1(current_cfg1)})")

    if args.read_cfg1:
        log("Read-only mode, exiting")
        mm.close()
        return 0

    target_cfg1 = CFG1_TARGETS[args.target]
    log(f"Target CFG1: 0x{target_cfg1:08x} ({args.target}, {decode_cfg1(target_cfg1)})")

    if current_cfg1 == target_cfg1:
        log("Current CFG1 already matches target, no write needed")
    else:
        log("Writing unlock values via BAR0...")
        for offset, value, label in UNLOCK_WRITES:
            if offset == 0x9A0204:
                value = target_cfg1
            log(f"  0x{offset:06x} = 0x{value:08x}  ({label})")
            write_reg(mm, offset, value)
            time.sleep(0.01)
            # Read back to verify
            readback = read_reg(mm, offset)
            if readback != value:
                log(f"    WARNING: readback mismatch (wrote 0x{value:08x}, got 0x{readback:08x})")
            else:
                log(f"    OK: readback 0x{readback:08x}")

    log("")
    new_cfg1 = read_reg(mm, 0x9A0204)
    log(f"After write: CFG1 = 0x{new_cfg1:08x} ({decode_cfg1(new_cfg1)})")

    if not args.no_flr:
        log("Triggering function-level reset to apply changes...")
        if flr_reset(bdf):
            log("  FLR triggered successfully")
        else:
            log("  FLR failed — you may need to reload the nvidia driver:")
            log("    sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia")
            log("    sudo modprobe nvidia")

    mm.close()
    log("")
    log("=" * 70)
    log("Done. Verify with:")
    log("  nvidia-smi --query-gpu=memory.total,clocks.max.sm --format=csv,noheader")
    log("=" * 70)


if __name__ == "__main__":
    main()

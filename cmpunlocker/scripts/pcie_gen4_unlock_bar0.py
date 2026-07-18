#!/usr/bin/env python3
"""
pcie_gen4_unlock_bar0.py — EXPERIMENTAL: Enable PCIe Gen 4 via BAR0 PTOP.

⚠️  WARNING: This script is EXPERIMENTAL and uses HYPOTHETICAL
register addresses. The addresses are based on NVIDIA naming
convention but are NOT empirically verified on a CMP 170HX.

Use scripts/pcie_gen4_unlock.sh instead — that uses standard
PCI Config Space access (setpci) which is the correct way.

The 0x88c20 address IS referenced twice in the GSP firmware
(as a data constant, not code) which gives some confidence
the register exists. The other addresses are educated guesses.

Hypothetical NV_PTOP_* register addresses (NOT verified):
  - NV_PTOP_DEVICE_CFG_0          @ 0x88c00
  - NV_PTOP_DEVICE_CFG_1          @ 0x88c10
  - NV_PTOP_DEVICE_CFG_LINK_CTRL  @ 0x88c14
  - NV_PTOP_DEVICE_CFG_GEN4_CTRL  @ 0x88c1c
  - NV_PTOP_DEVICE_CFG_GEN4_STATUS @ 0x88c20

These addresses follow NVIDIA's PTOP naming pattern but have
NOT been verified on real hardware. If they don't work, use
scripts/pcie_gen4_unlock.sh which uses PCI Config Space directly.

Usage:
    sudo python3 pcie_gen4_unlock_bar0.py [PCI_BDF]
"""

import argparse
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "cmpunlocker"))

from payload.bar0 import Bar0
from common.constants import get


# Hypothetical NV_PTOP_* register addresses (based on NVIDIA naming)
# NOTE: These are NOT empirically verified on CMP 170HX. The proper
# approach is to use setpci on the PCI Config Space.
PCIE_REGISTERS = {
    "device_cfg_0":    0x88c00,
    "device_cfg_1":    0x88c10,
    "link_ctrl":        0x88c14,
    "link_status":      0x88c18,
    "gen4_ctrl":        0x88c1c,
    "gen4_status":      0x88c20,
}


def find_gpu():
    """Auto-detect CMP 170HX or A100 PCIe device."""
    for dev_id in ["20c2", "20b0", "20b2", "20b4", "2082"]:
        result = subprocess.run(
            ["lspci", "-nn", "-D"],
            capture_output=True, text=True, check=False
        )
        for line in result.stdout.splitlines():
            if f"10de:{dev_id}" in line:
                return line.split()[0]
    return None


def read_pcie_regs(pci_full: str) -> dict:
    """Read all PCIe-related PTOP registers."""
    out = {}
    try:
        with Bar0(pci_full) as bar0:
            for name, addr in PCIE_REGISTERS.items():
                try:
                    out[name] = bar0.rd32(addr)
                except Exception as exc:
                    out[name] = f"ERROR: {exc}"
    except Exception as exc:
        out["__error__"] = str(exc)
    return out


def write_pcie_reg(pci_full: str, addr: int, value: int) -> bool:
    """Write a value to a PCIe register."""
    try:
        with Bar0(pci_full) as bar0:
            bar0.wr32(addr, value)
            actual = bar0.rd32(addr)
        return actual == value
    except Exception:
        return False


def decode_link_cap(value: int) -> dict:
    """Decode Link Capabilities register."""
    return {
        "max_speed_gen": value & 0xf,
        "max_width": (value >> 4) & 0x3f,
        "aspm_l0s": bool(value & (1 << 10)),
        "aspm_l1": bool(value & (1 << 11)),
    }


def decode_link_status(value: int) -> dict:
    """Decode Link Status register."""
    return {
        "current_speed_gen": value & 0xf,
        "current_width": (value >> 4) & 0x3f,
        "link_active": bool(value & (1 << 13)),
        "link_training": bool(value & (1 << 11)),
    }


def decode_gen4_status(value: int) -> dict:
    """Decode Gen 4 Status register (hypothetical)."""
    return {
        "gen4_capable": bool(value & 1),
        "gen4_active": bool(value & 2),
        "eq_done": bool(value & 4),
        "speed_negotiated": (value >> 4) & 0xf,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pci_bdf", nargs="?", default=None,
                        help="PCI BDF (auto-detect if not given)")
    parser.add_argument("--read-only", action="store_true",
                        help="Just read the registers, don't write")
    parser.add_argument("--target", type=int, default=4,
                        choices=[1, 2, 3, 4, 5],
                        help="Target PCIe generation (default: 4)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must run as root", file=sys.stderr)
        return 1

    pci = args.pci_bdf or find_gpu()
    if not pci:
        print("ERROR: no compatible GPU found", file=sys.stderr)
        return 1
    print(f"GPU: {pci}")

    print("\n=== Reading PCIe PTOP registers ===")
    regs = read_pcie_regs(pci)
    if "__error__" in regs:
        print(f"  ERROR: {regs['__error__']}")
        return 1
    for name, value in regs.items():
        if isinstance(value, str):
            print(f"  {name:20s} (0x{PCIE_REGISTERS[name]:06x}): {value}")
        else:
            print(f"  {name:20s} (0x{PCIE_REGISTERS[name]:06x}): 0x{value:08x}")

    link_cap = regs.get("link_ctrl", 0)
    if isinstance(link_cap, int):
        decoded = decode_link_cap(link_cap)
        print(f"\n  Link Capabilities decoded: {decoded}")
        if decoded["max_speed_gen"] < args.target:
            print(f"  WARNING: GPU max speed is Gen{decoded['max_speed_gen']}, "
                  f"target Gen{args.target} not supported")
            return 1

    if args.read_only:
        return 0

    print(f"\n=== Enabling PCIe Gen {args.target} ===")
    print("Step 1: Write target speed to Link Control 2 (Config Space 0x68)")
    print("        -- this requires setpci, see scripts/pcie_gen4_unlock.sh")
    print()
    print("Step 2: Attempt to write NV_PTOP_DEVICE_CFG_LINK_CTRL via BAR0")
    print(f"        Write 0x{(1 << 5) | args.target:04x} to 0x{PCIE_REGISTERS['link_ctrl']:06x} "
          "(retrain + target speed)")
    ok = write_pcie_reg(pci, PCIE_REGISTERS["link_ctrl"],
                        (1 << 5) | args.target)
    if ok:
        print(f"  Write succeeded! Reading back...")
        time.sleep(1)
        new_status = read_pcie_regs(pci).get("link_status", 0)
        if isinstance(new_status, int):
            print(f"  Link Status now: 0x{new_status:08x}")
            decoded = decode_link_status(new_status)
            print(f"  Decoded: {decoded}")
            if decoded["current_speed_gen"] == args.target:
                print(f"\n  SUCCESS: PCIe Gen {args.target} now active!")
                return 0
            else:
                print(f"\n  Write succeeded but link didn't retrain to Gen{args.target}")
    else:
        print("  Write failed (readback mismatch)")

    print("\n=== Alternative: try PTOP GEN4_CTRL ===")
    print(f"  Write 0x01 to 0x{PCIE_REGISTERS['gen4_ctrl']:06x} (Gen 4 enable)")
    ok = write_pcie_reg(pci, PCIE_REGISTERS["gen4_ctrl"], 0x01)
    if ok:
        print("  Write succeeded")
        time.sleep(1)
        new_status = read_pcie_regs(pci).get("gen4_status", 0)
        if isinstance(new_status, int):
            print(f"  Gen 4 Status now: 0x{new_status:08x}")
            decoded = decode_gen4_status(new_status)
            print(f"  Decoded: {decoded}")
    else:
        print("  Write failed")

    print("\n=== Recommended: use the setpci script instead ===")
    print("  sudo ./scripts/pcie_gen4_unlock.sh " + pci)
    print("\n  The setpci approach uses PCI Config Space directly,")
    print("  which is the correct way to enable Gen 4.")
    print("  BAR0 PTOP registers are speculative.")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)

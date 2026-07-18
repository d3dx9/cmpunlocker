#!/usr/bin/env python3
"""
a100_80gb_payload.py — Generate the complete 80GB unlock payload.

Writes ALL verified A100 80GB register values to the CMP 170HX.
Run AFTER fb_plm is open (apply_unlock pipeline step 1).

Two modes:
  1. --payload : write to a BAR0 device (VFIO or sysfs PCI resource0).
  2. --generate-fw-patch : produce a patched .ga100_resident_data
     section that programs the values during booter execution.

The register values are from a live BAR0 dump of an A100 PCIe 80GB
(a100-0000_01_00_0-bar0-16m.bin, 580.105.08 driver).

Tested by: booter_emu.py — booter and GSP-RM write paths validated.
"""

import argparse
import logging
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.constants import get

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('a100_80gb_payload')

# ---------------------------------------------------------------------------
# A100 80GB register values discovered 2026-07-17
# Source: a100-0000_01_00_0-bar0-16m.bin (live BAR0, fully analyzed)
# ---------------------------------------------------------------------------
# These are the registers whose values differ between A100 80GB and CMP 10GB.
# They are organized by "family" based on address range.

A100_80GB_REGISTERS = [
    # ============================================================================
    # EXPLOIT-CHAIN WRITES (community-verified 2026-07-18, Big Ptoughneigh)
    # Order matters: CFG1 → LMR → WPR2-lo → WPR2-hi → resetPLM
    # ============================================================================
    (0x9A0204, 0x02669000, "CFG1 — geometry flip (verified on 40GB)"),
    (0x100CE0, 0x0000028a, "LMR — memory rank config (verified)"),

    # ============================================================================
    # WPR2 TEARDOWN (community-verified)
    # Carving WPR2 to (0x1ffffe00, 0) clears the booter's protected region
    # so CPU-RM's BAR2 self-test sees fresh state.
    # ============================================================================
    (0x1FA824, 0x1FFFFE00, "WPR2 low — teardown"),
    (0x1FA828, 0x00000000, "WPR2 high — teardown"),

    # ============================================================================
    # RESETPLM REOPEN (community-verified)
    # 0xFF keeps PLM open across 0x8117 raw-exit.
    # 0x8103 path would re-lock to 0x8f via secure_teardown.
    # ============================================================================
    (0x8403C4, 0x000000FF, "resetPLM — reopen (must follow CFG1/LMR/WPR2)"),

    # ============================================================================
    # A100 live-dump values — NOT cfg1/lmr but other FB-controller registers
    # that do differ between 10GB CMP and 80GB A100. May still affect geometry.
    # ============================================================================
    (0x1100d8, 0x40000000, "Family A — FB timing (10GB was 0)"),
    (0x1100dc, 0x008e003f, "Family A — FB timing (10GB was 0)"),
    (0x1100e0, 0x003fffff, "Family A — FB timing (10GB was 0)"),
    (0x1100e8, 0x0000008f, "Family A — FB timing (10GB was 0)"),
    (0x1100ec, 0x000000ff, "Family A — FB timing (10GB was 0)"),
    (0x1100f0, 0x000000ff, "Family A — FB timing (10GB was 0)"),
    (0x1100f4, 0x000007f7, "Family A — FB timing (10GB was 0)"),
    (0x1100f8, 0x00110000, "Family A — FB timing (10GB was 0)"),
    (0x1100fc, 0x00108000, "Family A — FB timing (10GB was 0)"),
    (0x110600, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x110604, 0x00000114, "Family A2 — FB partition (10GB was 0)"),
    (0x110608, 0x00000005, "Family A2 — FB partition (10GB was 0)"),
    (0x11060c, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x110610, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x110614, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x110618, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x11061c, 0x00000110, "Family A2 — FB partition (10GB was 0)"),
    (0x110624, 0x00000190, "Family A2 — refresh *2 (10GB was 0x90, then driver wrote 0x190)"),
    (0x120040, 0x00000072, "Family B — FB geometry (10GB was 0)"),
    (0x120044, 0x00000012, "Family B — FB geometry (10GB was 0)"),
    (0x12006c, 0x00000014, "Family B — FB count (10GB was 0x10) — NOT cfg1, was wrong guess"),
    (0x120074, 0x0000000a, "Family B — FB addr map (10GB was 0x08)"),
    (0x120078, 0x00000007, "Family B — FB addr map (10GB was 0x05)"),
    (0x122004, 0x00000001, "Family C — LMR aux (10GB was 0)"),
    (0x122008, 0x0000010a, "Family C — LMR aux (10GB was 0)"),
    (0x12204c, 0x00000001, "Family C — LMR aux (10GB was 0)"),
    (0x122050, 0xffffff8f, "Family C — LMR aux (10GB was 0)"),
    (0x122134, 0x02811972, "Family C — LMR address map (10GB was 0) — NOT cfg1, was wrong guess"),
    (0x122138, 0xc7151015, "Family C — LMR address map (10GB was 0)"),
    (0x12213c, 0x00002224, "Family C — LMR address map (10GB was 0)"),
    (0x12214c, 0x170000a1, "Family C — LMR address map (10GB was 0)"),
    (0x1221f0, 0x0003c000, "Family C — FB size encoding (10GB was 0)"),
]


def write_payload(bar0_dev: str, dry_run: bool = False):
    """Write all A100 80GB values via BAR0.

    bar0_dev is either:
      - '/dev/vfio/<group>/<device>' (VFIO)
      - '/sys/bus/pci/devices/<bdf>/resource0'  (sysfs)
      - a PCI BDF string like '0000:01:00.0'  (uses Bar0 helper)
    """
    if dry_run:
        log.info("=== DRY RUN — would write %d registers ===", len(A100_80GB_REGISTERS))
        for addr, value, note in A100_80GB_REGISTERS:
            log.info("  0x%08x <- 0x%08x  (%s)", addr, value, note)
        return

    # Try using the payload.bar0 helper
    try:
        from payload.bar0 import Bar0
    except ImportError:
        log.error("Could not import Bar0 helper. "
                  "Run from the cmpunlocker project root.")
        sys.exit(1)

    written = 0
    errors = 0
    with Bar0(bar0_dev) as bar0:
        for addr, value, note in A100_80GB_REGISTERS:
            try:
                bar0.wr32(addr, value)
                rdback = bar0.rd32(addr)
                if rdback == value:
                    log.info("  OK  0x%08x <- 0x%08x  (%s)", addr, value, note)
                    written += 1
                else:
                    log.warning("  FAIL 0x%08x: wrote 0x%08x got back 0x%08x  (%s)",
                                addr, value, rdback, note)
                    errors += 1
            except Exception as e:
                log.error("  ERR  0x%08x <- 0x%08x: %s  (%s)", addr, value, e, note)
                errors += 1

    log.info("=== payload complete: %d OK, %d errors ===", written, errors)
    return written, errors


def generate_fw_patch(output_path: str):
    """Generate a patched firmware section that programs the A100 values.

    This creates a modified .ga100_resident_data section with a hook
    that writes the values during booter execution. The hook replaces
    the booter's final idle loop at 0x400c8d0.

    For HS-mode re-signing, you'll need to re-encrypt the section
    with the Falcon AES key (not implemented here).
    """
    log.info("Generating fw patch...")

    # The booter's idle loop at 0x400c8d0:
    #   jal x0, 0x400c8d0  (0x0000006f)
    # We replace this with a ROP chain that:
    #   1. Sets up a BAR0 write gadget
    #   2. Writes each A100 value
    #   3. Jumps back to the idle loop

    # Simple approach: append a small payload to .ga100_resident_data
    # and patch the idle loop to jump to it.
    booter_idle_off = 0x400c8d0

    # Build the BAR0 write sequence:
    # For each register:
    #   lui t0, high(addr)
    #   addi t0, low(addr)
    #   lui t1, high(value)
    #   addi t1, low(value)
    #   sw t1, 0(t0)
    #   fence

    code = bytearray()
    for addr, value, note in A100_80GB_REGISTERS:
        # Load address into t0 (x5)
        code += _lui_addi(5, addr)
        # Load value into t1 (x6)
        code += _lui_addi(6, value)
        # sw t1, 0(t0)
        code += struct.pack('<I', 0x0062a023)  # sw x6, 0(x5)
        # fence (ensure write lands)
        code += struct.pack('<I', 0x0ff0000f)  # fence iorw, iorw

    # After all writes, jump back to idle
    # jal x0, booter_idle_off (relative)
    idle_offset = (booter_idle_off - (booter_idle_off + len(code) + 4)) & 0x1fffff
    jal_imm = ((idle_offset >> 20) & 1) << 31 | \
              ((idle_offset >> 12) & 0xff) << 12 | \
              ((idle_offset >> 11) & 1) << 20 | \
              ((idle_offset >> 1) & 0x3ff) << 21
    code += struct.pack('<I', 0x0000006f | jal_imm)  # jal x0, idle_loop

    with open(output_path, 'wb') as f:
        f.write(code)

    log.info("Wrote %d bytes of patch payload to %s", len(code), output_path)

    # Also generate a .patch file with the patching recipe
    patch_recipe = output_path + '.recipe.txt'
    with open(patch_recipe, 'w') as f:
        f.write(f"# A100 80GB firmware patch recipe\n")
        f.write(f"# Generated: {time.ctime()}\n\n")
        f.write(f"# 1. Open gsp_tu10x.bin\n")
        f.write(f"# 2. Locate section .ga100_resident_data at vaddr 0x400d000\n")
        f.write(f"# 3. Append the payload at the end of the section\n")
        f.write(f"# 4. Patch the idle loop at 0x400c8d0:\n")
        f.write(f"#    jal x0, 0x400c8d0 -> jal x0, payload_start\n")
        f.write(f"# 5. Re-sign and re-encrypt the firmware\n")
        f.write(f"\n")
        f.write(f"Payload offset in .ga100_resident_data: end_of_section\n")
        f.write(f"Payload size: {len(code)} bytes\n")
        f.write(f"Jump target delta: {booter_idle_off} -> {booter_idle_off + len(code)}\n")

    log.info("Wrote recipe to %s", patch_recipe)


def _lui_addi(rd: int, imm32: int) -> bytes:
    """Generate LUI + ADDI sequence to load imm32 into register rd."""
    hi = (imm32 + 0x800) >> 12  # rounded high 20 bits
    lo = imm32 - (hi << 12)      # low 12 bits (sign-extended)
    if lo >= 2048:
        lo -= 4096
        hi += 1
    code = b''
    if hi:
        lui_enc = 0x00000037 | (rd << 7) | ((hi & 0xfffff) << 12)
        code += struct.pack('<I', lui_enc)
    if lo:
        addi_enc = 0x00000013 | (rd << 7) | (rd << 15) | ((lo & 0xfff) << 20)
        code += struct.pack('<I', addi_enc)
    if not code:
        # imm32 = 0: just addi x0, x0, 0
        code = struct.pack('<I', 0x00000013)
    return code


def main():
    ap = argparse.ArgumentParser(
        prog='a100_80gb_payload',
        description='Write verified A100 80GB register values to CMP 170HX')
    ap.add_argument('--payload', metavar='BDF',
                    help='Write payload to a BAR0 device (e.g. 0000:01:00.0)')
    ap.add_argument('--dry-run', action='store_true',
                    help='List registers without writing')
    ap.add_argument('--generate-fw-patch', metavar='FILE',
                    help='Generate firmware patch binary')
    args = ap.parse_args()

    if args.dry_run:
        write_payload(None, dry_run=True)
    elif args.payload:
        write_payload(args.payload)
    elif args.generate_fw_patch:
        generate_fw_patch(args.generate_fw_patch)
    else:
        ap.print_help()


if __name__ == '__main__':
    main()

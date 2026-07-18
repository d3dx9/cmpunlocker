"""candidate_unlocks.py — Test additional candidate efuse/reg writes.

Extends the mpopaddret chain with NVLink/PCIe/ECC candidate writes,
simulates them in the emulator, and reports which ones succeed
(the PC stays in the IMEM code section after the write).

If the CMP 170HX PCB is truly identical to A100 (which the user
noted), then all candidates should be just efuses/registers that
can be unlocked with register writes. Our exploit chain becomes:
  mpopaddret; sw; mpopaddret; sw; ... ; mpopaddret; sw; jal x0, self

We add extra frames for:
  - NVLink candidates (0x88000C link enable, 0x1180F8 ARC mutex)
  - PCIe candidates (0x000118 Link Control 2)
  - ECC candidates (0x100110 ECC enable, 0x100114 scrub interval)

Each candidate write is tested individually:
  1. Build a chain with just the standard 5 writes + this candidate
  2. Run in emulator
  3. Verify: did the write reach BAR0? Did PC stay in IMEM?
"""

import argparse
import logging
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.booter_emu import extract_booter_sections
from tools.booter_secure import FalconSecureBooter

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('candidate_unlocks')


def make_op(rd, rs1, rs2, funct7, funct3, opcode):
    """Build a 32-bit RV instruction."""
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


# Standard unlock writes (community-verified)
STANDARD_WRITES = [
    (0x9A0204, 0x02669000, 'CFG1 (40GB geometry)'),
    (0x100CE0, 0x0000028a, 'LMR (memory rank)'),
    (0x1FA824, 0x1FFFFE00, 'WPR2 lo (teardown)'),
    (0x1FA828, 0x00000000, 'WPR2 hi (teardown)'),
    (0x8403C4, 0x000000FF, 'resetPLM (open)'),
]

# Candidate writes for NVLink/PCIe/ECC (from find_efuses.py)
CANDIDATES = [
    # NVLink
    (0x82381C, 0x88888888, 'SS0 (compute/NVLink clock)', 'NVLink'),
    (0x823820, 0x00000008, 'SS1 (PLM/NVLink override)', 'NVLink'),
    (0x1180F8, 0x17100000, 'ARC mutex release (community-known)', 'NVLink'),
    (0x88000C, 0x00000001, 'NVLink link enable (guess)', 'NVLink'),
    (0x820050, 0x01FB01E8, 'NVLink init pattern (guess)', 'NVLink'),
    # PCIe
    (0x000118, 0x00000004, 'PCIe Link Control 2 → Gen 4', 'PCIe'),
    (0x000020, 0x00000020, 'PCIe Link Control → Gen 4 enable', 'PCIe'),
    # ECC
    (0x100110, 0x00000001, 'ECC enable bit', 'ECC'),
    (0x100114, 0x00000010, 'ECC scrub interval', 'ECC'),
    # HBM timing / refresh (from FWSEC analysis)
    (0x110600, 0x00000007, 'HBM timing (CMP baseline)', 'HBM'),
    (0x110624, 0x00000190, 'HBM refresh (80GB value)', 'HBM'),
]


def _make_chain(writes, imem_entry, frame_base, imem_base):
    """Build the mpopaddret chain in IMEM + ROP frames in DMEM."""
    SW = struct.pack('<I',
                      (0 << 25) | (1 << 20) | (10 << 15) |
                      (0x2 << 12) | (0 << 7) | 0x23)
    JAL = struct.pack('<I', 0x0000006f)

    code = bytearray()
    n = len(writes)
    for i in range(n):
        code += struct.pack('<I', 0x0000003b)  # mpopaddret
        code += SW
    code += JAL

    frames = bytearray()
    for i, (addr, value, _) in enumerate(writes):
        frame = bytearray(0x18)
        struct.pack_into('<I', frame, 0x08, value)
        struct.pack_into('<I', frame, 0x0C, addr)
        ra = imem_base + imem_entry + (i * 2 + 1) * 4
        struct.pack_into('<I', frame, 0x14, ra)
        frames += frame

    return bytes(code), bytes(frames)


def test_candidate(firmware_path, candidate_addr, candidate_value, candidate_desc):
    """Test a single candidate: does writing it in the ROP chain work?"""
    sections = extract_booter_sections(firmware_path)
    if not sections:
        log.error('No .ga100_* sections found')
        return None

    emu = FalconSecureBooter(
        sections, fuse_value_0x7ca=0, max_steps=10_000,
        trace=False, hmac_bypass=True, auto_hs=True)

    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    FRAME_BASE = 0x400de00

    writes = STANDARD_WRITES + [(candidate_addr, candidate_value, candidate_desc)]
    code, frames = _make_chain(
        writes, IMEM_ENTRY, FRAME_BASE, IMEM_BASE)
    emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
    emu.mem[FRAME_BASE - emu.MEM_BASE:
            FRAME_BASE - emu.MEM_BASE + len(frames)] = frames
    emu.regs[2] = FRAME_BASE
    emu.pc = IMEM_BASE + IMEM_ENTRY
    emu.enter_hs()
    emu.run()

    # Did the candidate write succeed?
    # Look for the candidate's address in BAR0 writes.
    # In our emulator, addresses in 0x0-0x1000000 range (PCIe config)
    # are written via _store (no BAR0 mapping). They just go into emu.mem.
    # We check both BAR0 writes AND emu.mem state.
    last_bar0_write = None
    for a, v in emu.bar0_writes:
        if a == candidate_addr:
            last_bar0_write = v

    # Check if the write happened in emu.mem (for PCIe config space)
    mem_value = None
    if emu.MEM_BASE <= candidate_addr < emu.MEM_BASE + len(emu.mem):
        off = candidate_addr - emu.MEM_BASE
        mem_value = struct.unpack_from('<I', emu.mem, off)[0]

    # Was PC still in code section when exploit finished?
    pc_ok = (IMEM_BASE <= emu.pc < IMEM_BASE + 0x400)
    halted_cleanly = emu.halted and emu.halt_reason == 'step limit 10000 hit at PC=0x' + f'{emu.pc:x}'

    # For BAR0 writes, check the write happened
    success = (last_bar0_write == candidate_value) if last_bar0_write is not None else (mem_value == candidate_value)

    return {
        'success': success,
        'final_pc': emu.pc,
        'pc_ok': pc_ok,
        'bar0_write': last_bar0_write,
        'mem_value': mem_value,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware', help='Path to gsp_tu10x.bin')
    ap.add_argument('--category', help='Filter to category (NVLink, PCIe, ECC, HBM)')
    args = ap.parse_args()

    candidates = CANDIDATES
    if args.category:
        candidates = [c for c in candidates
                      if c[3].lower() == args.category.lower()]

    log.info('=' * 75)
    log.info('CANDIDATE UNLOCK TESTS')
    log.info('  Testing %d candidates', len(candidates))
    log.info('=' * 75)

    results = []
    for addr, value, desc, category in candidates:
        log.info('')
        log.info('Testing 0x%06x = 0x%08x (%s, %s)',
                 addr, value, desc, category)
        r = test_candidate(args.firmware, addr, value, desc)
        if r is None:
            continue

        if r['success']:
            status = '✓ WROTE'
            extra = ''
        else:
            status = '✗ NOT WROTE'
            if r['bar0_write'] is not None:
                extra = f' (got 0x{r["bar0_write"]:08x})'
            elif r['mem_value'] is not None:
                extra = f' (mem 0x{r["mem_value"]:08x})'
            else:
                extra = ''

        log.info('  %s%s', status, extra)
        log.info('  final PC=0x%x, pc_in_imem=%s', r['final_pc'], r['pc_ok'])

        results.append((addr, value, desc, category, r))

    log.info('')
    log.info('=' * 75)
    log.info('SUMMARY')
    log.info('=' * 75)

    # Group by category
    by_cat = {}
    for addr, value, desc, cat, r in results:
        by_cat.setdefault(cat, []).append((addr, value, desc, r))

    for cat, items in by_cat.items():
        log.info('')
        log.info('  %s:', cat)
        for addr, value, desc, r in items:
            mark = '✓' if r['success'] else '?'
            log.info('    [%s] 0x%06x = 0x%08x  (%s)', mark, addr, value, desc)

    log.info('')
    log.info('Interpretation:')
    log.info('  [✓] = write reached its destination (BAR0 or mem)')
    log.info('  [?] = write may not have arrived or PC went off-rail')


if __name__ == '__main__':
    main()
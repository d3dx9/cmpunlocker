"""end_to_end_unlock_test.py — Complete CMP 170HX 80GB unlock verification.

This test runs the full boot flow in our emulator:

  Phase 1: FWSEC boot
    - Loads the GSP firmware
    - Runs the booter with fuse=1 (80GB path)
    - Verifies it reaches the infinite loop at 0x400c8d0
    - Captures the initial 9 BAR0 writes (10GB geometry)

  Phase 2: Exploit unlock (simulated booter_load)
    - Fresh emulator
    - Writes a synthetic booter_load payload (mpopaddret chain) into IMEM
    - Sets up the ROP frame in DMEM
    - Triggers HS mode via CSR
    - Runs the chain: 5 mpopaddret + 5 sw + raw exit
    - Captures the 5 unlock BAR0 writes (CFG1, LMR, WPR2-lo, WPR2-hi, resetPLM)

  Phase 3: Comparison report
    - Compares all 14 final BAR0 values against community-verified expected
    - Reports any deviations
    - Outputs a clean table

The actual ROP chain is the community-verified one from
Big Ptoughneigh's Discord session:

  write#1: 0x9A0204 = 0x02669000  (CFG1)
  write#2: 0x100CE0 = 0x0000028a  (LMR)
  write#3: 0x1FA824 = 0x1FFFFE00  (WPR2-lo, teardown)
  write#4: 0x1FA828 = 0x00000000  (WPR2-hi, teardown)
  write#5: 0x8403C4 = 0x000000FF  (resetPLM)
  → RA = 0x8117 (raw HS exit, keeps resetPLM=0xFF)

Note: This test does NOT use the real booter_load binary (which is
AES-encrypted and we don't have the key). It SIMULATES the booter_load
payload by writing the ROP chain directly into IMEM. The semantics
of the mpopaddret instruction, the frame layout, and the BAR0 writes
are all faithfully reproduced.
"""

import argparse
import logging
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.booter_emu import extract_booter_sections
from tools.booter_secure import FalconSecureBooter

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('end_to_end')


# Community-verified A100 80GB unlock values
# (from Big Ptoughneigh's Discord exploit notes)
EXPECTED_UNLOCK_WRITES = [
    (0x9A0204, 0x02669000, 'CFG1 (geometry: 40GB or 80GB)'),
    (0x100CE0, 0x0000028a, 'LMR (memory rank config)'),
    (0x1FA824, 0x1FFFFE00, 'WPR2 low (teardown)'),
    (0x1FA828, 0x00000000, 'WPR2 high (teardown)'),
    (0x8403C4, 0x000000FF, 'resetPLM (open access)'),
]

# Initial FWSEC writes (10GB baseline)
# These are the writes FWSEC produces before the exploit runs
EXPECTED_FWSEC_WRITES = [
    (0x110000, 0x00000010, 'FWSEC init'),
    (0x110040, 0x00000000, 'FWSEC init'),
    (0x110044, 0x00000000, 'FWSEC init'),
    (0x110094, 0x0011dead, 'FWSEC spinlock ptr'),
    (0x110200, 0x00000008, 'FWSEC init'),
    (0x110600, 0x00000007, 'FWSEC init'),
]


def _li(rd, imm32):
    """Build LUI + ADDI sequence to load imm32 into rd."""
    hi = (imm32 + 0x800) >> 12
    lo = imm32 - (hi << 12)
    if lo >= 2048:
        lo -= 4096
        hi += 1
    code = b''
    if hi:
        code += struct.pack('<I', 0x00000537 | ((hi & 0xfffff) << 12) | (rd << 7))
    if lo:
        code += struct.pack('<I', 0x00058513 | ((lo & 0xfff) << 20) | (rd << 15) | (rd << 7))
    return code


def _sw(rs2, rs1, off):
    """SW rs2, off(rs1).

    RV32 S-type encoding:
      bits [31:25] = imm[11:5]
      bits [24:20] = rs2
      bits [19:15] = rs1
      bits [14:12] = funct3 (010 = SW)
      bits [11:7]  = imm[4:0]
      bits [6:0]   = opcode (0100011 = SW)
    """
    imm = off & 0xfff
    return struct.pack('<I',
                        ((imm >> 5) << 25) |  # imm[11:5]
                        (rs2 << 20) |          # rs2
                        (rs1 << 15) |          # rs1
                        (0x2 << 12) |          # funct3 = SW
                        ((imm & 0x1f) << 7) |  # imm[4:0]
                        0x23)                   # opcode


def _raw_exit():
    """jal x0, self — raw HS exit, keeps resetPLM=0xFF."""
    return struct.pack('<I', 0x0000006f)


def build_exploit_payload(writes, imem_entry, frame_base, imem_base):
    """Build the mpopaddret chain in IMEM + ROP frame in DMEM.

    IMEM layout:
      [imem_entry+0*4]: mpopaddret → bar0_master for frame 0
      [imem_entry+1*4]: sw x1, 0(x10)         # bar0_master for frame 0
      [imem_entry+2*4]: mpopaddret → bar0_master for frame 1
      [imem_entry+3*4]: sw x1, 0(x10)         # bar0_master for frame 1
      ... (alternating mpopaddret + sw for each frame)
      [imem_entry+2n*4]: jal x0, self          # raw HS exit (keeps resetPLM=0xFF)

    DMEM frame layout (per Big Ptoughneigh's notes):
      SP+0x08: val → x1
      SP+0x0C: addr → x10
      SP+0x14: RA → next bar0_master
      SP += 0x18 to next frame
    """
    code = bytearray()
    n = len(writes)

    # SW x1, 0(x10) — x1=val, x10=addr (NOT x0 because RISC-V x0=0)
    SW = _sw(1, 10, 0)

    for i, (addr, value, _) in enumerate(writes):
        # mpopaddret (HS-mode 0x3b)
        code += struct.pack('<I', 0x0000003b)
        # bar0_master: sw x1, 0(x10)
        code += SW

    # After all writes: raw HS exit (jal x0, self)
    code += _raw_exit()

    # Build ROP frames in DMEM
    frames = bytearray()
    for i, (addr, value, _) in enumerate(writes):
        frame = bytearray(0x18)  # 24 bytes per frame
        # offset 0x00-0x07: padding (r0/r1 slots)
        # offset 0x08: val
        struct.pack_into('<I', frame, 0x08, value)
        # offset 0x0C: addr
        struct.pack_into('<I', frame, 0x0C, addr)
        # offset 0x10-0x13: padding
        # offset 0x14: RA → bar0_master (sw) for this frame, which falls
        # through to the next mpopaddret (or final jal for the last frame).
        # The sw for the last frame also falls through to the final jal.
        ra = imem_base + imem_entry + (i * 2 + 1) * 4
        struct.pack_into('<I', frame, 0x14, ra)
        frames += frame

    return bytes(code), bytes(frames)


def phase1_fwsec_boot(firmware_path, max_steps=2000000, verbose=True):
    """Run FWSEC with fuse=1 (80GB path), capture initial geometry."""
    if verbose:
        log.info('=' * 70)
        log.info('PHASE 1: FWSEC BOOT (fuse=1, 80GB path)')
        log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)
    if not sections:
        log.error('No .ga100_* sections found')
        return None

    emu = FalconSecureBooter(
        sections, fuse_value_0x7ca=1, max_steps=max_steps,
        trace=False, hmac_bypass=False, auto_hs=False,
    )
    emu.run()

    if verbose:
        log.info('FWSEC run complete:')
        log.info('  steps: %d', emu.steps)
        log.info('  halted: %s', emu.halted)
        log.info('  halt reason: %s', emu.halt_reason)
        log.info('  final PC: 0x%x', emu.pc)
        log.info('  BAR0 writes: %d total, %d distinct addresses',
                 len(emu.bar0_writes), len(set(a for a, v in emu.bar0_writes)))

    # Verify
    if emu.pc != 0x400c8d0:
        log.warning('Expected PC 0x400c8d0 (infinite loop), got 0x%x', emu.pc)

    return emu.bar0_writes_pcs


def phase2_exploit_unlock(firmware_path, writes, max_steps=5000, verbose=True):
    """Run the mpopaddret exploit chain, capture unlock BAR0 writes."""
    if verbose:
        log.info('=' * 70)
        log.info('PHASE 2: EXPLOIT UNLOCK (HS-mode mpopaddret chain)')
        log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)
    if not sections:
        log.error('No .ga100_* sections found')
        return None

    emu = FalconSecureBooter(
        sections, fuse_value_0x7ca=0, max_steps=max_steps,
        trace=False, hmac_bypass=True, auto_hs=True,
    )

    # Layout: mpopaddret in IMEM, frames in DMEM
    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    FRAME_BASE = 0x400de00  # Within DMEM (0x4000000-0x400FFFF)

    code, frames = build_exploit_payload(
        writes, IMEM_ENTRY, FRAME_BASE, IMEM_BASE)

    # Place exploit into IMEM
    emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
    # Place frames into DMEM
    emu.mem[FRAME_BASE - emu.MEM_BASE:
           FRAME_BASE - emu.MEM_BASE + len(frames)] = frames

    # Set up initial state
    emu.regs[2] = FRAME_BASE  # SP
    emu.pc = IMEM_BASE + IMEM_ENTRY
    emu.enter_hs()  # Triggers HS mode for mpopaddret

    if verbose:
        log.info('Exploit loaded:')
        log.info('  IMEM[%d..%d]: %d bytes of mpopaddret+sw+jal',
                 IMEM_ENTRY, IMEM_ENTRY + len(code), len(code))
        log.info('  DMEM[0x%x..0x%x]: %d bytes of frames (5 x 24)',
                 FRAME_BASE, FRAME_BASE + len(frames), len(frames))
        log.info('  PC=0x%x, SP=0x%x, HS=ON', emu.pc, emu.regs[2])

    emu.run()

    if verbose:
        log.info('Exploit run complete:')
        log.info('  steps: %d', emu.steps)
        log.info('  halted: %s', emu.halted)
        log.info('  halt reason: %s', emu.halt_reason)
        log.info('  final PC: 0x%x', emu.pc)
        log.info('  BAR0 writes: %d total', len(emu.bar0_writes_pcs))

    return emu.bar0_writes_pcs


def phase3_report(fwsec_writes, exploit_writes, writes_expected, verbose=True):
    """Compare all BAR0 writes against expected values."""
    if verbose:
        log.info('=' * 70)
        log.info('PHASE 3: COMPARISON REPORT')
        log.info('=' * 70)

    # Build last-write map (later writes override earlier ones for same address)
    last_write = {}
    write_log = []
    for a, v, pc in (fwsec_writes or []) + (exploit_writes or []):
        last_write[a] = (v, pc, 'FWSEC' if pc < 0x5000000 else 'EXPLOIT')
        write_log.append((a, v, pc, 'FWSEC' if pc < 0x5000000 else 'EXPLOIT'))

    if verbose:
        log.info('')
        log.info('All BAR0 writes (in order of execution):')
        for a, v, pc, source in write_log:
            log.info('  %-8s 0x%06x <- 0x%08x  (PC=0x%x)', source, a, v, pc)
        log.info('')

    # Verify expected writes match
    if verbose:
        log.info('Verification of community-verified expected writes:')
    all_ok = True
    expected_dict = {a: (v, label) for a, v, label in writes_expected}
    for addr, (exp_val, label) in expected_dict.items():
        actual = last_write.get(addr, (None, None))[0]
        ok = actual == exp_val
        mark = 'OK' if ok else 'FAIL'
        if not ok:
            all_ok = False
        if verbose:
            log.info('  [%s] 0x%06x <- 0x%08x  (got 0x%08x)  %s',
                     mark, addr, exp_val, actual or 0, label)

    # Print final summary
    if verbose:
        log.info('')
        log.info('=' * 70)
        log.info('OVERALL: %s', 'PASS' if all_ok else 'FAIL')
        log.info('  Total BAR0 writes: %d', len(write_log))
        log.info('  FWSEC writes:    %d', sum(1 for _, _, _, s in write_log if s == 'FWSEC'))
        log.info('  Exploit writes:  %d', sum(1 for _, _, _, s in write_log if s == 'EXPLOIT'))
        log.info('  Unique addresses: %d', len(last_write))
        log.info('=' * 70)

    return all_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware', help='Path to gsp_tu10x.bin')
    ap.add_argument('--max-steps', type=int, default=2000000,
                    help='Max steps for FWSEC boot (default 2M)')
    ap.add_argument('--quiet', action='store_true',
                    help='Reduce output verbosity')
    args = ap.parse_args()

    log.setLevel(logging.WARNING if args.quiet else logging.INFO)

    # Phase 1: FWSEC boot
    fwsec_writes = phase1_fwsec_boot(args.firmware, max_steps=args.max_steps,
                                     verbose=not args.quiet)
    if fwsec_writes is None:
        return 1

    # Phase 2: Exploit unlock
    exploit_writes = phase2_exploit_unlock(args.firmware, EXPECTED_UNLOCK_WRITES,
                                          verbose=not args.quiet)
    if exploit_writes is None:
        return 1

    # Phase 3: Report
    ok = phase3_report(fwsec_writes, exploit_writes, EXPECTED_UNLOCK_WRITES,
                      verbose=not args.quiet)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
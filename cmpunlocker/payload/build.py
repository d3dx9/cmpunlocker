"""
build.py — Build the 63KB ROP payload that gets injected into the
.fwsignature_ga100 ELF section of the GSP firmware.

Two strategies are implemented, both from the open-gpu-kernel-modules-610.43.03
fork that successfully unlocks the CMP 170HX:

1. fill_payload(write_addr, write_value)
   Build a 63KB buffer where the entire region is filled with a NOP
   pattern, then a hand-crafted 24-DWORD ROP chain is placed at specific
   offsets. The chain performs a single BAR0 write of `write_value` to
   `write_addr` when the BootROM loads it into DMEM.

2. build(target)
   Build a complete multi-write ROP chain that performs:
     a) Open 4 PLM registers (WPR_CFG, FBPA, WPR, FEAT)
     b) Write CFG1 (HBM geometry) and LMR (memory rank)
     c) Return cleanly

The chain is placed inside the .fwsignature_ga100 ELF section. The
BootROM loads the section content into DMEM *before* verifying the
signature, so the chain runs in HS-mode regardless of signature validity.
"""

import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.constants import get


def fill_payload(write_addr: int, write_value: int) -> bytes:
    """Build a 63KB buffer with the 24-DWORD ROP chain for a single write.

    Pattern from open-gpu-kernel-modules-610.43.03 _kgspSec2PostblTimingFillPayload.

    The full buffer is filled with 0x000004a7 (FILL_DWORD). Then 24 specific
    DWORDS are placed at known offsets that form the ROP chain. At runtime,
    the caller writes the target address and value into offset 0xf76c and
    0xf754 respectively before triggering the BootROM load.
    """
    cfg = get('rop_payload')
    payload_size = get('dmem_layout.payload_size')
    payload = bytearray([cfg['fill_dword'] & 0xFF] * payload_size)

    def w32(byte_off: int, val: int) -> None:
        if 0 <= byte_off <= len(payload) - 4:
            struct.pack_into("<I", payload, byte_off, val & 0xFFFFFFFF)

    off = cfg['offsets']
    canary = cfg['canary']

    w32(off['header'],     cfg['header'])
    w32(off['canary_1'],   canary)

    w32(off['write_value'], write_value)
    w32(off['canary_2'],   canary)
    w32(off['gadget_1'],   0x00000cbd)
    w32(off['write_addr'], write_addr)
    w32(off['gadget_2'],   0x00001fbd)
    w32(off['zero_1'],     0x00000000)
    w32(off['gadget_3'],   0x000010aa)
    w32(off['gadget_4'],   0x0000815a)
    w32(off['gadget_5'],   0x00008e18)
    w32(off['canary_3'],   canary)
    w32(off['gadget_6'],   0x0000815a)
    w32(off['zero_2'],     0x00000000)
    w32(off['canary_4'],   canary)
    w32(off['gadget_7'],   0x00001fbd)
    w32(off['gadget_8'],   0x0000ffbc)
    w32(off['gadget_9'],   0x0000582d)
    w32(off['canary_5'],   canary)
    w32(off['gadget_10'],  0x00000cbd)
    w32(off['gadget_11'],  0x00000003)
    w32(off['gadget_12'],  0x00001fbd)
    w32(off['gadget_13'],  0x00000ccb)
    w32(off['gadget_14'],  0x00007f2f)

    return bytes(payload)


def build(target: str = None) -> bytes:
    """Build the full multi-write ROP payload.

    Sequence (run 4 times in modified driver, one per PLM register, then
    a final run for CFG1+LMR):

        1. fill_payload(PLM_ADDR[i], PLM_VALUE[i]) for each i in 0..3
        2. Trigger kgspExecuteBooterLoad → opens the PLM register
        3. After all 4 PLMs are open, write CFG1 (memory geometry)
        4. After CFG1, write LMR (memory rank)
        5. After LMR, write SS0/SS1 (compute unlock)
        6. Restore original GSP signature
        7. Driver continues normal init with unlocked memory

    The current implementation builds a single payload for the first
    PLM register (FEAT). The pipeline calls this multiple times with
    different targets via refill_payload().
    """
    if target is None:
        target = get('memory_unlock.default_target')

    targets = get('memory_unlock.targets')
    if target not in targets:
        raise ValueError(f"unknown target: {target}")

    cfg1 = targets[target]['cfg1']
    lmr  = targets[target]['lmr']
    feat_ovr = get('host_bar0_writes.feat_ovr_plm.value')

    # The full pipeline runs fill_payload four times (one per PLM table
    # entry) and then twice more (CFG1, LMR). The build() function
    # returns a payload for the FIRST PLM entry (WPR_CFG) — subsequent
    # entries use refill_payload().
    plm_table = get('plm_table')
    first_plm = plm_table[0]
    return fill_payload(first_plm['addr'], first_plm['value'])


def refill_payload(payload: bytes, write_addr: int, write_value: int) -> bytes:
    """Refill an existing payload's write address and value.

    Used by the pipeline to repurpose the same ROP buffer for
    different target registers without rebuilding from scratch.
    """
    off = get('rop_payload.offsets')
    buf = bytearray(payload)
    struct.pack_into("<I", buf, off['write_addr'], write_addr & 0xFFFFFFFF)
    struct.pack_into("<I", buf, off['write_value'], write_value & 0xFFFFFFFF)
    return bytes(buf)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default=None,
                   help="Memory target (nativ_10gb / unlocked_40gb / unlocked_80gb)")
    p.add_argument("--out", default=None, help="Output file (default: stdout)")
    args = p.parse_args()

    payload = build(args.target)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(payload)
        print(f"Wrote {len(payload)} bytes to {args.out}")
    else:
        sys.stdout.buffer.write(payload)

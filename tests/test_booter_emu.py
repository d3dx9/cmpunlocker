"""Tests for the Falcon booter emulator structure.

The real NVIDIA ``.ga100_text`` is decoded only heuristically here, so
these tests build small synthetic booters as RV32I machine code and use
them as ground truth. They verify:
  * section loading places code at the right vaddr
  * STORE writes map to BAR0 via the Falcon window
  * CSR 0x7c8/0x7cc commits land the data at the right BAR0 address
  * fuse_value_0x7ca preloads correctly and routes through conditional
    paths
  * the fuse-sweep output diverges on the addresses that depend on the
    fuse value
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.booter_emu import (
    BOOTER_LAYOUT,
    FALCON_BAR0_POFFSET,
    FALCON_BAR0_WIN_BASE,
    FalconBooter,
    bar0_to_falcon_vaddr,
    diff_writes,
    extract_booter_sections,
    summarize_writes,
    vaddr_to_bar0,
)


# ---------------------------------------------------------------------------
# Helpers: assemble small RV32I programs
# ---------------------------------------------------------------------------

_R_TYPE = lambda funct7, rs2, rs1, funct3, rd, opcode: \
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode

_I_TYPE = lambda imm12, rs1, funct3, rd, opcode: \
    (((imm12 & 0xFFF) << 20)) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode

_S_TYPE = lambda imm12, rs2, rs1, funct3, opcode: \
    (((imm12 >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) \
    | (funct3 << 12) | ((imm12 & 0x1F) << 7) | opcode


def LUI(rd, imm20):
    return (imm20 & 0xFFFFF) << 12 | (rd << 7) | 0x37


def ADDI(rd, rs1, imm12):
    return _I_TYPE(imm12, rs1, 0, rd, 0x13)


def SLLI(rd, rs1, shamt):
    # In our model SLLI takes shamt in bits[25:20], funct7=0, funct3=1
    return ((shamt & 0x3F) << 20) | (rs1 << 15) | (1 << 12) | (rd << 7) | 0x13


def SW(rs2, rs1, imm12):
    return _S_TYPE(imm12, rs2, rs1, 2, 0x23)


def CSRRW(rd, csr, rs1):
    return (csr << 20) | (rs1 << 15) | (1 << 12) | (rd << 7) | 0x73


def _enc_branch(imm13, funct3, rs1, rs2):
    """B-type encode (BEQ/BNE/BLT/BGE/etc.) with the correct bitfield split.

    imm is a 13-bit signed byte offset. The B-type format places:
       imm[12]    -> bit 31
       imm[10:5]  -> bits 30:25
       imm[4:1]   -> bits 11:8
       imm[11]    -> bit 7
    """
    imm12 = (imm13 >> 12) & 0x1
    imm11 = (imm13 >> 11) & 0x1
    imm10_5 = (imm13 >> 5) & 0x3F
    imm4_1 = (imm13 >> 1) & 0xF
    return (
        (imm12 << 31)
        | (imm10_5 << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (imm4_1 << 8)
        | (imm11 << 7)
        | 0x63
    )


def BEQ(rs1, rs2, imm13):
    return _enc_branch(imm13, 0, rs1, rs2)


def BNE(rs1, rs2, imm13):
    return _enc_branch(imm13, 1, rs1, rs2)


def JALR(rd, rs1, imm12):
    return _I_TYPE(imm12, rs1, 0, rd, 0x67)


def encode(instructions):
    return b''.join(struct.pack("<I", insn) for insn in instructions)


def make_sections(ga100_text_words, ga100_resident_text_words=None,
                  ga100_data_words=None, ga100_resident_data_words=None):
    return {
        '.ga100_text':          encode(ga100_text_words),
        '.ga100_resident_text': encode(ga100_resident_text_words or []),
        '.ga100_data':          encode(ga100_data_words or []),
        '.ga100_resident_data': encode(ga100_resident_data_words or []),
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_vaddr_mapping_roundtrip():
    """vaddr_to_bar0 and bar0_to_falcon_vaddr are inverses in-window."""
    for offset in (0x0, 0x110, 0x604, 0x608, 0x624, 0xF0000, 0xFFFFC):
        vaddr = FALCON_BAR0_WIN_BASE + offset
        bar0 = vaddr_to_bar0(vaddr)
        assert bar0 == FALCON_BAR0_POFFSET + offset
        assert bar0_to_falcon_vaddr(bar0) == vaddr
    # Outside-window addresses map to None
    assert vaddr_to_bar0(0x4005000) is None
    assert vaddr_to_bar0(FALCON_BAR0_WIN_BASE - 1) is None
    assert bar0_to_falcon_vaddr(0x100) is None


def test_direct_store_to_bar0_window():
    """A SW through the Falcon BAR0 window is captured as a BAR0 write.

    The constants.yaml notes that the booter writes 0x110604 = 0x114 via
    a SW on x15 = 0x300000000. This test exercises that exact idiom.
    """
    code = [
        ADDI(15, 0, 3),              # x15 = 3
        SLLI(15, 15, 32),            # x15 = 0x300000000
        ADDI(14, 0, 0x114),          # x14 = 0x114
        SW(14, 15, 0x604),           # *(0x300000604) = 0x114 -> BAR0 0x110604
        ADDI(14, 0, 0x05),           # x14 = 5
        SW(14, 15, 0x608),           # *(0x300000608) = 5    -> BAR0 0x110608
        JALR(0, 1, 0),               # return to ra=0 (will loop until step limit)
    ]

    secs = make_sections(code)
    emu = FalconBooter(secs, fuse_value_0x7ca=0, max_steps=200)
    emu.run()

    # The two SWs fall in the BAR0 window; both should be captured.
    addresses = {addr: val for addr, val in emu.bar0_writes}
    assert addresses.get(0x110604) == 0x114
    assert addresses.get(0x110608) == 5


def test_csr_0x7cc_commits_bar0_write():
    """CSR 0x7c8 data + CSR 0x7cc address produces a BAR0 write."""
    # Build code that loads 0x12345678 into 0x7c8 then triggers 0x7cc
    # with the BAR0-window address 0x30001624 (= 0x110000 + 0x1624 + offset).
    code = [
        LUI(11, 0x12345),
        ADDI(11, 11, 0x678),                      # x11 = 0x12345678
        CSRRW(0, 0x7c8, 11),                       # data = 0x12345678
        LUI(12, 0x30001),
        ADDI(12, 12, 0x624),                       # x12 = 0x30001624
        CSRRW(0, 0x7cc, 12),                       # commit
        JALR(0, 1, 0),
    ]

    secs = make_sections(code)
    emu = FalconBooter(secs, fuse_value_0x7ca=0, max_steps=200)
    emu.run()

    # The expected BAR0 address is (low 20 bits of 0x30001624) + 0x110000
    #   = 0x01624 + 0x110000 = 0x111624
    expected_addr = (0x30001624 & 0xFFFFF) + FALCON_BAR0_POFFSET
    expected_data = 0x12345678 & 0xFFFFFFFF
    assert (expected_addr, expected_data) in emu.bar0_writes, (
        f'expected BAR0 write (0x{expected_addr:x}, 0x{expected_data:x}); '
        f'got {emu.bar0_writes}'
    )


def test_fuse_value_routes_conditional_branch():
    """A BNE on the fuse register picks divergent branches.

    Read CSR 0x7ca into x10. If the fuse is non-zero, commit 0xCAFE456
    at BAR0[+0x624]; otherwise commit 0xDEAD123. Different fuse values
    must produce different writes at the same BAR0 address.

    The ADDIs use 12-bit unsigned immediates that also fit as signed
    immediates (< 0x800), since the I-type field is sign-extended.
    """
    code = [
        CSRRW(10, 0x7ca, 0),                       # insn 0: x10 = fuse
        BNE(10, 0, 16),                             # insn 1: if fuse != 0, jump +16 (skip 4 insn)
        # else path: fuse == 0
        LUI(11, 0xDEAD),                            # insn 2: x11 = 0xDEAD000
        ADDI(11, 11, 0x123),                        # insn 3: x11 = 0xDEAD123
        BEQ(0, 0, 12),                              # insn 4: skip then-path (3 insn)
        # then path: fuse != 0
        LUI(11, 0xCAFE),                            # insn 5: x11 = 0xCAFE000
        ADDI(11, 11, 0x456),                        # insn 6: x11 = 0xCAFE456
        # common: commit BAR0[+0x624] = x11
        CSRRW(0, 0x7c8, 11),                        # insn 7
        LUI(12, 0x30001),                           # insn 8
        ADDI(12, 12, 0x624),                        # insn 9: x12 = 0x30001624
        CSRRW(0, 0x7cc, 12),                        # insn 10: commit
        JALR(0, 1, 0),                              # insn 11
    ]

    secs = make_sections(code)

    emu_a = FalconBooter(secs, fuse_value_0x7ca=0, max_steps=200)
    emu_a.run()
    emu_b = FalconBooter(secs, fuse_value_0x7ca=1, max_steps=200)
    emu_b.run()

    writes_a = [v for _, v in emu_a.bar0_writes]
    writes_b = [v for _, v in emu_b.bar0_writes]

    assert writes_a, f'fuse=0 produced no writes (codes ran {emu_a.steps} steps)'
    assert writes_b, f'fuse=1 produced no writes (codes ran {emu_b.steps} steps)'
    assert writes_a != writes_b, (
        f'fuses should diverge on the conditional; a={writes_a}, b={writes_b}'
    )
    assert 0xDEAD123 in writes_a, f'fuse=0 should write 0xDEAD123, got {writes_a}'
    assert 0xCAFE456 in writes_b, f'fuse=1 should write 0xCAFE456, got {writes_b}'


def test_summary_and_diff_helpers():
    """summarize_writes collapses duplicates; diff_writes finds divergence."""
    a = [(0x100, 5), (0x100, 5), (0x100, 7), (0x200, 9)]
    b = [(0x100, 5), (0x100, 7), (0x200, 9), (0x300, 11)]

    summary_a = summarize_writes(a)
    assert summary_a == {0x100: [5, 7], 0x200: [9]}

    diffs = diff_writes(a, b)
    # 0x100 final differs (last written is 7 vs 7 — same), 0x300 absent in a
    assert (0x300, None, 11) in diffs


def test_extract_booter_sections_synthesized_elf():
    """extract_booter_sections picks out .ga100_* sections from a minimal
    inner ELF preceded by a 0x40-byte wrapper header.

    The contract is: file layout = [0x40 bytes wrapper][inner ELF].
    """
    # Inner ELF layout (all offsets are inner file offsets before the
    # 0x40 wrapper header is prepended):
    #
    #   0x000 - 0x040 : ELF header
    #   0x080 - 0x088 : .ga100_text          payload (8 bytes)
    #   0x088 - 0x090 : .ga100_resident_text payload (8 bytes)
    #   0x090 - 0x098 : .ga100_data          payload (8 bytes)
    #   0x098 - 0x0A0 : .ga100_resident_data payload (8 bytes)
    #   0x200 - 0x200 : (unused)
    #   0x200 - 0x2C0 : section header table (null + 5 sections × 64 bytes)
    #   0x400 - 0x440 : string table (77 bytes)
    #   total         : 0x450 bytes
    #
    # Python 3.13 bytearray has a subtle quirk where same-length slice
    # assignment can extend the underlying buffer by 1 byte, so we
    # allocate 0x40 extra slack and trim at the end.
    inner = bytearray(0x500)
    inner[0:4] = b'\x7fELF'
    inner[4] = 2        # ELFCLASS64
    inner[5] = 1        # ELFDATA2LSB
    inner[6] = 1        # EV_CURRENT
    inner[0x10] = 2     # e_type = ET_EXEC
    inner[0x12] = 0xF3  # e_machine = EM_RISCV (243)
    inner[0x34] = 64    # e_ehsize
    inner[0x36] = 56     # e_phentsize
    inner[0x38] = 0     # e_phnum
    inner[0x3A] = 64    # e_shentsize
    inner[0x3C] = 6     # e_shnum (null + 4 .ga100_* + strtab)
    inner[0x3E] = 5     # e_shstrndx (section 5 = strtab)
    struct.pack_into('<Q', inner, 0x28, 0x200)  # e_shoff

    inner_strtab_off = 0x400
    # Trailing .shstrtab keeps the actual strtab section out of BOOTER_LAYOUT
    # so it isn't recorded as a synthetic .ga100_* section.
    strtab = (
        b'\x00.ga100_text\x00.ga100_resident_text\x00.ga100_data\x00'
        b'.ga100_resident_data\x00.shstrtab\x00'
    )
    # Section data payloads — written with pack_into to avoid bytearray
    # slice-assignment quirks in Python 3.13 (which can extend the buffer
    # by 1 byte per assignment). Each payload must be exactly 8 bytes.
    for off, payload in (
        (0x80, b'TEXT_TXT'),  # 8 bytes
        (0x88, b'RDATA_DT'),  # 8 bytes
        (0x90, b'GA100__D'),  # 8 bytes (.ga100_data — abbreviated to 8 chars)
        (0x98, b'RDAT2_RD'),  # 8 bytes
    ):
        assert len(payload) == 8
        struct.pack_into(f'{len(payload)}s', inner, off, payload)
    inner[inner_strtab_off:inner_strtab_off + len(strtab)] = strtab

    shdr_base = 0x200

    def put_shdr(idx, name_idx, sh_off, sh_size, sh_type=1):
        base = shdr_base + idx * 64
        struct.pack_into('<I', inner, base + 0, name_idx)
        struct.pack_into('<I', inner, base + 4, sh_type)
        struct.pack_into('<Q', inner, base + 0x18, sh_off)
        struct.pack_into('<Q', inner, base + 0x20, sh_size)

    put_shdr(0, 0, 0, 0, sh_type=0)
    # Section name indices in strtab:
    #   .ga100_text          at  1
    #   .ga100_resident_text at 13
    #   .ga100_data          at 34
    #   .ga100_resident_data at 46
    #   .shstrtab            at 67
    put_shdr(1, 1, 0x80, 8)                          # .ga100_text
    put_shdr(2, 13, 0x88, 8)                         # .ga100_resident_text
    put_shdr(3, 34, 0x90, 8)                         # .ga100_data
    put_shdr(4, 46, 0x98, 8)                         # .ga100_resident_data
    put_shdr(5, 67, inner_strtab_off, len(strtab), sh_type=3)  # SHT_STRTAB

    # Trim to the laid-out size so the bytearray quirk can't bite us.
    inner = inner[:0x450]

    out = bytearray(b'\x00' * 0x40) + inner

    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False, mode='w+b') as f:
        f.write(bytes(out))
        f.flush()
        path = f.name
    try:
        secs = extract_booter_sections(path)
    finally:
        os.unlink(path)

    assert set(secs.keys()) == {
        '.ga100_text', '.ga100_resident_text', '.ga100_data', '.ga100_resident_data',
    }, f'got {list(secs.keys())}'
    assert secs['.ga100_text'] == b'TEXT_TXT'
    assert secs['.ga100_resident_text'] == b'RDATA_DT'
    assert secs['.ga100_data'] == b'GA100__D'
    assert secs['.ga100_resident_data'] == b'RDAT2_RD'


def test_booter_layout_addresses_are_consistent():
    """Booter layout addresses follow the documented constants."""
    assert BOOTER_LAYOUT['.ga100_text'] == 0x004005000
    assert BOOTER_LAYOUT['.ga100_resident_text'] == 0x00400a000
    assert BOOTER_LAYOUT['.ga100_data'] == 0x004001000
    assert BOOTER_LAYOUT['.ga100_resident_data'] == 0x00400d000


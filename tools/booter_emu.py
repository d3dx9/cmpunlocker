"""Offline Falcon SEC2 booter emulator for cmpunlocker 580.x.

The NVIDIA SEC2 Falcon is a small RISC-V microcontroller with custom CSRs.
On GA100 the GSP firmware ships four RISC-V sections —
``.ga100_text``, ``.ga100_resident_text``, ``.ga100_data``,
``.ga100_resident_data`` — and the boot ROM loads ``.ga100_text`` as the
code the Falcon starts executing.

The booter configures the physical FB controller through a memory-mapped
window reachable from the Falcon via vaddr ``0x300000000``-``0x300100000``.
Each BAR0 write is executed as two CSR pokes:

* ``csrrw zero, 0x7c8, data_reg``   — load the data word
* ``csrrw zero, 0x7cc, addr_reg``   — commit: data goes to ``addr_reg``

The CMP 170HX firmware hard-codes the 10 GB geometry. The 80 GB A100 mode
can only be reached by replaying the booter with a different fuse-derived
constant at CSR ``0x7ca`` (which on real hardware reads fuse bits; here we
inject the value to model an A100 die).

This tool extracts the ``.ga100_*`` sections from
``/lib/firmware/nvidia/<ver>/gsp_tu10x.bin``, runs them under a pure-Python
RV32I interpreter with the Falcon CSR semantics, and prints every BAR0
write the booter would emit. With ``--fuse-sweep`` it tries a range of
``0x7ca`` values and reports which writes diverge, exposing the bits that
differentiate 10 GB from 80 GB.

The tool is offline and never touches real hardware.
"""

import argparse
import json
import logging
import struct
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('booter_emu')


# ---------------------------------------------------------------------------
# Falcon-specific CSR semantics
# ---------------------------------------------------------------------------
#
#   CSR 0x7c8 : BAR0 write data register (loaded with the 32-bit value to write)
#   CSR 0x7c9 : BAR0 control / status  (bit-OR writes; not modelled in detail)
#   CSR 0x7ca : FUSE READ                (returns device capability bits; the
#                                          firmware uses these to pick the
#                                          10/20/40/80 GB geometry)
#   CSR 0x7cc : BAR0 write trigger       (commit; carries the target address)
#
# The idiom for a Falcon BAR0 write is:
#     csrrw zero, 0x7c8, value_reg      # data
#     csrrw zero, 0x7cc, addr_reg       # address + commit (triggers the write)

# Falcon's view of the physical BAR0 window starts at vaddr 0x300000000
# and is 1 MB. Empirically the physical BAR0 offset for this window is
# +0x110000 — Family A addresses in common/constants.yaml (0x110xxx) all
# fall in this range.
FALCON_BAR0_WIN_BASE = 0x300000000
FALCON_BAR0_POFFSET = 0x110000
FALCON_BAR0_WIN_SIZE = 0x100000

# Booter vaddr layout per the .ga100_* sections in 580.x firmware.
BOOTER_LAYOUT = {
    '.ga100_text':           0x004005000,
    '.ga100_resident_text':  0x00400a000,
    '.ga100_data':           0x004001000,
    '.ga100_resident_data':  0x00400d000,
}


def vaddr_to_bar0(vaddr):
    """Return physical BAR0 offset for a Falcon-window vaddr, or None."""
    if FALCON_BAR0_WIN_BASE <= vaddr < FALCON_BAR0_WIN_BASE + FALCON_BAR0_WIN_SIZE:
        return (vaddr - FALCON_BAR0_WIN_BASE) + FALCON_BAR0_POFFSET
    return None


def bar0_to_falcon_vaddr(bar0_addr):
    """Inverse of ``vaddr_to_bar0`` for addresses in the Falcon BAR0 window."""
    if FALCON_BAR0_POFFSET <= bar0_addr < FALCON_BAR0_POFFSET + FALCON_BAR0_WIN_SIZE:
        return FALCON_BAR0_WIN_BASE + (bar0_addr - FALCON_BAR0_POFFSET)
    return None


# ---------------------------------------------------------------------------
# Boot section extraction
# ---------------------------------------------------------------------------

def extract_booter_sections(firmware_path):
    """Pull ``.ga100_text``, ``.ga100_resident_text``, ``.ga100_data``,
    ``.ga100_resident_data`` out of the GSP firmware ELF image.

    The shipped GSP file is a wrapper ELF whose program header points at
    the inner booter ELF at file offset 0x40. Returns a dict mapping
    section name to bytes.
    """
    with open(firmware_path, 'rb') as f:
        gsp = f.read()

    fwimage_off = 0x40
    e_shoff = struct.unpack_from("<Q", gsp, fwimage_off + 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp, fwimage_off + 0x3A)[0]
    e_shnum = struct.unpack_from("<H", gsp, fwimage_off + 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", gsp, fwimage_off + 0x3E)[0]

    strtab_hdr = fwimage_off + e_shoff + e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from("<Q", gsp, strtab_hdr + 0x18)[0]
    strtab_sz = struct.unpack_from("<Q", gsp, strtab_hdr + 0x20)[0]
    strtab = gsp[fwimage_off + strtab_off:fwimage_off + strtab_off + strtab_sz]

    sections = {}
    for i in range(e_shnum):
        base = fwimage_off + e_shoff + i * e_shentsize
        name_idx = struct.unpack_from("<I", gsp, base)[0]
        end = strtab.find(b"\x00", name_idx)
        name = strtab[name_idx:end].decode(errors='replace')
        sh_off = struct.unpack_from("<Q", gsp, base + 0x18)[0]
        sh_size = struct.unpack_from("<Q", gsp, base + 0x20)[0]
        if name in BOOTER_LAYOUT:
            sections[name] = gsp[fwimage_off + sh_off:fwimage_off + sh_off + sh_size]
    return sections


# ---------------------------------------------------------------------------
# RV32I interpreter with Falcon CSR semantics
# ---------------------------------------------------------------------------

class FalconBooter:
    """Pure-Python RV32I interpreter with Falcon CSR extensions.

    Models the SEC2 Falcon booter from ``.ga100_text`` +
    ``.ga100_resident_text``. On every CSR ``0x7cc`` write the booter
    "commits" a BAR0 write: the data in CSR ``0x7c8`` is written to the
    physical BAR0 address carried by the ``0x7cc`` value.

    ``fuse_value_0x7ca`` preloads the FUSE-read CSR; runs with different
    values to model A100 die variants.
    """

    MEM_BASE = 0x004000000  # arbitrary vaddr strictly below every section

    def __init__(self, sections, fuse_value_0x7ca=0, max_steps=1_000_000,
                 trace=False, trace_pc=False, pc_entry=None, **_unused):
        """Construct a Falcon interpreter preloaded with ``fuse_value_0x7ca``.

        Extra keyword arguments are ignored so callers can pass e.g.
        ``prompt_on_halt`` without breaking the constructor's signature.
        """
        self.regs = [0] * 32
        # CSR 0x7ca is the FUSE register. Real Falcon hardware reads
        # always return the fuse value; writes trigger a DMA into
        # Falcon memory at the address in the rs1 register. We model
        # the read-only semantics for the value while still recording
        # the writes so `trace=True` can show them.
        self.fuse_value_0x7ca = fuse_value_0x7ca
        self.csrs = {0x7ca: fuse_value_0x7ca}
        self.bar0_writes = []
        self.bar0_writes_pcs = []
        self.max_steps = max_steps
        self.trace = trace
        self.trace_pc = trace_pc
        self.steps = 0
        self.halted = False
        self.halt_reason = None
        self._sections = sections

        needed = 0
        for name, vaddr in BOOTER_LAYOUT.items():
            size = len(sections.get(name, b''))
            needed = max(needed, (vaddr - self.MEM_BASE) + size)
        self.mem = bytearray(needed)

        for name, vaddr in BOOTER_LAYOUT.items():
            data = sections.get(name, b'')
            if not data:
                continue
            off = vaddr - self.MEM_BASE
            self.mem[off:off + len(data)] = data

        # The booter's reset vector is the very first instruction of
        # .ga100_text (the first 0x40 bytes some booters reserve as a
        # boot descriptor are themselves code on GA100 SEC2; the entry is
        # at the section start, not +0x40).
        self.pc = pc_entry if pc_entry is not None else BOOTER_LAYOUT['.ga100_text'] + 0x00

    # ---- helpers -----------------------------------------------------------

    @staticmethod
    def _sxt(x, b):
        """Sign-extend the low ``b`` bits of ``x``."""
        return x - (1 << b) if x & (1 << (b - 1)) else x

    def _read_v(self, vaddr, sz):
        off = vaddr - self.MEM_BASE
        if off < 0 or off + sz > len(self.mem):
            # Unmapped: return fuse-derived bytes (low byte = low
            # fuse byte) so LBU/LW from a fuse-DMA region produces
            # fuse-dependent branch inputs. Without this the booter
            # never reaches size-dependent conditional paths.
            if sz <= 8:
                return (self.fuse_value_0x7ca >> ((off & 7) * 8)) & ((1 << (sz * 8)) - 1)
            return 0
        return int.from_bytes(self.mem[off:off + sz], 'little')

    def _write_v(self, vaddr, val, sz):
        off = vaddr - self.MEM_BASE
        if off < 0 or off + sz > len(self.mem):
            return
        self.mem[off:off + sz] = (val & ((1 << (sz * 8)) - 1)).to_bytes(sz, 'little')

    def _store(self, addr, val, sz, pc):
        self._write_v(addr, val, sz)
        bar0_addr = vaddr_to_bar0(addr)
        if bar0_addr is not None:
            v32 = val & ((1 << (sz * 8)) - 1)
            self.bar0_writes.append((bar0_addr, v32))
            self.bar0_writes_pcs.append((bar0_addr, v32, pc))
            if self.trace:
                log.info('BAR0 W 0x%06x <- 0x%08x  (Falcon 0x%x, sz=%d, pc=0x%x)',
                         bar0_addr, v32, addr, sz, pc)

    def _handle_csr_write(self, csr, _old_unused, new_val, pc, rs1_val=0):
        """Side-effect handler for Falcon CSRs.

        ``csr`` is the CSR number; ``new_val`` is the just-written
        value; ``pc`` is the address of the CSRRW instruction (for
        tracing); ``rs1_val`` is the rs1 register value at the time of
        the write (needed for the 0x7ca/0x7cb DMA semantics).

        Falcon-specific semantics we model:

        * CSR 0x7c8 : write-only data register; holds the data word
                       for an upcoming BAR0 write.
        * CSR 0x7c9 : control / status register (tracing only here).
        * CSR 0x7ca : FUSE-DMA destination address register. A write
                       to 0x7ca with rs1=address triggers a DMA that
                       copies the boot-time fuse value into Falcon
                       memory at that address.
        * CSR 0x7cb : FUSE-DMA control: 0 = write fuse_value_0x7ca;
                       1 = also DMA additional bytes. Real semantics
                       vary by driver/firmware build; we model the
                       write-the-fuse-value pattern.
        * CSR 0x7cc : BAR0 write trigger — data from 0x7c8 is written
                       to the BAR0 address encoded in new_val.
        """
        del _old_unused  # API reserve
        if csr == 0x7cc:
            data = self.csrs.get(0x7c8, 0) & 0xFFFFFFFFFFFFFFFF
            win_off = (new_val & 0xFFFFFFFF) & (FALCON_BAR0_WIN_SIZE - 1)
            vaddr = FALCON_BAR0_WIN_BASE + win_off
            self._store(vaddr, data, 4, pc)
        elif csr == 0x7ca:
            # DMA the fuse value into Falcon memory at rs1 (where rs1
            # is the address). This is the bit that makes subsequent
            # LBU/LW instructions see fuse-derived data.
            addr = rs1_val & 0xFFFFFFFF
            if addr:
                # write 8 bytes of fuse data (LSB = fuse value, high
                # bits are the high half of the simulated register).
                self._write_v(addr, self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF, 8)
                if self.trace:
                    log.info('FUSE DMA: 0x%x -> mem[0x%x] (pc=0x%x)',
                             self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF, addr, pc)
        elif csr == 0x7cb:
            if self.trace:
                log.info('BAR0 control <- 0x%x (pc=0x%x)', new_val & 0xFFFFFFFF, pc)

    # ---- single-step -------------------------------------------------------

    def step(self):
        if self.halted:
            return False

        off = self.pc - self.MEM_BASE
        if off < 0 or off + 4 > len(self.mem):
            self.halted = True
            self.halt_reason = f'PC 0x{self.pc:x} out of memory'
            return False
        # Confirm PC is inside a code-section (.ga100_text or
        # .ga100_resident_text) — without this, jumps that target the
        # .ga100_data / .ga100_resident_data regions execute them as
        # instructions, which produces bogus writes.
        rt_lo = BOOTER_LAYOUT['.ga100_resident_text']
        rt_hi = rt_lo + len(self._sections.get('.ga100_resident_text', b''))
        tx_lo = BOOTER_LAYOUT['.ga100_text']
        tx_hi = tx_lo + len(self._sections.get('.ga100_text', b''))
        if not (tx_lo <= self.pc < tx_hi or rt_lo <= self.pc < rt_hi):
            self.halted = True
            self.halt_reason = (
                f'PC 0x{self.pc:x} outside any code section (data/'
                f'rodata jump). booter JALR went off-rail — likely a '
                f'decoder fidelity gap.')
            return False
        insn = struct.unpack_from("<I", self.mem, off)[0]
        self.steps += 1
        if self.steps > self.max_steps:
            self.halted = True
            self.halt_reason = f'step limit {self.max_steps} hit at PC=0x{self.pc:x}'
            return False
        if self.trace_pc:
            log.info('PC=0x%x  insn=0x%08x', self.pc, insn)
        return self.exec(insn, self.pc)

    def _exec_op(self, rd, v1, v2, funct3, funct7, insn):
        """Execute an RV32 OP-family instruction (opc 0x33 or Falcon 0x3b).

        Returns ``(handled, msg)``. ``handled`` is True when the
        instruction executed. ``msg`` is non-None when the opcode was
        unrecognised.
        """
        # RV32I OP base
        if funct7 == 0:
            if funct3 == 0:
                self.regs[rd] = (v1 + v2) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 1:
                self.regs[rd] = (v1 << (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 2:
                self.regs[rd] = 1 if self._sxt(v1, 64) < self._sxt(v2, 64) else 0
                return True, None
            if funct3 == 3:
                self.regs[rd] = 1 if v1 < v2 else 0
                return True, None
            if funct3 == 4:
                self.regs[rd] = (v1 ^ v2) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 5:
                self.regs[rd] = (v1 >> (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 6:
                self.regs[rd] = (v1 | v2) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 7:
                self.regs[rd] = (v1 & v2) & 0xFFFFFFFFFFFFFFFF
                return True, None
        # RV32I OP alt-subset
        if funct7 == 0x20:
            if funct3 == 0:
                self.regs[rd] = (v1 - v2) & 0xFFFFFFFFFFFFFFFF
                return True, None
            if funct3 == 5:
                if v1 & (1 << 63):
                    shamt = v2 & 0x3f
                    self.regs[rd] = (
                        (v1 >> shamt)
                        | (((1 << shamt) - 1) << (64 - shamt))
                    ) & 0xFFFFFFFFFFFFFFFF
                else:
                    self.regs[rd] = (v1 >> (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
                return True, None
        # RV32M extension (MUL / MULH / MULHSU / MULHU / DIV / DIVU / REM / REMU)
        if funct7 == 0x01:
            mask32 = 0xFFFFFFFFFFFFFFFF
            s1 = self._sxt(v1 & 0xFFFFFFFF, 32)
            s2 = self._sxt(v2 & 0xFFFFFFFF, 32)
            if funct3 == 0:  # MUL
                self.regs[rd] = (v1 * v2) & mask32
                return True, None
            if funct3 == 1:  # MULH
                self.regs[rd] = ((s1 * s2) >> 32) & mask32
                return True, None
            if funct3 == 2:  # MULHSU
                self.regs[rd] = ((s1 * (v2 & 0xFFFFFFFF)) >> 32) & mask32
                return True, None
            if funct3 == 3:  # MULHU
                self.regs[rd] = (((v1 & 0xFFFFFFFF) * (v2 & 0xFFFFFFFF)) >> 32) & mask32
                return True, None
            if funct3 == 4:  # DIV (signed)
                if v2 == 0:
                    self.regs[rd] = (1 << 32) - 1   # canonical NaN-boxed -1
                elif v1 == (1 << 63) and (v2 & 0xFFFFFFFFFFFFFFFF) == mask32:
                    self.regs[rd] = (1 << 63)        # signed-overflow canonical
                else:
                    q = s1 // s2
                    if q < 0:
                        self.regs[rd] = q & mask32
                    else:
                        self.regs[rd] = q
                return True, None
            if funct3 == 5:  # DIVU
                if v2 == 0:
                    self.regs[rd] = (1 << 32) - 1
                else:
                    self.regs[rd] = (v1 // v2) & mask32
                return True, None
            if funct3 == 6:  # REM (signed)
                if v2 == 0:
                    self.regs[rd] = v1 & mask32
                elif v1 == (1 << 63) and (v2 & 0xFFFFFFFFFFFFFFFF) == mask32:
                    self.regs[rd] = 0
                else:
                    r = s1 % s2
                    if r < 0:
                        self.regs[rd] = r & mask32
                    else:
                        self.regs[rd] = r
                return True, None
            if funct3 == 7:  # REMU
                if v2 == 0:
                    self.regs[rd] = v1 & mask32
                else:
                    self.regs[rd] = (v1 % v2) & mask32
                return True, None
        # Zbb RORI (rotate right immediate). Falcon may use it with
        # funct7=0x30 for OPIMM-shift-by-funct5-amount variants.
        if funct7 in (0x30,):
            shamt = funct3  # funct3 encodes the shift amount
            v = v1 & 0xFFFFFFFF
            self.regs[rd] = (((v >> shamt) | (v << (32 - shamt))) & 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
            return True, None
        return False, 'unknown OP funct3/funct7'

    def exec(self, insn, pc_at):
        opc = insn & 0x7f
        rd = (insn >> 7) & 0x1f
        funct3 = (insn >> 12) & 0x7
        rs1 = (insn >> 15) & 0x1f
        rs2 = (insn >> 20) & 0x1f
        funct7 = (insn >> 25) & 0x7f

        # x0 always reads/writes zero
        self.regs[0] = 0

        if opc == 0x37:  # LUI
            imm = insn >> 12
            self.regs[rd] = (imm << 12) & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x17:  # AUIPC
            # imm is the high 20 bits of the I-type slot, sign-extended
            # from 20 bits (matches the RISC-V spec; without this we
            # end up at wildly wrong PCs for `auipc ra, <negative>`.)
            imm = self._sxt((insn >> 12) & 0xFFFFF, 20)
            self.regs[rd] = (self.pc + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x13:  # OPIMM
            imm = self._sxt((insn >> 20) & 0xfff, 12)
            v1 = self.regs[rs1]
            if funct3 == 0:    # ADDI
                self.regs[rd] = (v1 + imm) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 1:  # SLLI
                shamt = (insn >> 20) & 0x3f
                self.regs[rd] = (v1 << shamt) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 2:  # SLTI
                self.regs[rd] = 1 if v1 < imm else 0
            elif funct3 == 3:  # SLTIU
                self.regs[rd] = 1 if (v1 & 0xFFFFFFFFFFFFFFFF) < (imm & 0xFFFFFFFFFFFFFFFF) else 0
            elif funct3 == 4:  # XORI
                self.regs[rd] = (v1 ^ imm) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 5:  # SRLI/SRAI/Falcon-shift
                shamt = (insn >> 20) & 0x3f
                if funct7 == 0:    # SRLI
                    self.regs[rd] = (v1 >> shamt) & 0xFFFFFFFFFFFFFFFF
                elif funct7 == 0x20:  # SRAI
                    if v1 & (1 << 63):
                        self.regs[rd] = ((v1 >> shamt) | (((1 << shamt) - 1) << (64 - shamt))) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = (v1 >> shamt) & 0xFFFFFFFFFFFFFFFF
                elif funct7 == 0x30:  # RORI (Zbb — rotate right immediate)
                    v = v1 & 0xFFFFFFFF
                    if shamt:
                        self.regs[rd] = (((v >> shamt) | (v << (32 - shamt))) & 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = v1
                else:
                    # Falcon non-standard SRLI encoding (likely with the
                    # 6-bit shamt split across funct7:0 and imm:5). We
                    # treat it as a logical right shift with shamt taken
                    # from the 5-bit slot. This is good enough to clear
                    # unknown-OPIMM warnings; instruction semantics
                    # need confirming for production use.
                    self.regs[rd] = (v1 >> (shamt & 0x1f)) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 6:  # ORI
                self.regs[rd] = (v1 | imm) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 7:  # ANDI
                self.regs[rd] = (v1 & imm) & 0xFFFFFFFFFFFFFFFF
            else:
                log.warning('unknown OPIMM funct3=%d insn=0x%x', funct3, insn)
            self.pc += 4
        elif opc in (0x33, 0x3b):  # OP / Falcon-OP (duplicate space)
            # Falcon reuses opc=0x33's semantics under a second opcode
            # (0x3b) for what looks like an internal Falcon double-issued
            # ALU. Behaviour matches: funct7=0 → base, funct7=0x20 →
            # SUB/SRA, funct7=0x01 → RV32M, funct7=0x30 → RORI (Zbb).
            v1 = self.regs[rs1]
            v2 = self.regs[rs2]
            handled, unknown_msg = self._exec_op(rd, v1, v2, funct3, funct7, insn)
            if not handled and unknown_msg:
                log.warning('unknown OP (opc=0x%x) funct3=%d funct7=0x%x insn=0x%x',
                            opc, funct3, funct7, insn)
            self.pc += 4
        elif opc == 0x03:  # LOAD
            imm = self._sxt((insn >> 20) & 0xfff, 12)
            addr = (self.regs[rs1] + imm) & 0xFFFFFFFFFFFFFFFF
            sz_map = {0: 1, 1: 2, 2: 4, 3: 8, 4: 1, 5: 2, 6: 4}  # LB/LH/LW/LD/LBU/LHU/LWU
            signed_map = {0: True, 1: True, 2: True, 3: True, 4: False, 5: False, 6: False}
            sz = sz_map.get(funct3)
            signed = signed_map.get(funct3)
            if sz is None:
                log.warning('unknown LOAD funct3=%d insn=0x%x', funct3, insn)
                self.pc += 4
                return True
            val = self._read_v(addr, sz)
            if signed and sz < 8 and (val >> (sz * 8 - 1)) & 1:
                val -= (1 << (sz * 8))
            self.regs[rd] = val & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x23:  # STORE
            imm = self._sxt(((insn >> 25) << 5) | ((insn >> 7) & 0x1f), 12)
            addr = (self.regs[rs1] + imm) & 0xFFFFFFFFFFFFFFFF
            sz_map = {0: 1, 1: 2, 2: 4, 3: 8}
            sz = sz_map.get(funct3)
            if sz is None:
                log.warning('unknown STORE funct3=%d insn=0x%x', funct3, insn)
                self.pc += 4
                return True
            val = self.regs[rs2]
            self._store(addr, val, sz, pc_at)
            self.pc += 4
        elif opc == 0x63:  # BRANCH
            v1 = self.regs[rs1]
            v2 = self.regs[rs2]
            imm = self._sxt(
                ((insn >> 31) & 1) << 12
                | ((insn >> 7) & 1) << 11
                | ((insn >> 25) & 0x3f) << 5
                | ((insn >> 8) & 0xf) << 1,
                13,
            )
            taken = False
            if funct3 == 0:
                taken = v1 == v2
            elif funct3 == 1:
                taken = v1 != v2
            elif funct3 == 4:
                taken = self._sxt(v1, 64) < self._sxt(v2, 64)
            elif funct3 == 5:
                taken = self._sxt(v1, 64) >= self._sxt(v2, 64)
            elif funct3 == 6:
                taken = v1 < v2
            elif funct3 == 7:
                taken = v1 >= v2
            self.pc = (self.pc + imm) if taken else (self.pc + 4)
        elif opc == 0x6f:  # JAL
            imm = self._sxt(
                ((insn >> 31) & 1) << 20
                | ((insn >> 12) & 0xff) << 12
                | ((insn >> 20) & 1) << 11
                | ((insn >> 21) & 0x3ff) << 1,
                21,
            )
            if rd != 0:
                self.regs[rd] = (self.pc + 4) & 0xFFFFFFFFFFFFFFFF
            self.pc = (self.pc + imm) & 0xFFFFFFFFFFFFFFFF
        elif opc == 0x67:  # JALR
            imm = self._sxt((insn >> 20) & 0xfff, 12)
            tgt = (self.regs[rs1] + imm) & ~1
            if rd != 0:
                self.regs[rd] = (self.pc + 4) & 0xFFFFFFFFFFFFFFFF
            self.pc = tgt & 0xFFFFFFFFFFFFFFFF
        elif opc == 0x73:  # SYSTEM (CSR)
            csr_addr = (insn >> 20) & 0xfff
            if funct3 == 1:   # CSRRW
                old = self.csrs.get(csr_addr, 0)
                # CSR 0x7ca reads always return the fused value, not the
                # written value. The booter's CSR writes to 0x7ca/0x7cb
                # trigger DMA copy into Falcon memory, not register writes.
                # We simulate that by keeping self.csrs[0x7ca] pinned.
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                else:
                    self.csrs[csr_addr] = self.regs[rs1] & 0xFFFFFFFFFFFFFFFF
                if rd != 0:
                    self.regs[rd] = (old if csr_addr != 0x7ca
                                      else self.fuse_value_0x7ca) & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            elif funct3 == 2: # CSRRS
                old = self.csrs.get(csr_addr, 0)
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                elif rs1 != 0:
                    self.csrs[csr_addr] = old | (self.regs[rs1] & 0xFFFFFFFFFFFFFFFF)
                else:
                    self.csrs.setdefault(csr_addr, old)
                if rd != 0:
                    if csr_addr == 0x7ca:
                        self.regs[rd] = self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            elif funct3 == 3: # CSRRC
                old = self.csrs.get(csr_addr, 0)
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                elif rs1 != 0:
                    self.csrs[csr_addr] = old & ~(self.regs[rs1] & 0xFFFFFFFFFFFFFFFF)
                else:
                    self.csrs.setdefault(csr_addr, old)
                if rd != 0:
                    if csr_addr == 0x7ca:
                        self.regs[rd] = self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            elif funct3 == 5: # CSRRWI
                old = self.csrs.get(csr_addr, 0)
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                else:
                    self.csrs[csr_addr] = rs1 & 0xFFFFFFFFFFFFFFFF  # rs1 field is imm
                if rd != 0:
                    self.regs[rd] = (old if csr_addr != 0x7ca
                                      else self.fuse_value_0x7ca) & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            elif funct3 == 6: # CSRRSI
                old = self.csrs.get(csr_addr, 0)
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                elif rs1 != 0:
                    self.csrs[csr_addr] = old | (rs1 & 0xFFFFFFFFFFFFFFFF)
                else:
                    self.csrs.setdefault(csr_addr, old)
                if rd != 0:
                    if csr_addr == 0x7ca:
                        self.regs[rd] = self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            elif funct3 == 7: # CSRRCI
                old = self.csrs.get(csr_addr, 0)
                if csr_addr == 0x7ca:
                    self.csrs[csr_addr] = self.fuse_value_0x7ca
                elif rs1 != 0:
                    self.csrs[csr_addr] = old & ~(rs1 & 0xFFFFFFFFFFFFFFFF)
                else:
                    self.csrs.setdefault(csr_addr, old)
                if rd != 0:
                    if csr_addr == 0x7ca:
                        self.regs[rd] = self.fuse_value_0x7ca & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr], pc_at,
                                                 rs1_val=(self.regs[rs1] if funct3 in (1,2,3) else rs1))
            else:
                log.warning('unknown CSR funct3=%d csr=0x%x insn=0x%x', funct3, csr_addr, insn)
            self.pc += 4
        elif opc == 0x1b:  # AMO
            funct5 = (insn >> 27) & 0x1f
            addr = self.regs[rs1]
            if funct5 == 0x02:  # LR.W
                self.regs[rd] = self._read_v(addr, 4) & 0xFFFFFFFFFFFFFFFF
                self.pc += 4
            elif funct5 == 0x03:  # SC.W
                self._write_v(addr, self.regs[rs2], 4)
                self.regs[rd] = 0
                self.pc += 4
            elif funct5 in (0x00, 0x01, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c):
                v = self._read_v(addr, 4) & 0xFFFFFFFF
                rs2_v = self.regs[rs2] & 0xFFFFFFFF
                new_v = None
                if funct5 == 0x00:    # AMOADD
                    new_v = (v + rs2_v) & 0xFFFFFFFF
                elif funct5 == 0x01:  # AMOSWAP
                    new_v = rs2_v
                elif funct5 == 0x04:  # AMOXOR
                    new_v = v ^ rs2_v
                elif funct5 == 0x08:  # AMOOR
                    new_v = v | rs2_v
                elif funct5 == 0x0c:  # AMOAND
                    new_v = v & rs2_v
                elif funct5 == 0x10:
                    new_v = min(v, rs2_v) if (v >> 31) == (rs2_v >> 31) else (rs2_v if (v >> 31) else v)
                elif funct5 == 0x14:
                    new_v = max(v, rs2_v) if (v >> 31) == (rs2_v >> 31) else (v if (v >> 31) else rs2_v)
                elif funct5 == 0x18:  # AMOMINU
                    new_v = min(v, rs2_v)
                elif funct5 == 0x1c:  # AMOMAXU
                    new_v = max(v, rs2_v)
                self._write_v(addr, new_v if new_v is not None else v, 4)
                if rd != 0:
                    self.regs[rd] = v
                self.pc += 4
            else:
                # Unknown / non-standard AMO (e.g. funct5=0x1d). Falcon-specific.
                # Treat as NOP — advance PC, do not touch memory or registers.
                self.pc += 4
        else:
            log.warning('unknown opcode 0x%x insn=0x%x at PC=0x%x', opc, insn, self.pc)
            self.pc += 4
        return True

    # ---- run to completion -------------------------------------------------

    def run(self, max_steps=None):
        if max_steps is not None:
            self.max_steps = max_steps
        while self.step():
            if self.halted:
                break
        if self.halt_reason:
            log.warning('halted: %s', self.halt_reason)
        return self.halted


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def summarize_writes(writes):
    """Collapse repeated identical writes to the same BAR0 address.

    ``writes`` is the list of (bar0_addr, value) tuples recorded in order
    of execution. Returns a dict mapping bar0_addr -> list of distinct
    values, preserving first-seen order.
    """
    out = {}
    for addr, value in writes:
        out.setdefault(addr, [])
        if value not in out[addr]:
            out[addr].append(value)
    return out


def diff_writes(writes_a, writes_b):
    """Return the BAR0 addresses whose value diverges between two runs.

    Each input is the raw ``bar0_writes`` list (in execution order).
    Returns a list of (addr, val_a, val_b) tuples for addresses whose
    final value (most-recent write) differs, plus any address only
    present in one run.
    """
    last_a = {}
    for addr, value in writes_a:
        last_a[addr] = value
    last_b = {}
    for addr, value in writes_b:
        last_b[addr] = value

    addrs = sorted(set(last_a) | set(last_b))
    diffs = []
    for addr in addrs:
        va = last_a.get(addr)
        vb = last_b.get(addr)
        if va != vb:
            diffs.append((addr, va, vb))
    return diffs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        prog='booter_emu',
        description='Offline Falcon booter emulator (cmpunlocker 580.x)',
    )
    p.add_argument('firmware', help='Path to gsp_tu10x.bin')
    p.add_argument('--fuse', default='0',
                   help='CSR 0x7ca value to preload (hex or int). Default 0 (10 GB CMP).')
    p.add_argument('--fuse-sweep', default=None,
                   help='Comma-separated list of fuse values to run, e.g. "0,1,2,ff".')
    p.add_argument('--max-steps', type=int, default=500_000,
                   help='Steps per run before giving up. Default 500000.')
    p.add_argument('--trace', action='store_true', help='Verbose BAR0-write tracing.')
    p.add_argument('--list-sections', action='store_true',
                   help='Just dump the extracted booter sections and exit.')
    p.add_argument('--json', default=None,
                   help='Write machine-readable run output to this file.')
    return p


def _parse_int(x):
    return int(x, 16) if x.lower().startswith('0x') or any(c in 'abcdef' for c in x.lower()) else int(x)


def _run_one(firmware_path, fuse_val, max_steps, trace):
    log.info('extracting booter sections from %s', firmware_path)
    secs = extract_booter_sections(firmware_path)
    if not secs:
        raise SystemExit(f'no .ga100_* sections found in {firmware_path}')
    log.info('found: %s', {k: len(v) for k, v in secs.items()})

    log.info('running with fuse_value_0x7ca=0x%x', fuse_val)
    emu = FalconBooter(secs, fuse_value_0x7ca=fuse_val,
                        max_steps=max_steps, trace=trace)
    emu.run()
    log.info('run complete: %d steps, %d BAR0 writes, PC=0x%x',
             emu.steps, len(emu.bar0_writes), emu.pc)
    return emu


def main(argv=None):
    args = _build_parser().parse_args(argv)

    if args.list_sections:
        secs = extract_booter_sections(args.firmware)
        print(f'sections in {args.firmware}:')
        for name, data in secs.items():
            print(f'  {name}: 0x{len(data):x} bytes')
        return 0

    if args.fuse_sweep:
        fuses = [_parse_int(x) for x in args.fuse_sweep.split(',')]
        runs = []
        for f in fuses:
            emu = _run_one(args.firmware, f, args.max_steps, args.trace)
            runs.append((f, emu.bar0_writes))
            print()
            print(f'=== fuse=0x{f:x} — {len(emu.bar0_writes)} writes ===')
            for addr, val in emu.bar0_writes:
                print(f'  0x{addr:06x} <- 0x{val:08x}')
        print()
        print('=== DIFFS BETWEEN FIRST AND EVERY OTHER RUN ===')
        base_fuse, base_writes = runs[0]
        for fuse, writes in runs[1:]:
            diffs = diff_writes(base_writes, writes)
            print(f'fuse=0x{base_fuse:x} vs fuse=0x{fuse:x}: {len(diffs)} diverging addresses')
            for addr, va, vb in diffs:
                va_str = f'{va:#010x}' if va is not None else 'absent    '
                vb_str = f'{vb:#010x}' if vb is not None else 'absent    '
                print(f'  0x{addr:06x}: {va_str}  ->  {vb_str}')
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump({
                    'fuses': [{'fuse': f, 'writes': w} for f, w in runs],
                }, f, indent=2)
            log.info('wrote %s', args.json)
        return 0

    fuse_val = _parse_int(args.fuse)
    emu = _run_one(args.firmware, fuse_val, args.max_steps, args.trace)
    summary = summarize_writes(emu.bar0_writes)
    print()
    print(f'=== BAR0 WRITES (fuse=0x{fuse_val:x}, {len(emu.bar0_writes)} total, {len(summary)} distinct addresses) ===')
    for addr in sorted(summary.keys()):
        vals = summary[addr]
        if len(vals) == 1:
            print(f'  0x{addr:08x} = 0x{vals[0]:08x}')
        else:
            for v in vals:
                print(f'  0x{addr:08x} <- 0x{v:08x}')

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({
                'fuse': fuse_val,
                'bar0_writes': [
                    {'addr': addr, 'value': val, 'pc': pc}
                    for (addr, val, pc) in emu.bar0_writes_pcs
                ],
                'summary': {f'0x{a:08x}': [f'0x{v:08x}' for v in vs]
                            for a, vs in summary.items()},
            }, f, indent=2)
        log.info('wrote %s', args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())

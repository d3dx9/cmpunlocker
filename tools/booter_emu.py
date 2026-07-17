"""
Offline Falcon booter emulator for cmpunlocker 580.159.03.

Emulates the SEC2 Falcon booter (.ga100_text + .ga100_resident_text) using
angr's RISC-V engine with custom handlers for the Falcon-specific CSR
instructions (0x7c8-0x7cc) that implement the BAR0 MMIO write mechanism.

Output: a log of every BAR0 write the booter would perform, with the
computed target address and value. With different "fuse" inputs (modeled
by initializing the Falcon CSRs differently), we can find conditional
paths and find the 80 GB mode configuration writes.

Usage:
  python3 -m tools.booter_emu /lib/firmware/nvidia/580.159.03/gsp_tu10x.bin
"""

import sys
import struct
import logging
from pathlib import Path

import angr
import claripy

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('booter_emu')


# Falcon-specific CSRs (NVIDIA's Falcon microarchitecture extends RISC-V)
# Based on the cmpunlocker / Discord transcript analysis:
#   CSR 0x7c8: BAR0 write data register (written by SW rX, 0x7c8, ...)
#   CSR 0x7c9: BAR0 control / status (set by bit-OR writes)
#   CSR 0x7ca: FUSE READ (returns device-specific capability bits including memory size)
#   CSR 0x7b: related control
#   CSR 0x7cc: BAR0 write trigger (write address + commit)
#
# The booter executes writes via the idiom:
#   csrrw zero, 0x7c8, value_reg     # data
#   csrrw zero, 0x7cc, addr_reg     # address + commit (triggers the write)
#
# Some functions also read CSR 0x7ca to get fuse-derived values.

BAR0_WRITES = []  # list of (addr, value) captured during emulation
CSR_SNAPSHOTS = {}  # snapshots of CSR state at interesting points


def make_falcon_state_factory(fuse_value_0x7ca=0):
    """Returns an angr SimState factory pre-configured for the Falcon booter.

    fuse_value_0x7ca: what CSR 0x7ca (the 'fuse' register) returns. Default 0
    (10 GB CMP 170HX). Try different values to simulate 80 GB A100 fuses.
    """

    def factory(blobs, **kwargs):
        # Memory layout (approximate — the real booter uses similar but
        # we don't know exact IMEM/DMEM mapping; we lay out the .ga100_text
        # at IMEM 0 and treat the rest as opaque data memory).

        # Base addresses (convention used by cmpunlocker):
        IMEM_BASE = 0x40000000  # where .ga100_text is loaded
        # The booter's .ga100_text section has vaddr 0x4005000 but
        # cmpunlocker's payload_frames.frame_start_addr = 0xFF48 is in DMEM.
        # The Falcon booter is loaded at offset 0x4005000 by the boot ROM.
        # For our emulator, we put .ga100_text at 0x4005000.
        BOOT_TEXT_VADDR = 0x4005000
        BOOT_RES_TEXT_VADDR = 0x400A000
        BOOT_DATA_VADDR = 0x4001000
        BOOT_RES_DATA_VADDR = 0x400D000

        # We need to find the .ga100_text etc. sections in the firmware
        raise NotImplementedError("Use the script that loads the firmware")

    return factory


# Inline state machine (faster than angr for this small booter)
class FalconBooter:
    """Lightweight interpreter for the Falcon booter."""

    def __init__(self, sections, fuse_value_0x7ca=0, trace_writes=True):
        """sections: dict mapping section name -> bytes.
           We place each section at its real booter vaddr in a single memory image.
           Falcon booter vaddr layout (per cmpunlocker/Discord transcripts):
             .ga100_resident_text : 0x400a000 - 0x402d000
             .ga100_text          : 0x4005000 - 0x4026414
             .ga100_resident_data : 0x400d000 - 0x401d000
             .ga100_data          : 0x4001000 - 0x4021700
        """
        self.regs = [0] * 32      # x0..x31
        self.csrs = {}            # CSR state
        self.csrs[0x7ca] = fuse_value_0x7ca
        self.bar0_writes = []
        self.trace_writes = trace_writes
        self.max_steps = 1000000
        self.steps = 0

        # Build a unified memory image (IMEM and DMEM combined as one bytearray).
        # Use a dict mapping vaddr -> bytes. The booter uses both IMEM and DMEM
        # in its address space; we don't know the exact split, but we can
        # model each section at its known vaddr.
        self.mem_base = 0x4000000  # arbitrary base below all sections
        self.mem = bytearray(0x100000)  # 1 MB

        # Place sections at their vaddrs (relative to mem_base)
        layout = {
            '.ga100_resident_text': 0x400a000,
            '.ga100_text':          0x4005000,
            '.ga100_resident_data': 0x400d000,
            '.ga100_data':          0x4001000,
        }
        self.section_layout = layout
        for name, vaddr in layout.items():
            if name not in sections:
                continue
            data = sections[name]
            off = vaddr - self.mem_base
            if off + len(data) > len(self.mem):
                self.mem.extend(b'\x00' * (off + len(data) - len(self.mem)))
            self.mem[off:off+len(data)] = data

        # Default PC: .ga100_text + 0x40 (entry point after the 64-byte header)
        self.pc = 0x4005040

    def sxt(self, x, b):
        return x - (1 << b) if x & (1 << (b-1)) else x

    def _vaddr_to_offset(self, vaddr):
        """Convert a Falcon vaddr to our memory array offset."""
        if vaddr < self.mem_base:
            return None  # unmapped
        off = vaddr - self.mem_base
        if off >= len(self.mem):
            return None
        return off

    def _read_mem(self, vaddr, sz):
        off = self._vaddr_to_offset(vaddr)
        if off is None or off + sz > len(self.mem):
            return 0  # unmapped → 0 (safe for booter execution)
        return int.from_bytes(self.mem[off:off+sz], 'little')

    def _write_mem(self, vaddr, val, sz):
        off = self._vaddr_to_offset(vaddr)
        if off is None or off + sz > len(self.mem):
            return
        val_bytes = val.to_bytes(sz, 'little')
        self.mem[off:off+sz] = val_bytes

    def sxt(self, x, b):
        return x - (1 << b) if x & (1 << (b-1)) else x

    def step(self):
        # Translate vaddr PC to our memory offset
        off = self._vaddr_to_offset(self.pc)
        if off is None or off + 4 > len(self.mem):
            return False
        insn = struct.unpack_from("<I", self.mem, off)[0]
        self.steps += 1
        if self.steps > self.max_steps:
            log.warning("step limit hit at PC=0x%x", self.pc)
            return False
        return self.exec(insn)

    def exec(self, insn):
        opc = insn & 0x7f
        rd = (insn >> 7) & 0x1f
        funct3 = (insn >> 12) & 0x7
        rs1 = (insn >> 15) & 0x1f
        rs2 = (insn >> 20) & 0x1f
        funct7 = (insn >> 25) & 0x7f

        # x0 is always zero
        self.regs[0] = 0

        if opc == 0x37:  # LUI
            imm = insn >> 12
            self.regs[rd] = (imm << 12) & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x17:  # AUIPC
            imm = insn >> 12
            self.regs[rd] = (self.pc + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x13:  # OPIMM
            imm = self.sxt((insn >> 20) & 0xfff, 12)
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
            elif funct3 == 5:  # SRLI/SRAI
                shamt = (insn >> 20) & 0x3f
                if funct7 == 0:    # SRLI
                    self.regs[rd] = (v1 >> shamt) & 0xFFFFFFFFFFFFFFFF
                elif funct7 == 0x20:  # SRAI
                    if v1 & (1 << 63):
                        self.regs[rd] = ((v1 >> shamt) | (((1 << shamt) - 1) << (64 - shamt))) & 0xFFFFFFFFFFFFFFFF
                    else:
                        self.regs[rd] = (v1 >> shamt) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 6:  # ORI
                self.regs[rd] = (v1 | imm) & 0xFFFFFFFFFFFFFFFF
            elif funct3 == 7:  # ANDI
                self.regs[rd] = (v1 & imm) & 0xFFFFFFFFFFFFFFFF
            else:
                log.warning("unknown OPIMM funct3=%d insn=0x%x", funct3, insn)
                self.pc += 4
            self.pc += 4
        elif opc == 0x33:  # OP
            v1 = self.regs[rs1]
            v2 = self.regs[rs2]
            if funct7 == 0:
                ops = {0:'ADD',1:'SLL',2:'SLT',3:'SLTU',4:'XOR',5:'SRL',6:'OR',7:'AND'}
            elif funct7 == 0x20:
                ops = {0:'SUB',5:'SRA'}
            else:
                ops = {}
            op = ops.get(funct3)
            if op == 'ADD': self.regs[rd] = (v1 + v2) & 0xFFFFFFFFFFFFFFFF
            elif op == 'SUB': self.regs[rd] = (v1 - v2) & 0xFFFFFFFFFFFFFFFF
            elif op == 'SLL': self.regs[rd] = (v1 << (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
            elif op == 'SLT': self.regs[rd] = 1 if self.sxt(v1, 64) < self.sxt(v2, 64) else 0
            elif op == 'SLTU': self.regs[rd] = 1 if v1 < v2 else 0
            elif op == 'XOR': self.regs[rd] = (v1 ^ v2) & 0xFFFFFFFFFFFFFFFF
            elif op == 'SRL': self.regs[rd] = (v1 >> (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
            elif op == 'SRA':
                if v1 & (1 << 63):
                    shamt = v2 & 0x3f
                    self.regs[rd] = ((v1 >> shamt) | (((1 << shamt) - 1) << (64 - shamt))) & 0xFFFFFFFFFFFFFFFF
                else:
                    self.regs[rd] = (v1 >> (v2 & 0x3f)) & 0xFFFFFFFFFFFFFFFF
            elif op == 'OR': self.regs[rd] = (v1 | v2) & 0xFFFFFFFFFFFFFFFF
            elif op == 'AND': self.regs[rd] = (v1 & v2) & 0xFFFFFFFFFFFFFFFF
            else:
                log.warning("unknown OP funct3=%d funct7=0x%x insn=0x%x", funct3, funct7, insn)
            self.pc += 4
        elif opc == 0x03:  # LOAD
            imm = self.sxt((insn >> 20) & 0xfff, 12)
            addr = (self.regs[rs1] + imm) & 0xFFFFFFFFFFFFFFFF
            sz_map = {0:1, 1:2, 2:4, 3:8, 4:1, 5:2, 6:4}  # LB/LH/LW/LD/LBU/LHU/LWU
            signed_map = {0:True, 1:True, 2:True, 3:True, 4:False, 5:False, 6:False}
            sz = sz_map.get(funct3)
            signed = signed_map.get(funct3)
            if sz is None:
                log.warning("unknown LOAD funct3=%d insn=0x%x", funct3, insn)
                self.pc += 4
                return True
            val = self._read_mem(addr, sz)
            if signed and sz < 8 and (val >> (sz * 8 - 1)) & 1:
                val -= (1 << (sz * 8))
            self.regs[rd] = val & 0xFFFFFFFFFFFFFFFF
            self.pc += 4
        elif opc == 0x23:  # STORE
            imm = self.sxt(((insn >> 25) << 5) | ((insn >> 7) & 0x1f), 12)
            addr = (self.regs[rs1] + imm) & 0xFFFFFFFFFFFFFFFF
            sz_map = {0:1, 1:2, 2:4, 3:8}
            sz = sz_map.get(funct3)
            if sz is None:
                log.warning("unknown STORE funct3=%d insn=0x%x", funct3, insn)
                self.pc += 4
                return True
            val = self.regs[rs2]
            self._write_mem(addr, val, sz)
            # Also record as BAR0 write if the address falls in the FB window
            val32 = val & ((1 << (sz * 8)) - 1)
            if 0x300000000 <= addr <= 0x300100000:
                bar0_addr = (addr - 0x300000000) + 0x110000
                self.bar0_writes.append((bar0_addr, val32))
                if self.trace_writes:
                    log.info("BAR0 WRITE: 0x%06x <- 0x%x (Falcon 0x%x)",
                             bar0_addr, val32, addr)
            self.pc += 4
        elif opc == 0x63:  # BRANCH
            v1 = self.regs[rs1]
            v2 = self.regs[rs2]
            imm = self.sxt(
                ((insn >> 31) & 1) << 12 |
                ((insn >> 7) & 1) << 11 |
                ((insn >> 25) & 0x3f) << 5 |
                ((insn >> 8) & 0xf) << 1,
                13)
            taken = False
            if funct3 == 0:   taken = v1 == v2
            elif funct3 == 1: taken = v1 != v2
            elif funct3 == 4: taken = self.sxt(v1, 64) < self.sxt(v2, 64)
            elif funct3 == 5: taken = self.sxt(v1, 64) >= self.sxt(v2, 64)
            elif funct3 == 6: taken = v1 < v2
            elif funct3 == 7: taken = v1 >= v2
            if taken:
                self.pc += imm
            else:
                self.pc += 4
        elif opc == 0x6f:  # JAL
            imm = self.sxt(
                ((insn >> 31) & 1) << 20 |
                ((insn >> 12) & 0xff) << 12 |
                ((insn >> 20) & 1) << 11 |
                ((insn >> 21) & 0x3ff) << 1,
                21)
            if rd != 0:
                self.regs[rd] = (self.pc + 4) & 0xFFFFFFFFFFFFFFFF
            self.pc = (self.pc + imm) & 0xFFFFFFFFFFFFFFFF
        elif opc == 0x67:  # JALR
            imm = self.sxt((insn >> 20) & 0xfff, 12)
            tgt = (self.regs[rs1] + imm) & ~1
            if rd != 0:
                self.regs[rd] = (self.pc + 4) & 0xFFFFFFFFFFFFFFFF
            self.pc = tgt & 0xFFFFFFFFFFFFFFFF
        elif opc == 0x73:  # SYSTEM (CSR)
            csr_addr = (insn >> 20) & 0xfff
            if funct3 == 1:   # CSRRW
                old = self.csrs.get(csr_addr, 0)
                self.csrs[csr_addr] = self.regs[rs1] & 0xFFFFFFFFFFFFFFFF
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.regs[rs1])
            elif funct3 == 2: # CSRRS
                old = self.csrs.get(csr_addr, 0)
                if rs1 != 0:
                    self.csrs[csr_addr] = old | (self.regs[rs1] & 0xFFFFFFFFFFFFFFFF)
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr])
            elif funct3 == 3: # CSRRC
                old = self.csrs.get(csr_addr, 0)
                if rs1 != 0:
                    self.csrs[csr_addr] = old & ~(self.regs[rs1] & 0xFFFFFFFFFFFFFFFF)
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr])
            elif funct3 == 5: # CSRRWI (CSR Write Immediate)
                old = self.csrs.get(csr_addr, 0)
                self.csrs[csr_addr] = rs1 & 0xFFFFFFFFFFFFFFFF  # rs1 field is the imm
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr])
            elif funct3 == 6: # CSRRSI
                old = self.csrs.get(csr_addr, 0)
                self.csrs[csr_addr] = old | (rs1 & 0xFFFFFFFFFFFFFFFF)
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr])
            elif funct3 == 7: # CSRRCI
                old = self.csrs.get(csr_addr, 0)
                self.csrs[csr_addr] = old & ~(rs1 & 0xFFFFFFFFFFFFFFFF)
                if rd != 0:
                    self.regs[rd] = old & 0xFFFFFFFFFFFFFFFF
                self._handle_csr_write(csr_addr, old, self.csrs[csr_addr])
            else:
                log.warning("unknown CSR funct3=%d csr=0x%x insn=0x%x",
                            funct3, csr_addr, insn)
            self.pc += 4
        elif opc == 0x1b:  # AMO (atomic) — single-core Falcon, treat as memory access
            # funct5 (bits 31-27) selects AMO subtype.
            funct5 = (insn >> 27) & 0x1f
            addr = self.regs[rs1]
            if funct5 == 0x02:  # LR.W (Load Reserved Word)
                self.regs[rd] = self._read_mem(addr, 4) & 0xFFFFFFFFFFFFFFFF
                self.pc += 4
            elif funct5 == 0x03:  # SC.W (Store Conditional Word)
                self._write_mem(addr, self.regs[rs2], 4)
                self.regs[rd] = 0  # success
                self.pc += 4
            elif funct5 in (0x00, 0x01, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c):
                # Standard AMOs: load + combine with rs2 + store
                v = self._read_mem(addr, 4) & 0xFFFFFFFF
                rs2_v = self.regs[rs2] & 0xFFFFFFFF
                if funct5 == 0x00:    new_v = (v + rs2_v) & 0xFFFFFFFF           # AMOADD
                elif funct5 == 0x01:  new_v = rs2_v                                # AMOSWAP
                elif funct5 == 0x04:  new_v = v ^ rs2_v                            # AMOXOR
                elif funct5 == 0x08:  new_v = v | rs2_v                            # AMOOR
                elif funct5 == 0x0c:  new_v = v & rs2_v                            # AMOAND
                elif funct5 == 0x10:  new_v = min(v, rs2_v) if (v >> 31) == (rs2_v >> 31) else (rs2_v if (v >> 31) else v)  # AMOMIN
                elif funct5 == 0x14:  new_v = max(v, rs2_v) if (v >> 31) == (rs2_v >> 31) else (v if (v >> 31) else rs2_v)  # AMOMAX
                elif funct5 == 0x18:  new_v = min(v, rs2_v)                        # AMOMINU
                elif funct5 == 0x1c:  new_v = max(v, rs2_v)                        # AMOMAXU
                self._write_mem(addr, new_v, 4)
                if rd != 0:
                    self.regs[rd] = v  # load returns old value
                self.pc += 4
            else:
                # Unknown / non-standard AMO (e.g. funct5=0x1d). Falcon-specific.
                # Treat as NOP — advance PC, don't touch memory or registers.
                self.pc += 4
        else:
            log.warning("unknown opcode 0x%x insn=0x%x at PC=0x%x",
                        opc, insn, self.pc)
            self.pc += 4
        return True

    def _read_memory(self, addr, sz, signed):
        # Backwards-compat shim; uses vaddr-based mem.
        val = self._read_mem(addr, sz)
        if signed and sz < 8 and (val >> (sz * 8 - 1)) & 1:
            val -= (1 << (sz * 8))
        return val

    def _write_memory(self, addr, val, sz):
        # Backwards-compat shim; uses vaddr-based mem.
        self._write_mem(addr, val, sz)
        val32 = val & ((1 << (sz * 8)) - 1)
        if 0x300000000 <= addr <= 0x300100000:
            bar0_addr = (addr - 0x300000000) + 0x110000
            self.bar0_writes.append((bar0_addr, val32))
            if self.trace_writes:
                log.info("BAR0 WRITE: 0x%06x <- 0x%x (Falcon 0x%x)",
                         bar0_addr, val32, addr)

    def _handle_csr_write(self, csr, old, new):
        """Handle Falcon-specific CSR writes that trigger side effects."""
        if csr == 0x7cc:
            # BAR0 write commit: if CSR 0x7c8 (data) is set, write data to
            # the address stored in this CSR. The commit semantics are
            # implementation-specific; we model it as: write 0x7c8's value to
            # the BAR0 address that was just set in 0x7cc.
            data = self.csrs.get(0x7c8, 0)
            # The 0x7cc write usually includes the address; for our
            # purposes we treat any 0x7cc write as triggering a write
            # of the data register to whatever address was last loaded.
            # The actual address comes from the loaded value.
            addr = new & 0xFFFFFFFF  # 32-bit BAR0 address
            self._write_memory(0x300000000 + addr, data, 4)

    def run(self, max_steps=None):
        if max_steps is not None:
            self.max_steps = max_steps
        while self.step():
            pass


def extract_booter_sections(firmware_path):
    """Pull .ga100_text, .ga100_resident_text, .ga100_data, .ga100_resident_data
    out of the GSP firmware file."""
    with open(firmware_path, 'rb') as f:
        gsp = f.read()

    fwimage_off = 0x40
    inner_e_shoff = struct.unpack_from("<Q", gsp, fwimage_off + 0x28)[0]
    inner_shentsize = struct.unpack_from("<H", gsp, fwimage_off + 0x3A)[0]
    inner_shnum = struct.unpack_from("<H", gsp, fwimage_off + 0x3C)[0]
    inner_shstrndx = struct.unpack_from("<H", gsp, fwimage_off + 0x3E)[0]
    strtab_hdr = fwimage_off + inner_e_shoff + inner_shstrndx*inner_shentsize
    strtab_off = struct.unpack_from("<Q", gsp, strtab_hdr + 0x18)[0]
    strtab_sz = struct.unpack_from("<Q", gsp, strtab_hdr + 0x20)[0]
    strtab = gsp[fwimage_off+strtab_off:fwimage_off+strtab_off+strtab_sz]

    sections = {}
    for i in range(inner_shnum):
        base = fwimage_off + inner_e_shoff + i*inner_shentsize
        name_idx = struct.unpack_from("<I", gsp, base)[0]
        end = strtab.find(b"\x00", name_idx)
        name = strtab[name_idx:end].decode(errors='replace')
        sh_off = struct.unpack_from("<Q", gsp, base + 0x18)[0]
        sh_size = struct.unpack_from("<Q", gsp, base + 0x20)[0]
        if name in ('.ga100_text', '.ga100_resident_text',
                     '.ga100_data', '.ga100_resident_data'):
            sections[name] = gsp[fwimage_off+sh_off:fwimage_off+sh_off+sh_size]
    return sections


def main():
    if len(sys.argv) < 2:
        print("Usage: booter_emu.py <firmware_path> [fuse_value_hex]")
        sys.exit(1)
    firmware_path = sys.argv[1]
    fuse_value = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0

    log.info("Extracting booter sections from %s", firmware_path)
    secs = extract_booter_sections(firmware_path)
    if not secs:
        log.error("No booter sections found")
        sys.exit(1)
    log.info("Found: %s", {k: len(v) for k, v in secs.items()})

    log.info("Emulating booter with fuse_value_0x7ca=0x%x", fuse_value)
    emu = FalconBooter(secs, fuse_value_0x7ca=fuse_value)
    log.info("Starting at PC=0x%x", emu.pc)
    emu.run(max_steps=500000)
    log.info("Emulation complete: %d steps, ended at PC=0x%x, %d BAR0 writes captured",
             emu.steps, emu.pc, len(emu.bar0_writes))
    print()
    print("=== ALL BAR0 WRITES BY BOOTER (sorted by address) ===")
    by_addr = {}
    for addr, value in emu.bar0_writes:
        by_addr.setdefault(addr, []).append(value)
    for addr in sorted(by_addr.keys()):
        vals = by_addr[addr]
        if len(set(vals)) == 1:
            print(f"  0x{addr:08x} = 0x{vals[0]:08x}")
        else:
            for v in vals:
                print(f"  0x{addr:08x} <- 0x{v:08x}")


if __name__ == "__main__":
    main()
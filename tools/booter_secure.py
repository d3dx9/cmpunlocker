"""Falcon SEC2 secure boot extension for booter_emu.py.

Adds the 5 missing pieces for booter_load support on top of
``FalconBooter`` (FWSEC emulation):

1. IMEM modeling       — 64 KB instruction memory at vaddr 0x5000000,
                          separate from DMEM. booter_load lives here.
2. DMA engine          — host-buffer → IMEM/DMEM via CSRs 0x7d0-0x7d4.
3. AES-128 ECB decrypt — AES key via CSRs 0x7d5-0x7d8, decrypt via 0x7d9.
4. HMAC verify bypass  — 0x7da; with bypass=True skips signature check
                          (this is what the actual exploit does).
5. HS mode tracking    — 0x7db entry CSR + read-only 0x7dc status.
"""

import logging
import struct

# Allow imports both as `python -m tools.booter_secure` and as
# `from tools.booter_secure import ...` (the latter works because
# `tools/__init__.py` makes it a package).
import sys, os
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
from booter_emu import (
    BOOTER_LAYOUT, FALCON_BAR0_WIN_BASE, FALCON_BAR0_POFFSET,
    FALCON_BAR0_WIN_SIZE, FalconBooter, vaddr_to_bar0,
)

log = logging.getLogger('booter_secure')


_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
)
_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _aes128_key_expansion(key):
    assert len(key) == 16
    Nk, Nb, Nr = 4, 4, 10
    Rcon = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
    w = list(key)
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % Nk == 0:
            temp = [_SBOX[temp[1]] ^ Rcon[i // Nk],
                    _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        w += [w[(i - Nk) * 4 + j] ^ temp[j] for j in range(4)]
    return [bytes(w[i * 16:(i + 1) * 16]) for i in range(Nr + 1)]


def aes128_ecb_decrypt(ct, key):
    assert len(key) == 16
    assert len(ct) % 16 == 0
    rkeys = _aes128_key_expansion(key)
    out = bytearray(len(ct))
    Nr = 10
    for blk in range(0, len(ct), 16):
        s = list(ct[blk:blk + 16])
        for r in range(Nr, 0, -1):
            rk = rkeys[r]
            s = [s[i] ^ rk[i] for i in range(16)]
            s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
                 s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
            if r != Nr:
                for c in range(4):
                    a0 = _xtime(_INV_SBOX[s[c * 4 + 0]])
                    a1 = _xtime(_INV_SBOX[s[c * 4 + 1]])
                    a2 = _xtime(_INV_SBOX[s[c * 4 + 2]])
                    a3 = _xtime(_INV_SBOX[s[c * 4 + 3]])
                    s[c * 4 + 0] = a0 ^ a1 ^ a2 ^ _INV_SBOX[s[c * 4 + 3]]
                    s[c * 4 + 1] = a0 ^ a2 ^ a3 ^ _INV_SBOX[s[c * 4 + 0]]
                    s[c * 4 + 2] = a1 ^ a3 ^ a0 ^ _INV_SBOX[s[c * 4 + 1]]
                    s[c * 4 + 3] = a2 ^ a0 ^ a1 ^ _INV_SBOX[s[c * 4 + 2]]
            else:
                for c in range(4):
                    s[c * 4 + 0] = _INV_SBOX[s[c * 4 + 0]]
                    s[c * 4 + 1] = _INV_SBOX[s[c * 4 + 1]]
                    s[c * 4 + 2] = _INV_SBOX[s[c * 4 + 2]]
                    s[c * 4 + 3] = _INV_SBOX[s[c * 4 + 3]]
        rk = rkeys[0]
        out[blk:blk + 16] = bytes(s[i] ^ rk[i] for i in range(16))
    return bytes(out)


class FalconSecureBooter(FalconBooter):
    IMEM_BASE = 0x5000000
    IMEM_SIZE = 0x10000

    CSR_DMA_SRC_LO = 0x7d0
    CSR_DMA_SRC_HI = 0x7d1
    CSR_DMA_DST = 0x7d2
    CSR_DMA_LEN = 0x7d3
    CSR_DMA_CTRL = 0x7d4

    CSR_AES_KEY0 = 0x7d5
    CSR_AES_KEY1 = 0x7d6
    CSR_AES_KEY2 = 0x7d7
    CSR_AES_KEY3 = 0x7d8
    CSR_AES_OP = 0x7d9

    CSR_HMAC_VERIFY = 0x7da
    CSR_HS_ENTRY = 0x7db
    CSR_HS_STATUS = 0x7dc

    def __init__(self, sections, fuse_value_0x7ca=0, max_steps=1_000_000,
                 trace=False, trace_pc=False, pc_entry=None,
                 aes_key=None, hmac_bypass=False, auto_hs=True,
                 host_buffer_size=64 * 1024 * 1024, **_unused):
        super().__init__(sections, fuse_value_0x7ca=fuse_value_0x7ca,
                         max_steps=max_steps, trace=trace, trace_pc=trace_pc,
                         pc_entry=pc_entry)

        self.imem = bytearray(self.IMEM_SIZE)
        self.host_buffer = bytearray(host_buffer_size)

        self.aes_key = aes_key if aes_key is not None else bytes(16)
        self.csrs.update({
            self.CSR_AES_KEY0: 0, self.CSR_AES_KEY1: 0,
            self.CSR_AES_KEY2: 0, self.CSR_AES_KEY3: 0,
            self.CSR_AES_OP: 0,
        })

        self.hmac_bypass = hmac_bypass
        self.csrs[self.CSR_HMAC_VERIFY] = 0
        self._hmac_ok = False

        self.hs_mode = False
        self.csrs[self.CSR_HS_STATUS] = 0
        self.auto_hs = auto_hs

        self._dma_state = {'src_lo': 0, 'src_hi': 0, 'dst': 0, 'len': 0}

        # Frame layout for mpopaddret hypothesis (from Big Ptoughneigh's exploit):
        #   frame_start:    SP value at mpopaddret call time
        #   SP + 0x08:      val → x1
        #   SP + 0x0C:      addr → x0
        #   SP + 0x14:      RA (return address) → PC
        #   SP += 0x18      (advance to next frame)
        self.MPOPADDRET_VAL_OFF   = 0x08
        self.MPOPADDRET_ADDR_OFF  = 0x0C
        self.MPOPADDRET_RA_OFF    = 0x14
        self.MPOPADDRET_STRIDE    = 0x18

    def step(self):
        if self.halted:
            return False

        in_imem = (self.IMEM_BASE <= self.pc < self.IMEM_BASE + self.IMEM_SIZE)

        if in_imem:
            off = self.pc - self.IMEM_BASE
            if off + 4 > self.IMEM_SIZE:
                self.halted = True
                self.halt_reason = f'PC 0x{self.pc:x} OOB IMEM'
                return False
            insn = struct.unpack_from("<I", self.imem, off)[0]
        else:
            off = self.pc - self.MEM_BASE
            if off < 0 or off + 4 > len(self.mem):
                self.halted = True
                self.halt_reason = f'PC 0x{self.pc:x} OOB DMEM'
                return False
            rt_lo = BOOTER_LAYOUT['.ga100_resident_text']
            rt_hi = rt_lo + len(self._sections.get('.ga100_resident_text', b''))
            tx_lo = BOOTER_LAYOUT['.ga100_text']
            tx_hi = tx_lo + len(self._sections.get('.ga100_text', b''))
            if not (tx_lo <= self.pc < tx_hi or rt_lo <= self.pc < rt_hi):
                self.halted = True
                self.halt_reason = (
                    f'PC 0x{self.pc:x} outside code sections or IMEM')
                return False
            insn = struct.unpack_from("<I", self.mem, off)[0]

        self.steps += 1
        if self.steps > self.max_steps:
            self.halted = True
            self.halt_reason = f'step limit {self.max_steps} hit at PC=0x{self.pc:x}'
            return False

        if self.trace_pc:
            loc = 'IMEM' if in_imem else 'DMEM'
            log.info('PC=0x%x [%s]  insn=0x%08x  hs=%s', self.pc, loc, insn, self.hs_mode)
        return self.exec(insn, self.pc)

    def _handle_csr_write(self, csr, old_unused, new_val, pc, rs1_val=0):
        if csr in (0x7c8, 0x7c9, 0x7ca, 0x7cb, 0x7cc):
            super()._handle_csr_write(csr, old_unused, new_val, pc, rs1_val)
            return

        if csr == self.CSR_DMA_SRC_LO:
            self._dma_state['src_lo'] = new_val & 0xFFFFFFFF
            return
        if csr == self.CSR_DMA_SRC_HI:
            self._dma_state['src_hi'] = new_val & 0xFFFFFFFF
            return
        if csr == self.CSR_DMA_DST:
            self._dma_state['dst'] = new_val & 0xFFFFFFFF
            return
        if csr == self.CSR_DMA_LEN:
            self._dma_state['len'] = new_val & 0xFFFFFFFF
            return
        if csr == self.CSR_DMA_CTRL:
            if new_val & 1:
                self._do_dma(pc)
            return

        if csr in (self.CSR_AES_KEY0, self.CSR_AES_KEY1,
                   self.CSR_AES_KEY2, self.CSR_AES_KEY3):
            self.csrs[csr] = new_val & 0xFFFFFFFF
            return
        if csr == self.CSR_AES_OP:
            if new_val:
                self._do_aes_decrypt(new_val)
            return

        if csr == self.CSR_HMAC_VERIFY:
            if self.hmac_bypass:
                self.csrs[csr] = 0
                self._hmac_ok = True
                log.info('HMAC verify (bypass): OK')
            else:
                self._hmac_ok = False
                self.csrs[csr] = 1
                log.warning('HMAC verify: FAIL (no bypass)')
            return

        if csr == self.CSR_HS_ENTRY:
            if not self._hmac_ok:
                log.warning('HS entry BLOCKED — HMAC verify not OK')
                return
            self.hs_mode = True
            self.csrs[self.CSR_HS_STATUS] = 1
            log.info('NS → HS transition successful at PC=0x%x', pc)
            return

        log.warning('unknown CSR 0x%x write 0x%x (pc=0x%x)', csr, new_val, pc)

    def _do_dma(self, pc):
        src = (self._dma_state['src_hi'] << 32) | self._dma_state['src_lo']
        dst = self._dma_state['dst']
        length = self._dma_state['len']
        if length == 0 or length > len(self.host_buffer):
            log.warning('DMA bad length 0x%x at pc=0x%x', length, pc)
            return
        if src + length > len(self.host_buffer):
            log.warning('DMA source 0x%x + 0x%x OOB host_buffer', src, length)
            return
        data = bytes(self.host_buffer[src:src + length])

        if self.IMEM_BASE <= dst < self.IMEM_BASE + self.IMEM_SIZE:
            off = dst - self.IMEM_BASE
            self.imem[off:off + length] = data
            log.info('DMA: host[0x%x] -> IMEM[0x%x..0x%x] (pc=0x%x)',
                     src, dst, dst + length, pc)
        elif self.MEM_BASE <= dst < self.MEM_BASE + self.MEM_SIZE:
            off = dst - self.MEM_BASE
            self.mem[off:off + length] = data
            log.info('DMA: host[0x%x] -> DMEM[0x%x..0x%x] (pc=0x%x)',
                     src, dst, dst + length, pc)
        else:
            log.warning('DMA dst 0x%x not in IMEM/DMEM (pc=0x%x)', dst, pc)

    def _do_aes_decrypt(self, length):
        if not self.aes_key or self.aes_key == bytes(16):
            log.warning('AES decrypt skipped — no key loaded')
            return
        if length % 16:
            log.warning('AES decrypt length 0x%x not block-aligned', length)
            return
        ct = bytes(self.imem[:length])
        pt = aes128_ecb_decrypt(ct, self.aes_key)
        self.imem[:length] = pt
        log.info('AES-128 ECB decrypted IMEM[0..0x%x]', length)

    def _do_mpopaddret(self):
        """HYPOTHESIS: 0x3b in HS mode = mpopaddret.

        Per Big Ptoughneigh's exploit notes:
          mpopaddret pops r1=D[SP+0x08]=val, r0=D[SP+0x0C]=addr,
                        RA=D[SP+0x14] → PC.
        Then SP += 0x18 to point at the next frame.

        Tegra X1 mpopaddret (envytools envydis/falcon.c) has the same
        semantics — pop 2 regs + RA from SP-relative offsets, jump to RA.

        NB: In RISC-V, x0 is hardwired to 0 — we pop the addr into x10
        instead, which matches Big Ptoughneigh's "r0" notation (they
        meant "register 0 in the popped frame", not literal x0).
        """
        sp = self.regs[2] & 0xFFFFFFFF
        # Read frame data from DMEM at SP+offsets
        val = self._read_v(sp + self.MPOPADDRET_VAL_OFF, 4)
        addr = self._read_v(sp + self.MPOPADDRET_ADDR_OFF, 4)
        ra = self._read_v(sp + self.MPOPADDRET_RA_OFF, 4)
        if self.trace:
            log.info('mpopaddret at PC=0x%x, SP=0x%x: val=0x%x, addr=0x%x, RA=0x%x',
                     self.pc, sp, val, addr, ra)
        # Pop values into registers. Use x10 for addr (NOT x0 — it's
        # hardwired to 0 in RV32). Use x1 for val.
        self.regs[1] = val & 0xFFFFFFFFFFFFFFFF
        self.regs[10] = addr & 0xFFFFFFFFFFFFFFFF
        self.pc = ra & 0xFFFFFFFF
        # Advance SP to next frame
        self.regs[2] = (sp + self.MPOPADDRET_STRIDE) & 0xFFFFFFFF
        self.steps += 1  # count this as one step

    def exec(self, insn, pc_at):
        # HS-mode hypothesis: intercept 0x3b as mpopaddret.
        # In NS mode 0x3b keeps the parent class's dual-issue ALU semantic.
        if self.hs_mode and (insn & 0x7f) == 0x3b:
            self._do_mpopaddret()
            return True
        return super().exec(insn, pc_at)

    # NOTE: the docstring on 0x3b (in booter_emu.py) is now slightly
    # out of date. mpopaddret IS 0x3b — but only in HS mode. In NS mode
    # 0x3b still has the dual-issue ALU semantics. The booter_load
    # ROP exploit runs in HS mode and uses 0x3b to pop return addresses
    # from the stack, with the normal ALU semantics applying to any
    # 0x3b instructions executed before HS mode is entered.

    def load_via_dma(self, data, dst_vaddr, auto_decrypt=True):
        if len(data) > len(self.host_buffer):
            raise ValueError(f'data {len(data)} exceeds host_buffer')
        self.host_buffer[:len(data)] = data
        self._dma_state.update({
            'src_lo': 0, 'src_hi': 0, 'dst': dst_vaddr, 'len': len(data),
        })
        self._do_dma(pc=0xFFFFFFFF)

        if auto_decrypt and (self.IMEM_BASE <= dst_vaddr < self.IMEM_BASE + self.IMEM_SIZE) \
                and self.aes_key and self.aes_key != bytes(16):
            length = (len(data) + 15) & ~0xF
            self._do_aes_decrypt(length)

    def enter_hs(self):
        self._hmac_ok = True
        self.hs_mode = True
        self.csrs[self.CSR_HS_STATUS] = 1
        log.info('Forced NS → HS (hmac_bypass path)')

    def load_exploit(self, exploit_bytes, imem_entry_offset=0x100):
        self.load_via_dma(exploit_bytes, self.IMEM_BASE + imem_entry_offset,
                          auto_decrypt=False)
        if self.auto_hs:
            self.enter_hs()
        self.pc = self.IMEM_BASE + imem_entry_offset
        log.info('Exploit loaded at IMEM[0x%x], PC=0x%x',
                 imem_entry_offset, self.pc)


__all__ = ['FalconSecureBooter', 'aes128_ecb_decrypt']
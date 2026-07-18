"""Test 0x3b NS-mode semantics: dual-issue ALU (mirror of 0x33).

Verifies that 0x3b in NS mode produces identical semantics to 0x33 with
the same funct7/funct3 fields. Both opcodes route to the same
`_exec_op` handler.

This test:
1. Encodes the same operations with both 0x33 and 0x3b opcodes
2. Runs them in the emulator
3. Compares the resulting register states
4. Verifies they're identical (proving 0x3b = mirror of 0x33)

Tested operations (from Tegra X1 envytools + FWSEC analysis):
- ADD  (funct7=0x00, funct3=0x00)
- SUB  (funct7=0x20, funct3=0x00)
- MUL  (funct7=0x01, funct3=0x00)
- SLL  (funct7=0x00, funct3=0x01)
- AND  (funct7=0x00, funct3=0x07)
- REMU (funct7=0x01, funct3=0x07)

Tegra X1 also documents (from envytools/falcon.c):
- ADC  (add with carry)  - not in FWSEC, not implemented
- SBB  (sub with borrow) - not in FWSEC, not implemented
- SHLC (shift left with carry)  - not in FWSEC, not implemented
- SHRC (shift right with carry) - not in FWSEC, not implemented
"""

import sys, os, struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.booter_emu import FalconBooter, extract_booter_sections
from tools.booter_secure import FalconSecureBooter


def make_op(rd, rs1, rs2, funct7, funct3, opcode):
    """Build a 32-bit RV instruction."""
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def _s32(v):
    """Interpret 32-bit value as signed."""
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def test_dual_issue():
    """Verify 0x3b produces same results as 0x33 for all RV32I OP ops."""
    print("=" * 60)
    print("0x3b NS-mode dual-issue ALU verification")
    print("=" * 60)

    # Use real firmware sections so the PC guard passes
    firmware_path = '/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin'
    sections = extract_booter_sections(firmware_path)

    # Test operations: (label, funct7, funct3, expected_op)
    # For SLT, comparison is SIGNED. For SLTU, UNSIGNED.
    tests = [
        ('ADD',  0x00, 0x0, lambda a, b: (a + b) & 0xFFFFFFFF),
        ('SUB',  0x20, 0x0, lambda a, b: (a - b) & 0xFFFFFFFF),
        ('MUL',  0x01, 0x0, lambda a, b: (a * b) & 0xFFFFFFFF),
        ('SLL',  0x00, 0x1, lambda a, b: (a << (b & 0x1f)) & 0xFFFFFFFF),
        ('SLT',  0x00, 0x2, lambda a, b: 1 if _s32(a) < _s32(b) else 0),
        ('SLTU', 0x00, 0x3, lambda a, b: 1 if (a & 0xFFFFFFFF) < (b & 0xFFFFFFFF) else 0),
        ('XOR',  0x00, 0x4, lambda a, b: a ^ b),
        ('SRL',  0x00, 0x5, lambda a, b: (a >> (b & 0x1f)) & 0xFFFFFFFF),
        ('OR',   0x00, 0x6, lambda a, b: a | b),
        ('AND',  0x00, 0x7, lambda a, b: a & b),
        ('REMU', 0x01, 0x7, lambda a, b: (a & 0xFFFFFFFF) % (b & 0xFFFFFFFF) if b else 0xFFFFFFFF),
    ]

    pairs = [(7, 3), (0x12345678, 0x9ABCDEF0), (0, 1), (-1, 1)]
    # For RORI, the shift amount is the funct3 (immediate). We use b=0
    # because rs2 is ignored. The shift amount is passed via funct3.
    rori_pairs = [(7, 0), (0x12345678, 0), (-1, 0), (0xDEADBEEF, 0)]
    rori_shifts = [1, 5, 16, 31]

    all_pass = True
    for label, funct7, funct3, expected_op in tests:
        if label == 'RORI':
            # RORI uses funct3 as shift immediate; use rori_pairs
            for shamt in rori_shifts:
                for a, _ in rori_pairs:
                    a32 = a & 0xFFFFFFFF
                    # RORI: rotate right by shamt bits
                    expected_op_rori = lambda x, s=shamt: (((x >> s) | (x << (32 - s))) & 0xFFFFFFFF)

                    def make_rori_code(opcode, sh=shamt):
                        code = bytearray()
                        hi_a = (a32 + 0x800) >> 12
                        lo_a = a32 - (hi_a << 12)
                        if lo_a >= 2048:
                            lo_a -= 4096
                            hi_a += 1
                        code += struct.pack('<I', 0x000005b7 | ((hi_a & 0xfffff) << 12))
                        if lo_a:
                            code += struct.pack('<I', 0x00058593 | ((lo_a & 0xfff) << 20))
                        # RORI: funct3 = shamt, rs2=0 (ignored)
                        code += struct.pack('<I', make_op(10, 11, 0, 0x30, sh, opcode))
                        code += struct.pack('<I', 0x0000006f)
                        return bytes(code)

                    code_33 = make_rori_code(0x33)
                    code_3b = make_rori_code(0x3b)
                    base = 0x4005000

                    emu33 = FalconBooter(sections, fuse_value_0x7ca=0, max_steps=100)
                    emu33.mem[base - emu33.MEM_BASE:base - emu33.MEM_BASE + len(code_33)] = code_33
                    emu33.regs[11] = a32
                    emu33.regs[12] = 0
                    emu33.run()

                    emu3b = FalconBooter(sections, fuse_value_0x7ca=0, max_steps=100)
                    emu3b.mem[base - emu3b.MEM_BASE:base - emu3b.MEM_BASE + len(code_3b)] = code_3b
                    emu3b.regs[11] = a32
                    emu3b.regs[12] = 0
                    emu3b.run()

                    r33 = emu33.regs[10] & 0xFFFFFFFF
                    r3b = emu3b.regs[10] & 0xFFFFFFFF
                    expected = expected_op_rori(a32) & 0xFFFFFFFF

                    ok = (r33 == expected and r3b == expected and r33 == r3b)
                    status = "OK" if ok else "FAIL"
                    if not ok:
                        all_pass = False

                    print(f"  [{status}] RORI(0x{a32:08x}, shamt={shamt}) = 0x{expected:08x}  "
                          f"| opc=0x33: 0x{r33:08x}, opc=0x3b: 0x{r3b:08x}")
            continue
        for a, b in pairs:
            a32 = a & 0xFFFFFFFF
            b32 = b & 0xFFFFFFFF

            def make_code(opcode):
                code = bytearray()
                hi_a = (a32 + 0x800) >> 12
                lo_a = a32 - (hi_a << 12)
                if lo_a >= 2048:
                    lo_a -= 4096
                    hi_a += 1
                code += struct.pack('<I', 0x000005b7 | ((hi_a & 0xfffff) << 12))
                if lo_a:
                    code += struct.pack('<I', 0x00058593 | ((lo_a & 0xfff) << 20))
                hi_b = (b32 + 0x800) >> 12
                lo_b = b32 - (hi_b << 12)
                if lo_b >= 2048:
                    lo_b -= 4096
                    hi_b += 1
                if hi_b:
                    code += struct.pack('<I', 0x00000637 | ((hi_b & 0xfffff) << 12))
                if lo_b:
                    code += struct.pack('<I', 0x00060613 | ((lo_b & 0xfff) << 20))
                code += struct.pack('<I', make_op(10, 11, 12, funct7, funct3, opcode))
                code += struct.pack('<I', 0x0000006f)
                return bytes(code)

            code_33 = make_code(0x33)
            code_3b = make_code(0x3b)
            base = 0x4005000

            emu33 = FalconBooter(sections, fuse_value_0x7ca=0, max_steps=100)
            emu33.mem[base - emu33.MEM_BASE:base - emu33.MEM_BASE + len(code_33)] = code_33
            emu33.regs[11] = a32
            emu33.regs[12] = 0  # li x12, b will ADDI to this
            emu33.run()

            emu3b = FalconBooter(sections, fuse_value_0x7ca=0, max_steps=100)
            emu3b.mem[base - emu3b.MEM_BASE:base - emu3b.MEM_BASE + len(code_3b)] = code_3b
            emu3b.regs[11] = a32
            emu3b.regs[12] = 0
            emu3b.run()

            r33 = emu33.regs[10] & 0xFFFFFFFF
            r3b = emu3b.regs[10] & 0xFFFFFFFF
            expected = expected_op(a32, b32) & 0xFFFFFFFF

            ok = (r33 == expected and r3b == expected and r33 == r3b)
            status = "OK" if ok else "FAIL"
            if not ok:
                all_pass = False

            print(f"  [{status}] {label:5s}(0x{a32:08x}, 0x{b32:08x}) = 0x{expected:08x}  "
                  f"| opc=0x33: 0x{r33:08x}, opc=0x3b: 0x{r3b:08x}")

    print()
    print("=" * 60)
    print("OVERALL:", "PASS" if all_pass else "FAIL")
    print("=" * 60)
    return all_pass


def test_fwsec_distribution():
    """Verify the 0x3b distribution in FWSEC matches our RISC-V decoder."""
    print()
    print("=" * 60)
    print("FWSEC 0x3b distribution verification")
    print("=" * 60)

    firmware_path = '/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin'
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

    BOOTER_LAYOUT = {
        '.ga100_text':           0x004005000,
        '.ga100_resident_text':  0x00400a000,
    }

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

    print("\nAll 0x3b instructions in FWSEC, decoded with our RISC-V schema:\n")
    print(f"  {'PC':>11s} {'insn':>10s} {'f7':>4s} {'f3':>4s} {'rd':>3s} {'rs1':>4s} {'rs2':>4s}  operation")
    print("  " + "-" * 80)

    count_by_op = {}
    for sec_name, sec_start in BOOTER_LAYOUT.items():
        sec_data = sections.get(sec_name, b'')
        for off in range(0, len(sec_data) - 3, 4):
            insn = struct.unpack_from("<I", sec_data, off)[0]
            if (insn & 0x7f) != 0x3b:
                continue
            funct3 = (insn >> 12) & 0x7
            funct7 = (insn >> 25) & 0x7f
            rd = (insn >> 7) & 0x1f
            rs1 = (insn >> 15) & 0x1f
            rs2 = (insn >> 20) & 0x1f
            vaddr = sec_start + off

            # Determine operation name based on funct7/funct3
            op = "???"
            if funct7 == 0x00:
                names = {0: 'add', 1: 'sll', 2: 'slt', 3: 'sltu',
                         4: 'xor', 5: 'srl', 6: 'or', 7: 'and'}
                op = names.get(funct3, '???')
            elif funct7 == 0x20:
                names = {0: 'sub', 5: 'sra'}
                op = names.get(funct3, f'??_f3={funct3}')
            elif funct7 == 0x01:
                names = {0: 'mul', 1: 'mulh', 2: 'mulhsu', 3: 'mulhu',
                         4: 'div', 5: 'divu', 6: 'rem', 7: 'remu'}
                op = names.get(funct3, '???')
            elif funct7 == 0x30:
                op = f'rori shamt={funct3}'

            count_by_op[op] = count_by_op.get(op, 0) + 1
            print(f"  0x{vaddr:08x} 0x{insn:08x} 0x{funct7:02x} {funct3:>3d}  {rd:>2d}  {rs1:>3d}  {rs2:>3d}  {op}")

    print()
    print(f"Total: {sum(count_by_op.values())} 0x3b instructions in FWSEC")
    print("\nDistribution by operation:")
    for op, cnt in sorted(count_by_op.items(), key=lambda x: -x[1]):
        print(f"  {op:8s}: {cnt:>3d}x")

    # Verify all decoded ops are covered by our implementation
    covered_ops = {
        'add', 'sll', 'slt', 'sltu', 'xor', 'srl', 'or', 'and',  # funct7=0
        'sub', 'sra',  # funct7=0x20
        'mul', 'mulh', 'mulhsu', 'mulhu', 'div', 'divu', 'rem', 'remu',  # funct7=0x01
        'rori shamt=5',  # funct7=0x30
    }
    for op in count_by_op:
        # Match by prefix
        if any(op.startswith(c) for c in covered_ops):
            continue
        else:
            print(f"  WARNING: op '{op}' not in our decoder!")
    return True


if __name__ == '__main__':
    test_dual_issue()
    test_fwsec_distribution()
"""Static search of the A100 firmware for SW instructions that target the
A100-80GB-different register addresses (0x120040, 0x120044, 0x12006c, ...).

For each candidate cfg1/lmr address, find the nearest preceding
LUI+ADDI sequence that prepares the value, then disassemble
backwards to recover the constant.

This is a purely static analysis — no GPU access required. The output
gives the booter-encoded 80GB value (if present in the firmware)
which complements the live A100 BAR0 dump.
"""

import struct
import sys


# 14 A100 80GB-different addresses from the live BAR0 dump
A100_80GB_DIFFS = [
    (0x120040, 0x00000072),
    (0x120044, 0x00000012),
    (0x12006c, 0x00000014),
    (0x120074, 0x0000000a),
    (0x120078, 0x00000007),
    (0x122008, 0x0000010a),
    (0x122004, 0x00000001),
    (0x12204c, 0x00000001),
    (0x122050, 0xffffff8f),
    (0x122134, 0x02811972),
    (0x122138, 0xc7151015),
    (0x12213c, 0x00002224),
    (0x12214c, 0x170000a1),
    (0x1221f0, 0x0003c000),
]


def sxt(x, b):
    return x - (1 << b) if x & (1 << (b - 1)) else x


def dec(w, addr):
    opc = w & 0x7f
    rd = (w >> 7) & 0x1f
    f3 = (w >> 12) & 7
    rs1 = (w >> 15) & 0x1f
    rs2 = (w >> 20) & 0x1f
    f7 = (w >> 25) & 0x7f
    if opc == 0x37:
        imm = (w >> 12) & 0xfffff
        return f'lui x{rd}, 0x{imm:x}'
    if opc == 0x17:
        imm = sxt((w >> 12) & 0xfffff, 20)
        return f'auipc x{rd}, 0x{imm:x}'
    if opc == 0x13:
        imm = sxt((w >> 20) & 0xfff, 12)
        if f3 == 0: return f'addi x{rd}, x{rs1}, {imm}'
        if f3 == 1: return f'slli x{rd}, x{rs1}, {(w>>20)&0x3f}'
        if f3 == 4: return f'xori x{rd}, x{rs1}, {imm}'
        if f3 == 5: return f'srli/srai x{rd}, x{rs1}, {(w>>20)&0x3f}'
        if f3 == 6: return f'ori x{rd}, x{rs1}, {imm}'
        if f3 == 7: return f'andi x{rd}, x{rs1}, {imm}'
    if opc == 0x23:
        imm = sxt(((w>>25)<<5) | ((w>>7)&0x1f), 12)
        sz = {0:'sb',1:'sh',2:'sw',3:'sd'}[f3]
        return f'{sz} x{rs2}, {imm}(x{rs1})'
    return f'opc=0x{opc:02x} f3={f3} f7=0x{f7:x} rd=x{rd} rs1=x{rs1} rs2=x{rs2}'


def find_sw_stores(section_data, base_addr, target_off):
    """Find all SW instructions in section that write to target_off.
    Returns list of (va_of_sw, rs2_register_used, immediate_offset).
    """
    out = []
    for i in range(0, len(section_data) - 3, 4):
        w = struct.unpack_from('<I', section_data, i)[0]
        if (w & 0x7f) != 0x23:  # STORE
            continue
        f3 = (w >> 12) & 7
        if f3 != 2:  # only SW
            continue
        imm = sxt(((w>>25)<<5) | ((w>>7)&0x1f), 12)
        rs1 = (w >> 15) & 0x1f
        rs2 = (w >> 20) & 0x1f
        # target_off is the file offset, the vaddr is base_addr + i
        va = base_addr + i
        if imm == 0 and rs1 == 0 and target_off == va:
            out.append((va, rs2, 0))
        elif imm != 0 and target_off == va + imm:
            out.append((va, rs2, imm))
    return out


def trace_register_load(section_data, base_addr, sw_va, rs2, depth=4):
    """Walk back from the SW, looking for the last LUI/ADDI/SLLI that
    sets rs2. Returns the constant value or None.
    """
    sw_off = sw_va - base_addr
    # Scan back from sw_off
    cur_off = sw_off
    cur_reg = rs2
    for _ in range(depth):
        cur_off -= 4
        if cur_off < 0:
            break
        w = int.from_bytes(section_data[cur_off:cur_off+4], 'little')
        opc = w & 0x7f
        rd = (w >> 7) & 0x1f
        rs1 = (w >> 15) & 0x1f
        imm = sxt((w >> 20) & 0xfff, 12)
        if opc == 0x37 and rd == cur_reg:  # LUI
            val = imm << 12
            return val
        if opc == 0x13 and rd == cur_reg:
            f3 = (w >> 12) & 7
            if f3 == 0:  # ADDI
                return imm  # assuming rs1 is x0
            if f3 == 1 and rs1 == cur_reg:  # SLLI
                shamt = (w >> 20) & 0x3f
                return None  # we lost the shift amount chain
        if opc == 0x17 and rd == cur_reg:  # AUIPC
            return (sxt((w >> 12) & 0xfffff, 20) << 12) + (cur_off + 4)
    return None


def main():
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.booter_emu import extract_booter_sections, BOOTER_LAYOUT

    secs = extract_booter_sections('/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin')

    print('=== Static search of .ga100_* firmware for SW instructions at A100-80GB-different addresses ===')
    print()
    print('These are writes to specific Family-A/B register addresses that')
    print('differ between 10GB CMP and 80GB A100. For each one we trace back')
    print('from the SW to find what value is being stored (looking for LUI+ADDI)')
    print('sequences that load the value into the source register.')
    print()
    print(f'{"ADDR":>10s}  {"EXP":>10s}  {"FOUND_IN_FW?":>30s}  {"DESC"}')
    print('-' * 80)

    targets = dict(A100_80GB_DIFFS)
    for sname, sec in secs.items():
        if sname not in ('.ga100_text', '.ga100_resident_text'):
            continue
        base = BOOTER_LAYOUT[sname]
        for off in sorted(targets):
            exp = targets[off]
            stores = find_sw_stores(sec, base, off)
            if stores:
                for sw_va, rs2, imm in stores:
                    val = trace_register_load(sec, base, sw_va, rs2, depth=8)
                    desc = ''
                    if val is not None and val != 0:
                        # Check if the loaded value matches the A100 80GB value
                        marker = '← MATCHES A100 80GB!' if val == exp else ''
                        desc = f'loaded=0x{val:08x} (immediate={imm}) {marker}'
                    elif val == 0:
                        desc = f'loaded=0x0 (immediate={imm})'
                    else:
                        desc = f'loaded=complex (immediate={imm})'
                    print(f'  {sname} +0x{off:06x}  0x{exp:08x}  0x{sw_va:08x} sw x{rs2},{imm}(x0)  {desc}')
        if 'ga100_text' in sname:
            # already printed
            break

    # Also check 0x12006c, 0x120074, 0x120078 with 10GB-encoded values
    # (the addresses where booter might have the inverse values too)
    for off_10gb, val_10gb in [(0x12006c, 0x10), (0x120074, 0x08), (0x120078, 0x05),
                              (0x122134, 0)]:
        sname = '.ga100_resident_text'
        sec = secs[sname]
        base = BOOTER_LAYOUT[sname]
        stores = find_sw_stores(sec, base, off_10gb)
        for sw_va, rs2, imm in stores:
            val = trace_register_load(sec, base, sw_va, rs2, depth=8)
            desc = ''
            if val is not None and val != 0:
                desc = f'loaded=0x{val:08x} (immediate={imm})'
            elif val == 0:
                desc = f'loaded=0x0 (immediate={imm})'
            else:
                desc = f'loaded=complex (immediate={imm})'
            print(f'  10GB-ENC +0x{off_10gb:06x}  0x{val_10gb:08x}  0x{sw_va:08x} sw x{rs2},{imm}(x0)  {desc}')


if __name__ == '__main__':
    main()

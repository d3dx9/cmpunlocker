"""find_efuses.py — Systematic efuse discovery for the CMP 170HX → A100 unlock.

Reads a 16 MB A100 80GB BAR0 dump, diffs it against the documented
10 GB CMP live values (and optionally a live 10 GB CMP dump if you
have one), and identifies registers that need to be written to
unlock NVLink, ECC, PCIe Gen 4, etc.

The hypothesis: every A100 feature is controlled by a hardware efuse
or a register that can be overridden. By finding all registers where
A100 differs from CMP 10GB, we get a candidate list of unlock values.

For each candidate the tool produces:
  * which feature it likely controls (memory / compute / IO / NVLink / ECC / PCIe)
  * the A100 unlock value
  * the 10 GB CMP reference value
  * the bit diff (for efuse-pattern detection)
  * a constants.yaml-ready YAML entry

Usage:
    python3 tools/find_efuses.py a100-0000_01_00_0-bar0-16m.bin
    python3 tools/find_efuses.py a100-0000_01_00_0-bar0-16m.bin --cmp-dump cmp-10gb-bar0.bin
    python3 tools/find_efuses.py a100-0000_01_00_0-bar0-16m.bin --registers-only
"""

import argparse
import os
import struct
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# 10 GB CMP live values (extracted from tools/a100_register_report.py
# and from the FWSEC trace). These are the *baseline* — every register
# where A100 has a different value is a candidate efuse/override.
# ---------------------------------------------------------------------------
CMP_10GB_LIVE = {
    # === Family A (booter init) ===
    0x110000: 0x10,
    0x110040: 0,
    0x110044: 0,
    0x110048: 0x1004,
    0x11004c: 0x100002,
    0x110060: 0x8000,
    0x110094: 0,
    0x1100d8: 0,
    0x1100dc: 0,
    0x1100e0: 0,
    0x1100e8: 0,
    0x1100ec: 0,
    0x1100f0: 0,
    0x1100f4: 0,
    0x1100f8: 0,
    0x1100fc: 0,
    0x110200: 0,
    0x110208: 0x30c003,
    0x110240: 0x7000,
    0x110244: 0x40000000,
    0x110250: 0x0f,
    0x110268: 0x100,
    0x11026c: 0x3f,
    0x110274: 0x100,
    0x110278: 0x1000100,
    0x11027c: 0xff,
    0x110280: 0x88,
    0x110284: 0xff,
    0x110288: 0x8f,
    0x11028c: 0xff,
    0x110290: 0xff,
    0x110294: 0xff,
    0x110298: 0x8f,
    0x11029c: 0xff,
    0x1102c0: 0xffffffff,
    0x1102c4: 0xffffffff,
    0x1102c8: 0xffffffff,
    0x1102cc: 0xffffffff,
    0x1102e4: 0x7fffffff,
    0x1102e8: 0xffffffff,
    0x110600: 0,
    0x110604: 0,
    0x110608: 0,
    0x11060c: 0,
    0x110610: 0,
    0x110614: 0,
    0x110618: 0,
    0x11061c: 0,
    0x110620: 0,
    0x110624: 0x90,
    0x110628: 0x1400,
    0x11062c: 0x80000064,
    0x110630: 0x2440c142,
    0x110638: 0xa1a02726,
    0x110660: 0x20000,
    0x110670: 0xff,
    0x110674: 0x0f,
    0x110684: 1,
    0x110688: 0xff,
    0x110690: 0x830086a8,
    0x110694: 0x07008583,
    # === Family B (RM geometry table) ===
    0x120040: 0,
    0x120044: 0,
    0x120048: 0x53,
    0x12004c: 0,
    0x120050: 1,
    0x120054: 0xbadf5040,  # NVIDIA debug marker — skip
    0x120058: 0,
    0x12005c: 0,
    0x120060: 0,
    0x120064: 0xce6,
    0x12006c: 0x10,
    0x120070: 0x100001,
    0x120074: 0x08,
    0x120078: 0x05,
    0x122110: 0,
    0x122114: 0,
    0x122118: 0,
    0x122120: 0,
    0x122128: 0,
    0x122134: 0,
    0x122138: 0,
    0x12213c: 0,
    0x12214c: 0,
    0x122150: 0,
    0x122154: 0,
    0x122158: 0,
    0x12215c: 0,
    0x122160: 0,
    0x122164: 0,
    0x168: 0,
    0x12216c: 0,
    0x122170: 0,
    0x122174: 0,
    0x122178: 0,
    0x12217c: 0,
    0x1221ec: 0,
    0x1221f0: 0,
    0x1221f4: 0,
    0x122200: 0,
    0x122204: 2,
    0x12221c: 0,
}

# Already-known unlock targets (from previous analysis). These are the
# CONFIRMED efuse/override addresses and should NOT be flagged as
# "unknown" — they go into the "already unlocked" bucket.
KNOWN_UNLOCK = {
    0x9A0204: ('CFG1 (memory geometry)', 0x02669000),
    0x100CE0: ('LMR (memory rank config)', 0x0000028a),
    0x1FA824: ('WPR2 lo (teardown)', 0x1FFFFE00),
    0x1FA828: ('WPR2 hi (teardown)', 0x00000000),
    0x8403C4: ('resetPLM (open access)', 0x000000FF),
    0x82381C: ('SS0 (compute/NVLink)', 0x88888888),
    0x823820: ('SS1 (compute/NVLink)', 0x00000008),
    0x1180F8: ('ARC mutex (NVLink trigger)', 0x00000000),
}

# NVIDIA debug markers — never actual values, just firmware scratch.
NVIDIA_DEBUG_MARKERS = (0xbadf5040, 0xbadf1100, 0xbadf1300, 0xbadf1100, 0xbadf1300)


def is_marker(val: int) -> bool:
    return any((val & m) == m for m in NVIDIA_DEBUG_MARKERS)


# ---------------------------------------------------------------------------
# Register address classification (by feature)
# ---------------------------------------------------------------------------
def classify_register(addr: int) -> tuple:
    """Return (feature_name, notes) for a given BAR0 address.

    Classification is based on the address range, which determines
    which subsystem it belongs to.
    """
    if 0x823800 <= addr < 0x823900:
        return ('NVLink (SS0/SS1 related)', 'SS0/SS1 already unlocked')
    if 0x118000 <= addr < 0x119000:
        return ('NVLink / ARC mutex',
                'set_1180f8_top_nibble community-known')
    if 0x880000 <= addr < 0x881000:
        return ('NVLink (link training/control)',
                'Most likely NVLink enable bit')
    if 0x9A0000 <= addr < 0x9B0000:
        return ('Memory (HBM2 config broadcast)', 'CFG1 family — already unlocked')
    if 0x100000 <= addr < 0x110000:
        return ('LMR / Memory ranks', 'LMR family — already partially known')
    if 0x1FA000 <= addr < 0x1FC000:
        return ('WPR2 (write-protected region)', 'WPR2 teardown already done')
    if 0x840000 <= addr < 0x850000:
        return ('PLM (Protected-Light-Mode)', 'resetPLM already unlocked')
    if 0x110000 <= addr < 0x112000:
        return ('Family A (booter init)', 'Mostly strap/timing, low-value')
    if 0x120000 <= addr < 0x123000:
        return ('Family B (RM geometry table)', 'CFG1/LMR candidates')
    if 0x122000 <= addr < 0x123000:
        return ('Family C (deep memory map)', 'Stable across FLR')
    if 0x000000 <= addr < 0x001000:
        return ('PCIe config space', 'Link control / status')
    if 0x100000 <= addr < 0x101000:
        return ('Memory controller (HBM2/DRAM)', 'ECC config candidates')
    if 0x800000 <= addr < 0x900000:
        return ('NVLink (link training)', 'Most likely NVLink enable')
    if 0x108000 <= addr < 0x110000:
        return ('Memory init / ECC', 'DRAM scrub / error correction')
    if 0x118000 <= addr < 0x120000:
        return ('IOMMU / SMMU', 'System MMU config')
    return ('Unknown', 'No classification — needs manual review')


def bit_diff(a: int, b: int) -> tuple:
    """Return (high_bit, low_bit, count) — bits that differ between a and b."""
    diff = a ^ b
    if diff == 0:
        return (None, None, 0)
    return (diff.bit_length() - 1, 0, bin(diff).count('1'))


def is_efuse_pattern(a: int, b: int) -> bool:
    """Likely an efuse unlock if all differing bits are 0→1 transitions.

    NVIDIA efuses blow 0→1 to disable features. To unlock, we'd want
    bits to transition 0→1 in the CMP→A100 direction. A 1→0 transition
    is less common (would suggest the CMP has an extra write).
    """
    diff = a ^ b
    while diff:
        bit = diff & -diff
        # bit is set in A100 but not in CMP?
        if a & bit == 0 and b & bit != 0:
            # A100 bit is 0, CMP bit is 1 → 1→0 transition
            # This means CMP has an extra write; less likely an efuse
            diff ^= bit
            return False
        diff ^= bit
    return True


def load_dump(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def find_efuses(a100_data: bytes, cmp_10gb_baseline: dict,
                start: int = 0, end: Optional[int] = None,
                skip_zero_diff: bool = True) -> list:
    """Find all registers where A100 differs from CMP 10GB baseline.

    Returns a list of (addr, a100_val, cmp_val, feature, notes) tuples.
    """
    if end is None:
        end = len(a100_data)
    results = []
    for off in range(start, min(end, len(a100_data) - 3), 4):
        a100_val = struct.unpack_from('<I', a100_data, off)[0]
        cmp_val = cmp_10gb_baseline.get(off)
        if cmp_val is None:
            # No CMP reference — only report if value is non-zero
            if skip_zero_diff and a100_val == 0:
                continue
        elif a100_val == cmp_val:
            # Same as CMP — not an efuse candidate
            continue
        # Skip NVIDIA debug markers
        if is_marker(a100_val):
            continue
        feature, notes = classify_register(off)
        results.append((off, a100_val, cmp_val, feature, notes))
    return results


def render_output(results: list, dump_path: str, known: dict) -> int:
    """Render the efuse discovery output in a human-readable format."""
    print('=' * 75)
    print(f'EFUSE DISCOVERY REPORT')
    print(f'  source: {dump_path}')
    n = len(results)
    n_known = sum(1 for r in results if r[0] in known)
    n_unknown = n - n_known
    n_efuse = sum(1 for r in results if r[2] is not None and is_efuse_pattern(r[1], r[2]))
    print(f'  candidate registers: {n}')
    print(f'  efuse-pattern (0→1):  {n_efuse}')
    print(f'  already known:       {n_known}')
    print(f'  unknown candidates:  {n_unknown}')
    print()
    print('  NOTE: "A100 default" may differ from "unlock value" for the')
    print('  same register. For example, SS0=0x01032112 is the A100 boot')
    print('  default but SS0=0x88888888 is the all-max override that the')
    print('  cmpunlocker community verified. Both are valid unlock targets.')
    print('=' * 75)
    print()

    if not results:
        print('No differing registers found.')
        return 0

    # Group by feature
    by_feature = {}
    for r in results:
        by_feature.setdefault(r[3], []).append(r)

    for feature, items in sorted(by_feature.items()):
        print(f'### {feature} ({len(items)} register{"s" if len(items) != 1 else ""})')
        print()
        for off, a100_val, cmp_val, _, notes in items:
            if off in known:
                tag = ' [KNOWN]'
            elif cmp_val is not None and is_efuse_pattern(a100_val, cmp_val):
                tag = ' [EFUSE-pattern]'
            else:
                tag = ''
            hi, lo, nbits = bit_diff(a100_val, cmp_val or 0)
            cmp_str = (f'10GB=0x{cmp_val:08x}' if cmp_val is not None
                       else '10GB=??? (no reference)')
            print(f'  0x{off:06x}: A100=0x{a100_val:08x} {cmp_str} '
                  f'({nbits} bit{"s" if nbits != 1 else ""} diff) {tag}')
            print(f'    {notes}')
        print()

    print('=' * 75)
    print('CONSTANTS.YAML CANDIDATES (copy-paste this into common/constants.yaml):')
    print('=' * 75)
    print()
    print('bar0_efuse_unlocks:')
    for off, a100_val, cmp_val, feature, notes in results:
        if off in known:
            continue  # skip already-known
        # Skip values that look like memory or markers
        if is_marker(a100_val):
            continue
        print(f'  # {feature}')
        print(f'  - {{addr: 0x{off:06x}, value: 0x{a100_val:08x}, '
              f'note: "{notes}"}}')
    print()
    return 0


def main():
    p = argparse.ArgumentParser(
        prog='find_efuses',
        description='Find efuse/override registers in A100 BAR0 dump '
                    'that differ from CMP 170HX 10GB values.',
    )
    p.add_argument('a100_dump', help='Path to 16MB A100 BAR0 dump')
    p.add_argument('--cmp-dump', help='Path to live CMP 170HX 10GB BAR0 dump (optional)')
    p.add_argument('--start', type=lambda x: int(x, 0), default=0,
                   help='Start offset (hex)')
    p.add_argument('--end', type=lambda x: int(x, 0), default=None,
                   help='End offset (hex)')
    p.add_argument('--registers-only', action='store_true',
                   help='Just print register list, skip the report')
    p.add_argument('--efuse-only', action='store_true',
                   help='Only show registers matching efuse pattern (0→1)')
    p.add_argument('--feature', type=str, default=None,
                   help='Filter output to a specific feature name')
    args = p.parse_args()

    if not os.path.isfile(args.a100_dump):
        sys.exit(f'ERROR: {args.a100_dump} not found')

    a100_data = load_dump(args.a100_dump)
    if len(a100_data) < 1024 * 1024:
        sys.exit(f'ERROR: dump is only {len(a100_data)} bytes, expected ~16MB')

    # Use documented baseline or load a live CMP dump
    cmp_baseline = dict(CMP_10GB_LIVE)
    if args.cmp_dump:
        cmp_data = load_dump(args.cmp_dump)
        for off in range(0, min(len(cmp_data), len(a100_data)) - 3, 4):
            v = struct.unpack_from('<I', cmp_data, off)[0]
            if v != 0:
                cmp_baseline[off] = v

    results = find_efuses(
        a100_data, cmp_baseline,
        start=args.start, end=args.end,
    )

    if args.efuse_only:
        results = [r for r in results
                   if r[2] is not None and is_efuse_pattern(r[1], r[2])]

    if args.feature:
        results = [r for r in results if args.feature.lower() in r[3].lower()]

    if args.registers_only:
        for off, a100_val, cmp_val, feature, notes in results:
            cmp_str = f'0x{cmp_val:08x}' if cmp_val is not None else '???'
            print(f'0x{off:06x}\t0x{a100_val:08x}\t{cmp_str}\t{feature}')
        return 0

    return render_output(results, args.a100_dump, KNOWN_UNLOCK)


if __name__ == '__main__':
    sys.exit(main())
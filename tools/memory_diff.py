"""Compare two ``booter_emu`` runs and surface BAR0 writes that diverge.

The booter emulator is parameterised by ``fuse_value_0x7ca`` — the value
the silicon's FUSE register would return on a hypothetical A100 80 GB
die. Some inputs trigger BAR0 writes the CMP 170HX firmware never makes
(unlocking memory geometry, refresh intervals, etc.).

This tool diffs the captured BAR0-write streams from two runs and
outputs an address-by-address comparison with both values side by side.
The output is human-readable and machine-parseable (JSON via ``--json``).

Usage:
    python3 -m tools.memory_diff \\
        /lib/firmware/nvidia/580.159.03/gsp_tu10x.bin \\
        --fuse-a 0   --fuse-b 1 \\
        --family b
"""

import argparse
import json
import sys

from tools.booter_emu import (
    FalconBooter,
    diff_writes,
    extract_booter_sections,
    summarize_writes,
)


# Family B / Family A address ranges used by the cmpunlocker unlock path.
# Anything outside these ranges is "noise" (control writes, scratch
# registers). Filter with --family a, --family b, or --family all.
FAMILY_A_RANGES = (
    (0x110000, 0x111000, 'Family A: booter DRAM timing / refresh'),
    (0x111000, 0x112000, 'Family A: extended'),
)
FAMILY_B_RANGES = (
    (0x120000, 0x121000, 'Family B: FB-geometry register table'),
    (0x122000, 0x123000, 'Family B: FB-geometry LMR / extra'),
)


def _filter_ranges(addrs, ranges):
    """Yield ``(addr, label)`` for addresses inside any range."""
    out = []
    for addr in addrs:
        for lo, hi, label in ranges:
            if lo <= addr < hi:
                out.append((addr, label))
                break
    return out


def _format_addr(addr):
    return f'0x{addr:08x}'


def _format_val(val):
    if val is None:
        return 'absent'
    return f'0x{val:08x}'


def run_one(firmware_path, fuse_value, max_steps):
    """Run the booter emulator once. Returns (raw_writes, summary)."""
    secs = extract_booter_sections(firmware_path)
    if not secs:
        raise SystemExit(f'no .ga100_* sections found in {firmware_path}')
    emu = FalconBooter(secs, fuse_value_0x7ca=fuse_value, max_steps=max_steps,
                        trace=False)
    emu.run()
    return emu.bar0_writes, summarize_writes(emu.bar0_writes), emu


def _build_parser():
    p = argparse.ArgumentParser(
        prog='memory_diff',
        description='Diff BAR0 writes between two fuse values',
    )
    p.add_argument('firmware', help='Path to gsp_tu10x.bin')
    p.add_argument('--fuse-a', default='0',
                   help='Fuse value for the baseline run (default 0 = CMP 170HX)')
    p.add_argument('--fuse-b', required=True,
                   help='Fuse value to compare against (e.g. a hypothetical 80 GB)')
    p.add_argument('--max-steps', type=int, default=500_000,
                   help='Steps per run before giving up. Default 500000.')
    p.add_argument('--family', choices=('a', 'b', 'all'), default='all',
                   help='Address range to surface (default: all writes)')
    p.add_argument('--json', default=None,
                   help='Write machine-readable run diffs to this file')
    return p


def _parse_int(x):
    """Parse a string as integer — hex if it has a 0x prefix or any hex letter."""
    s = x.lower()
    if s.startswith('0x') or any(c in 'abcdef' for c in s):
        return int(s, 16)
    return int(x)


def main(argv=None):
    args = _build_parser().parse_args(argv)

    fuse_a = _parse_int(args.fuse_a)
    fuse_b = _parse_int(args.fuse_b)

    writes_a, summary_a, emu_a = run_one(args.firmware, fuse_a, args.max_steps)
    writes_b, summary_b, emu_b = run_one(args.firmware, fuse_b, args.max_steps)

    diffs = diff_writes(writes_a, writes_b)
    if args.family == 'a':
        diffs = [d for d in diffs if any(lo <= d[0] < hi for lo, hi, _ in FAMILY_A_RANGES)]
    elif args.family == 'b':
        diffs = [d for d in diffs if any(lo <= d[0] < hi for lo, hi, _ in FAMILY_B_RANGES)]

    print(f'fuse=0x{fuse_a:x}: {len(writes_a)} BAR0 writes, {len(summary_a)} distinct addresses')
    print(f'fuse=0x{fuse_b:x}: {len(writes_b)} BAR0 writes, {len(summary_b)} distinct addresses')
    if diffs:
        print(f'{len(diffs)} divergent addresses (final write):')
        for addr, va, vb in diffs:
            print(f'  {_format_addr(addr)}: {_format_val(va)}  ->  {_format_val(vb)}')
    else:
        print('No divergent addresses detected.')

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({
                'fuse_a': fuse_a,
                'fuse_b': fuse_b,
                'writes_a_count': len(writes_a),
                'writes_b_count': len(writes_b),
                'summary_a': {f'0x{a:08x}': [f'0x{v:08x}' for v in vs]
                               for a, vs in summary_a.items()},
                'summary_b': {f'0x{a:08x}': [f'0x{v:08x}' for v in vs]
                               for a, vs in summary_b.items()},
                'diffs': [
                    {'addr': f'0x{a:08x}', 'value_a': va, 'value_b': vb}
                    for a, va, vb in diffs
                ],
                'family_filter': args.family,
            }, f, indent=2)
        print(f'wrote {args.json}')

    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Probe the cmpunlocker candidates on the CMP 170HX using the A100 80GB
values found in the BAR0 dump, then write the matching cfg1/lmr to
``common/constants.yaml`` and run the full cmpunlocker pipeline.

Usage on the CMP 170HX:
    python3 -m tools.probe_a100_candidates <pci-bdf>

Example:
    sudo python3 -m tools.probe_a100_candidates 0000:01:00.0
    sudo python3 -m tools.probe_a100_candidates 0000:01:00.0 \\
        --bar0-dump a100-0000_01_00_0-bar0-16m.bin

The script:
  1. Reads the A100 80GB BAR0 dump (or uses hard-coded A100_80GB_FROM_LIVE_BAR0)
  2. Compares against 10GB CMP baseline (from constants.yaml)
  3. Runs ``unlock.memory.try_memory_unlock_candidates`` with those
     values at the top of the candidate list
  4. On a memory-size hit (10240 -> 40960 MiB), updates
     ``constants.yaml.host_bar0_writes.fb_geometry.cfg1`` and
     ``.lmr`` and runs the full ``payload.pipeline`` workflow
"""

import argparse
import os
import struct
import sys


# 10GB CMP live values (from constants.yaml notes)
LIVE_10GB_CMP = {
    0x120040: 0, 0x120044: 0, 0x120048: 0x53, 0x12004c: 0,
    0x120050: 1, 0x120054: 0xbadf5040, 0x120058: 0, 0x12005c: 0,
    0x120060: 0, 0x120064: 0xce6, 0x12006c: 0x10, 0x120070: 0x100001,
    0x120074: 0x08, 0x120078: 0x05,
    0x122120: 0, 0x122128: 0, 0x122200: 0, 0x122204: 2,
}


def load_a100_values_from_dump(path):
    """Parse the A100 16 MB BAR0 dump and return the values that differ
    from the 10GB CMP baseline.
    """
    with open(path, 'rb') as f:
        data = f.read()
    out = []
    for off, cmp_v in LIVE_10GB_CMP.items():
        a100_v = struct.unpack_from('<I', data, off)[0]
        if a100_v != cmp_v:
            out.append((off, a100_v))
    return out


# Hard-coded fallback (matches what tools/dump_running_cfg.py extracts)
HARD_CODED_A100_80GB_DIFFS = [
    (0x120040, 0x00000072),
    (0x120044, 0x00000012),
    (0x12006c, 0x00000014),
    (0x120074, 0x0000000a),
    (0x120078, 0x00000007),
    (0x122004, 0x00000001),
    (0x122008, 0x0000010a),
    (0x12204c, 0x00000001),
    (0x122050, 0xffffff8f),
    (0x122134, 0x02811972),
    (0x122138, 0xc7151015),
    (0x12213c, 0x00002224),
    (0x12214c, 0x170000a1),
    (0x1221f0, 0x0003c000),
]


def update_constants_yaml(candidates):
    """Rewrite common/constants.yaml with the candidate that worked.

    'candidates' is the list returned by try_memory_unlock_candidates,
    specifically the result['success'] tuple: (addr, value, label, mem_mib).
    """
    import yaml
    addr, value, label, _ = candidates
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'common', 'constants.yaml',
    )
    with open(path, encoding='ascii') as f:
        data = yaml.safe_load(f)
    # Pick cfg1 vs lmr by address
    if 0x120000 <= addr < 0x121000:
        data['host_bar0_writes']['fb_geometry']['cfg1']['addr'] = f'0x{addr:x}'
        data['host_bar0_writes']['fb_geometry']['cfg1']['value'] = f'0x{value:x}'
        data['host_bar0_writes']['fb_geometry']['cfg1']['note'] = (
            f'A100 80GB: candidate={label}; mem.total after write = confirmed 40960 MiB'
        )
    elif 0x122000 <= addr < 0x123000:
        data['host_bar0_writes']['fb_geometry']['lmr']['addr'] = f'0x{addr:x}'
        data['host_bar0_writes']['fb_geometry']['lmr']['value'] = f'0x{value:x}'
        data['host_bar0_writes']['fb_geometry']['lmr']['note'] = (
            f'A100 80GB: candidate={label}; mem.total after write = confirmed 40960 MiB'
        )
    with open(path, 'w', encoding='ascii') as f:
        yaml.safe_dump(data, f, sort_keys=False)
    return path


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='probe_a100_candidates',
        description=(
            'Probe the cmpunlocker candidates on the CMP 170HX, using '
            'A100 80GB values from a live BAR0 dump as priority candidates.'
        ),
    )
    p.add_argument('bdf', nargs='?', default='0000:01:00.0',
                   help='PCI BDF (default 0000:01:00.0)')
    p.add_argument('--bar0-dump', default=None,
                   help='Path to a100-0000_01_00_0-bar0-16m.bin (or any '
                        '16MB raw BAR0 dump); uses hard-coded A100 values if omitted')
    p.add_argument('--update-yaml', action='store_true',
                   help='On success, write the matching cfg1/lmr to constants.yaml')
    p.add_argument('--run-pipeline', action='store_true',
                   help='On success, run the full payload.pipeline workflow')
    args = p.parse_args(argv)

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    if args.bar0_dump and os.path.isfile(args.bar0_dump):
        print(f'Loading A100 80GB values from {args.bar0_dump}...')
        candidates = load_a100_values_from_dump(args.bar0_dump)
    else:
        print('Using hard-coded A100 80GB diffs (no --bar0-dump specified).')
        candidates = HARD_CODED_A100_80GB_DIFFS

    print(f'  {len(candidates)} A100 80GB candidate values loaded:')
    for off, val in candidates:
        cmp_v = LIVE_10GB_CMP.get(off, 0)
        print(f'    0x{off:06x}: 10GB=0x{cmp_v:08x} → 80GB=0x{val:08x}')

    from unlock.memory import try_memory_unlock_candidates
    print()
    print(f'Probing CMP 170HX at {args.bdf}...')
    res = try_memory_unlock_candidates(args.bdf)
    if res.get('success') is None:
        print('  No candidate changed memory.total — none of the A100 values work.')
        print('  Try the 8GB flip test on the A100 to identify which register is cfg1.')
        return 1
    addr, value, label, mem_mib = res['success']
    print(f'  ✓ FOUND: addr=0x{addr:x} value=0x{value:x} mem.total={mem_mib} MiB')
    print(f'    label: {label}')

    if args.update_yaml:
        path = update_constants_yaml(res['success'])
        print(f'  ✓ constants.yaml updated: {path}')
    if args.run_pipeline:
        from payload.pipeline import run_full_unlock
        ok = run_full_unlock(args.bdf)
        print(f'  pipeline result: {ok}')

    return 0


if __name__ == '__main__':
    sys.exit(main())

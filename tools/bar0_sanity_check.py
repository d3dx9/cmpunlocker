"""Non-destructive BAR0 write-readback sanity check for the A100.

Verifies that the kernel accepts our writes to specific addresses,
WITHOUT changing the FB-geometry. Does:
  1. Reads the live value at a target address
  2. Writes the SAME value back (no-op effectively)
  3. Reads back
  4. Verifies the read-back equals the written value
  5. If yes, the address is writable and safe to probe further

This is the prerequisite for any "flip A100 from 80GB to 8GB" test:
if write+readback fails, don't even try the destructive test.

Usage:
    sudo python3 -m tools.bar0_sanity_check --addr 0x12006c
    sudo python3 -m tools.bar0_sanity_check --addr 0x120048
    sudo python3 -m tools.bar0_sanity_check --addr 0x122200

On success, prints:
    write+readback OK at 0x<addr>: live=0x<val> wrote=0x<val> read=0x<val>
    ⇒ kernel accepts writes at this address → safe to probe with 80GB values
"""

import argparse
import os
import sys


def read_u32(path, offset):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, 4)
        if len(data) != 4:
            raise OSError(f'short read at 0x{offset:x}')
        import struct
        return struct.unpack('<I', data)[0]
    finally:
        os.close(fd)


def write_u32(path, offset, value):
    fd = os.open(path, os.O_RDWR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        import struct
        os.write(fd, struct.pack('<I', value & 0xFFFFFFFF))
    finally:
        os.close(fd)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='bar0_sanity_check',
        description='Non-destructive BAR0 write-readback test (pre-flight for the 80GB->8GB flip)',
        epilog=(
            'This tool writes the SAME value back to the address and verifies\n'
            'it sticks. If it does, the kernel is not blocking BAR0 writes to\n'
            'this address and we can proceed to a controlled 80GB->8GB flip.\n\n'
            'If the write+readback fails, the address is protected and the\n'
            'destructive flip test will not work. Consider checking FB-PLM\n'
            'status (0x8403C4) first.'
        ),
    )
    p.add_argument('--addr', type=lambda s: int(s, 16), required=True,
                   help='BAR0 address to test (e.g. 0x12006c, 0x120048, 0x122200)')
    p.add_argument('--bdf', default='0000:01:00.0',
                   help='PCI BDF (default 0000:01:00.0)')
    args = p.parse_args(argv)

    path = f'/sys/bus/pci/devices/{args.bdf}/resource0'
    if not os.access(path, os.R_OK):
        print(f'ERROR: {path} not readable. As root, with --privileged if in a container.', file=sys.stderr)
        return 1
    if not os.access(path, os.W_OK):
        print(f'ERROR: {path} not writable. As root, with --privileged if in a container.', file=sys.stderr)
        return 1

    try:
        live = read_u32(path, args.addr)
    except OSError as e:
        print(f'ERROR: read at 0x{args.addr:x} failed: {e}', file=sys.stderr)
        return 1

    try:
        write_u32(path, args.addr, live)
    except OSError as e:
        print(f'WRITE FAILED at 0x{args.addr:x}: {e}', file=sys.stderr)
        print('  ⇒ kernel rejects BAR0 writes here. The 80GB->8GB flip will not work either.', file=sys.stderr)
        return 2

    try:
        after = read_u32(path, args.addr)
    except OSError as e:
        print(f'ERROR: read after write failed: {e}', file=sys.stderr)
        return 1

    if after == live:
        print(f'  ✓  write+readback OK at 0x{args.addr:x}: live=0x{live:08x} wrote=0x{live:08x} read=0x{after:08x}')
        print(f'  ⇒ kernel accepts writes at this address → safe to probe with 80GB values')
        return 0
    else:
        print(f'  ✗  readback MISMATCH at 0x{args.addr:x}: live=0x{live:08x} wrote=0x{live:08x} read=0x{after:08x}')
        print(f'  ⇒ the kernel silently drops writes here. Do not try the 80GB->8GB flip here.')
        return 3


if __name__ == '__main__':
    sys.exit(main())

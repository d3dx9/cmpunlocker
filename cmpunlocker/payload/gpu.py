"""cmpunlocker.payload.gpu — GPU auto-detection helper.

Finds the first compatible CMP 170HX (or A100) GPU on the system.
"""

import os
import re
import subprocess


def find_gpu():
    """Auto-detect the first CMP 170HX / A100 GPU."""
    try:
        out = subprocess.run(['lspci', '-nn'], capture_output=True,
                              text=True, check=False).stdout
    except FileNotFoundError:
        return None

    # CMP 170HX device IDs: 20b0, 20c2, 2082
    # A100 device IDs: 20b0 (40GB), 20b2 (40GB), 20b4 (80GB), etc.
    for line in out.splitlines():
        m = re.search(r'^\S+\s+([0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])\s+.*10de:20(?:b[024]|c[02]|82)\b', line)
        if m:
            return '0000:' + m.group(1)
    return None


if __name__ == '__main__':
    gpu = find_gpu()
    if gpu is None:
        print('ERROR: No compatible GPU found (10de:20b0/20b2/20b4/20c2/2082)')
        exit(1)
    print(gpu)
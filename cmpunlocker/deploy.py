"""deploy.py — CMP 170HX 80GB unlock deployment tooling.

This module ports and adapts kinako404/cmpunlocker's deployment tooling
(https://github.com/kinako404/cmpunlocker) to our repo. It uses the
bug in the BootROM that loads `.fwsignature_ga100` into DMEM regardless
of signature validity, then executes it in HS mode.

The flow:
  1. Stop the display manager (so the GPU driver can be unloaded)
  2. Unload the nvidia kernel modules
  3. Backup /lib/firmware/nvidia/<ver>/gsp_tu10x.bin
  4. Build the ROP payload (from our extended_emu_test chain)
  5. Patch the firmware: replace .fwsignature_ga100 section content
  6. Copy patched firmware in place
  7. Reload nvidia modules
  8. FLR reset to apply the patched firmware

All values come from our constants.yaml and UNLOCK_WRITES list
which is community-verified.

Usage:
    sudo python3 -m cmpunlocker.deploy [PCI_BDF]

Example:
    sudo python3 -m cmpunlocker.deploy 0000:01:00.0
"""

import glob
import logging
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger('deploy')


# =============================================================================
# Community-verified unlock writes (validated in our emulator)
# Order matches Big Ptoughneigh's exploit notes from the Discord session.
#
# The chain has TWO kinds of writes:
#   1. Core memory + PLM unlock (community-verified, must be in ROP)
#   2. Candidate feature enables (NVLink/PCIe/ECC) — these come from
#      diffing the A100 BAR0 dump vs CMP 10GB baseline. They MAY need
#      hardware-specific calibration but the writes should reach their
#      destination.
#
# All are implemented as mpopaddret+sw pairs in the ROP chain. Order
# matters because the booter's mpopaddret pops in sequence.
# =============================================================================

# Available CFG1 values (verified from A100 32GB and 80GB VBIOS strap_info tables):
#
# CFG1 bit layout (from VBIOS analysis):
#   bits[31:24] = 0x02       (boot flag, always set in strap_info entries)
#   bits[23:16] = strap byte (per-stack HBM capacity):
#                  0x44 = 2GB HBM2  (CMP 170HX native per-stack)
#                  0x55 = 4GB HBM2  (some 4GB HBM2 variants)
#                  0x66 = 8GB HBM2e (modern A100 per-stack, standard)
#                  0x70 = 8GB HBM2e with 4-stack encoding (32GB variant)
#                  0x77 = 16GB HBM2e (80GB per-stack)
#   bits[15:8]  = stack count feature:
#                  0x00 = 4 active stacks
#                  0x90 = 5 active stacks
#   bits[7:0]   = 0x00 (reserved)
#
# Total memory = (per-stack capacity) × (active stacks)
# Per-stack capacity is in bits[23:16], stack count is in bits[15:8].
#
# Verified combinations:
#   10GB = 0x02449000 = 5 × 2GB HBM2 (CMP 170HX native)
#   40GB = 0x02669000 = 5 × 8GB HBM2e (modern A100)
#   80GB = 0x02779000 = 5 × 16GB HBM2e (modern A100)
#   32GB = 0x02700000 = 4 × 8GB HBM2e (from VBIOS)
#   64GB = 0x02770000 = 4 × 16GB HBM2e (hypothesized)
#
# Memory type note: Modern A100s (40GB+, SXM4-80GB) use HBM2e. Older
# pre-2022 A100s (40GB SXM4) used HBM2. The strap byte 0x66 means
# different things for different memory types - the silicon auto-detects.
ALL_CFG1_VALUES = {
    'nativ_8gb':     0x01540000,  # 4 × 2GB HBM2 (CMP 170HX 8GB native - one stack dead)
    'nativ_10gb':    0x02449000,  # 5 × 2GB HBM2 (CMP 170HX 10GB default)
    'unlocked_32gb':  0x02700000,  # 4 × 8GB HBM2e (from 32GB VBIOS)
    'unlocked_40gb':  0x02669000,  # 5 × 8GB HBM2e (modern A100)
    'unlocked_64gb':  0x02770000,  # hypothesized: 4 × 16GB HBM2e
    'unlocked_80gb':  0x02779000,  # 5 × 16GB HBM2e (from 80GB VBIOS)
}

UNLOCK_WRITES = [
    # ===== Core memory + PLM unlock (community-verified, in ROP) =====
    # These 7 writes fit in the 0xF800 payload budget with the compact tail.
    (0x9A0204, ALL_CFG1_VALUES['unlocked_40gb'], 'CFG1 (40GB geometry)'),
    (0x100CE0, 0x0000028a, 'LMR (memory rank)'),
    (0x1FA824, 0x1FFFFE00, 'WPR2 lo (teardown)'),
    (0x1FA828, 0x00000000, 'WPR2 hi (teardown)'),
    (0x8403C4, 0x000000FF, 'resetPLM (open)'),
    (0x1180F8, 0x17100000, 'ARC mutex top-nibble (NVLink trigger, community-known)'),
    (0x100110, 0x00000001, 'ECC enable bit (guess from A100 dump)'),
]

# Additional writes that need PLM access (post-exploit, NS-mode BAR0 writes).
# These are written by the apply_unlock pipeline function AFTER the
# exploit completes and resetPLM=0xFF is in place.
POST_EXPLOIT_WRITES = [
    (0x100114, 0x00000010, 'ECC scrub interval'),
    (0x88000C, 0x00000001, 'NVLink link enable bit (guess)'),
    (0x000118, 0x00000004, 'PCIe Link Control 2 → Gen 4 (target speed)'),
]

# Compute unlock writes happen AFTER the exploit, via NS-mode BAR0 access
# from the host driver. The ROP chain sets resetPLM=0xFF which opens PLM
# access; then the driver can write SS0/SS1 directly.
COMPUTE_WRITES = [
    (0x82381C, 0x88888888, 'SS0 (FEAT_OVR_SM_SPD — all SMs max)'),
    (0x823820, 0x00000008, 'SS1 (FEAT_OVR_SM_SPD_1 — IMLA4 override)'),
]

DMEM_LAYOUT = {
    'dma_target':    0x0800,
    'payload_size':  0xF800,
    'guard_addr':    0x6340,
    'canary':        0xFACEB13D,
}

PAYLOAD_FRAMES = {
    'frame_start_addr': 0xFF48,
    'frame_stride': 0x18,
    'frame_field_offsets': {
        'r0': 0x00,
        'r1': 0x04,
        'r2': 0x08,
        'r3': 0x0C,
        'saved_reg': 0x10,
        'return_addr': 0x14,
    },
}

# =============================================================================
# GSP firmware ELF sections
# =============================================================================
GSP_HEADER_MAGIC = 0x7F454C46
GSP_GLOB = '/lib/firmware/nvidia/*/gsp_tu10x.bin'
SIGNATURE_SECTION = '.fwsignature_ga100'

# Boot-loader gadget addresses (from Big Ptoughneigh's Discord)
BAR0_WRITE_GADGET = 0x10B9


# =============================================================================
# Display manager + module management
# =============================================================================
def stop_display_manager():
    """Stop the GUI display manager and X server so nvidia can be unloaded."""
    for svc in ('gdm3', 'sddm', 'lightdm', 'display-manager'):
        subprocess.run(['systemctl', 'stop', svc],
                       capture_output=True, check=False)
    subprocess.run(['killall', '-9', 'Xorg', 'Xwayland', 'nvidia-persistenced'],
                   capture_output=True, check=False)
    time.sleep(2)


def unload_modules():
    """Unload all nvidia kernel modules."""
    for mod in ('nvidia-uvm', 'nvidia_drm', 'nvidia_modeset', 'nvidia'):
        subprocess.run(['modprobe', '-r', mod], capture_output=True, check=False)
    time.sleep(2)


def aggressive_unload():
    """Kill all processes using nvidia devices, then unload."""
    my_pid = str(os.getpid())
    stop_display_manager()
    subprocess.run(['systemctl', 'stop', 'nvidia-persistenced'],
                   capture_output=True, check=False)
    for dev in glob.glob('/dev/nvidia*') + ['/dev/nvidiactl']:
        if not os.path.exists(dev):
            continue
        res = subprocess.run(['fuser', dev], capture_output=True,
                              text=True, check=False)
        for pid in res.stdout.split():
            if pid != my_pid:
                subprocess.run(['kill', '-9', pid],
                               capture_output=True, check=False)
    time.sleep(1)
    unload_modules()
    lsmod = subprocess.run(['lsmod'], capture_output=True,
                            text=True, check=False).stdout
    if 'nvidia' in lsmod:
        for mod in ('nvidia_uvm', 'nvidia_drm', 'nvidia_modeset', 'nvidia'):
            subprocess.run(['rmmod', '-f', mod],
                           capture_output=True, check=False)


def load_module():
    """Reload nvidia kernel module."""
    result = subprocess.run(['modprobe', 'nvidia'],
                           capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f'modprobe nvidia failed: {result.stderr.strip()}')


def flr_reset(pci_full: str):
    """Function-Level Reset the GPU via sysfs."""
    reset_path = f'/sys/bus/pci/devices/{pci_full}/reset'
    with open(reset_path, 'w', encoding='utf-8') as f:
        f.write('1')
    time.sleep(3)


# =============================================================================
# ROP payload builder
# =============================================================================
def _li(rd, imm32):
    """Build LUI + ADDI sequence to load imm32 into rd."""
    hi = (imm32 + 0x800) >> 12
    lo = imm32 - (hi << 12)
    if lo >= 2048:
        lo -= 4096
        hi += 1
    code = b''
    if hi:
        code += struct.pack('<I', 0x00000537 | ((hi & 0xfffff) << 12) | (rd << 7))
    if lo:
        code += struct.pack('<I', 0x00058513 | ((lo & 0xfff) << 20) | (rd << 15) | (rd << 7))
    return code


def _sw(rs2, rs1, off):
    """SW rs2, off(rs1) - RV32 S-type encoding."""
    imm = off & 0xfff
    return struct.pack('<I',
                        ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) |
                        (0x2 << 12) | ((imm & 0x1f) << 7) | 0x23)


def build_payload(writes=None, canary=None, frame_start=None, frame_stride=None,
              guard_addr=None, gadget_addr=None, target='unlocked_40gb'):
    """Build the full 0xF800-byte payload with ROP chain and frames.

    Args:
        writes: list of (addr, value, label) tuples
        canary: sentinel value for stack canaries (default 0xFACEB13D)
        frame_start: DMEM addr of first frame (default 0xFF48)
        frame_stride: frame size in bytes (default 0x18)
        guard_addr: stack canary addr (default 0x6340)
        gadget_addr: bar0_master write gadget (default 0x10B9)
        target: CFG1 target key (default 'unlocked_40gb'). If writes are None,
                the function builds UNLOCK_WRITES with CFG1 from ALL_CFG1_VALUES.
    """
    if writes is None:
        cfg1_value = ALL_CFG1_VALUES.get(target, ALL_CFG1_VALUES['unlocked_40gb'])
        writes = []
        for addr, value, label in UNLOCK_WRITES:
            if addr == 0x9A0204:
                value = cfg1_value
            writes.append((addr, value, label))
    """Build the full 0xF800-byte payload with ROP chain and frames.

    Args:
        writes: list of (addr, value, label) tuples
        canary: sentinel value for stack canaries (default 0xFACEB13D)
        frame_start: DMEM addr of first frame (default 0xFF48)
        frame_stride: frame size in bytes (default 0x18)
        guard_addr: stack canary addr (default 0x6340)
        gadget_addr: bar0_master write gadget (default 0x10B9)

    Returns:
        bytes of length payload_size (default 0xF800)
    """
    if writes is None:
        writes = UNLOCK_WRITES
    if canary is None:
        canary = DMEM_LAYOUT['canary']
    if frame_start is None:
        frame_start = PAYLOAD_FRAMES['frame_start_addr']
    if frame_stride is None:
        frame_stride = PAYLOAD_FRAMES['frame_stride']
    if guard_addr is None:
        guard_addr = DMEM_LAYOUT['guard_addr']
    if gadget_addr is None:
        gadget_addr = BAR0_WRITE_GADGET

    payload_size = DMEM_LAYOUT['payload_size']
    payload = bytearray(payload_size)
    offsets = PAYLOAD_FRAMES['frame_field_offsets']

    def w32(addr, val):
        off = addr - DMEM_LAYOUT['dma_target']
        if 0 <= off <= payload_size - 4:
            struct.pack_into('<I', payload, off, val & 0xFFFFFFFF)

    # Place canary at guard_addr
    w32(guard_addr, canary)

    # Build frames
    a = frame_start
    for addr, val, _ in writes:
        w32(a + offsets['r0'], guard_addr)        # r0 = canary address
        w32(a + offsets['r1'], 0x00000000)        # r1 = 0 (unused)
        w32(a + offsets['r2'], val)              # r2 = value
        w32(a + offsets['r3'], addr)              # r3 = address
        w32(a + offsets['saved_reg'], canary)    # saved_reg = canary
        w32(a + offsets['return_addr'], gadget_addr)
        a += frame_stride

    # Tail frame (compact - only 4 needed dwords, not 6).
    # The booter's mpopaddret only reads offsets 0x08 (val→r1),
    # 0x0C (addr→r10), and 0x14 (ra→PC). r0, r2, r3 are unused.
    # So we only need saved_reg (canary) + val (0) + addr (0) + ra (raw exit).
    w32(a + offsets['r2'], 0x00000000)        # r1 = 0 (val for mpopaddret)
    w32(a + offsets['r3'], 0x00000000)        # r10 = 0 (addr for mpopaddret)
    w32(a + offsets['saved_reg'], canary)    # canary check passes
    # Raw exit (jal x0, self) — keeps resetPLM=0xFF
    w32(a + offsets['return_addr'], 0x0000006f)

    return bytes(payload)


# Compute unlock writes happen AFTER the exploit, via NS-mode BAR0 access
# from the host driver. The ROP chain sets resetPLM=0xFF which opens PLM
# access; then the driver can write SS0/SS1 directly.
COMPUTE_WRITES = [
    (0x82381C, 0x88888888, 'SS0 (FEAT_OVR_SM_SPD — all SMs max)'),
    (0x823820, 0x00000008, 'SS1 (FEAT_OVR_SM_SPD_1 — IMLA4 override)'),
]


# =============================================================================
# GSP firmware ELF patcher
# =============================================================================
def _parse_section_headers(gsp):
    e_shoff = struct.unpack_from('<Q', gsp, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', gsp, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', gsp, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', gsp, 0x3E)[0]

    shdr_total = e_shnum * e_shentsize
    shdrs = bytearray(gsp[e_shoff:e_shoff + shdr_total])

    strtab_hdr_off = e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from('<Q', shdrs, strtab_hdr_off + 0x18)[0]
    strtab_sz = struct.unpack_from('<Q', shdrs, strtab_hdr_off + 0x20)[0]
    strtab = bytes(gsp[strtab_off:strtab_off + strtab_sz])

    return e_shentsize, shdrs, strtab, strtab_hdr_off


def _find_signature_section(shdrs, e_shentsize, strtab, signature_section):
    for i in range(len(shdrs) // e_shentsize):
        base = i * e_shentsize
        name_idx = struct.unpack_from('<I', shdrs, base)[0]
        end = strtab.find(b'\x00', name_idx)
        if end == -1:
            end = len(strtab)
        if strtab[name_idx:end] == signature_section:
            return i, struct.unpack_from('<Q', shdrs, base + 0x18)[0]
    raise ValueError(f'Section {signature_section.decode()} not found in ELF')


def patch_gsp(input_path, payload, output_path):
    """Patch the GSP firmware ELF: overwrite .fwsignature_ga100 with our payload.

    The bug we're exploiting: when the BootROM reads the signature
    section, it loads the content into DMEM regardless of whether the
    signature is valid. Our payload is the ROP chain that runs in HS mode.
    """
    payload_size = len(payload)
    signature_section = SIGNATURE_SECTION.encode()

    gsp = bytearray(Path(input_path).read_bytes())

    if struct.unpack_from('>I', gsp, 0)[0] != GSP_HEADER_MAGIC:
        raise ValueError(f'{input_path} is not an ELF file')

    e_shentsize, shdrs, strtab, strtab_hdr_off = _parse_section_headers(gsp)
    sig_idx, sig_file_off = _find_signature_section(
        shdrs, e_shentsize, strtab, signature_section)

    payload_end = sig_file_off + payload_size
    if len(gsp) < payload_end:
        gsp.extend(b'\x00' * (payload_end - len(gsp)))

    gsp[sig_file_off:sig_file_off + payload_size] = payload
    struct.pack_into('<Q', shdrs, sig_idx * e_shentsize + 0x20, payload_size)

    new_strtab_off = len(gsp)
    gsp.extend(strtab)
    struct.pack_into('<Q', shdrs, strtab_hdr_off + 0x18, new_strtab_off)

    new_shoff = len(gsp)
    gsp.extend(shdrs)
    struct.pack_into('<Q', gsp, 0x28, new_shoff)

    Path(output_path).write_bytes(bytes(gsp))


# =============================================================================
# Main pipeline
# =============================================================================
def _find_gsp():
    paths = sorted(glob.glob(GSP_GLOB), reverse=True)
    if not paths:
        raise FileNotFoundError(f'No GSP firmware found matching {GSP_GLOB}')
    return paths[0]


def run_full_unlock(pci_full: str, gsp_path: str = None,
                     target: str = 'unlocked_40gb') -> bool:
    """Run the complete unlock pipeline.

    Args:
        pci_full: PCI BDF string like '0000:01:00.0'
        gsp_path: path to gsp_tu10x.bin (auto-detect if not given)
        target: CFG1 target key, one of:
            'nativ_10gb'    - don't unlock, just verify native state
            'unlocked_32gb'  - 4 stacks × 8GB HBM2e
            'unlocked_40gb'  - 5 stacks × 8GB HBM2 (default)
            'unlocked_64gb'  - 4 stacks × 16GB HBM2e (hypothesized)
            'unlocked_80gb'  - 5 stacks × 16GB HBM2e
    """
    if gsp_path is None:
        gsp_path = _find_gsp()

    backup_path = gsp_path + '.cmpunlocker.bak'
    patched_path = gsp_path + '.cmpunlocker.patched'

    if target not in ALL_CFG1_VALUES:
        log.error('[%s] Unknown target: %s (valid: %s)',
                  pci_full, target, list(ALL_CFG1_VALUES.keys()))
        return False

    log.info('[%s] Starting full unlock pipeline', pci_full)
    log.info('[%s] Target: %s → CFG1=0x%08X', pci_full, target,
             ALL_CFG1_VALUES[target])
    log.info('[%s] GSP firmware: %s', pci_full, gsp_path)

    log.info('[%s] Stopping display manager and unloading modules', pci_full)
    stop_display_manager()
    unload_modules()

    if not os.path.exists(backup_path):
        shutil.copy2(gsp_path, backup_path)
        log.info('[%s] GSP backup written to %s', pci_full, backup_path)

    log.info('[%s] Building ROP payload for target %s', pci_full, target)
    payload = build_payload(target=target)
    log.info('[%s] Payload size: %d bytes (7 ROP writes + tail)', pci_full, len(payload))

    log.info('[%s] Injecting payload into GSP firmware', pci_full)
    patch_gsp(backup_path, payload, patched_path)
    shutil.copy2(patched_path, gsp_path)
    log.info('[%s] Patched firmware in place: %s', pci_full, gsp_path)

    log.info('[%s] Loading patched driver', pci_full)
    load_module()
    time.sleep(5)

    log.info('[%s] FLR reset to apply patched firmware', pci_full)
    flr_reset(pci_full)

    log.info('[%s] Post-exploit writes (PLM=0xFF now open)', pci_full)
    log.info('[%s]   Writing %d additional feature enables via NS-mode BAR0',
             pci_full, len(POST_EXPLOIT_WRITES))
    for addr, val, label in POST_EXPLOIT_WRITES:
        # These need actual hardware — the emulator can't do this.
        # The real driver has to do these via sysfs/PCI config space.
        log.info('[%s]   (would write) 0x%06x = 0x%08x  (%s)',
                 pci_full, addr, val, label)

    log.info('[%s] Pipeline complete', pci_full)
    log.info('[%s] Verify with: nvidia-smi --query-gpu=clocks.max.sm,memory.total', pci_full)
    return True


def main():
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
    )
    p = argparse.ArgumentParser()
    p.add_argument('pci_bdf', nargs='?', default=None,
                   help='PCI BDF like 0000:01:00.0 (auto-detect if not given)')
    p.add_argument('--gsp', help='Path to gsp_tu10x.bin (auto-detect if not given)')
    p.add_argument('--dry-run', action='store_true',
                   help='Build payload + patch firmware, but do NOT copy to system location')
    args = p.parse_args()

    pci = args.pci_bdf
    if pci is None:
        # Try to auto-detect
        from payload.gpu import find_gpu
        try:
            pci = find_gpu()
        except ImportError:
            pass
        if pci is None:
            log.error('No PCI BDF given and auto-detect failed')
            log.error('Usage: sudo python3 -m cmpunlocker.deploy 0000:01:00.0')
            return 1

    try:
        if args.dry_run:
            gsp = args.gsp or _find_gsp()
            log.info('Dry-run: building payload + patching to temp file')
            backup = gsp + '.cmpunlocker.bak'
            patched = gsp + '.cmpunlocker.patched'
            if not os.path.exists(backup):
                shutil.copy2(gsp, backup)
            payload = build_payload()
            patch_gsp(backup, payload, patched)
            log.info('Patched firmware written to: %s', patched)
            log.info('Not copied to system location (dry-run).')
            return 0
        run_full_unlock(pci, args.gsp)
    except Exception as exc:
        log.error('Unlock failed: %s', exc)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
"""
pipeline.py — Run the full unlock sequence.

Mirrors the open-gpu-kernel-modules-610.43.03 fork's SEC2 post-bootloader
timing unlock exactly:

  1. Stop display manager, unload nvidia modules
  2. Find GSP firmware and the stock signature section
  3. Save the stock signature for later restore
  4. For each of 4 PLM registers (WPR_CFG, FBPA, WPR, FEAT):
     a. Refill the ROP payload with the target address/value
     b. Patch the GSP firmware .fwsignature_ga100 section
     c. modprobe nvidia → triggers kgspBootGspRm → kgspExecuteBooterLoad
     d. Verify the PLM register was opened (loop up to 2 times)
  5. After all PLMs are open, write the memory unlock values (CFG1, LMR)
  6. Write the compute unlock values (SS0, SS1) via BAR0
  7. Restore the original GSP signature (so the driver doesn't detect
     tampering)
  8. modprobe nvidia to reload with the original signature but the
     unlocked memory configuration still in place

The result: full SM clock + full memory capacity, with the GSP
firmware integrity preserved. The unlock is volatile (lost on power
cycle) but reapplied automatically by the daemon on every driver
reload.
"""

import glob
import logging
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.constants import get
from payload.driver import (
    aggressive_unload, flr_reset, load_module, stop_display_manager, unload_modules,
)
from payload.gsp_patch import patch_gsp
from payload.build import build as build_payload, fill_payload, refill_payload

log = logging.getLogger(__name__)

_GSP_GLOB = "/lib/firmware/nvidia/*/gsp_tu10x.bin"


def _find_gsp() -> str:
    paths = sorted(glob.glob(_GSP_GLOB), reverse=True)
    if not paths:
        raise FileNotFoundError(f"No GSP firmware found matching {_GSP_GLOB}")
    return paths[0]


def _save_stock_signature(gsp_path: str) -> bytes:
    """Read and return the original .fwsignature_ga100 section content."""
    import struct
    sig_name = get('elf.signature_section').encode()
    gsp = Path(gsp_path).read_bytes()

    e_shoff     = struct.unpack_from("<Q", gsp, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp, 0x3A)[0]
    e_shnum     = struct.unpack_from("<H", gsp, 0x3C)[0]
    e_shstrndx  = struct.unpack_from("<H", gsp, 0x3E)[0]

    shdr_total = e_shnum * e_shentsize
    shdrs = gsp[e_shoff : e_shoff + shdr_total]

    strtab_hdr_off = e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from("<Q", shdrs, strtab_hdr_off + 0x18)[0]
    strtab_sz  = struct.unpack_from("<Q", shdrs, strtab_hdr_off + 0x20)[0]
    strtab = gsp[strtab_off : strtab_off + strtab_sz]

    for i in range(e_shnum):
        base = i * e_shentsize
        name_idx = struct.unpack_from("<I", shdrs, base)[0]
        end = strtab.find(b"\x00", name_idx)
        if end == -1:
            end = len(strtab)
        if strtab[name_idx:end] == sig_name:
            sig_file_off = struct.unpack_from("<Q", shdrs, base + 0x18)[0]
            sig_size = struct.unpack_from("<Q", shdrs, base + 0x20)[0]
            return bytes(gsp[sig_file_off : sig_file_off + sig_size])
    raise ValueError(f"Section {sig_name.decode()} not found in {gsp_path}")


def _open_plm_register(pci_full: str, gsp_path: str, stock_sig: bytes,
                         write_addr: int, write_value: int, reg_name: str) -> bool:
    """Try to open one PLM register by running the ROP chain.

    The chain performs a single BAR0 write to the target address.
    """
    payload = fill_payload(write_addr, write_value)
    backup = gsp_path + ".cmpunlocker.bak"
    patched = gsp_path + ".cmpunlocker.patched"

    patch_gsp(backup, payload, patched)
    shutil.copy2(patched, gsp_path)

    for attempt in range(2):
        aggressive_unload()
        load_module()
        time.sleep(5)
        flr_reset(pci_full)

        from payload.bar0 import Bar0
        with Bar0(pci_full) as bar0:
            actual = bar0.rd32(write_addr)
        if actual == write_value:
            log.info("[%s] %s (0x%08x) opened (attempt %d, reg=0x%08x)",
                     pci_full, reg_name, write_addr, attempt + 1, actual)
            return True
        log.warning("[%s] %s (0x%08x) attempt %d failed (got 0x%08x, want 0x%08x)",
                    pci_full, reg_name, write_addr, attempt + 1, actual, write_value)

    return False


def _write_bar0(pci_full: str, addr: int, value: int, label: str) -> bool:
    """Write a value to BAR0 and verify it stuck."""
    from payload.bar0 import Bar0
    with Bar0(pci_full) as bar0:
        bar0.wr32(addr, value)
        actual = bar0.rd32(addr)
    if actual == value:
        log.info("[%s] %s = 0x%08x OK", pci_full, label, value)
        return True
    log.warning("[%s] %s write failed (wrote 0x%08x, got 0x%08x)",
                pci_full, label, value, actual)
    return False


def run_full_unlock(pci_full: str, gsp_path: str = None,
                     target: str = None) -> bool:
    """Run the full unlock pipeline (mirrors modified driver)."""
    if gsp_path is None:
        gsp_path = _find_gsp()
    if target is None:
        target = get('memory_unlock.default_target')

    backup = gsp_path + ".cmpunlocker.bak"

    log.info("[%s] Starting full unlock pipeline", pci_full)
    log.info("[%s] GSP firmware: %s", pci_full, gsp_path)
    log.info("[%s] Target: %s", pci_full, target)

    log.info("[%s] Stopping display manager and unloading modules", pci_full)
    stop_display_manager()
    unload_modules()

    if not os.path.exists(backup):
        shutil.copy2(gsp_path, backup)
        log.info("[%s] GSP backup written to %s", pci_full, backup)

    log.info("[%s] Saving stock GSP signature", pci_full)
    stock_sig = _save_stock_signature(gsp_path)

    plm_table = get('plm_table')
    all_plm_open = True
    for entry in plm_table:
        ok = _open_plm_register(
            pci_full, gsp_path, stock_sig,
            entry['addr'], entry['value'], entry['name'])
        if not ok:
            log.error("[%s] Failed to open %s (0x%08x)",
                      pci_full, entry['name'], entry['addr'])
            all_plm_open = False

    if not all_plm_open:
        log.error("[%s] Not all PLM registers opened, aborting", pci_full)
        return False

    targets = get('memory_unlock.targets')
    mem = targets[target]

    log.info("[%s] Writing memory unlock: CFG1=0x%08x LMR=0x%08x",
             pci_full, mem['cfg1'], mem['lmr'])
    cfg1_ok = _write_bar0(pci_full, get('memory_unlock.cfg1.addr'),
                            mem['cfg1'], 'CFG1')
    lmr_ok  = _write_bar0(pci_full, get('memory_unlock.lmr.addr'),
                            mem['lmr'], 'LMR')

    ss0_addr = get('host_bar0_writes.ss0.addr')
    ss0_val  = get('host_bar0_writes.ss0.value')
    ss1_addr = get('host_bar0_writes.ss1.addr')
    ss1_val  = get('host_bar0_writes.ss1.value')
    log.info("[%s] Writing compute unlock: SS0=0x%08x SS1=0x%08x",
             pci_full, ss0_val, ss1_val)
    ss0_ok = _write_bar0(pci_full, ss0_addr, ss0_val, 'SS0')
    ss1_ok = _write_bar0(pci_full, ss1_addr, ss1_val, 'SS1')

    log.info("[%s] Restoring original GSP signature", pci_full)
    shutil.copy2(backup, gsp_path)

    log.info("[%s] Reloading driver with restored signature", pci_full)
    load_module()
    time.sleep(3)

    all_ok = cfg1_ok and lmr_ok and ss0_ok and ss1_ok
    log.info("[%s] Pipeline complete — memory=%s compute=%s overall=%s",
             pci_full,
             "OK" if (cfg1_ok and lmr_ok) else "FAIL",
             "OK" if (ss0_ok and ss1_ok) else "FAIL",
             "OK" if all_ok else "FAIL")
    return all_ok


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    pci = sys.argv[1] if len(sys.argv) > 1 else None
    gsp = sys.argv[2] if len(sys.argv) > 2 else None
    target = sys.argv[3] if len(sys.argv) > 3 else None
    if pci is None:
        from payload.gpu import find_gpu
        pci = find_gpu()
        if pci is None:
            print("ERROR: No compatible GPU found")
            sys.exit(1)
    ok = run_full_unlock(pci, gsp, target)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

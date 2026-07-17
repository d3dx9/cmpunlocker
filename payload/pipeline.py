import glob
import logging
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from payload.driver import (
    aggressive_unload, flr_reset, load_module, stop_display_manager, unload_modules,
)
from payload.gsp_patch import patch_gsp
from payload.build import build as build_payload

log = logging.getLogger(__name__)

_GSP_GLOB = "/lib/firmware/nvidia/*/gsp_tu10x.bin"

_RESET_PLM_ADDR = 0x8403C4
_MAILBOX_ADDR = 0x00001000
_DIAG_EXTRA_ADDRS = (
    (0x009A0204, "SM-PLM (WRITES[0])"),
    (0x00100CE0, "FB-PLM (WRITES[1])"),
    (0x00823804, "SM-override (WRITES[2])"),
    (0x0082381C, "ss0"),
    (0x00823820, "ss1"),
)


def _dump_state(pci_full: str, label: str) -> None:
    try:
        with Bar0(pci_full) as bar0:
            plm = bar0.rd32(_RESET_PLM_ADDR)
            mbx = bar0.rd32(_MAILBOX_ADDR)
            log.info("[%s] %s resetPLM=0x%08X mailbox=0x%08X",
                     pci_full, label, plm, mbx)
            for addr, name in _DIAG_EXTRA_ADDRS:
                try:
                    log.info("[%s] %s %s@0x%08X=0x%08X",
                             pci_full, label, name, addr, bar0.rd32(addr))
                except Exception as exc:
                    log.warning("[%s] %s %s@0x%08X read failed: %s",
                                pci_full, label, name, addr, exc)
    except Exception as exc:
        log.warning("[%s] %s state dump failed: %s", pci_full, label, exc)


def _find_gsp() -> str:
    paths = sorted(glob.glob(_GSP_GLOB), reverse=True)
    if not paths:
        raise FileNotFoundError(f"No GSP firmware found matching {_GSP_GLOB}")
    return paths[0]


def _run_patched_phase(pci_full: str) -> tuple:
    log.info("[%s] Loading patched driver", pci_full)
    load_module()
    time.sleep(5)

    log.info("[%s] FLR reset #1", pci_full)
    flr_reset(pci_full)

    log.info("[%s] Aggressive driver unload", pci_full)
    aggressive_unload()

    log.info("[%s] FLR reset #2", pci_full)
    flr_reset(pci_full)

    log.info("[%s] State after patched firmware boot + FLRs", pci_full)
    _dump_state(pci_full, "[post-flr]")

    from unlock.compute import apply_unlock
    from unlock.memory import (
        apply_memory_unlock, try_memory_unlock_candidates,
        _read_memory_total_mib,
    )

    log.info("[%s] Applying compute unlock", pci_full)
    ok, msg = apply_unlock(pci_full)
    if ok:
        log.info("[%s] Compute unlock succeeded", pci_full)
    else:
        log.warning("[%s] Compute unlock: %s", pci_full, msg)

    mem_ok, mem_msg = apply_memory_unlock(pci_full)
    if mem_ok:
        log.info("[%s] Memory geometry unlock succeeded", pci_full)
    else:
        log.info("[%s] Memory geometry (configured): %s", pci_full, mem_msg)

    log.info("[%s] State after host-side BAR0 writes", pci_full)
    _dump_state(pci_full, "[post-apply]")
    return ok, msg


def _restore_phase(pci_full: str, gsp_path: str, backup_path: str) -> None:
    log.info("[%s] Restoring original GSP firmware (guaranteed)", pci_full)
    shutil.copy2(backup_path, gsp_path)

    log.info("[%s] Reloading driver", pci_full)
    load_module()
    time.sleep(3)

    log.info("[%s] State after restore+reload (final)", pci_full)
    _dump_state(pci_full, "[post-restore]")


def run_full_unlock(pci_full: str, gsp_path: str = None) -> bool:
    if gsp_path is None:
        gsp_path = _find_gsp()

    backup_path = gsp_path + ".cmpunlocker.bak"
    patched_path = gsp_path + ".cmpunlocker.patched"

    log.info("[%s] Starting full unlock pipeline", pci_full)
    log.info("[%s] GSP firmware: %s", pci_full, gsp_path)

    log.info("[%s] Baseline state (pre-patch)", pci_full)
    _dump_state(pci_full, "[baseline]")

    log.info("[%s] Stopping display manager and unloading modules", pci_full)
    stop_display_manager()
    unload_modules()

    if not os.path.exists(backup_path):
        shutil.copy2(gsp_path, backup_path)
        log.info("[%s] GSP backup written to %s", pci_full, backup_path)

    log.info("[%s] Building ROP payload", pci_full)
    payload = build_payload()

    log.info("[%s] Injecting payload into GSP firmware", pci_full)
    patch_gsp(backup_path, payload, patched_path)
    shutil.copy2(patched_path, gsp_path)

    ok = False
    try:
        ok, _msg = _run_patched_phase(pci_full)
    finally:
        _restore_phase(pci_full, gsp_path, backup_path)

    log.info("[%s] Pipeline complete — ok=%s", pci_full, ok)
    return ok


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    args = sys.argv[1:]
    no_restore = '--no-restore' in args
    args = [a for a in args if a != '--no-restore']

    pci = args[0] if len(args) > 0 else None
    gsp = args[1] if len(args) > 1 else None
    if pci is None:
        from payload.gpu import find_gpu
        pci = find_gpu()
        if pci is None:
            print("ERROR: No compatible GPU found")
            sys.exit(1)

    if no_restore:
        _run_no_restore(pci, gsp)
    else:
        run_full_unlock(pci, gsp)


def _run_no_restore(pci_full: str, gsp_path: str = None) -> None:
    """Empirical 80GB mode: run pipeline up to apply_unlock, FLR + reload driver,
       check nvidia-smi, but DO NOT restore firmware. Leaves GPU in patched state.
       User can manually restore with: cp *.cmpunlocker.bak gsp_tu10x.bin
    """
    if gsp_path is None:
        gsp_path = _find_gsp()
    backup_path = gsp_path + ".cmpunlocker.bak"

    log.info("[%s] === EMPIRICAL 80GB MODE (no firmware restore) ===", pci_full)
    log.info("[%s] Save backup if not exists: %s", pci_full, backup_path)
    if not os.path.exists(backup_path):
        import shutil
        shutil.copy2(gsp_path, backup_path)

    log.info("[%s] Stopping display manager and unloading modules", pci_full)
    stop_display_manager()
    unload_modules()

    log.info("[%s] Building ROP payload", pci_full)
    payload = build_payload()

    log.info("[%s] Injecting payload into GSP firmware", pci_full)
    patch_gsp(backup_path, payload, gsp_path + ".cmpunlocker.patched")
    import shutil
    shutil.copy2(gsp_path + ".cmpunlocker.patched", gsp_path)

    try:
        log.info("[%s] Loading patched driver", pci_full)
        load_module()
        time.sleep(5)

        log.info("[%s] FLR #1", pci_full)
        flr_reset(pci_full)
        log.info("[%s] Aggressive driver unload", pci_full)
        aggressive_unload()
        log.info("[%s] FLR #2", pci_full)
        flr_reset(pci_full)

        log.info("[%s] State after patched firmware boot + FLRs", pci_full)
        _dump_state(pci_full, "[post-flr]")

        from unlock.compute import apply_unlock
        from unlock.memory import (
            apply_memory_unlock, try_memory_unlock_candidates,
            _read_memory_total_mib,
        )

        log.info("[%s] Applying compute unlock", pci_full)
        ok, msg = apply_unlock(pci_full)
        log.info("[%s] Compute unlock: %s", pci_full, msg)

        log.info("[%s] State after apply_unlock", pci_full)
        _dump_state(pci_full, "[post-apply]")

        # Empirical 80GB probe — try candidates from PL0 with FB-PLM open.
        log.info("[%s] State after apply_unlock", pci_full)
        _dump_state(pci_full, "[post-apply]")
    finally:
        log.warning("[%s] === GPU left in PATCHED state. To restore: ===", pci_full)
        log.warning("[%s]   cp %s %s", pci_full, backup_path, gsp_path)
        log.warning("[%s]   modprobe -r nvidia && modprobe nvidia", pci_full)


if __name__ == "__main__":
    main()

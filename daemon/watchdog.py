import logging
import sys
import time

sys.path.insert(0, "/opt/cmpunlocker")

from payload.gpu import find_all_gpus
from payload.pipeline import run_full_unlock
from unlock.compute import apply_unlock, is_plm_open, is_unlocked

CHECK_INTERVAL = 1  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s cmpunlocker[%(process)d]: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cmpunlocker")


def _unlock_card(pci: str) -> None:
    try:
        run_full_unlock(pci)
    except Exception as exc:
        log.error("[%s] Full unlock failed: %s", pci, exc)


def _check_card(pci: str) -> None:
    try:
        if is_unlocked(pci):
            return

        if is_plm_open(pci):
            ok, msg = apply_unlock(pci)
            if ok:
                log.info("[%s] Reapplied SS0/SS1", pci)
            else:
                log.warning("[%s] Quick reapply failed: %s", pci, msg)
        else:
            log.warning("[%s] PLM closed — re-running full unlock", pci)
            _unlock_card(pci)

    except Exception as exc:
        log.error("[%s] Monitor error: %s", pci, exc)


def main() -> None:
    log.info("cmpunlocker daemon starting")

    gpus = find_all_gpus()
    if not gpus:
        log.error("No compatible GPU found (10de:20b0/20c2/2082)")
        sys.exit(1)

    log.info("Found %d GPU(s): %s", len(gpus), ", ".join(gpus))

    for pci in gpus:
        log.info("[%s] Running initial unlock", pci)
        _unlock_card(pci)

    log.info("Entering monitor loop (interval=%ds)", CHECK_INTERVAL)
    while True:
        for pci in gpus:
            _check_card(pci)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()

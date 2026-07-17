import logging
import subprocess
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from common.constants import get

log = logging.getLogger(__name__)


def _memory_config():
    return {
        'cfg1_addr':       get('host_bar0_writes.fb_geometry.cfg1'),
        'cfg1_value':      get('host_bar0_writes.fb_geometry.cfg1_value'),
        'lmr_addr':        get('host_bar0_writes.fb_geometry.lmr'),
        'lmr_value':       get('host_bar0_writes.fb_geometry.lmr_value'),
        'refresh_addr':    get('host_bar0_writes.fb_geometry.refresh_interval'),
        'refresh_value':   get('host_bar0_writes.fb_geometry.refresh_interval_value'),
    }


def is_memory_unlocked(pci_full: str) -> bool:
    c = _memory_config()
    if c['cfg1_addr'] is None or c['cfg1_value'] is None:
        return False
    with Bar0(pci_full) as bar0:
        return bar0.rd32(c['cfg1_addr']) == c['cfg1_value']


def _read_memory_total_mib() -> int:
    """Returns nvidia-smi memory.total in MiB, or None on failure."""
    try:
        r = subprocess.run(
            ['nvidia-smi', '--query-gpu=memory.total',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=False, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return int(r.stdout.strip().split()[0])
    except Exception:
        pass
    return None


def apply_memory_unlock(pci_full: str) -> tuple:
    c = _memory_config()

    if c['cfg1_addr'] is None or c['cfg1_value'] is None:
        return False, (
            "fb_geometry.cfg1 not configured in constants.yaml — refusing to "
            "attempt memory geometry override without knowing the verified 80GB "
            "value. See unlock/memory.py docstring for derivation sources."
        )

    with Bar0(pci_full) as bar0:
        bar0.wr32(c['cfg1_addr'], c['cfg1_value'])
        if c['lmr_addr'] is not None and c['lmr_value'] is not None:
            bar0.wr32(c['lmr_addr'], c['lmr_value'])
        if c['refresh_addr'] is not None and c['refresh_value'] is not None:
            bar0.wr32(c['refresh_addr'], c['refresh_value'])

        cfg1 = bar0.rd32(c['cfg1_addr'])
        lmr = bar0.rd32(c['lmr_addr']) if c['lmr_addr'] is not None else None
        refresh = bar0.rd32(c['refresh_addr']) if c['refresh_addr'] is not None else None

        ok = (cfg1 == c['cfg1_value']
              and (c['lmr_addr'] is None or lmr == c['lmr_value'])
              and (c['refresh_addr'] is None or refresh == c['refresh_value']))
        if ok:
            return True, "framebuffer geometry / refresh applied"
        return False, (
            f"values did not stick "
            f"(cfg1=0x{cfg1:08X} lmr={lmr} refresh={refresh})"
        )


def try_candidate(pci_full: str, addr: int, value: int,
                  candidates_log: list = None) -> tuple:
    """Write a candidate 80GB value to addr. Returns (wrote_ok, before, after, mem_mib).
       Restores original on failure.
    """
    before_mib = _read_memory_total_mib()
    with Bar0(pci_full) as bar0:
        original = bar0.rd32(addr)
        bar0.wr32(addr, value)
        new = bar0.rd32(addr)
    mem_mib = _read_memory_total_mib()
    ok = new == value
    log.info("[%s]   probe 0x%08x <- 0x%08x: was=0x%08x now=0x%08x wrote_ok=%s mem.total=%s MiB",
             pci_full, addr, value, original, new, ok, mem_mib)
    if not ok and candidates_log is not None:
        # Restore original
        with Bar0(pci_full) as bar0:
            bar0.wr32(addr, original)
    if candidates_log is not None:
        candidates_log.append({
            'addr': addr, 'value': value,
            'before': original, 'after': new, 'wrote_ok': ok,
            'mem_before_mib': before_mib, 'mem_after_mib': mem_mib,
        })
    return ok, original, new, mem_mib


def try_memory_unlock_candidates(pci_full: str) -> dict:
    """Empirically probe candidate values for 80GB unlock.
       FB-PLM must already be open (run pipeline apply_unlock first).
       Returns dict with 'baseline_mib', 'success' (addr,value,mem_mib), 'attempts' list.
    """
    log.info("[%s] === empirical 80GB candidate probe ===", pci_full)
    baseline_mib = _read_memory_total_mib()
    log.info("[%s] baseline memory.total = %s MiB", pci_full, baseline_mib)
    if baseline_mib is None:
        log.warning("[%s] nvidia-smi unavailable at probe time; driver may be unloaded.",
                    pci_full)
        log.warning("[%s] probe can only verify BAR0 write-stickiness, not memory size.",
                    pci_full)
    # Read baseline resetPLM and a sample probe-target register to verify the
    # writes will stick before we try candidates.
    with Bar0(pci_full) as bar0:
        baseline_plm = bar0.rd32(0x8403C4)
        baseline_target = bar0.rd32(0x120048)
    log.info("[%s] baseline resetPLM=0x%08X  0x120048=0x%08X", pci_full,
             baseline_plm, baseline_target)

    # If driver is unloaded, try to reload so nvidia-smi can report memory size.
    # This is required for the probe to actually validate a candidate worked.
    try:
        subprocess.run(['modprobe', 'nvidia'], capture_output=True, timeout=10,
                        check=False)
        import time as _time
        _time.sleep(3)
    except Exception:
        pass
    post_reload_mib = _read_memory_total_mib()
    if post_reload_mib:
        log.info("[%s] post-modprobe memory.total = %s MiB", pci_full, post_reload_mib)
    else:
        log.warning("[%s] nvidia-smi still not functional after modprobe", pci_full)

    attempts = []

    # The cmpunlocker pipeline already proved FB-PLM is open after apply_unlock.
    # Candidate addresses (Family B - the 13-register FB-controller geometry table):
    candidates = [
        # (addr, value, label)
        (0x120048, 0x53 * 8,        "refresh * 8"),
        (0x120048, 0x0A,            "refresh / 8 (more frequent)"),
        (0x120048, 0x53 | 0x80000000, "refresh with bit31 set"),
        (0x120048, 0x53 | 0x40000000, "refresh with bit30 set"),
        (0x120048, 0x00000003,      "size encoding 11b (binary 80GB?)"),
        (0x120048, 0x00000004,      "size encoding 100b"),
        (0x120048, 0x00000007,      "size encoding 111b"),
        # Family A - DRAM timing/refresh candidates
        (0x110624, 0x90,            "refresh A = boot value"),
        (0x110624, 0x48,            "refresh A / 4"),
        (0x110624, 0x24,            "refresh A / 8"),
        (0x110624, 0x900,           "refresh A * 16"),
        # FB-PLM is already open from apply_unlock. Direct writes should work.
    ]

    for addr, value, label in candidates:
        log.info("[%s] trying 0x%08x <- 0x%08x (%s)", pci_full, addr, value, label)
        _ok, _before, _after, mem_mib = try_candidate(
                pci_full, addr, value, attempts)
        if mem_mib and baseline_mib and mem_mib != baseline_mib:
            log.warning(
                "[%s] >>> MEMORY SIZE CHANGED: %s -> %s MiB "
                "(addr=0x%x, value=0x%x, %s) <<<",
                pci_full, baseline_mib, mem_mib, addr, value, label)
            return {
                'baseline_mib': baseline_mib,
                'success': (addr, value, label, mem_mib),
                'attempts': attempts,
            }
        log.info("[%s]   mem.total stayed at %s MiB", pci_full, mem_mib)

    log.info("[%s] === probe complete: no candidate changed memory size ===", pci_full)
    return {
        'baseline_mib': baseline_mib,
        'success': None,
        'attempts': attempts,
    }

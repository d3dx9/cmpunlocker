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
    # Candidate addresses (Family B - the 13-register FB-controller geometry table).
    #
    # Heuristics used (none of these are documented in public sources — the
    # cmpunlocker Discord has the real values, but the Discord is closed).
    # Without ground-truth we have to brute-force around the live 0x53
    # baseline at 0x120048 and the size-encoding 0x10 vs 0x8 transition
    # our boot emulator found at 0x110000 (Family A — refresh-related).
    candidates = [
        # ===== Family B (0x120xxx) — the 80GB config target =====
        # Live baseline at 0x120048 is 0x53 (10GB). Size encodings tried as
        # a 2-/3-bit field (00=10GB, 01=20GB, 10=40GB, 11=80GB):
        (0x120048, 0x00000000, "size-encoding: 00b (=0, 10GB?)"),
        (0x120048, 0x00000001, "size-encoding: 01b"),
        (0x120048, 0x00000002, "size-encoding: 10b"),
        (0x120048, 0x00000003, "size-encoding: 11b (=3, 80GB?)"),
        (0x120048, 0x00000004, "size-encoding: 100b"),
        (0x120048, 0x00000005, "size-encoding: 101b"),
        (0x120048, 0x00000007, "size-encoding: 111b"),
        # Refresh-multiplier variants around the live 0x53 value:
        (0x120048, 0x53,            "live 0x53 (10GB baseline — no change)"),
        (0x120048, 0x53 * 8,        "refresh * 8"),
        (0x120048, 0x0A,            "refresh / 8"),
        (0x120048, 0x53 | 0x80000000, "0x53 with bit31 set"),
        (0x120048, 0x53 | 0x40000000, "0x53 with bit30 set"),
        (0x120048, 0x53 | 0x20000000, "0x53 with bit29 set"),
        (0x120048, 0x53 ^ 0x80,     "0x53 with bit7 toggled"),
        (0x120048, 0x53 ^ 0x01,     "0x53 with bit0 toggled"),
        (0x120048, 0x53 + 1,        "0x53 + 1"),
        (0x120048, 0x53 - 1,        "0x53 - 1"),
        # 'k'-style candidates: 0x5X for X in 0..F
        *((0x120048, 0x50 + n, f"0x{0x50+n:02x} low-nibble sweep")
          for n in range(16)),
        # lmr-candidate at 0x122200 (live 0x00)
        (0x122200, 0x00000001,      "lmr: 1"),
        (0x122200, 0x00000002,      "lmr: 2"),
        (0x122200, 0x00000003,      "lmr: 3"),
        (0x122200, 0x00000007,      "lmr: 7"),
        (0x122200, 0x000000ff,      "lmr: 0xff"),
        (0x122200, 0x00005300,      "lmr: 0x5300 (cfg1-relative)"),
        (0x122200, 0x00005353,      "lmr: 0x5353"),
        (0x122200, 0x53,            "lmr: 0x53"),
        (0x122200, 0xff,            "lmr: 0xff"),
        # lmr-candidate at 0x122204 (live 0x02)
        (0x122204, 0x00000000,      "lmr-b: 0"),
        (0x122204, 0x00000001,      "lmr-b: 1"),
        (0x122204, 0x00000002,      "lmr-b: 2 (live)"),
        (0x122204, 0x00000003,      "lmr-b: 3"),
        (0x122204, 0x00000010,      "lmr-b: 0x10"),
        # lmr at 0x122120 (live 0x00)
        (0x122120, 0x00000001,      "lmr-c: 1"),
        (0x122120, 0x00000003,      "lmr-c: 3"),
        (0x122120, 0x000000ff,      "lmr-c: 0xff"),
        # lmr at 0x122128 (live 0x00)
        (0x122128, 0x00000001,      "lmr-d: 1"),
        (0x122128, 0x000000ff,      "lmr-d: 0xff"),
        # ===== Family A (0x110xxx) — booter-driven refresh/size =====
        # The booter emulator finds 0x10 (10GB) vs 0x8 (80GB) at 0x110000
        # and 0x7 (10GB) vs 0x5 (80GB) at 0x110600. These don't directly
        # change the host nvidia-smi memory.total; they're FB-controller
        # internal registers. Including them anyway for completeness.
        (0x110000, 0x8,             "size-encoding 80GB candidate (emulator-derived)"),
        (0x110000, 0x10,            "size-encoding 10GB (live)"),
        (0x110600, 0x5,             "refresh-enc 80GB candidate (emulator)"),
        (0x110600, 0x7,             "refresh-enc 10GB (live)"),
        (0x110624, 0x90,            "refresh A = boot value"),
        (0x110624, 0x48,            "refresh A / 4"),
        (0x110624, 0x24,            "refresh A / 8"),
        (0x110624, 0x900,           "refresh A * 16"),
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

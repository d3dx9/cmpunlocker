"""
features.py — Optional feature unlocks (PCIe Gen4, NVLink, ECC, PLL, Power).

These writes are applied AFTER the core memory + compute unlock
succeeds. They are best-effort: failure on any one is logged but
does not fail the whole unlock.

Each feature has a `sequence` in constants.yaml that defines an
ordered list of operations:
  - write: write a value to BAR0
  - read: read a BAR0 register (optional mask+expect for verification)
  - delay: sleep for N milliseconds (for hardware settling)

The sequence format is critical because hardware features like PCIe
link retraining and NVLink initialization need timed operations.
"""

import logging
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from common.constants import get

log = logging.getLogger(__name__)


# Order of feature unlock execution
FEATURE_ORDER = [
    "pcie_gen4",
    "nvlink_enable",
    "arc_mutex",
    "ecc_enable",
    "ecc_scrub",
    "pll_unlock",
    "power_limit",
    "thermal_limit",
]


def is_pcie_gen4(pci_full: str) -> bool:
    """Check if PCIe Link Control 2 is set to Gen 4 target speed."""
    pcie = get('feature_unlocks.pcie_gen4')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(pcie['addr']) == pcie['value']


def is_nvlink_enabled(pci_full: str) -> bool:
    """Check if NVLink is enabled."""
    nvl = get('feature_unlocks.nvlink_enable')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(nvl['addr']) == nvl['value']


def is_ecc_enabled(pci_full: str) -> bool:
    """Check if ECC is enabled."""
    ecc = get('feature_unlocks.ecc_enable')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(ecc['addr']) == ecc['value']


def is_pll_unlocked(pci_full: str) -> bool:
    """Check if PLL frequency is unlocked."""
    pll = get('feature_unlocks.pll_unlock')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(pll['addr']) == pll['value']


def is_power_limit_set(pci_full: str) -> bool:
    """Check if power limit has been raised."""
    pwr = get('feature_unlocks.power_limit')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(pwr['addr']) == pwr['value']


def apply_feature_unlocks(pci_full: str) -> dict:
    """Apply all optional feature unlocks in the correct order.

    Each feature may have a multi-step sequence (e.g. write → delay → read)
    defined in constants.yaml. If a sequence is defined, it's executed;
    otherwise a simple write is performed.

    Returns a dict mapping feature name → {attempted, stuck, steps}.
    """
    result = {}

    if not _plm_open(pci_full):
        log.warning("[%s] PLM not open — skipping feature unlocks", pci_full)
        return result

    for name in FEATURE_ORDER:
        cfg = get(f'feature_unlocks.{name}')
        if cfg is None:
            continue
        if 'sequence' in cfg:
            ok = _apply_sequence(pci_full, name, cfg['sequence'])
        else:
            ok = _try_write(pci_full, cfg['addr'], cfg['value'], name)
        result[name] = {"attempted": True, "stuck": ok}

    return result


def _apply_sequence(pci_full: str, name: str, sequence: list) -> bool:
    """Execute a multi-step sequence for a feature unlock.

    Each step is a dict with 'op' key:
      - {op: "write",  addr: int, value: int, label: str}
      - {op: "read",   addr: int, label: str}
      - {op: "read",   addr: int, mask: int, expect: int, label: str}
      - {op: "delay",  ms: int, label: str}

    Returns True if all steps succeed.
    """
    log.info("[%s] Running sequence: %s (%d steps)",
             pci_full, name, len(sequence))

    for i, step in enumerate(sequence):
        op = step.get('op')
        label = step.get('label', f'step {i}')

        if op == 'write':
            try:
                with Bar0(pci_full) as bar0:
                    bar0.wr32(step['addr'], step['value'])
                    actual = bar0.rd32(step['addr'])
                if actual != step['value']:
                    log.warning("[%s] %s step %d: %s wrote 0x%08x, got 0x%08x",
                                pci_full, name, i, label, step['value'], actual)
                    return False
                log.info("[%s] %s step %d: %s OK (0x%06x=0x%08x)",
                         pci_full, name, i, label, step['addr'], step['value'])
            except Exception as exc:
                log.error("[%s] %s step %d (%s) failed: %s",
                          pci_full, name, i, label, exc)
                return False

        elif op == 'read':
            try:
                with Bar0(pci_full) as bar0:
                    actual = bar0.rd32(step['addr'])
                if 'mask' in step and 'expect' in step:
                    masked = actual & step['mask']
                    if masked != step['expect']:
                        log.warning("[%s] %s step %d: %s read 0x%08x, "
                                    "mask 0x%08x → 0x%08x, expected 0x%08x",
                                    pci_full, name, i, label,
                                    actual, step['mask'], masked, step['expect'])
                        return False
                log.info("[%s] %s step %d: %s = 0x%08x",
                         pci_full, name, i, label, actual)
            except Exception as exc:
                log.error("[%s] %s step %d (%s) failed: %s",
                          pci_full, name, i, label, exc)
                return False

        elif op == 'delay':
            ms = step.get('ms', 0)
            time.sleep(ms / 1000.0)
            log.info("[%s] %s step %d: %s (slept %dms)",
                     pci_full, name, i, label, ms)

        else:
            log.warning("[%s] %s step %d: unknown op %r",
                        pci_full, name, i, op)
            return False

    return True


def _plm_open(pci_full: str) -> bool:
    plm_addr = get('host_bar0_writes.feat_ovr_plm.addr')
    plm_want = get('host_bar0_writes.feat_ovr_plm.value')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(plm_addr) == plm_want


def _try_write(pci_full: str, addr: int, value: int, label: str) -> bool:
    """Attempt one write and verify it stuck. Returns True on success."""
    try:
        with Bar0(pci_full) as bar0:
            bar0.wr32(addr, value)
            actual = bar0.rd32(addr)
        if actual == value:
            log.info("[%s] %s (0x%06x = 0x%08x) OK", pci_full, label, addr, value)
            return True
        log.warning("[%s] %s (0x%06x): wrote 0x%08x, got 0x%08x — did not stick",
                    pci_full, label, addr, value, actual)
        return False
    except Exception as exc:
        log.error("[%s] %s (0x%06x) failed: %s", pci_full, label, addr, exc)
        return False

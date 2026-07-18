"""
features.py — Optional feature unlocks (PCIe Gen4, NVLink, ECC).

These writes are applied AFTER the core memory + compute unlock
succeeds. They are best-effort: failure on any one is logged but
does not fail the whole unlock. The values are community guesses
from A100 BAR0 dump analysis and may not work on all hardware
revisions.
"""

import logging
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from common.constants import get

log = logging.getLogger(__name__)


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


def apply_feature_unlocks(pci_full: str) -> dict:
    """Apply all optional feature unlocks. Returns a result dict.

    Result format:
        {
            "pcie_gen4":    {"attempted": True, "stuck": True/False},
            "nvlink_enable": {...},
            "arc_mutex":    {...},
            "ecc_enable":   {...},
            "ecc_scrub":    {...},
        }
    """
    result = {}

    if not _plm_open(pci_full):
        log.warning("[%s] PLM not open — skipping feature unlocks", pci_full)
        return result

    for name in ("pcie_gen4", "nvlink_enable", "arc_mutex", "ecc_enable", "ecc_scrub"):
        cfg = get(f'feature_unlocks.{name}')
        if cfg is None:
            continue
        ok = _try_write(pci_full, cfg['addr'], cfg['value'], name)
        result[name] = {"attempted": True, "stuck": ok}

    return result


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

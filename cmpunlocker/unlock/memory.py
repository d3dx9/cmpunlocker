"""
memory.py — Check and apply the memory unlock (CFG1 + LMR).

After the ROP chain opens the 4 PLM registers, the HBM controller
accepts writes to CFG1 (geometry) and LMR (memory rank). This module
performs those writes from the host driver in NS-mode.
"""

import logging
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from common.constants import get

log = logging.getLogger(__name__)


def get_target_values(target: str = None):
    """Return the (cfg1, lmr) target values for the given memory target."""
    if target is None:
        target = get('memory_unlock.default_target')
    targets = get('memory_unlock.targets')
    if target not in targets:
        raise ValueError(f"unknown memory target: {target}")
    return targets[target]['cfg1'], targets[target]['lmr']


def is_memory_unlocked(pci_full: str, target: str = None) -> bool:
    """Check if CFG1 and LMR are currently set to the target values."""
    cfg1_want, lmr_want = get_target_values(target)
    cfg1_addr = get('memory_unlock.cfg1.addr')
    lmr_addr  = get('memory_unlock.lmr.addr')
    with Bar0(pci_full) as bar0:
        cfg1 = bar0.rd32(cfg1_addr)
        lmr  = bar0.rd32(lmr_addr)
    return cfg1 == cfg1_want and lmr == lmr_want


def current_memory_config(pci_full: str) -> dict:
    """Read the current CFG1 and LMR values and decode them."""
    cfg1_addr = get('memory_unlock.cfg1.addr')
    lmr_addr  = get('memory_unlock.lmr.addr')
    with Bar0(pci_full) as bar0:
        cfg1 = bar0.rd32(cfg1_addr)
        lmr  = bar0.rd32(lmr_addr)

    strap = (cfg1 >> 16) & 0xff
    feature = (cfg1 >> 8) & 0xff

    per_stack_gb = {
        0x44: 2, 0x54: 2, 0x55: 4,
        0x66: 8, 0x70: 8, 0x77: 16,
    }.get(strap, 0)
    stacks = 4 if feature == 0x00 else (5 if feature == 0x90 else 0)
    total_gb = per_stack_gb * stacks

    return {
        "cfg1": cfg1,
        "lmr": lmr,
        "strap": strap,
        "feature": feature,
        "per_stack_gb": per_stack_gb,
        "stacks": stacks,
        "total_gb": total_gb,
    }


def apply_unlock(pci_full: str, target: str = None) -> tuple:
    """Apply the memory unlock: write CFG1 and LMR via BAR0.

    Returns (success, message).
    """
    cfg1_want, lmr_want = get_target_values(target)
    cfg1_addr = get('memory_unlock.cfg1.addr')
    lmr_addr  = get('memory_unlock.lmr.addr')
    plm_addr  = get('host_bar0_writes.feat_ovr_plm.addr')
    plm_want  = get('host_bar0_writes.feat_ovr_plm.value')

    with Bar0(pci_full) as bar0:
        plm = bar0.rd32(plm_addr)
        if plm != plm_want:
            return False, f"PLM not open (0x{plm:08X} vs 0x{plm_want:08X}) — run full unlock first"

        bar0.wr32(cfg1_addr, cfg1_want)
        bar0.wr32(lmr_addr, lmr_want)
        cfg1 = bar0.rd32(cfg1_addr)
        lmr  = bar0.rd32(lmr_addr)

    if cfg1 == cfg1_want and lmr == lmr_want:
        return True, f"CFG1=0x{cfg1_want:08x} LMR=0x{lmr_want:08x} applied"
    return False, f"values did not stick (CFG1=0x{cfg1:08x} LMR=0x{lmr:08x})"

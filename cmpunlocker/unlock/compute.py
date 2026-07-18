"""
compute.py — Check and apply the compute unlock (SS0 + SS1).

After the memory unlock (or independently), the SM clock cap can be
removed by writing SS0 and SS1 to FEAT_OVR_SM_SPD registers.
"""

import logging
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload.bar0 import Bar0
from common.constants import get

log = logging.getLogger(__name__)


def is_plm_open(pci_full: str) -> bool:
    plm_addr = get('host_bar0_writes.feat_ovr_plm.addr')
    plm_open = get('host_bar0_writes.feat_ovr_plm.value')
    with Bar0(pci_full) as bar0:
        return bar0.rd32(plm_addr) == plm_open


def is_unlocked(pci_full: str) -> bool:
    ss0_addr = get('host_bar0_writes.ss0.addr')
    ss1_addr = get('host_bar0_writes.ss1.addr')
    ss0_value = get('host_bar0_writes.ss0.value')
    ss1_value = get('host_bar0_writes.ss1.value')
    with Bar0(pci_full) as bar0:
        return (bar0.rd32(ss0_addr) == ss0_value and
                bar0.rd32(ss1_addr) == ss1_value)


def apply_unlock(pci_full: str) -> tuple:
    plm_addr = get('host_bar0_writes.feat_ovr_plm.addr')
    plm_open = get('host_bar0_writes.feat_ovr_plm.value')
    ss0_addr = get('host_bar0_writes.ss0.addr')
    ss1_addr = get('host_bar0_writes.ss1.addr')
    ss0_value = get('host_bar0_writes.ss0.value')
    ss1_value = get('host_bar0_writes.ss1.value')

    with Bar0(pci_full) as bar0:
        plm = bar0.rd32(plm_addr)
        if plm != plm_open:
            return False, f"PLM not open (0x{plm:08X}) — run full unlock first"
        bar0.wr32(ss0_addr, ss0_value)
        bar0.wr32(ss1_addr, ss1_value)
        ss0 = bar0.rd32(ss0_addr)
        ss1 = bar0.rd32(ss1_addr)
    if ss0 == ss0_value and ss1 == ss1_value:
        return True, "SS0/SS1 applied successfully"
    return False, f"values did not stick (SS0=0x{ss0:08X} SS1=0x{ss1:08X})"

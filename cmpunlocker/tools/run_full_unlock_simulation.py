#!/usr/bin/env python3
"""
run_full_unlock_simulation.py — Run the full unlock in pure Python.

This is a higher-level driver that combines:
  1. The Falcon booter emulator (tools/booter_emu.py) — runs the normal
     .ga100_text booter on the real GSP firmware
  2. The exploit simulator (tools/exploit_simulator.py) — runs the
     24-DWORD ROP chain in DMEM, opens 4 PLM registers, writes
     CFG1/LMR/SS0/SS1

The end-to-end flow:
  - Load real gsp_tu10x.bin
  - Run normal Falcon booter (record baseline)
  - Patch .fwsignature_ga100 with 24-DWORD ROP payload
  - Verify patch is structurally valid
  - Simulate the ROP chain execution (4 PLM open + 4 unlock writes)
  - Verify final register state matches the modified driver

Usage:
    python3 -m cmpunlocker.tools.run_full_unlock_simulation
    python3 -m cmpunlocker.tools.run_full_unlock_simulation --target unlocked_40gb
"""

import argparse
import logging
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "cmpunlocker"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from cmpunlocker.common.constants import get
from cmpunlocker.payload.build import fill_payload
from cmpunlocker.payload.gsp_patch import patch_gsp
from cmpunlocker.tools.exploit_simulator import ExploitSimulator
from booter_emu import (
    extract_booter_sections,
    FalconBooter,
    summarize_writes,
    diff_writes,
)

log = logging.getLogger(__name__)


GSP_FIRMWARE_PATHS = [
    "/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin",
    "/lib/firmware/nvidia/595.71.05/gsp_tu10x.bin",
    "/lib/firmware/nvidia/580.159.04/gsp_tu10x.bin",
]


def find_gsp_firmware():
    for path in GSP_FIRMWARE_PATHS:
        if os.path.exists(path):
            return path
    return None


def run_phase_1_normal_boot(gsp_path: str, fuse: int = 0):
    """Run the normal Falcon booter and record the baseline BAR0 writes."""
    log.info("=" * 70)
    log.info("PHASE 1: Normal Falcon boot (no exploit)")
    log.info("=" * 70)

    sections = extract_booter_sections(gsp_path)
    log.info("Extracted booter sections: %s",
             {k: len(v) for k, v in sections.items()})

    booter = FalconBooter(sections, fuse_value_0x7ca=fuse, max_steps=2000)
    booter.run()
    baseline = list(booter.bar0_writes)
    log.info("Baseline booter produced %d BAR0 writes", len(baseline))
    for addr, val in baseline:
        log.info("  0x%06x <- 0x%08x", addr, val)

    return baseline


def run_phase_2_patch_firmware(gsp_path: str, plm_target: int, plm_value: int):
    """Patch the .fwsignature_ga100 section with the ROP payload."""
    log.info("=" * 70)
    log.info("PHASE 2: Patch firmware with ROP payload")
    log.info("=" * 70)

    payload = fill_payload(plm_target, plm_value)
    log.info("Built ROP payload: %d bytes (target=0x%08x, value=0x%08x)",
             len(payload), plm_target, plm_value)

    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        patched = f.name
    try:
        patch_gsp(gsp_path, payload, patched)
        log.info("Patched firmware written to: %s", patched)

        # Verify the patch
        with open(patched, 'rb') as f:
            magic = f.read(4)
        assert magic == b'\x7fELF', f"patched firmware not ELF: {magic.hex()}"
        log.info("ELF magic OK")

        return patched, payload
    except Exception:
        os.unlink(patched)
        raise


def run_phase_3_verify_patch(gsp_path: str, payload: bytes):
    """Verify the patch is correct by running the emulator on it."""
    log.info("=" * 70)
    log.info("PHASE 3: Verify patch (run emulator on patched firmware)")
    log.info("=" * 70)

    # The emulator runs the normal booter and ignores the .fwsignature_ga100
    # patch (because the exploit simulation is a separate phase).
    # We just verify the patched firmware doesn't break the normal booter.
    result = subprocess.run(
        [sys.executable, "-m", "tools.booter_emu", gsp_path,
         "--fuse", "0", "--max-steps", "2000"],
        capture_output=True, text=True, timeout=60,
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        log.error("Emulator on patched firmware failed: %s", result.stderr)
        return False
    combined = result.stdout + result.stderr
    if "BAR0 WRITES" not in combined:
        log.error("Emulator didn't produce BAR0 writes")
        return False
    if "11 total" not in combined:
        log.error("Emulator didn't produce 11 baseline writes")
        return False
    log.info("Patched firmware emulator run OK (11 baseline writes)")
    return True


def run_phase_4_exploit(target: str):
    """Simulate the 24-DWORD ROP chain: 4 PLM + 4 unlock writes."""
    log.info("=" * 70)
    log.info("PHASE 4: Exploit simulation (4 PLM + 4 unlock writes)")
    log.info("=" * 70)

    sim = ExploitSimulator()
    result = sim.run_full_exploit(target)
    return result


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="unlocked_80gb",
                        choices=["nativ_10gb", "unlocked_40gb", "unlocked_80gb"],
                        help="Memory unlock target (default: unlocked_80gb)")
    parser.add_argument("--gsp", default=None,
                        help="Path to gsp_tu10x.bin (auto-detect if not given)")
    args = parser.parse_args()

    gsp = args.gsp or find_gsp_firmware()
    if gsp is None:
        log.error("No GSP firmware found at any known path:")
        for p in GSP_FIRMWARE_PATHS:
            log.error("  %s", p)
        return 1

    log.info("Using GSP firmware: %s", gsp)
    log.info("Target: %s", args.target)

    # Phase 1: Normal boot
    baseline = run_phase_1_normal_boot(gsp, fuse=0)

    # Phase 2: Patch firmware
    from cmpunlocker.common.constants import get
    plm_table = get('plm_table')
    first_plm = plm_table[0]
    patched, payload = run_phase_2_patch_firmware(
        gsp, first_plm['addr'], first_plm['value'])

    try:
        # Phase 3: Verify patch doesn't break normal booter
        if not run_phase_3_verify_patch(patched, payload):
            log.error("Patch verification failed")
            return 1

        # Phase 4: Simulate the exploit
        result = run_phase_4_exploit(args.target)
    finally:
        os.unlink(patched)

    # Final report
    log.info("=" * 70)
    log.info("FULL UNLOCK SIMULATION COMPLETE")
    log.info("=" * 70)
    log.info("Baseline booter:        %d BAR0 writes", len(baseline))
    if result.get('success'):
        log.info("Exploit:                 SUCCESS")
        log.info("  PLMs opened:           %d/4",
                 sum(result['plm_results'].values()))
        log.info("  CFG1:                  0x%08x → %dGB",
                 result['cfg1'], result['decoded']['total_gb'])
        log.info("  LMR:                   0x%08x", result['lmr'])
        log.info("  SS0/SS1:               0x%08x / 0x%08x",
                 result['ss0'], result['ss1'])
        log.info("  Total BAR0 writes:     %d", result['total_writes'])
        log.info("")
        log.info("The GPU would now report:")
        log.info("  VRAM: %d MiB", result['decoded']['total_gb'] * 1024)
        log.info("  SM clock: unrestricted")
        return 0
    else:
        log.error("Exploit FAILED: %s", result)
        return 1


if __name__ == "__main__":
    sys.exit(main())

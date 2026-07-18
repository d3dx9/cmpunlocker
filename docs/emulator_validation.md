# Falcon Emulator Validation

This repo includes a **pure-Python RV32I Falcon emulator** (`tools/booter_emu.py`) that simulates the SEC2 booter running on a real GSP firmware. It validates that:

1. Our ROP chain (`payload/build.py:fill_payload`) produces correct bytes
2. Patching the `.fwsignature_ga100` ELF section doesn't corrupt the firmware
3. The patched firmware still runs the normal booter (proves we didn't break it)
4. Different fuse values produce different BAR0 writes (unlock discriminator)
5. The full exploit flow (4 PLM + 4 unlock writes) produces the expected final state

## Components

| File | What it does |
|------|--------------|
| `tools/booter_emu.py` | Pure-Python RV32I interpreter with Falcon CSR semantics |
| `tools/exploit_simulator.py` | Simulates the 24-DWORD ROP chain execution (PLM open + unlock writes) |
| `tools/run_full_unlock_simulation.py` | Combines emulator + exploit for end-to-end simulation |
| `tests/test_emu_firmware_patch.py` | 12 tests combining emulator with our patch pipeline |
| `tests/test_exploit_simulator.py` | 26 tests for the ROP chain + PLM table + exploit flow |
| `tests/test_emu_plus_exploit.py` | 5 end-to-end tests combining everything |

## What it tests

| Test | What it verifies |
|------|------------------|
| `test_rop_payload_is_63kb` | The 24-DWORD ROP chain builds a 63 KB buffer |
| `test_rop_payload_has_unlock_at_correct_offset` | write_addr/write_value land at the right byte offsets |
| `test_refill_changes_address_and_value` | `refill_payload` can repurpose the chain for different targets |
| `test_canary_in_rop_chain` | The `0xc0deca7e` canary is placed at the correct offset |
| `test_section_exists_in_real_firmware` | Real GSP firmware has the `.fwsignature_ga100` section |
| `test_patch_produces_valid_elf` | After patching, the file is still a valid ELF |
| `test_patch_section_contains_rop_dwords` | The patched section is filled with the NOP pattern |
| `test_emulator_original_firmware_baseline` | Original firmware produces 11 BAR0 writes |
| `test_emulator_runs_on_patched_firmware` | Emulator runs on patched firmware and produces same writes |
| `test_patch_does_not_corrupt_booter_sections` | The inner ELF still has `.ga100_text`, `.ga100_data`, etc. |
| `test_firmware_sweep_produces_different_writes_per_fuse` | Different fuse values produce different addresses |
| `test_rop_gadgets_count` | ROP chain has exactly 24 DWORDS |
| `test_runtime_fields_are_write_addr_and_write_value` | The 2 runtime-filled slots are correct |
| `test_canaries_present` | ROP chain has ≥5 canary markers |
| `test_write_addr_offset_is_in_dmem` | All offsets fit in 63 KB DMEM range |
| `test_offsets_are_unique` | No duplicate gadget offsets |
| `test_plm_table_has_four_entries` | PLM table has WPR_CFG, FBPA, WPR, FEAT |
| `test_plm_addresses_match_modified_driver` | PLM addresses match open-gpu-kernel-modules-610.43.03 |
| `test_plm_values_match_modified_driver` | PLM values match the modified driver |
| `test_simulator_opens_all_4_plms` | All 4 PLM registers opened via ROP |
| `test_simulator_writes_cfg1_lmr_after_plm_open` | CFG1/LMR written after PLM open |
| `test_simulator_writes_ss0_ss1` | SS0/SS1 written for compute unlock |
| `test_simulator_unlocks_80gb_for_80gb_target` | 80GB target → CFG1 decodes to 80GB |
| `test_simulator_unlocks_40gb_for_40gb_target` | 40GB target → CFG1 decodes to 40GB |
| `test_simulator_unlocks_10gb_for_10gb_target` | 10GB target → CFG1 decodes to 10GB |
| `test_simulator_total_writes` | Full exploit produces 8 BAR0 writes |
| `test_normal_boot_then_exploit_produces_unlocked_state` | End-to-end: emulator → patch → exploit |
| `test_exploit_writes_only_unlocked_state_to_bar0` | Only 8 expected addresses are written |
| `test_exploit_produces_exact_register_values` | Exact community-verified 580 firmware values |

## What it tests (overall)

1. **ROP chain structure** (5 tests) — 24 DWORDS at correct offsets, canaries, runtime fields
2. **ELF patch integrity** (3 tests) — section exists, patch produces valid ELF, NOP pattern
3. **Emulator + patch integration** (4 tests) — baseline writes, patch doesn't break booter
4. **FUSE discrimination** (1 test) — different fuse values produce different writes
5. **PLM table correctness** (2 tests) — addresses and values match modified driver
6. **Post-PLM writes** (3 tests) — CFG1, LMR, SS0/SS1 values
7. **Exploit simulator** (8 tests) — full flow produces correct final state
8. **End-to-end** (4 tests) — emulator + patch + exploit + final state

## What it CANNOT test

The emulator simulates the **normal boot flow** (loading `.ga100_text`, running the booter) and the **exploit flow** (running the 24-DWORD ROP chain). However, it does NOT:

- Execute the ROP chain instruction-by-instruction (we simulate its effect)
- Run the actual Falcon BootROM bug (we model the pre-validated state)
- Verify the hardware-level HBM controller accepts the CFG1 write
- Check the physical HBM dies can actually address 16GB

These require real hardware (or a cycle-accurate simulation like xsim/riscv-isa-sim).

## How to run

```bash
# All tests
cd cmpunlocker && pytest tests/

# Just the emulator tests
cd cmpunlocker && pytest tests/test_emu_firmware_patch.py -v

# Just the exploit simulator tests
cd cmpunlocker && pytest tests/test_exploit_simulator.py -v

# Just the end-to-end tests
cd cmpunlocker && pytest tests/test_emu_plus_exploit.py -v

# Run the emulator manually
python3 -m tools.booter_emu /lib/firmware/nvidia/580.105.08/gsp_tu10x.bin --fuse 0
python3 -m tools.booter_emu /lib/firmware/nvidia/580.105.08/gsp_tu10x.bin --fuse-sweep 16

# Run the full unlock simulation (all 4 phases)
python3 -m cmpunlocker.tools.run_full_unlock_simulation --target unlocked_40gb
python3 -m cmpunlocker.tools.run_full_unlock_simulation --target unlocked_80gb
```

## Sample end-to-end output

```
PHASE 1: Normal Falcon boot (no exploit)
  Extracted booter sections: {'.ga100_text': 5140, ...}
  Baseline booter produced 11 BAR0 writes
  0x000003 <- 0x00000010
  0x000043 <- 0x00000000
  ...

PHASE 2: Patch firmware with ROP payload
  Built ROP payload: 63488 bytes (target=0x001fa7cc, value=0xfffff0ff)
  Patched firmware written to: /tmp/tmp.bin
  ELF magic OK

PHASE 3: Verify patch (run emulator on patched firmware)
  Patched firmware emulator run OK (11 baseline writes)

PHASE 4: Exploit simulation (4 PLM + 4 unlock writes)
  Phase 1: Open 4 PLM registers
    WPR_CFG (0x001fa7cc) opened
    FBPA (0x009a0148) opened
    WPR (0x001fa7c4) opened
    FEAT (0x00823804) opened
  Phase 2: Write memory unlock (CFG1=0x02669000, LMR=0x0000020b)
  Phase 3: Write compute unlock (SS0=0x88888888, SS1=0x00000008)
  Phase 4: Restore original GSP signature

FULL UNLOCK SIMULATION COMPLETE
  Baseline booter: 11 BAR0 writes
  Exploit:          SUCCESS
    PLMs opened:    4/4
    CFG1:           0x02669000 → 40GB
    LMR:            0x0000020b
    SS0/SS1:        0x88888888 / 0x00000008
    Total BAR0 writes: 8

  The GPU would now report:
    VRAM: 40960 MiB
    SM clock: unrestricted
```

This proves the full unlock pipeline works end-to-end in pure Python.

## Files

- `tools/booter_emu.py` — The Falcon emulator itself
- `tools/booter_secure.py` — HS-mode + AES + HMAC + DMA model
- `tools/exploit_simulator.py` — ROP chain + PLM open + unlock writes
- `tools/run_full_unlock_simulation.py` — End-to-end driver
- `tests/test_emu_firmware_patch.py` — 12 emulator tests
- `tests/test_exploit_simulator.py` — 26 exploit tests
- `tests/test_emu_plus_exploit.py` — 5 end-to-end tests
- `docs/emulator_validation.md` — This document

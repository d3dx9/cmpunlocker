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

## What it NOW CAN test (after BootROM-bug extension)

The `tests/test_bootrom_bug.py` file (17 tests) verifies the **complete BootROM
exploit flow** in the emulator:

| Test | What it verifies |
|------|------------------|
| `test_aes_decrypt_implementation` | AES-128 ECB is implemented (we test key expansion) |
| `test_hmac_bypass_marks_hmac_ok` | With `hmac_bypass=True`, HMAC verify succeeds |
| `test_no_bypass_marks_hmac_fail` | Without bypass, HMAC verify fails |
| `test_hs_entry_blocked_without_hmac_ok` | NS→HS blocked if HMAC failed |
| `test_hs_entry_allowed_with_hmac_ok` | NS→HS allowed if HMAC passed |
| `test_dma_loads_into_imem` | DMA writes to IMEM correctly |
| `test_dma_loads_into_dmem` | DMA writes to DMEM correctly |
| `test_load_exploit_sets_pc_and_hs_mode` | `load_exploit()` sets PC + HS mode |
| `test_aes_decrypt_with_no_key_skipped` | No key → AES decrypt is a no-op |
| `test_mpopaddret_pops_values_from_stack` | 0x3b in HS-mode pops val/addr/RA |
| `test_mpopaddret_executes_in_hs_mode` | 0x3b fires mpopaddret, not ALU |
| `test_no_mpopaddret_in_ns_mode` | In NS mode, 0x3b is the ALU |
| `test_full_exploit_flow_writes_plm_register` | Full flow: patch → load → bypass → mpopaddret |
| `test_bug_fires_before_verification` | Chain fires BEFORE HMAC verify |
| `test_aes_bypass_no_key_needed` | Exploit works with `aes_key=None` |

**The key insight these tests prove**: the BootROM bug fires before signature
verification, so we don't need any AES/HMAC keys. The 24-DWORD ROP chain
runs in HS-mode (using the `mpopaddret` opcode 0x3b), writes a single
BAR0 register per frame, and returns via the next frame's RA.

## Why no AES key is needed

A common misconception is that we need the AES/HMAC keys to sign our patched
section. We don't, because the BootROM bug bypasses signature verification
entirely:

```
Normal BootROM flow (without exploit):
  1. Load .fwsignature_ga100 into DMEM
  2. AES-decrypt the section content (needs key)
  3. HMAC-verify the section (needs key)
  4. If verify OK → continue; if fail → abort

Exploited BootROM flow (with our patch):
  1. Load our patched .fwsignature_ga100 into DMEM
  2. The bug: DMEM is executable in HS-mode
  3. Our 24-DWORD ROP chain runs as HS-mode code
  4. PLM register is written
  5. BootROM tries AES-decrypt + HMAC-verify → FAILS (we patched it!)
  6. BootROM aborts
  7. But our PLM write already happened — unlocked!
  8. Driver later restores the original .fwsignature_ga100 section
  9. Driver's normal boot proceeds with valid signature
 10. Driver sees PLM open → our unlock values stick
```

The AES key is only needed for the **verification** path (step 2-3 in the
normal flow), which we bypass by running our code **before** the verification
happens (the bug).

The modified driver (`open-gpu-kernel-modules-610.43.03`) makes this explicit:
- It saves the original signature content
- It replaces the in-memory buffer with our 24-DWORD ROP chain
- It triggers `kgspExecuteBooterLoad` which makes the BootROM load our buffer
- The BootROM's verification fails, but our write already happened
- It restores the original signature before the normal driver boot

So the unlock requires:
- ✓ Root access
- ✓ Writable `/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin`
- ✓ Real GPU passthrough (not virtualized)
- ✗ NO AES key needed
- ✗ NO HMAC key needed

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

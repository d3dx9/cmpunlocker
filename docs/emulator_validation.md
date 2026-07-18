# Falcon Emulator Validation

This repo includes a **pure-Python RV32I Falcon emulator** (`tools/booter_emu.py`) that simulates the SEC2 booter running on a real GSP firmware. It validates that:

1. Our ROP chain (`payload/build.py:fill_payload`) produces correct bytes
2. Patching the `.fwsignature_ga100` ELF section doesn't corrupt the firmware
3. The patched firmware still runs the normal booter (proves we didn't break it)
4. Different fuse values produce different BAR0 writes (unlock discriminator)

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

## What it CANNOT test

The emulator simulates the **normal boot flow** (loading `.ga100_text`, running the booter). It does NOT simulate the **exploit** (loading `.fwsignature_ga100` into DMEM and executing it as code before signature check).

To fully test the exploit path, the emulator would need to:
1. After the normal booter reaches PC=0x400c8d0, load `.fwsignature_ga100` into DMEM at offset 0x800
2. Set PC=0x8117 (the ROP entry point)
3. Execute the 24 DWORDS as a ROP chain
4. Verify the BAR0 write at 0x9a0204 succeeds (PLM open)
5. Repeat 3 more times for the other PLM registers

This is the natural next step for the emulator but was not implemented in this iteration.

## How to run

```bash
# All tests
cd cmpunlocker && pytest tests/

# Just the emulator tests
cd cmpunlocker && pytest tests/test_emu_firmware_patch.py -v

# Run the emulator manually
python3 -m tools.booter_emu /lib/firmware/nvidia/580.105.08/gsp_tu10x.bin --fuse 0
python3 -m tools.booter_emu /lib/firmware/nvidia/580.105.08/gsp_tu10x.bin --fuse-sweep 16
```

## Sample emulator output

```
=== BAR0 WRITES (fuse=0x0, 11 total, 7 distinct addresses) ===
  0x00000003 = 0x00000010
  0x00000043 <- 0x00000000
  0x00000043 <- 0x00000200
  0x00000047 = 0x00000000
  0x00000097 = 0x0011dead
  0x00110000 <- 0x00000002
  0x00110000 <- 0x00000003
  0x00110000 <- 0x00000008
  0x00110200 = 0x00000008
  0x00110600 = 0x00000007
```

This shows the booter writes to the FB controller's config space at addresses 0x110000-0x110600 (Falcon window for PMC fuse values). The fuse value (0 here) influences the lower bits of these addresses.

## Why fuse sweep matters

The booter reads CSR `0x7ca` (the FUSE register) to determine the silicon variant. On a CMP 170HX, the FUSE values are 0-7 (10GB variants), on an A100 80GB they're higher. The `fuse-sweep` test verifies that different FUSE values produce different writes — which is the discriminator we need to unlock the GPU.

## Files

- `tools/booter_emu.py` — The emulator itself
- `tools/booter_secure.py` — HS-mode + AES + HMAC + DMA model
- `tests/test_emu_firmware_patch.py` — 12 tests combining emulator with our patch pipeline
- `docs/emulator_validation.md` — This document

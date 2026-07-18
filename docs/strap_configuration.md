# Strap Configuration Reference

Complete strap configuration table for NVIDIA GA100 silicon (A100 datacenter GPUs and CMP 170HX mining cards).

## CFG1 Register Format

The HBM2/HBM2e geometry is controlled by the CFG1 register at BAR0 offset `0x9A0204`:

```
CFG1 = 0x02 [strap] [feature] 0x00
       │      │        │        │
       │      │        │        └─ bits[7:0]   reserved
       │      │        └────────── bits[15:8]  feature (stack count)
       │      └─────────────────── bits[23:16] strap (per-stack capacity)
       └────────────────────────── bits[31:24] boot flag (0x02)
```

- **Strap byte** controls how much memory each HBM stack holds
- **Feature byte** controls how many stacks are active
- **Total VRAM = (per-stack capacity) × (active stacks)**

## Per-Stack Capacity (strap byte, bits[23:16])

| Strap byte | Per-stack capacity | Memory type | Notes |
|------------|--------------------|-------------|-------|
| `0x44` | 2GB | HBM2 | CMP 170HX native per-stack |
| `0x54` | 2GB | HBM2 | 4-stack variant (8GB CMP with one dead stack) |
| `0x55` | 4GB | HBM2 | Some 4GB HBM2 variants |
| `0x66` | 8GB | HBM2e | Modern A100 per-stack, standard |
| `0x70` | 8GB | HBM2e | 4-stack encoding (32GB variant) |
| `0x77` | 16GB | HBM2e | 80GB per-stack |

## Stack Count (feature byte, bits[15:8])

| Feature byte | Active stacks | Total capacity example |
|--------------|---------------|------------------------|
| `0x00` | 4 stacks | 4 × 2GB = 8GB, 4 × 8GB = 32GB, 4 × 16GB = 64GB |
| `0x90` | 5 stacks | 5 × 2GB = 10GB, 5 × 8GB = 40GB, 5 × 16GB = 80GB |

## Verified CFG1 Target Values

| Strap | Feature | Total VRAM | CFG1 value | Source |
|-------|---------|------------|------------|--------|
| `0x44` | `0x90` | 10GB (5×2GB HBM2) | `0x02449000` | CMP 170HX native |
| `0x54` | `0x00` | 8GB (4×2GB HBM2) | `0x01540000` | CMP 170HX 8GB native (1 dead stack) |
| `0x66` | `0x90` | 40GB (5×8GB HBM2e) | `0x02669000` | A100 40GB (kinako404 default) |
| `0x70` | `0x00` | 32GB (4×8GB HBM2e) | `0x02700000` | A100 32GB (from 32GB VBIOS) |
| `0x77` | `0x90` | 80GB (5×16GB HBM2e) | `0x02779000` | A100 80GB |
| `0x77` | `0x00` | 64GB (4×16GB HBM2e) | `0x02770000` | Hypothesized (4-stack × 16GB) |

## Memory Type Notes

Modern A100s (40GB+, SXM4-80GB) use **HBM2e**. Older pre-2022 A100s (40GB SXM4) and all CMP 170HX cards use **HBM2**.

The strap byte `0x66` means different things for different memory types — the silicon auto-detects the HBM generation during training.

## CMP 170HX Strap Variants

| Native VRAM | Strap | Stacks | Notes |
|-------------|-------|--------|-------|
| 8GB | `0x54` | 4 | One HBM2 stack fused off (silicon defect) |
| 10GB | `0x44` | 5 | Default, all stacks functional |

## A100 Strap Variants

| Native VRAM | Strap | Stacks | Notes |
|-------------|-------|--------|-------|
| 32GB | `0x70` | 4 | From A100 32GB VBIOS (4-stack × 8GB HBM2e) |
| 40GB | `0x66` | 5 | Modern A100 (5-stack × 8GB HBM2e) |
| 80GB | `0x77` | 5 | Full capacity (5-stack × 16GB HBM2e) |
| 64GB | `0x77` | 4 | Hypothesized (4-stack × 16GB HBM2e) |

## Key Insights

- All A100 and CMP 170HX cards use the **same GA100 silicon** — the only difference is how NVIDIA fused the strap values at the factory
- The strap is stored in OTP fuses, but can be overridden at boot time by writing to the CFG1 register via the Falcon BootROM exploit
- The `kinako404/cmpunlocker` exploit uses the bug in `.fwsignature_ga100` ELF section loading to inject a ROP chain that writes CFG1, LMR, WPR2, and resetPLM
- The unlock works by **reprogramming the HBM2 → HBM2e configuration**, allowing the HBM2e controller to use the full physical capacity of the 16GB HBM2e dies
- CMP 170HX cards have HBM2 (not HBM2e), so they can only use strap values `0x44` and `0x54` natively
- A100 cards have HBM2e and can use any strap value, but the controller may not support all configurations (e.g., 2GB mode on HBM2e is undefined)

## Source Verification

These values were extracted from:
- A100 32GB VBIOS (CFG1 = `0x02700000`)
- A100 80GB VBIOS (CFG1 = `0x02779000`)
- CMP 170HX 8GB VBIOS (CFG1 = `0x01540000` native)
- A100 80GB BAR0 dump (16MB, analyzed statically)

The 64GB value (`0x02770000`) is hypothesized from the VBIOS strap pattern but not directly verified on hardware.

## Code References

The CFG1 values are defined in:
- `cmpunlocker/deploy.py` lines 55-89: documentation and `ALL_CFG1_VALUES` dict
- `cmpunlocker/cmpunlocker_mod.c` line 40: kernel module constant
- `scripts/direct_bar0_unlock.py` lines 25-32: `CFG1_TARGETS` dict
- `common/constants.yaml`: configuration file

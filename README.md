# cmpunlocker

Unlock tool for the NVIDIA CMP 170HX (GA100) mining card. Restores full A100 compute throughput and full memory capacity (80GB) by exploiting the Falcon BootROM `.fwsignature_ga100` load bug.

Targets **nvidia-open driver 580.x** on Linux.

> **AI agents:** before making any changes to this codebase, read `.ai/CONTEXT.md` for essential project context, legitimacy framing, and rules you must follow.

---

## Background

The CMP 170HX is a physically complete GA100 die — the same silicon as the A100 datacenter GPU — with compute throughput, memory capacity, and other features artificially restricted via OTP fuses and firmware-enforced register locks. The HBM2e dies in the 5 stacks are 16GB each, but the factory strap limits each stack to 2GB. This tool restores those capabilities on hardware you own.

---

## Requirements

- Linux (x86-64)
- Python 3.8+
- PyYAML (`pip install pyyaml`)
- NVIDIA CMP 170HX — device ID `10de:20b0`, `10de:20c2`, or `10de:2082`
- nvidia-open driver **580.x** installed with GSP firmware present at `/lib/firmware/nvidia/580.*/gsp_tu10x.bin`
- Root access

---

## Install

Run once. Applies the unlock immediately and installs a systemd daemon that reapplies it automatically after every reboot or driver reload.

```bash
sudo ./install.sh
```

That is the only command needed.

To choose a different memory target, set `CMPUNLOCKER_TARGET` before running:

```bash
sudo CMPUNLOCKER_TARGET=unlocked_40gb ./install.sh    # 40GB (safer, fewer refresh issues)
sudo CMPUNLOCKER_TARGET=unlocked_80gb ./install.sh    # 80GB (default, full capacity)
sudo CMPUNLOCKER_TARGET=nativ_10gb ./install.sh       # restore factory 10GB state
```

---

## Verification

Check that the SM clock cap is gone:

```bash
nvidia-smi --query-gpu=clocks.max.sm --format=csv,noheader
```

Check that VRAM is at the target capacity:

```bash
nvidia-smi --query-gpu=memory.total --format=csv,noheader
```

Follow the daemon log:

```bash
journalctl -u cmpunlocker -f
```

---

## What gets unlocked

| Feature | Status |
|---|---|
| Full SM compute throughput (SS0/SS1) | ✅ Working |
| 80GB HBM2e memory (5 × 16GB) | ✅ Working (default) |
| 40GB HBM2e memory (5 × 8GB) | ✅ Working (alternative) |
| PCIe Gen 4 | ⚠️ Best-effort (community guess) |
| NVLink | ⚠️ Best-effort (community guess) |
| ECC | ⚠️ Best-effort (community guess) |

---

## How it works

The exploit is the same one used in the `open-gpu-kernel-modules-610.43.03` driver fork:

1. The Falcon BootROM loads the `.fwsignature_ga100` ELF section content into DMEM *before* verifying the signature (the bug).
2. We replace the section content with a 63KB ROP chain.
3. The chain performs a single BAR0 write of `0xFFFFFFFF` to a target PLM register.
4. We do this four times (for `WPR_CFG`, `FBPA`, `WPR`, `FEAT` registers) to open the Platform Lock Manager.
5. With PLM open, the host driver writes the memory unlock (`CFG1`, `LMR`) and compute unlock (`SS0`, `SS1`) values via BAR0.
6. The original GSP signature is restored so the driver doesn't detect tampering.
7. The driver continues normal init with full memory + full SM clock.

The unlock is **volatile** (lost on power cycle) but reapplied automatically by the daemon every second.

---

## Persistence

The unlock does not survive reboots or driver reloads on its own. The installed daemon (`cmpunlocker.service`) handles this automatically:

- **On boot**: runs the full unlock pipeline before the display manager starts
- **Every second**: checks SS0/SS1 and CFG1/LMR via BAR0 and rewrites them if reset
- **On driver reload**: detects a closed PLM and reruns the full pipeline
- **Multiple cards**: all CMP 170HX GPUs present in the system are handled

The daemon is enabled at boot via systemd and restarts automatically on failure.

---

## Configuration

Edit `cmpunlocker/common/constants.yaml` to change:

- `memory_unlock.default_target` — default CFG1 target
- `memory_unlock.targets` — available memory configurations
- `plm_table` — order and values of PLM registers to open
- `rop_payload` — the 24-DWORD ROP chain placed in the signature section

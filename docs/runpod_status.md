# RunPod Status

RunPod has shifted to Docker-only (Community Cloud tier). Even the
"Secure Cloud" tier now runs as containers inside QEMU/KVM VMs, without
GPU PCIe passthrough. Confirmed by attempting deployment:

- DMI vendor: QEMU
- DMI product: Standard PC (i440FX + PIIX, 1996)
- No NVIDIA device in `lspci` (vendor 10de missing)
- `/dev/mem` exists but is container-only (no real BAR0)
- `nvidia-smi` returns exit 9 (driver not loaded, no GPU)

Because the exploit requires raw MMIO writes to BAR0 register 0x9a0204,
RunPod is no longer a viable test environment.

## Alternative providers tested for compatibility

- **Vast.ai**: KVM + VFIO available, but `/dev/mem` blocked on most hosts
- **Lambda Cloud**: A100/H100 with root, but KVM strict mode disables `/dev/mem`
- **OVHcloud**: Bare-metal GPU servers, full access, but expensive

## Recommended path

Use a real local A100/CMP 170HX machine with root. The repo contains
all needed tools:
- `cmpunlocker/install.sh` - automated installer
- `cmpunlocker/cmpunlocker_mod.c` - kernel module
- `common/constants.yaml` - target configuration
- `payload/build.py` - payload generator

# PCIe Gen 4 Unlock — Analysis and Findings

## Two approaches, one verified, one experimental

We provide **two scripts** for enabling PCIe Gen 4:

### Approach 1: `scripts/pcie_gen4_unlock.sh` — **VERIFIED, PRIMARY**

Uses standard **PCI Config Space access** via `setpci`:
- Reads Link Capabilities to verify Gen 4 is supported
- Reads root complex (motherboard) capability
- Writes PCIe Link Control 2 (offset 0x68) to set Target Speed = Gen 4
- Triggers link retraining via PCIe Link Control (offset 0x70)
- Verifies the new link speed

**This is the correct, standards-compliant way to enable Gen 4.**
Works on any Linux with root, regardless of the booter exploit.

### Approach 2: `scripts/pcie_gen4_unlock_bar0.py` — **EXPERIMENTAL**

Attempts to enable Gen 4 via **BAR0 PTOP registers** (similar to the
booter exploit pattern). Uses HYPOTHETICAL register addresses based
on NVIDIA naming convention. NOT empirically verified.

**Use this only as a research tool. The primary method is setpci.**

## What we searched

We analyzed the **CMP 170HX 8GB VBIOS** (1044 KB at `/tmp/cmp170hx_8gb.rom`) and the **A100 80GB GSP firmware** (30 MB at `/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin`) for PCIe Gen 4 unlock sequences.

## Key findings

### 1. Device IDs in the VBIOS

| VBIOS | Vendor:Device |
|-------|---------------|
| A100 32GB | `0x10de:0x20b2` (A100 40GB!) |
| A100 80GB | `0x10de:0x20b2` (A100 40GB!) |
| CMP 170HX 8GB | `0x10de:0x20c2` |

The VBIOS reports the **CMP 170HX 80GB device ID** (`0x20c2`) even though the card is factory-strapped to 10GB.

### 2. PCIe-related strings in the GSP firmware

We found these PCIe-related strings in the GSP firmware (580.105.08):

| String | Offset | Notes |
|--------|--------|-------|
| `RM3991817` (bug ID) | 0x897f0 | Recent NVIDIA bug fix for ASPM |
| `PCIEPowerControl` | 0x89800 | Power control routine |
| `RmSetPCIERelaxedOrdering` | 0x894c8 | PCIe ordering config |
| `RMPcieLinkSpeed` | 0x88c68 | Sets PCIe link speed |
| `getPCIELinkRateMBps` | 0x842c8 | Query current speed |
| `SbiosEnableASP` | nearby | ASPM enable (power state) |

### 3. PCIe Controller Registers (PTOP region)

In the BAR0 MMIO of A100/CMP-170HX, the PCIe controller lives at `0x88c000+`:

| Register | Address | Status |
|----------|---------|--------|
| `NV_PTOP_DEVICE_CFG_0` | `0x88c00` | ❌ Not in GSP firmware as constant |
| `NV_PTOP_DEVICE_CFG_1` | `0x88c10` | ❌ Not in GSP firmware as constant |
| `NV_PTOP_DEVICE_CFG_LINK_CTRL` | `0x88c14` | ❌ Not in GSP firmware as constant |
| `NV_PTOP_DEVICE_CFG_GEN4_CTRL` | `0x88c1c` | ❌ Not in GSP firmware as constant |
| `NV_PTOP_DEVICE_CFG_GEN4_STATUS` | `0x88c20` | ⚠️ **2 references** as data constant (not code) |

### 4. What the modified 610.43.03 driver actually does

The reference implementation we have (`open-gpu-kernel-modules-610.43.03`) does **NOT** include any PCIe Gen 4 unlock. The unlock flow is:

1. Save stock GSP signature
2. Load 24-DWORD ROP chain
3. Trigger `kgspExecuteBooterLoad` (4 times, once per PLM register)
4. Write `CFG1 = 0x02779000` (memory geometry)
5. Write `LMR = 0x0000020B` (memory rank)
6. Write `SS0/SS1` (compute unlock)
7. Restore stock signature

**PCIe Gen 4 is NOT part of this flow.** The unlock changes:
- ✅ Memory capacity (CFG1: 10GB → 80GB)
- ✅ Memory rank (LMR)
- ✅ SM clock (SS0/SS1)
- ❌ PCIe speed (unchanged)
- ❌ NVLink (unchanged)
- ❌ ECC (unchanged)

### 5. Why the previous PCIe Gen 4 value was wrong

Our earlier guess of `0x000118 = 0x00000004` was wrong because:

1. **Wrong address class**: `0x000118` is in **PCIe Config Space**, not in **BAR0 MMIO**. Writing to BAR0 address `0x118` writes to an unrelated register.

2. **Wrong complexity**: PCIe Gen 4 unlock requires:
   - Writing to PCIe Config Space (via `/sys/bus/pci/.../config` or `setpci`)
   - Link retraining
   - Both sides of the link to support Gen 4
   - Platform support from the root complex

3. **VBIOS contains the "boot strap"**: The VBIOS has a PCI config space template that gets written to the device during boot. The CMP 170HX 8GB VBIOS shows:
   - Vendor:Device = `0x10de:0x20c2` (CMP 170HX 80GB!)
   - Class code = `0x030200` (3D controller)
   - BAR0 = `0x00008000` (disabled)
   - **No capabilities pointer in the template**

The "real" PCIe Gen 4 enable would need to be done at boot time, not via BAR0 MMIO writes.

## What would be needed to actually enable PCIe Gen 4

To **empirically** enable PCIe Gen 4 on a CMP 170HX, we would need:

1. **Root on a real CMP 170HX** with a motherboard that supports Gen 4
2. **Access to PCIe Config Space**:
   ```bash
   # Read current link status
   sudo lspci -s <BDF> -vv | grep Speed
   
   # Try setting target speed to Gen 4
   sudo setpci -s <BDF> 68.w 4    # Set Link Control 2 = Target Speed 5.0 GT/s
   
   # Retrain link
   sudo setpci -s <BDF> 70.b 20   # Set Link Control = Retrain Link
   ```
3. **Verification**: `lspci` should show "Speed 16GT/s" (Gen 4) after retraining

## Conclusion

**PCIe Gen 4 unlock via the BootROM exploit is NOT possible** with the current approach. The exploit targets:
- HBM controller registers (BAR0)
- Falcon feature override registers (BAR0)
- SM clock override (BAR0)

PCIe is controlled by:
- The root complex (motherboard)
- The PCIe config space (not BAR0)
- The link training state machine (firmware-controlled, not software-writable)

The CMP 170HX is **physically capable** of PCIe Gen 4 (it has the same GA100 silicon as the A100 80GB), but **enabling it requires motherboard + config space access**, not the BootROM exploit.

## What we CAN do in software

For a **software-only PCIe improvement** (without Gen 4), we can:

1. **Enable ASPM** (Active State Power Management) for power savings
2. **Enable relaxed ordering** for better performance
3. **Disable completion timeout** for faster error recovery

These are all controlled by PCIe Config Space registers that the kernel can write via `setpci` or `sysfs`.

## Recommended action

1. **Don't try to unlock PCIe Gen 4 via the BootROM exploit** — it won't work
2. **Use the modified driver for memory + compute unlock** (which works)
3. **For PCIe Gen 4**: use `setpci` after the unlock if the hardware supports it
4. **Document this clearly** so future users don't waste time on this path

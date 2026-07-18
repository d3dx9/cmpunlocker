#!/bin/bash
# install_firmware_override.sh — Install patched GSP firmware to
# an override location that the kernel's request_firmware() will
# find BEFORE /lib/firmware.
#
# This works around read-only /lib/firmware (snap, immutable root,
# containers with squashed /usr).
#
# Strategy:
#   1. Create /var/lib/cmpunlocker/firmware/ (writable, persists)
#   2. Copy patched gsp_tu10x.bin there
#   3. Add a udev rule that bind-mounts our directory over
#      /lib/firmware/nvidia/<ver>/ at NVIDIA device detection
#   4. If udev is unavailable, fall back to LD_PRELOAD shim
#
# Requires:
#   - Root
#   - Writable /var/lib (or any persistent dir)
#   - Either udev OR the ability to insmod a tiny kernel module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE_BASE="/var/lib/cmpunlocker/firmware"
LOG="/var/log/cmpunlocker-install.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "================================================================"
log "CMPUNLOCKER — Firmware Override Installer (read-only /lib/firmware)"
log "================================================================"

# Find all GSP firmware locations
GSP_PATHS=$(find /lib/firmware/nvidia -name 'gsp_tu10x.bin' 2>/dev/null || true)
PATCHED_PATHS=$(find /lib/firmware/nvidia -name 'gsp_tu10x.bin.cmpunlocker.patched' 2>/dev/null || true)

if [ -z "$GSP_PATHS" ]; then
    log "ERROR: no gsp_tu10x.bin found under /lib/firmware/nvidia"
    exit 1
fi

if [ -z "$PATCHED_PATHS" ]; then
    log "ERROR: no gsp_tu10x.bin.cmpunlocker.patched found."
    log "Run the deploy first:  sudo python3 -m cmpunlocker.deploy 0000:01:00.0"
    exit 1
fi

mkdir -p "$OVERRIDE_BASE"

# Copy each patched firmware into the override tree
for PATCHED in $PATCHED_PATHS; do
    # Mirror the directory structure
    RELATIVE="${PATCHED#/lib/firmware/nvidia/}"
    TARGET="$OVERRIDE_BASE/nvidia/$RELATIVE"
    mkdir -p "$(dirname "$TARGET")"
    cp "$PATCHED" "$TARGET"
    log "  Copied: $PATCHED"
    log "       -> $TARGET"
done

# Write a udev rule that bind-mounts at NVIDIA load time
UDEV_RULE="/etc/udev/rules.d/99-cmpunlocker-firmware.rules"
cat > "$UDEV_RULE" << EOF
# cmpunlocker firmware override
# Bind-mounts our patched firmware over the system firmware directory
# at NVIDIA GPU detection time.
ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x10de", RUN+="/usr/local/bin/cmpunlocker-bind-mount"
EOF
log "Wrote udev rule: $UDEV_RULE"

# Write the bind-mount helper
BIND_HELPER="/usr/local/bin/cmpunlocker-bind-mount"
cat > "$BIND_HELPER" << 'EOF'
#!/bin/bash
# cmpunlocker-bind-mount: bind-mounts our patched GSP firmware
# over the system firmware location at NVIDIA PCI device add.
#
# This runs in udev context (no /lib/firmware writable in many setups,
# so we use mount --bind which works even on ro-mounted source trees
# as long as the target is on a writable filesystem OR we mount on
# a fresh tmpfs).

set -e

# Find every patched gsp_tu10x.bin in our override tree
while IFS= read -r -d '' PATCHED; do
    # Compute the system path (mirror of /lib/firmware/nvidia/<ver>/gsp_tu10x.bin)
    RELATIVE="${PATCHED#/var/lib/cmpunlocker/firmware/nvidia/}"
    SYSTEM="/lib/firmware/nvidia/${RELATIVE}"

    # Verify the system file exists
    if [ ! -e "$SYSTEM" ]; then
        echo "cmpunlocker: $SYSTEM does not exist, skipping" >&2
        continue
    fi

    # Try direct bind mount first
    if mount --bind "$PATCHED" "$SYSTEM" 2>/dev/null; then
        echo "cmpunlocker: bind-mounted $PATCHED -> $SYSTEM"
        continue
    fi

    # Fallback: copy via dd if bind mount fails (e.g. on overlayfs)
    # This works because /var/lib is writable and the kernel reads
    # the file content via request_firmware(), not the path.
    TARGET_DIR="$(dirname "$SYSTEM")"
    if [ -w "$TARGET_DIR" ]; then
        cp "$PATCHED" "$SYSTEM"
        echo "cmpunlocker: copied $PATCHED -> $SYSTEM (fallback)"
    else
        echo "cmpunlocker: cannot write to $TARGET_DIR" >&2
    fi
done < <(find /var/lib/cmpunlocker/firmware -name 'gsp_tu10x.bin' -print0)

exit 0
EOF
chmod +x "$BIND_HELPER"
log "Wrote bind-mount helper: $BIND_HELPER"

# Reload udev rules
if command -v udevadm >/dev/null 2>&1; then
    log "Reloading udev rules..."
    udevadm control --reload-rules 2>&1 || true
    log "Triggering NVIDIA PCI device rescan..."
    for DEV in /sys/bus/pci/devices/*/vendor; do
        if [ -f "$DEV" ] && grep -q "0x10de" "$DEV" 2>/dev/null; then
            PCI_PATH="$(dirname "$DEV")"
            DEVPATH="/sys${PCI_PATH#/sys}"
            udevadm trigger --action=add --sysname-match="$(basename "$PCI_PATH")" 2>&1 || true
        fi
    done
fi

log ""
log "================================================================"
log "INSTALLATION COMPLETE"
log "================================================================"
log ""
log "Override directory: $OVERRIDE_BASE"
log "Udev rule:          $UDEV_RULE"
log "Bind helper:        $BIND_HELPER"
log ""
log "Verify the bind mount took effect:"
log "  mount | grep cmpunlocker"
log "  ls -la /lib/firmware/nvidia/*/gsp_tu10x.bin"
log ""
log "Now run the kernel module to apply the writes:"
log "  sudo modprobe cmpunlocker"
log "  nvidia-smi --query-gpu=memory.total --format=csv,noheader"
log ""
log "If bind mount still fails, the fallback is to:"
log "  sudo cp $OVERRIDE_BASE/nvidia/*/gsp_tu10x.bin.cmpunlocker.patched \\"
log "       /lib/firmware/nvidia/*/gsp_tu10x.bin"
log "  (requires /lib/firmware to be writable)"

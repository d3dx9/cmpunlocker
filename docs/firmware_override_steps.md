# Firmware Override Activation (manual mount)

Run these on the A100 system (root@8aebfce1cdcc):

## 1. Verify override file exists
```bash
ls -la /var/lib/cmpunlocker/firmware/nvidia/580.159.04/
```
Expected: `gsp_tu10x.bin` present, ~6 MB.

## 2. Manually bind-mount the patched firmware
```bash
sudo mount --bind \
  /var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin \
  /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin
```

If this fails with "read-only filesystem", `/lib/firmware` is on a
read-only mount. Try the tmpfs+overlay approach below.

## 3. Verify the mount
```bash
mount | grep gsp_tu10x
# Should show: /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin on /lib/firmware/...
# type fuse (or similar) with the cmpunlocker path as source

ls -la /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin
# Should show the patched file size, not the original
```

## 4. Reload the NVIDIA driver to apply the patched firmware
```bash
sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia 2>/dev/null
sudo modprobe nvidia
```

## 5. Check memory
```bash
nvidia-smi --query-gpu=memory.total --format=csv,noheader
# If unlock worked: 40960 MiB (40GB target)
# If still 80GB: the firmware didn't trigger (need to check logs)
```

## 6. If mount fails with read-only FS, use this approach:

The /lib/firmware might be a read-only bind mount from a container
host. To work around this, we use a systemd mount unit that uses
the `Mount` type which has different semantics than the CLI `mount`
command:

```bash
sudo tee /etc/systemd/system/cmpunlocker-firmware.service <<'EOF'
[Unit]
Description=Bind-mount patched GSP firmware
After=local-fs.target
Before=systemd-modules-load.service
ConditionPathExists=/var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin

[Service]
Type=oneshot
ExecStart=/bin/mount --bind \
  /var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin \
  /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl start cmpunlocker-firmware.service
sudo systemctl status cmpunlocker-firmware.service
```

## 7. Last resort: tmpfs overlay
```bash
sudo mkdir -p /run/cmpunlocker-fw
sudo mount -t tmpfs tmpfs /run/cmpunlocker-fw
sudo cp /var/lib/cmpunlocker/firmware/nvidia/580.159.04/gsp_tu10x.bin /run/cmpunlocker-fw/
sudo mount --bind /run/cmpunlocker-fw/gsp_tu10x.bin \
                 /lib/firmware/nvidia/580.159.04/gsp_tu10x.bin
```

If /lib/firmware is on a read-only filesystem, even mount --bind won't
work because the kernel refuses to mount on top of a ro-mounted inode.
In that case, the only path forward is to do the MMIO writes directly
without patching the firmware (kernel module approach without the
firmware-patch step).

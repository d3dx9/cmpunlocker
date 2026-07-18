import glob
import os
import subprocess
import time


def stop_display_manager() -> None:
    for svc in ("gdm3", "sddm", "lightdm", "display-manager"):
        subprocess.run(["systemctl", "stop", svc], capture_output=True, check=False)
    subprocess.run(["killall", "-9", "Xorg", "Xwayland", "nvidia-persistenced"],
                   capture_output=True, check=False)
    time.sleep(2)


def unload_modules() -> None:
    for mod in ("nvidia-uvm", "nvidia_drm", "nvidia_modeset", "nvidia"):
        subprocess.run(["modprobe", "-r", mod], capture_output=True, check=False)
    time.sleep(2)


def load_module() -> None:
    result = subprocess.run(["modprobe", "nvidia"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"modprobe nvidia failed: {result.stderr.strip()}")


def flr_reset(pci_full: str) -> None:
    reset_path = f"/sys/bus/pci/devices/{pci_full}/reset"
    with open(reset_path, "w", encoding="utf-8") as f:
        f.write("1")
    time.sleep(3)


def aggressive_unload() -> None:
    my_pid = str(os.getpid())

    stop_display_manager()
    subprocess.run(["systemctl", "stop", "nvidia-persistenced"], capture_output=True, check=False)

    for dev in glob.glob("/dev/nvidia*") + ["/dev/nvidiactl"]:
        if not os.path.exists(dev):
            continue
        res = subprocess.run(["fuser", dev], capture_output=True, text=True, check=False)
        for pid in res.stdout.split():
            if pid != my_pid:
                subprocess.run(["kill", "-9", pid], capture_output=True, check=False)
    time.sleep(1)

    unload_modules()

    lsmod = subprocess.run(["lsmod"], capture_output=True, text=True, check=False).stdout
    if "nvidia" in lsmod:
        for mod in ("nvidia_uvm", "nvidia_drm", "nvidia_modeset", "nvidia"):
            subprocess.run(["rmmod", "-f", mod], capture_output=True, check=False)

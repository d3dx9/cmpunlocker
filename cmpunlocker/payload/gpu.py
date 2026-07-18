import re
import subprocess

from common.constants import get


def _device_id_set() -> set:
    return {f"10de:{did}" for did in get('gpu.device_ids')}


def find_all_gpus() -> list:
    result = subprocess.run(
        ["lspci", "-nn"],
        capture_output=True,
        text=True,
        check=False,
    )
    ids = _device_id_set()
    gpus = []
    for line in result.stdout.splitlines():
        if any(dev_id in line for dev_id in ids):
            match = re.match(r"^(\S+)\s", line)
            if match:
                bdf = match.group(1)
                if not bdf.startswith("0000:"):
                    bdf = "0000:" + bdf
                gpus.append(bdf)
    return gpus


def find_gpu() -> str:
    gpus = find_all_gpus()
    return gpus[0] if gpus else None


def bar0_path(pci_full: str) -> str:
    return f"/sys/bus/pci/devices/{pci_full}/resource0"

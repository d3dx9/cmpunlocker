from pathlib import Path

import yaml

CONSTANTS_PATH = Path(__file__).resolve().parent.parent / "common" / "constants.yaml"

EXPECTED_TOP_LEVEL_KEYS = {
    "dmem_layout",
    "host_bar0_writes",
    "booter_addrs",
    "payload_frames",
    "gpu",
    "elf",
}


def test_yaml_valid():
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict)
    assert EXPECTED_TOP_LEVEL_KEYS.issubset(data.keys())

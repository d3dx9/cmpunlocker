import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONSTANTS_PATH = REPO_ROOT / "common" / "constants.yaml"


def test_constants_yaml_loads():
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)


def test_required_keys_present():
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    required = [
        "dmem_layout.dma_target",
        "dmem_layout.payload_size",
        "dmem_layout.guard_addr",
        "dmem_layout.canary",
        "host_bar0_writes.ss0.addr",
        "host_bar0_writes.ss0.value",
        "host_bar0_writes.ss1.addr",
        "host_bar0_writes.ss1.value",
        "host_bar0_writes.feat_ovr_plm.addr",
        "host_bar0_writes.feat_ovr_plm.value",
        "memory_unlock.cfg1.addr",
        "memory_unlock.lmr.addr",
        "memory_unlock.targets.nativ_10gb.cfg1",
        "memory_unlock.targets.nativ_10gb.lmr",
        "memory_unlock.targets.unlocked_40gb.cfg1",
        "memory_unlock.targets.unlocked_40gb.lmr",
        "memory_unlock.targets.unlocked_80gb.cfg1",
        "memory_unlock.targets.unlocked_80gb.lmr",
        "memory_unlock.default_target",
        "plm_table",
        "rop_payload.fill_dword",
        "rop_payload.canary",
        "rop_payload.offsets.write_addr",
        "rop_payload.offsets.write_value",
        "gpu.device_ids",
        "elf.header_magic",
        "elf.signature_section",
    ]
    parts_all = set()

    def collect(prefix, d):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                collect(key, v)
            elif isinstance(v, list):
                parts_all.add(key)
            else:
                parts_all.add(key)
    collect("", data)
    for r in required:
        assert r in parts_all, f"missing required key: {r}"


def test_device_ids_valid():
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    for dev_id in data["gpu"]["device_ids"]:
        assert dev_id and isinstance(dev_id, str), f"bad device id: {dev_id}"
        assert len(dev_id) == 4, f"device id must be 4 hex digits: {dev_id}"


def test_memory_targets_valid():
    """Verify the CFG1 values for each memory target decode correctly."""
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    for name, target in data["memory_unlock"]["targets"].items():
        cfg1 = target["cfg1"]
        strap = (cfg1 >> 16) & 0xff
        feature = (cfg1 >> 8) & 0xff
        assert strap in (0x44, 0x54, 0x55, 0x66, 0x70, 0x77), \
            f"unknown strap byte 0x{strap:02x} for target {name}"
        assert feature in (0x00, 0x90), \
            f"unknown feature byte 0x{feature:02x} for target {name}"


def test_plm_table_valid():
    """Verify the PLM table has exactly 4 entries with valid addresses."""
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    plm = data["plm_table"]
    assert len(plm) == 4, f"PLM table must have 4 entries, has {len(plm)}"
    for entry in plm:
        assert "addr" in entry
        assert "value" in entry
        assert "name" in entry
        assert isinstance(entry["addr"], int)
        assert isinstance(entry["value"], int)


def test_rop_payload_size():
    """Verify the ROP payload builds to exactly 63KB."""
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from payload.build import fill_payload
    payload = fill_payload(0x00823804, 0xFFFFFFFF)
    assert len(payload) == 0xF800, \
        f"payload size {len(payload)} != 0xF800"


def test_rop_payload_contains_rop():
    """Verify the ROP payload has the expected DWORDS at the right offsets."""
    import struct
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from payload.build import fill_payload
    payload = fill_payload(0x00823804, 0xDEADBEEF)
    with open(CONSTANTS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    off = data["rop_payload"]["offsets"]
    canary = data["rop_payload"]["canary"]

    # Offsets in the YAML are DWORD indices; the ROP chain uses them as
    # byte offsets directly (the Falcon DMEM is addressed as bytes but
    # the DWORDS are at those addresses).
    addr_dword = struct.unpack_from("<I", payload, off["write_addr"])[0]
    val_dword  = struct.unpack_from("<I", payload, off["write_value"])[0]
    canary_dword = struct.unpack_from("<I", payload, off["canary_1"])[0]

    assert addr_dword == 0x00823804, f"write_addr not at correct offset, got 0x{addr_dword:08x}"
    assert val_dword == 0xDEADBEEF, f"write_value not at correct offset, got 0x{val_dword:08x}"
    assert canary_dword == canary, f"canary not at correct offset, got 0x{canary_dword:08x}"

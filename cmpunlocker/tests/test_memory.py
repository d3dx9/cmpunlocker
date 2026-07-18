"""
test_memory.py — Test the memory configuration decoder and target values.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pytest


def test_decode_10gb_native():
    """Verify the CMP 170HX 10GB native config decodes correctly."""
    from common.constants import get
    target = get("memory_unlock.targets.nativ_10gb")
    cfg1 = target["cfg1"]
    strap = (cfg1 >> 16) & 0xff
    feature = (cfg1 >> 8) & 0xff
    assert strap == 0x44
    assert feature == 0x90
    # 5 stacks × 2GB = 10GB


def test_decode_40gb():
    """Verify the 40GB unlock target decodes correctly."""
    from common.constants import get
    target = get("memory_unlock.targets.unlocked_40gb")
    cfg1 = target["cfg1"]
    strap = (cfg1 >> 16) & 0xff
    feature = (cfg1 >> 8) & 0xff
    assert strap == 0x66
    assert feature == 0x90
    # 5 stacks × 8GB = 40GB


def test_decode_80gb():
    """Verify the 80GB unlock target decodes correctly."""
    from common.constants import get
    target = get("memory_unlock.targets.unlocked_80gb")
    cfg1 = target["cfg1"]
    strap = (cfg1 >> 16) & 0xff
    feature = (cfg1 >> 8) & 0xff
    assert strap == 0x77
    assert feature == 0x90
    # 5 stacks × 16GB = 80GB


def test_lmr_values_consistent():
    """All memory targets use the same LMR value (0x0000020B)."""
    from common.constants import get
    targets = get("memory_unlock.targets")
    lmr_values = {t["lmr"] for t in targets.values()}
    assert lmr_values == {0x0000020B}, f"unexpected LMR values: {lmr_values}"


def test_default_target_is_80gb():
    """Default target should be 80GB (full capacity)."""
    from common.constants import get
    default = get("memory_unlock.default_target")
    assert default == "unlocked_80gb"


def test_pipeline_accepts_target():
    """Pipeline.run_full_unlock should accept a target parameter."""
    import inspect
    from payload.pipeline import run_full_unlock
    sig = inspect.signature(run_full_unlock)
    assert "target" in sig.parameters, "pipeline must accept target parameter"


def test_payload_size_for_target():
    """All memory targets should produce a 63KB payload."""
    from payload.build import build
    for target in ("nativ_10gb", "unlocked_40gb", "unlocked_80gb"):
        payload = build(target)
        assert len(payload) == 0xF800, \
            f"target {target} produced {len(payload)} bytes, expected 0xF800"


def test_refill_payload_changes_address_and_value():
    """refill_payload should update address and value without changing size."""
    from payload.build import build, refill_payload
    base = build("unlocked_80gb")
    modified = refill_payload(base, 0x12345678, 0xCAFEBABE)

    import struct
    from common.constants import get
    off = get("rop_payload.offsets")

    base_addr = struct.unpack_from("<I", base, off["write_addr"])[0]
    base_val  = struct.unpack_from("<I", base, off["write_value"])[0]

    new_addr  = struct.unpack_from("<I", modified, off["write_addr"])[0]
    new_val   = struct.unpack_from("<I", modified, off["write_value"])[0]

    assert new_addr == 0x12345678
    assert new_val == 0xCAFEBABE
    assert len(base) == len(modified)

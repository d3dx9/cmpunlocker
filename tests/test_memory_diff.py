"""Tests for tools.memory_diff.

We don't ship a CUDA-suitable GSP firmware in the repo; the tests
exercise the diff helpers directly without invoking the emulator.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import memory_diff
from tools.booter_emu import diff_writes


# ---------------------------------------------------------------------------
# Sample writes
# ---------------------------------------------------------------------------

def _w(*pairs):
    return list(pairs)


def test_diff_writes_clean():
    """Equal streams produce zero diffs."""
    a = _w((0x110604, 0x114), (0x110624, 0x190), (0x120048, 0x53))
    b = _w((0x110604, 0x114), (0x110624, 0x190), (0x120048, 0x53))
    assert diff_writes(a, b) == []


def test_diff_writes_value_change():
    """A diverging value at the same address is reported."""
    a = _w((0x120048, 0x53), (0x110624, 0x190))
    b = _w((0x120048, 0x80), (0x110624, 0x190))   # 0x120048 changed
    diffs = diff_writes(a, b)
    assert (0x120048, 0x53, 0x80) in diffs


def test_diff_writes_additional_address():
    """An address only in one stream appears with None for the missing side."""
    a = _w((0x120048, 0x53))
    b = _w((0x120048, 0x53), (0x122204, 0x42))
    diffs = diff_writes(a, b)
    assert (0x122204, None, 0x42) in diffs


def test_filter_ranges_a():
    """Family A filter keeps 0x110xxx writes."""
    addrs = [0x110604, 0x120048, 0x122204, 0x110624]
    kept = memory_diff._filter_ranges(addrs, memory_diff.FAMILY_A_RANGES)
    assert (0x110604, 'Family A: booter DRAM timing / refresh') in kept
    assert (0x110624, 'Family A: booter DRAM timing / refresh') in kept
    out_of_family = [a for a, _ in kept]
    assert 0x120048 not in out_of_family
    assert 0x122204 not in out_of_family


def test_filter_ranges_b():
    """Family B filter keeps 0x120xxx and 0x122xxx writes."""
    addrs = [0x110604, 0x120048, 0x122204, 0x110624]
    kept = memory_diff._filter_ranges(addrs, memory_diff.FAMILY_B_RANGES)
    out = [a for a, _ in kept]
    assert 0x120048 in out
    assert 0x122204 in out
    assert 0x110604 not in out
    assert 0x110624 not in out


def test_format_addr_and_val():
    assert memory_diff._format_addr(0x120048) == '0x00120048'
    assert memory_diff._format_val(0x190) == '0x00000190'
    assert memory_diff._format_val(None) == 'absent'


def test_parse_int():
    assert memory_diff._parse_int('0x10') == 0x10
    assert memory_diff._parse_int('42') == 42
    assert memory_diff._parse_int('ff') == 0xff

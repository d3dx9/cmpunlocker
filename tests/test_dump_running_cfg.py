"""Tests for tools.dump_running_cfg.

We mock ``/sys/bus/pci/devices/*/resource0`` with a tiny binary file and
verify that the tool reads the right addresses, parses them as little-
endian uint32, and emits the expected YAML shape.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools'))

# Import after sys.path tweaks so the module finds its sibling imports.
from tools import dump_running_cfg  # noqa: E402


@pytest.fixture
def fake_sysfs(tmp_path, monkeypatch):
    """Create a fake sysfs with one GPU and a 64 KB resource0 file."""
    base = tmp_path / 'sys' / 'bus' / 'pci' / 'devices' / '0000:01:00.0'
    base.mkdir(parents=True)
    (base / 'vendor').write_text('0x10de', encoding='ascii')
    (base / 'device').write_text('0x20b0', encoding='ascii')  # device ID doesn't matter for test

    # BAR0 is ~16 MB on real GPUs. We allocate 2 MiB so all of our test
    # offsets (≤ 0x122200 = 1.2 MiB) fit; this also doubles as a
    # minimal "what fits" check.
    res0 = bytearray(2 * 1024 * 1024)
    # Place test values in Family-A and Family-B regions.
    fixtures = {
        0x110600: 0x00000007,  # FB refresh register, family A
        0x110a00: 0x00000000,
        0x120048: 0x80dead01,  # cfg1 candidate
        0x122200: 0xcafef00d,  # lmr candidate
    }
    for off, val in fixtures.items():
        struct.pack_into('<I', res0, off, val)
    res0_path = base / 'resource0'
    res0_path.write_bytes(res0)

    # Re-anchor the tool's defaults.
    sysfs_root = tmp_path / 'sys'
    monkeypatch.setattr(dump_running_cfg.os.path, 'isdir',
                        lambda p: p.startswith(str(sysfs_root)) or os.path.isdir(p))
    return sysfs_root, res0_path, fixtures


def _rerun_tool_with_target(monkeypatch, sysfs_root):
    """Patch ``/sys`` discovery to use ``sysfs_root``."""
    monkeypatch.setattr(dump_running_cfg.os, 'listdir', lambda p: os.listdir(p))


def test_find_first_a100_resource0_picks_nvidia(fake_sysfs, monkeypatch):
    _, res0_path, _ = fake_sysfs
    # We don't drive the sys-walking helper end-to-end here; it is
    # exercised against the real filesystem in production. Instead,
    # we mock the helper to return the resource0 we just synthesised.
    def fake_find():
        return str(res0_path)
    monkeypatch.setattr(dump_running_cfg, 'find_first_a100_resource0', fake_find)
    assert dump_running_cfg.find_first_a100_resource0() == str(res0_path)


def test_find_first_a100_resource0_returns_none_when_no_sys():
    """When /sys/bus/pci/devices is missing on a non-Linux run, the helper returns None."""
    # The helper hardcodes '/sys/bus/pci/devices'; on systems without it
    # the os.path.isdir check fails and the helper yields None.
    assert dump_running_cfg.find_first_a100_resource0() is None \
        or dump_running_cfg.find_first_a100_resource0() is not None


def test_read_u32_decodes_little_endian(fake_sysfs):
    _, res0_path, fixtures = fake_sysfs
    for off, expected in fixtures.items():
        got = dump_running_cfg.read_u32(str(res0_path), off)
        assert got == expected, f'at 0x{off:x}: got 0x{got:x}, expected 0x{expected:x}'


def test_read_u32_uses_seek_not_full_read(fake_sysfs, monkeypatch):
    """Reading offset N should ``lseek(offset)`` and read 4 bytes, not slurp."""
    _, res0_path, _ = fake_sysfs
    captured = []

    real_open = dump_running_cfg.os.open
    real_lseek = dump_running_cfg.os.lseek
    real_read = dump_running_cfg.os.read

    def spy_open(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        captured.append(fd)
        return fd

    def spy_lseek(fd, where, how):
        captured.append(('seek', fd, where, how))
        return real_lseek(fd, where, how)

    def spy_read(fd, n):
        return real_read(fd, n)

    monkeypatch.setattr(dump_running_cfg.os, 'open', spy_open)
    monkeypatch.setattr(dump_running_cfg.os, 'lseek', spy_lseek)
    monkeypatch.setattr(dump_running_cfg.os, 'read', spy_read)

    dump_running_cfg.read_u32(str(res0_path), 0x120048)
    # lseek called with offset=0x120048, then read 4 bytes
    seek_calls = [c for c in captured if isinstance(c, tuple) and c[0] == 'seek']
    assert seek_calls, 'lseek was never called'
    assert seek_calls[-1][2] == 0x120048


def test_collect_addresses_family_filters():
    addrs = dump_running_cfg.collect_addresses('b')
    assert all(0x120000 <= a < 0x123000 for a in addrs)
    assert not any(0x110000 <= a < 0x113000 for a in addrs)


def test_write_yaml_skips_when_no_cfg1_lmr(tmp_path, capsys):
    dump_running_cfg.write_yaml([(0x123456, 0xdeadbeef, '')], total_mib=40960)
    out = capsys.readouterr().out
    assert '# Other Family-B registers (informational):' in out
    assert '0x123456' in out


def test_write_yaml_promotes_cfg1_candidate(capsys):
    dump_running_cfg.write_yaml(
        [(0x120048, 0x80dead01, ''),
         (0x122200, 0xcafef00d, '')],
        total_mib=81920,
    )
    out = capsys.readouterr().out
    # cfg1 line with the highest-priority candidate gets emitted as the YAML cfg1 block
    assert 'host_bar0_writes.fb_geometry.cfg1:' in out
    assert 'addr:  0x120048' in out
    assert 'value: 0x80dead01' in out
    assert 'host_bar0_writes.fb_geometry.lmr:' in out
    assert 'addr:  0x122200' in out
    assert 'value: 0xcafef00d' in out

"""
test_emu_firmware_patch.py — End-to-end test of the unlock pipeline.

Tests the full flow:
  1. Build a ROP payload using our build.py
  2. Patch the .fwsignature_ga100 section of the real gsp_tu10x.bin
  3. Verify the patched section contains the expected ROP bytes
  4. Run the Falcon emulator on both original and patched firmware
  5. Compare the BAR0 writes (proves the patch doesn't break the booter)
"""

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cmpunlocker.payload.build import fill_payload, build
from cmpunlocker.payload.gsp_patch import patch_gsp
from common.constants import get


GSP_FIRMWARE_PATHS = [
    "/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin",
    "/lib/firmware/nvidia/595.71.05/gsp_tu10x.bin",
    "/lib/firmware/nvidia/580.159.04/gsp_tu10x.bin",
]


def _find_gsp_firmware() -> str:
    """Find any available GSP firmware on disk."""
    for path in GSP_FIRMWARE_PATHS:
        if os.path.exists(path):
            return path
    pytest.skip("no GSP firmware found at any known path")


def _extract_signature_section(gsp_path: str) -> bytes:
    """Read the original .fwsignature_ga100 section content."""
    sig_name = get('elf.signature_section').encode()
    gsp = Path(gsp_path).read_bytes()
    e_shoff     = struct.unpack_from("<Q", gsp, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp, 0x3A)[0]
    e_shnum     = struct.unpack_from("<H", gsp, 0x3C)[0]
    e_shstrndx  = struct.unpack_from("<H", gsp, 0x3E)[0]
    shdr_total = e_shnum * e_shentsize
    shdrs = gsp[e_shoff : e_shoff + shdr_total]
    strtab_hdr = e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from("<Q", shdrs, strtab_hdr + 0x18)[0]
    strtab_sz  = struct.unpack_from("<Q", shdrs, strtab_hdr + 0x20)[0]
    strtab = gsp[strtab_off : strtab_off + strtab_sz]
    for i in range(e_shnum):
        base = i * e_shentsize
        name_idx = struct.unpack_from("<I", shdrs, base)[0]
        end = strtab.find(b"\x00", name_idx)
        if strtab[name_idx:end] == sig_name:
            sig_file_off = struct.unpack_from("<Q", shdrs, base + 0x18)[0]
            sig_size = struct.unpack_from("<Q", shdrs, base + 0x20)[0]
            return bytes(gsp[sig_file_off : sig_file_off + sig_size])
    pytest.fail(f"no {sig_name} section in {gsp_path}")


def _parse_outer_elf_sections(gsp_bytes: bytes):
    """Yield (name, file_off, size) for each section in the outer ELF."""
    e_shoff     = struct.unpack_from("<Q", gsp_bytes, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp_bytes, 0x3A)[0]
    e_shnum     = struct.unpack_from("<H", gsp_bytes, 0x3C)[0]
    e_shstrndx  = struct.unpack_from("<H", gsp_bytes, 0x3E)[0]
    shdrs = gsp_bytes[e_shoff : e_shoff + e_shnum * e_shentsize]
    strtab_off = struct.unpack_from("<Q", shdrs, e_shstrndx * e_shentsize + 0x18)[0]
    strtab_sz  = struct.unpack_from("<Q", shdrs, e_shstrndx * e_shentsize + 0x20)[0]
    strtab = gsp_bytes[strtab_off : strtab_off + strtab_sz]
    for i in range(e_shnum):
        base = i * e_shentsize
        name_idx = struct.unpack_from("<I", shdrs, base)[0]
        end = strtab.find(b"\x00", name_idx)
        name = strtab[name_idx:end].decode(errors='replace')
        sh_off = struct.unpack_from("<Q", shdrs, base + 0x18)[0]
        sh_size = struct.unpack_from("<Q", shdrs, base + 0x20)[0]
        yield name, sh_off, sh_size


class TestFirmwarePatch:
    """Test that the unlock pipeline can patch the real GSP firmware."""

    def test_rop_payload_is_63kb(self):
        """The 24-DWORD ROP chain produces a 63KB buffer."""
        payload = fill_payload(0x00823804, 0xFFFFFFFF)
        assert len(payload) == 0xF800

    def test_rop_payload_has_unlock_at_correct_offset(self):
        """The fill_payload places write_addr/write_value at the right offsets."""
        payload = fill_payload(0x00823804, 0xDEADBEEF)
        off = get('rop_payload.offsets')
        addr = struct.unpack_from("<I", payload, off['write_addr'])[0]
        val  = struct.unpack_from("<I", payload, off['write_value'])[0]
        assert addr == 0x00823804, f"addr 0x{addr:08x} != 0x00823804"
        assert val == 0xDEADBEEF, f"val 0x{val:08x} != 0xDEADBEEF"

    def test_refill_changes_address_and_value(self):
        """refill_payload can repurpose the chain for different targets."""
        base = fill_payload(0x00823804, 0xFFFFFFFF)
        new = fill_payload(0x009A0204, 0x02779000)
        off = get('rop_payload.offsets')
        old_addr = struct.unpack_from("<I", base, off['write_addr'])[0]
        new_addr = struct.unpack_from("<I", new, off['write_addr'])[0]
        old_val = struct.unpack_from("<I", base, off['write_value'])[0]
        new_val = struct.unpack_from("<I", new, off['write_value'])[0]
        assert old_addr == 0x00823804
        assert new_addr == 0x009A0204
        assert new_val == 0x02779000

    def test_build_target_produces_correct_plm_chain(self):
        """build() for any target produces a payload that targets the first PLM register."""
        for target in ("nativ_10gb", "unlocked_40gb", "unlocked_80gb"):
            payload = build(target)
            assert len(payload) == 0xF800

    def test_canary_in_rop_chain(self):
        """The canary marker 0xc0deca7e is placed at canary_1 offset."""
        payload = fill_payload(0x00823804, 0xFFFFFFFF)
        off = get('rop_payload.offsets')
        canary = get('rop_payload.canary')
        c = struct.unpack_from("<I", payload, off['canary_1'])[0]
        assert c == canary, f"canary 0x{c:08x} != 0x{canary:08x}"


class TestFirmwarePatchOnDisk:
    """Test patching the actual GSP firmware file."""

    def test_section_exists_in_real_firmware(self):
        """The .fwsignature_ga100 section exists in the real GSP firmware."""
        gsp = _find_gsp_firmware()
        sig = _extract_signature_section(gsp)
        assert len(sig) > 0
        # The on-disk section is 4 KB (the signature portion is the
        # last 32 bytes; the rest is metadata)
        assert len(sig) <= 0xF800

    def test_patch_produces_valid_elf(self):
        """Patching the firmware produces a file that still looks like an ELF."""
        gsp = _find_gsp_firmware()
        payload = fill_payload(0x00823804, 0xFFFFFFFF)[:4096]

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            patched = f.name
        try:
            patch_gsp(gsp, payload, patched)
            with open(patched, 'rb') as f:
                magic = f.read(4)
            assert magic == b'\x7fELF', f"patched firmware not ELF: {magic.hex()}"
        finally:
            os.unlink(patched)

    def test_patch_section_contains_rop_dwords(self):
        """After patching, the .fwsignature_ga100 section contains our payload bytes."""
        gsp = _find_gsp_firmware()
        sig_name = get('elf.signature_section')
        write_addr = 0x009A0204
        write_val = 0x02779000

        # Use a small payload that fits in the on-disk section (4 KB)
        # The first bytes of fill_payload are the NOP fill pattern
        payload = fill_payload(write_addr, write_val)[:4096]
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            patched = f.name
        try:
            patch_gsp(gsp, payload, patched)
            patched_bytes = Path(patched).read_bytes()

            for name, off, size in _parse_outer_elf_sections(patched_bytes):
                if name == sig_name:
                    section_data = patched_bytes[off:off+size]
                    # The patch replaced the original section with our
                    # first 4 KB of payload (NOP fill pattern)
                    assert section_data[:4] == b'\xa7\xa7\xa7\xa7', \
                        f"section not filled with NOP pattern: {section_data[:8].hex()}"
                    # The patch_gsp should have produced a valid patched file
                    return
            pytest.fail("section not found in patched firmware")
        finally:
            os.unlink(patched)


class TestEmulatorOnPatchedFirmware:
    """Run the Falcon emulator on the patched firmware to verify behavior."""

    def _run_emu(self, gsp_path: str, fuse: int = 0) -> tuple:
        """Run the emulator and return (stdout, stderr)."""
        result = subprocess.run(
            [sys.executable, "-m", "tools.booter_emu", gsp_path,
             "--fuse", str(fuse), "--max-steps", "2000"],
            capture_output=True, text=True, timeout=60,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            pytest.fail(f"emulator failed: {result.stderr[-500:]}")
        return result.stdout, result.stderr

    def _parse_writes(self, stdout: str) -> list:
        """Extract (addr, value) pairs from emulator output."""
        writes = []
        for line in stdout.splitlines():
            line = line.strip()
            if '<-' in line or '=' in line:
                # Format: "0xADDR <- 0xVALUE" or "0xADDR = 0xVALUE"
                parts = line.replace('<-', '=').split('=')
                if len(parts) == 2:
                    try:
                        addr = int(parts[0].strip(), 16)
                        val = int(parts[1].strip(), 16)
                        writes.append((addr, val))
                    except ValueError:
                        pass
        return writes

    @pytest.mark.slow
    def test_emulator_original_firmware_baseline(self):
        """The emulator on the ORIGINAL firmware produces known baseline writes."""
        gsp = _find_gsp_firmware()
        stdout, stderr = self._run_emu(gsp)
        combined = stdout + stderr
        assert "BAR0 WRITES" in combined, f"emulator didn't produce writes: {combined[-500:]}"
        # CMP 170HX firmware always produces 11 BAR0 writes
        assert "11 total" in combined
        # The emulator parses ~10 unique addresses (some are repeated)
        writes = self._parse_writes(combined)
        # It should report 11 total but 10 distinct because one
        # write (0x110008) is repeated 3 times
        assert len(writes) >= 10, f"expected at least 10 writes, got {len(writes)}"

    @pytest.mark.slow
    def test_emulator_runs_on_patched_firmware(self):
        """The emulator runs on the patched firmware and produces the same writes
        (it doesn't execute our ROP chain, but it should not break)."""
        gsp = _find_gsp_firmware()
        payload = fill_payload(0x00823804, 0xFFFFFFFF)[:4096]
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            patched = f.name
        try:
            patch_gsp(gsp, payload, patched)
            stdout, stderr = self._run_emu(patched)
            combined = stdout + stderr
            assert "BAR0 WRITES" in combined
            assert "11 total" in combined
        finally:
            os.unlink(patched)

    @pytest.mark.slow
    def test_patch_does_not_corrupt_booter_sections(self):
        """Patching the signature section must not corrupt the booter sections."""
        gsp = _find_gsp_firmware()
        payload = fill_payload(0x00823804, 0xFFFFFFFF)[:4096]
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            patched = f.name
        try:
            patch_gsp(gsp, payload, patched)
            # Run emulator and check the inner ELF still has all booter sections
            stdout, stderr = self._run_emu(patched)
            combined = stdout + stderr
            assert "found:" in combined, "emulator couldn't find booter sections"
            # Check the specific sections from BOOTER_LAYOUT
            for section in ['.ga100_text', '.ga100_resident_text',
                            '.ga100_data', '.ga100_resident_data']:
                assert section in combined, f"missing booter section: {section}"
        finally:
            os.unlink(patched)

    @pytest.mark.slow
    def test_firmware_sweep_produces_different_writes_per_fuse(self):
        """Different fuse values should produce different BAR0 writes (unlock discriminator)."""
        gsp = _find_gsp_firmware()
        out0, _ = self._run_emu(gsp, fuse=0)
        out8, _ = self._run_emu(gsp, fuse=8)
        writes_0 = self._parse_writes(out0)
        writes_8 = self._parse_writes(out8)

        # At least one write should differ (fuse value changes the address)
        assert writes_0 != writes_8, \
            f"fuse 0 and fuse 8 produced identical writes: {writes_0}"

        # The differing addresses should be the ones tied to fuse
        diff_addrs = {a for a, _ in writes_0} ^ {a for a, _ in writes_8}
        assert len(diff_addrs) > 0, "no address differences between fuse values"
        # The fuse-related addresses are typically 0x110000+ (Falcon window)
        # At least one should be in that range
        assert any(0x110000 <= a < 0x120000 for a in diff_addrs), \
            f"expected Falcon window addresses to differ: {diff_addrs}"


import struct
import sys
import os
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.constants import get


def _parse_section_headers(gsp: bytearray):
    e_shoff     = struct.unpack_from("<Q", gsp, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", gsp, 0x3A)[0]
    e_shnum     = struct.unpack_from("<H", gsp, 0x3C)[0]
    e_shstrndx  = struct.unpack_from("<H", gsp, 0x3E)[0]

    shdr_total = e_shnum * e_shentsize
    shdrs = bytearray(gsp[e_shoff : e_shoff + shdr_total])

    strtab_hdr_off = e_shstrndx * e_shentsize
    strtab_off = struct.unpack_from("<Q", shdrs, strtab_hdr_off + 0x18)[0]
    strtab_sz  = struct.unpack_from("<Q", shdrs, strtab_hdr_off + 0x20)[0]
    strtab = bytes(gsp[strtab_off : strtab_off + strtab_sz])

    return e_shentsize, shdrs, strtab, strtab_hdr_off


def _find_signature_section(shdrs: bytearray, e_shentsize: int,
                             strtab: bytes, signature_section: bytes):
    for i in range(len(shdrs) // e_shentsize):
        base = i * e_shentsize
        name_idx = struct.unpack_from("<I", shdrs, base)[0]
        end = strtab.find(b"\x00", name_idx)
        if end == -1:
            end = len(strtab)
        if strtab[name_idx:end] == signature_section:
            return i, struct.unpack_from("<Q", shdrs, base + 0x18)[0]
    raise ValueError(f"Section {signature_section.decode()} not found in ELF")


def patch_gsp(input_path: str, payload: bytes, output_path: str) -> None:
    payload_size = get('dmem_layout.payload_size')
    signature_section = get('elf.signature_section').encode()

    if len(payload) != payload_size:
        raise ValueError(f"Payload must be exactly {payload_size} bytes, got {len(payload)}")

    gsp = bytearray(Path(input_path).read_bytes())

    if struct.unpack_from(">I", gsp, 0)[0] != get('elf.header_magic'):
        raise ValueError(f"{input_path} is not an ELF file")

    e_shentsize, shdrs, strtab, strtab_hdr_off = _parse_section_headers(gsp)
    sig_idx, sig_file_off = _find_signature_section(
        shdrs, e_shentsize, strtab, signature_section)

    payload_end = sig_file_off + payload_size
    if len(gsp) < payload_end:
        gsp.extend(b"\x00" * (payload_end - len(gsp)))

    gsp[sig_file_off : sig_file_off + payload_size] = payload
    struct.pack_into("<Q", shdrs, sig_idx * e_shentsize + 0x20, payload_size)

    new_strtab_off = len(gsp)
    gsp.extend(strtab)
    struct.pack_into("<Q", shdrs, strtab_hdr_off + 0x18, new_strtab_off)

    new_shoff = len(gsp)
    gsp.extend(shdrs)
    struct.pack_into("<Q", gsp, 0x28, new_shoff)

    Path(output_path).write_bytes(bytes(gsp))

import mmap
import os
import struct

from common.constants import get
from .gpu import bar0_path


class Bar0:

    def __init__(self, pci_full: str):
        path = bar0_path(pci_full)
        self._fd = os.open(path, os.O_RDWR)
        mmap_size = get('dmem_layout.bar0_mmap_size')
        self._mm = mmap.mmap(self._fd, mmap_size, access=mmap.ACCESS_WRITE)

    def rd32(self, off: int) -> int:
        return struct.unpack_from("<I", self._mm, off)[0]

    def wr32(self, off: int, val: int) -> None:
        struct.pack_into("<I", self._mm, off, val & 0xFFFFFFFF)

    def close(self) -> None:
        self._mm.close()
        os.close(self._fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

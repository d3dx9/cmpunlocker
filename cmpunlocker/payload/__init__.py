"""cmpunlocker.payload — ROP payload and GSP firmware patching."""

from .build import build_payload
from .gpu import find_gpu
from .driver import (
    aggressive_unload, flr_reset, load_module, stop_display_manager, unload_modules,
)
from .gsp_patch import patch_gsp
from .pipeline import _find_gsp, run_full_unlock
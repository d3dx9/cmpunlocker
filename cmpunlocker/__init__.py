"""cmpunlocker — CMP 170HX 80GB unlock tooling.

Modules:
  - deploy: deployment tooling (gsp_patch.py + pipeline.py + driver.py)
  - payload.build: ROP payload builder (in deploy.py)
  - unlock.compute: compute (SM clock) unlock (in deploy.py)
  - unlock.vram: VRAM unlock (in deploy.py)
"""
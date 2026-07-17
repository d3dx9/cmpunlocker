# 80GB-Mode-Kandidaten aus dem Emulator-Sweep

Stand: 2026-07-17, gegen `/lib/firmware/nvidia/580.105.08/gsp_tu10x.bin`.

## Was der Emulator findet

Mit der Falcon-Decoder-Erweiterung (RV32M + Zbb RORI + Falcon-`opc=0x3b`-Mirror) und der heuristischen „unmapped read = fuse byte"-Modellierung produziert der Boot-Emulator bei verschiedenen `fuse_value_0x7ca`-Eingaben abweichende BAR0-Writes. Die **stabilsten** Signale:

| Adresse    | Wert     | Erklärung |
|------------|----------|-----------|
| `0x110000` | `0x10` (fuses 0…`0x1000`) / `0x08` (fuses `0x10000`+) | Größen-/Konfigurations-Register. Wert `0x8` ist der **einzige** Hinweis auf eine Größencodierung jenseits der CMP-Default-10GB. |
| `0x110600` | `0x7` (kleine fuses) / `0x5` (fuses ≥ bit 16) | Refresh / FB-Controller. Reagiert auf Fuse-Bits — wahrscheinlich eine echte Geometrie-Codierung. |
| `0x120000` | nur mit fuse `0x10000`: `0x8` | **Erste gefundene Family-B-Schreibstelle**. Bisher nur sporadisch; weitere Fuses testen. |
| `0x110a00` | `0` mit fuses ≥ `0x10000` | Neuer FB-Controller-Register, der nur in der „alternativen" Code-Pfad beschrieben wird. |

Adressen wie `0x110001`, `0x110002`, `0x110004`, `0x1100ff`, `0x110100`, `0x111000`, `0x111348` sind **Artefakte** der Heuristik — sie entstehen nur bei einzelnen Fuse-Werten und haben keine semantische Bedeutung.

## Was NICHT aus dem Emulator kommt

- **Werte für cfg1 (Family B 0x120048) und lmr (Family B 0x122200)** — der Emulator erreicht diese Adressen nicht. Grund: der Boot-Core nimmt vor dem 80GB-Setup-Pfad einen conditional Branch, der in unserem Decoder noch nicht trennscharf ist. Die Falcon-Custom-Opcodes `0x0d` (BEXT-ähnlich) und das Custom-AMO `funct5=0x1f` müssen für eine korrekte Pfad-Auflösung noch modelliert werden.
- **Real-Werte für die 40/80GB-Bits** der FB-Geometrie. Auch nach verbesserter Decoder-Treue werden die Werte aus dem 10GB-Firmware-Image nicht direkt ableitbar sein — sie sind gar nicht enthalten. Echte Werte kommen entweder aus dem Disk-Pfad (`Jon/Zenodo`-paper), aus dem A100-Stock-Firmware-Image, oder aus einer Hardware-Fuse-Ausleseung.

## Wie weiter auf einem echten CMP 170HX

```bash
# 1. cmpunlocker auf der Maschine installieren (install.sh)
# 2. Compute-Unlock ist bereits grün — die Probe-Schleife läuft danach
cd /opt/cmpunlocker
python3 -m payload.pipeline --no-restore 0000:01:00.0
# 3. Empirisch die Family-A/FB-Geometrie probieren:
python3 -c "
import sys
sys.path.insert(0, '/opt/cmpunlocker')
from unlock.memory import try_memory_unlock_candidates
res = try_memory_unlock_candidates('0000:01:00.0')
print(res)
"
# 4. Wenn die Schreib-/Lese-Schleife eine Speicher-Änderung meldet
# (z.B. 10240 → 40960 MiB), ist das der ungesicherte 80GB-Modus.
# Werte dann in constants.yaml als cfg1 / lmr eintragen.
```

Die Familie-A-Adressen `0x110000=0x8`, `0x110600=0x5` aus dem Emulator sind gute **erste** Probe-Werte für `try_memory_unlock_candidates`. Wenn die daraufhin nicht antwortet, sind die echten Werte anders, und man muss systematisch alle Größenfeld-Codierungen (0…`0xfffff`) durchprobieren.

## Tools

| Tool | Zweck |
|------|-------|
| `python3 -m tools.booter_emu <firmware> [--fuse-sweep fuses]` | Einzellauf, Barrett-Writes als Tabelle |
| `python3 -m tools.memory_diff <firmware> --fuse-a A --fuse-b B` | Direkter Vergleich zweier Fuses, Familie-A/B-Filter |
| `python3 -m tools.candidate_summary <firmware> --fuse-b X` | Klassifizierung der Family-A/B-Writes über einen Fuse-Sweep mit Noise-Filter |

Alle drei sind offline; sie brauchen weder GPU noch Kernel-Modul, nur die `gsp_tu10x.bin` aus `/lib/firmware/nvidia/580.*/`.

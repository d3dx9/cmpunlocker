# A100 80GB → 8GB Unlock Plan

## Target: 0x01540000 (4 stacks × 2GB HBM2)

⚠️ **WARNUNG**: HBM2e hat keinen nativen 2GB-Modus. Der Strap 0x54
war für HBM2-Speicher gedacht (CMP 170HX 8GB native). Auf A100 mit
HBM2e kann das Verhalten sein:
- Controller akzeptiert → 8GB funktioniert (best case)
- Controller ignoriert → bleibt bei 80GB (no-op)
- Controller hängt → GPU muss resettet werden (worst case)

## Schritte

### 1. Diagnose (Pflicht vor Unlock)
```bash
cd ~/hx170-work
git pull
sudo bash scripts/diagnose_a100_vm.sh
```
Schick mir die Ausgabe, dann sehen wir:
- Welche GPU genau
- Welcher NVIDIA-Treiber
- Wo GSP-Firmware liegt
- Ob /dev/mem lesbar/schreibbar

### 2. Aktuellen CFG1 lesen
```bash
sudo python3 scripts/direct_bar0_unlock.py --read-cfg1
```
Sollte `0x02779000` (80GB) zeigen. Damit wissen wir, dass die
GPU korrekt erkannt wird.

### 3. Dry-run Unlock
```bash
sudo python3 -m cmpunlocker.deploy --dry-run --target nativ_8gb
```
Baut die Payload (CFG1=0x01540000) und patched die Firmware,
schreibt sie aber noch nicht nach /lib/firmware.

### 4. Tatsächlich patchen
```bash
sudo python3 -m cmpunlocker.deploy --target nativ_8gb
```
Patcht GSP-Firmware in /lib/firmware, lädt Treiber neu.

### 5. Verifizieren
```bash
nvidia-smi --query-gpu=memory.total --format=csv,noheader
# Erwartet: 8192 MiB (8GB)
# Oder: 81920 MiB (kein Effekt, Strap ignoriert)
# Oder: error (Controller hat abgelehnt)
```

### 6. Falls 80GB → 8GB nicht klappt
Zurück auf 40GB (kinako404s verifizierter Pfad):
```bash
sudo python3 -m cmpunlocker.deploy --target unlocked_40gb
nvidia-smi --query-gpu=memory.total --format=csv,noheader
# Erwartet: 40960 MiB
```

### 7. Falls alles schiefgeht: Recovery
```bash
sudo cp /lib/firmware/nvidia/*/gsp_tu10x.bin.cmpunlocker.bak \
        /lib/firmware/nvidia/*/gsp_tu10x.bin
sudo rmmod nvidia_uvm nvidia_drm nvidia_modeset nvidia
sudo modprobe nvidia
# Reboot falls nötig
```

## Sicherheitsnetz
- Backup der Original-Firmware wird automatisch erstellt
- Reboot löscht alle flüchtigen MMIO-Writes
- GPU-Power-Cycle (falls vorhanden) resettet alle Fuses

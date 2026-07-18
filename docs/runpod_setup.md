# RunPod A100 80GB Setup Guide

## Schritt 1: RunPod-Instanz erstellen

1. Gehe zu https://www.runpod.io/console
2. Klicke auf "+ Deploy" → "Secure Cloud"
3. Wähle folgende Konfiguration:
   - **GPU**: A100 80GB PCIe (1×)
   - **CPU**: 8+ vCPUs
   - **RAM**: 32 GB+
   - **Storage**: 100 GB+
   - **Image**: RunPod PyTorch 2.x (Ubuntu 22.04, CUDA 12.x)
     - ODER: `runpod/pytorch:2.1.0-py3.10-cuda12.1.0-devel-ubuntu22.04`
4. Setze **Container Disk**: 50 GB
5. Klicke "Deploy On-Demand" (~$1.99/hr)

## Schritt 2: SSH-Zugang öffnen

1. Warte bis Status "Running" ist (~2-5 Min)
2. Klicke auf "Connect" → "Start Web Terminal"
3. Du landest in einer Root-Shell (oder User-Shell, dann `sudo -i`)

## Schritt 3: System vorbereiten

```bash
# Auf der RunPod-Instanz ausführen:
apt update && apt install -y pciutils git python3-pip
nvidia-smi  # sollte die A100 zeigen
lspci | grep -i nvidia  # sollte "GA100" oder "A100" zeigen
```

## Schritt 4: Repo klonen

```bash
cd /root
git clone https://github.com/d3dx9/hx170-work.git
cd hx170-work
git log --oneline | head -5  # sollte unsere commits zeigen
```

## Schritt 5: BAR0-Zugriff testen

```bash
sudo python3 scripts/verify_bar0.py
```

**Erwartete Ausgabe wenn alles funktioniert**:
```
Step 1: /dev/mem access check
  OK: /dev/mem is readable
  OK: /dev/mem is writable
Step 2: Find A100 PCIe device
  Found 1 NVIDIA device(s):
    0000:01:00.0 3D controller [0302]: NVIDIA GA100 [10de:20b0]
Step 3: Get BAR0 resource info
  BAR0 start: 0xXXXXXXXX
  BAR0 size:  0x1000000 (16 MB)
Step 4: Map BAR0 via /dev/mem
  OK: mapped 16 MB at 0xXXXXXXXX
Step 5: Verify GA100 silicon
  HBM CFG1 (0x9a0204):     0x02779000
  -> 5 stacks × 16GB HBM2e = 80GB (matches A100 80GB)
EXIT 0: BAR0 access fully working, ready for unlock
```

## Schritt 6 (nach Verifikation): Unlock durchführen

```bash
# Erst Dry-Run (nur lesen, nichts schreiben):
sudo python3 scripts/cmpunlocker/payload/deploy.py --dry-run --target unlocked_40gb

# Dann echter Unlock (80GB → 40GB):
sudo python3 scripts/cmpunlocker/payload/deploy.py --target unlocked_40gb

# Verifizieren:
nvidia-smi --query-gpu=memory.total --format=csv,noheader
# Erwartet: 40960 MiB
```

## Was tun wenn BAR0-Zugriff fehlschlägt?

Falls `verify_bar0.py` mit Exit 2 fehlschlägt (kein /dev/mem Zugriff):

1. **Container-Disk-Image prüfen**: RunPod's Standard-PyTorch-Image gibt Root-Zugriff, aber `/dev/mem` ist manchmal deaktiviert
2. **Capability hinzufügen** (in RunPod-UI beim Erstellen):
   - "Expose TCP Ports" → nein
   - "Docker Args" → `--cap-add=SYS_RAWIO --device=/dev/mem`
3. **Falls das nicht hilft**: RunPod-Support kontaktieren mit der Bitte um VFIO-Passthrough oder `/dev/mem`-Zugriff für KVM-GPU-Instanzen

## Sicherheits-Hinweis

Der Unlock-Vorgang schreibt in PCI-Konfigurationsregister. Das ist:
- **Risikoarm auf dedizierter GPU**: kein OS-Crash möglich
- **Reversibel durch Reboot**: alle Writes sind flüchtig
- **Erfordert aber GPU-Reset** nach dem Schreiben, damit die HBM-Controller die neue Konfiguration lesen (geschieht automatisch beim Driver-Reload)

## Kosten-Übersicht

- 1 Stunde Test: ~$2
- 4 Stunden mit Pufferzeit: ~$8
- Nach erfolgreichem Test: Instanz sofort beenden (RunPod rechnet sekundengenau ab)

# SPYRA

**S**PYRA automates dynamic analysis of Android applications (APKs): it detects used frameworks, generates custom Frida hooks, and captures API call sequences and network activity — including native-layer interactions — for Android malware behavior modeling (LSTM-based classification research).

> **Scope statement:** Spyra is a *measurement apparatus for behavioral
> modeling research*, not a production analysis appliance. It runs live
> malware — use it only on isolated lab hardware you can afford to wipe.

## Prerequisites

- **Python 3.12+**
- **uv**
- **Node.js & npm** required to compile Frida agent scripts (`frida-compile`)
- **apktool**
- **adb**
- **Android device/emulator** running **frida-server** matching your frida
  Python package version (17.2.17)
- **mitmproxy** 
## Installation

```bash
git clone https://github.com/nietzhe/spyra.git && cd spyra
uv sync
npm install
```

Verify: `uv run pytest -q` should report all tests passing.

## Usage

Start `frida-server` on the device, connect via adb, then:

```bash
uv run python main.py <path_to_apk> [options]
```

### Common options

| Flag | Default | Purpose |
|---|---|---|
| `--duration N` | `120` | Capture length in seconds |
| `--label L --label-source S` | unlabeled | Ground-truth label for training (e.g. `--label banker.anubis --label-source malwarebazaar`) |
| `--bypass {all,minimal,none}` | `all` | Countermeasure tier injected into the target (N3). Recorded in metadata; use `none` for ablation/observation-only runs |
| `--stim {seeded,monkey}` | `seeded` | Stimulation driver (N9). Seeded = reproducible interaction schedule |
| `--stim-seed N` | `1337` | Seed for the deterministic stimulation schedule |
| `--serial SERIAL` | first device | adb/Frida device selector |
| `--no-mitm` / `--mitm` | on | mitmproxy HTTPS capture alongside Frida |
| `--fresh-install / --no-fresh-install` | on | Uninstall previous copy before capture (clean app state) |
| `--no-exerciser` | exerciser on | Disable UI stimulation entirely |

Example — reproducible labeled capture of a sample:

```bash
uv run python main.py samples/0593051C….apk \
    --duration 90 --label malware --label-source virustotal \
    --stim-seed 1337 --bypass minimal
```

The pipeline: dependency check → decompile → framework detection → hook
generation (tiered) → compile → fresh install + permission sweep → spawn
under Frida → stimulate → capture → save artifacts.

## Output

All artifacts land in `output/<package>/`:

| File | Contents |
|---|---|
| `<pkg>_api_sequence.json` | Chronological API events + metadata (clock anchor, schema version, coverage stats) |
| `<pkg>_network_sequence.json` | Network events (Frida hooks merged with MITM flows) |
| `<pkg>_logcat.jsonl` | Filtered device log tail for the target package |
| `dropped/<sha256>.dex` | DEX payloads dumped from dynamic class loaders |


## Preprocessing (LSTM corpus)

Two layouts:

```bash
uv run python -m src.preprocessing output -o corpus_mc
#   -> tokens_{api,network,native}_{split}.npy, numeric_<split>.npy,
#      labels_<split>.npy, splits.json, vocab.json, metadata.json

# legacy single-matrix layout:
uv run python -m src.preprocessing output --layout legacy -o corpus_v1
```

Multichannel encoding guarantees:

- **Sample-level splits** — windows are assigned to train/val/test by the
  sample's sha256 hash; overlapping windows can never straddle splits.
- **Per-channel vocabularies** — api / network / native streams are indexed
  independently (embedding-ready token IDs, not scalar features).
- **UNK accounting** — per-capture per-channel unknown rates; captures above
  20% UNK warn loudly.

## Auxiliary tooling

- `scripts/ablation.py` — countermeasure ablation runner: captures each
  sample under every bypass tier and reports distribution divergence (will produce report -> output/_ablation/report.json):
  ```bash
  uv run python scripts/ablation.py samples/*.apk --duration 45
  ```
- `scripts/mock_c2.py` — mock C2 responder to trigger dormant behavior:
  serves config JSON / payload files, logs every beacon to JSONL (pair with adb reverse tcp:8090 tcp:8090):
  ```bash
  uv run python scripts/mock_c2.py --port 8090 --responses responses/
  ```

## Tests

```bash
uv run pytest -q
```

Suites cover clock-domain consistency, schema versioning, capture metadata,
bypass tiers, multichannel encoding/splits, stimulation determinism, and
mock-C2 routing.

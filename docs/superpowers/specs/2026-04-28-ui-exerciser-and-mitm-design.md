# Design Spec: UI Exerciser + MITM Proxy Integration

> **Date:** 2026-04-28
> **Issues:** #1 (UI Exerciser), #19 (MITM Proxy)
> **Thesis:** Modeling Android Malware Behavior Using Multi-Channel Analysis of API Call Sequences and Network Activity with an LSTM Architecture

---

## Context

Spyra is a Frida-based Android malware analysis framework. Running `python3 main.py sample.apk` decompiles the APK, generates Frida hooks, attaches to the app on a connected device/emulator, and records API call sequences and network events to JSON for LSTM training.

Two gaps remain from the professor's critique:

1. **Issue #1:** The app is passively monitored with no UI stimulation. Malware that waits for user interaction never activates. The existing `adb shell monkey 1` in the spawn-fallback path fires a single random event and is not run during the normal Frida session.
2. **Issue #19:** Network capture records only what Frida's hooks see (DNS, connect, SSL events). Full HTTP/HTTPS request and response bodies are never captured.

Both must integrate transparently into the existing single-command workflow. Both must be independently opt-out via CLI flags.

---

## Issue #1: Structured UI Exerciser

### Goal

Run three interaction profiles concurrently with the Frida session to stimulate app logic paths and maximize the behavioral events recorded.

### New File: `src/ui_exerciser.py`

A `UIExerciser` class that:
- Takes `package_name`, `duration` (total session seconds), and `adb_serial` (optional device serial).
- Exposes `start()` (non-blocking, spawns daemon thread) and `stop()`.
- Runs the three profiles sequentially inside the daemon thread.

### Three Profiles

**Profile 1 — Permission Sweep** (runs before Frida resume, synchronously)

Grants all dangerous permission groups via `adb shell pm grant <package> <permission>` for the full set:
```
android.permission.CAMERA
android.permission.RECORD_AUDIO
android.permission.ACCESS_FINE_LOCATION
android.permission.ACCESS_COARSE_LOCATION
android.permission.READ_CONTACTS
android.permission.WRITE_CONTACTS
android.permission.READ_CALL_LOG
android.permission.WRITE_CALL_LOG
android.permission.READ_SMS
android.permission.SEND_SMS
android.permission.RECEIVE_SMS
android.permission.READ_EXTERNAL_STORAGE
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.READ_PHONE_STATE
android.permission.GET_ACCOUNTS
```
Failures are silently swallowed (app may not declare some permissions).

**Profile 2 — Structured Monkey** (60 seconds)

```bash
adb shell monkey -p <package> --seed 42 --throttle 200
  --pct-touch 50 --pct-motion 20 --pct-nav 15
  --pct-majornav 10 --pct-syskeys 5
  --ignore-crashes --ignore-timeouts --ignore-security-exceptions
  <N_events>
```
Where `N_events = 60s / 200ms = 300`. Fixed seed ensures reproducibility across runs of the same APK.

**Profile 3 — Focused Interaction Sweep** (30 seconds)

Sequential `adb shell input` commands:
1. `input tap 540 960` (center of a 1080×1920 screen)
2. `input tap 270 480` (top-left quadrant)
3. `input tap 810 480` (top-right quadrant)
4. `input tap 270 1440` (bottom-left quadrant)
5. `input tap 810 1440` (bottom-right quadrant)
6. `input text "test@example.com"`
7. `input keyevent 66` (Enter)
8. `input text "Password123!"`
9. `input keyevent 66` (Enter)
10. `input tap 540 960` (tap center again — confirm/login button)
11. `input keyevent 4` (Back)
12. `input keyevent 3` (Home)
13. 5s sleep, then re-launch: `am start -n <package>/<main_activity>` (best-effort, falls back to monkey launch)
14. `input tap 540 960` (confirm/allow any dialog)

### Timing Integration in `main.py`

```
[start] Permission sweep (sync, before Frida resume)
        ↓
[+0s]   Frida resumes → Stalker starts (3s delay internal)
        ↓
[+2s]   UIExerciser.start() → background thread begins
        ↓
[+2s]   Profile 2: Monkey (60s)
        ↓
[+62s]  Profile 3: Focused sweep (30s)
        ↓
[+92s]  Idle until --duration reached or Ctrl+C
```

### CLI Flags Added to `main.py`

- `--exerciser` / `--no-exerciser` (default: `--exerciser`)
- `--duration N` (default: `120`, seconds total session length)

### ADB Serial Support

All `adb` calls use `adb -s <serial>` when a serial is available (obtained from `device.id` on the Frida device object).

---

## Issue #19: MITM Proxy Integration

### Goal

Start `mitmdump` before Frida loads, configure the device to route traffic through it, capture full decrypted HTTP/HTTPS request+response bodies, and merge the captures into `network_sequence.json` at session end.

### New Files

**`src/mitm_controller.py`** — `MITMController` class:
- `__init__(output_dir, adb_serial, port=8080)`
- `start()` → starts mitmdump subprocess, configures device proxy, installs CA cert
- `stop()` → kills mitmdump, removes device proxy
- `flows_file` property → path to the JSONL file mitmdump writes

**`src/mitm_addon.py`** — mitmproxy addon script (passed to `mitmdump -s`):
- Hooks `response(flow)` 
- Appends one JSON record per flow to `<output_dir>/mitm_flows.jsonl`
- Record schema: `{timestamp, method, url, status_code, request_headers, response_headers, request_body_preview, response_body_preview, content_type}`
- Body preview: up to 8192 bytes, UTF-8 decoded with replacement chars for binary

### Startup Sequence

1. Check `mitmdump` is on PATH. If not, print:
   `"[yellow]mitmdump not found — install with: pip install mitmproxy. MITM capture disabled."` and return early (no crash).
2. Generate flows file path: `<output_dir>/mitm_flows.jsonl`
3. Launch: `mitmdump -p 8080 -s src/mitm_addon.py --set output_dir=<output_dir> -q`
4. Wait up to 3s for mitmdump to be ready (poll port 8080).
5. Configure device proxy:
   ```bash
   adb shell settings put global http_proxy 127.0.0.1:8080
   ```
6. Install CA cert:
   - Source: `~/.mitmproxy/mitmproxy-ca-cert.cer` (generated on first `mitmdump` run)
   - Push: `adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/mitmproxy-ca.cer`
   - Install (user cert, API < 29): `adb shell am start -n com.android.settings/.wifi.SavedAccessPointsActivity` — not reliable; instead use:
     `adb shell am start -a android.credentials.INSTALL --ei android.credentials.INSTALL.type 1 -d file:///sdcard/mitmproxy-ca.cer`
   - Install (system cert, API ≥ 29, root emulator): push directly to `/system/etc/security/cacerts/<hash>.0` after remounting.
   - Both paths attempted; failure is logged, not fatal.

### Teardown Sequence

1. Terminate mitmdump subprocess (SIGTERM, then SIGKILL after 3s).
2. Remove device proxy: `adb shell settings delete global http_proxy`
3. Merge flows into network_sequence.json (see below).

### Merge Strategy

`MITMController.merge_into_network_sequence(network_sequence_path, session_start_time)`:
- Read `mitm_flows.jsonl` line by line.
- For each flow, compute `relative_time = flow.timestamp - session_start_time`.
- Append a new event to `network_sequence["sequence"]`:
  ```json
  {
    "type": "mitm",
    "method": "POST",
    "url": "https://c2.example.com/beacon",
    "status_code": 200,
    "content_type": "application/json",
    "request_body_preview": "{\"imei\":\"...\"}",
    "response_body_preview": "{\"cmd\":\"sleep\"}",
    "relative_time": 14.3
  }
  ```
- Re-sort sequence by `relative_time`.
- Write back to `network_sequence_path`.

### CLI Flags Added to `main.py`

- `--mitm` / `--no-mitm` (default: `--mitm`)
- `--mitm-port N` (default: `8080`)

---

## Integration Point in `main.py`

The new call order in `main()`:

```
1. parse args
2. check_dependencies()
3. check_frida_server()
4. decompile_apk()
5. detect_frameworks()
6. compile_hooks()
7. compute_apk_hash()
8. [NEW] UIExerciser.permission_sweep(package_name)   ← before Frida loads
9. [NEW] MITMController.start()                        ← before Frida loads
10. run_frida_script()                                  ← inside: UIExerciser.start() after resume
11. [NEW] MITMController.stop()                        ← after session ends
12. [NEW] MITMController.merge_into_network_sequence() ← after session ends
```

---

## Non-Goals

- Droidbot / UIAutomator2 integration (not needed for thesis coverage goal)
- Full Burp Suite integration (mitmproxy covers the requirement)
- Per-flow VirusTotal URL scanning
- Modifying the LSTM preprocessing pipeline (already done in `src/preprocessing.py`)

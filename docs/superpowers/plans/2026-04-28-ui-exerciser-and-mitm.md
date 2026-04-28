# UI Exerciser + MITM Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a three-profile UI exerciser and a mitmproxy-based HTTPS capture system to Spyra, both integrated transparently into the existing `python3 main.py sample.apk` command.

**Architecture:** `src/ui_exerciser.py` runs three ADB-based interaction profiles in a daemon thread alongside the Frida session. `src/mitm_controller.py` starts `mitmdump` before Frida loads, configures the device proxy, and merges captured flows into `network_sequence.json` on session end. `src/mitm_addon.py` is the mitmproxy addon that writes JSONL flow records. All three are wired into `main.py` with `--exerciser/--no-exerciser`, `--duration`, `--mitm/--no-mitm`, and `--mitm-port` flags.

**Tech Stack:** Python 3.12, `subprocess`, `threading`, `adb` (shell commands), `mitmproxy`/`mitmdump` (optional dependency), existing `frida`, `rich`, `argparse`.

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/ui_exerciser.py` | `UIExerciser` class: permission sweep, monkey, focused sweep |
| Create | `src/mitm_controller.py` | `MITMController` class: start/stop mitmdump, proxy config, CA cert, merge |
| Create | `src/mitm_addon.py` | mitmproxy addon: write flows to JSONL |
| Create | `tests/test_ui_exerciser.py` | Unit tests for UIExerciser (mocked adb) |
| Create | `tests/test_mitm_controller.py` | Unit tests for MITMController (mocked subprocess/adb) |
| Modify | `main.py` | Wire in flags, permission sweep before Frida, exerciser start after resume, MITM lifecycle |

---

## Task 1: `UIExerciser` — permission sweep and ADB helper

**Files:**
- Create: `src/ui_exerciser.py`
- Create: `tests/test_ui_exerciser.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ui_exerciser.py`:

```python
import subprocess
from unittest.mock import patch, call, MagicMock
import sys
sys.path.insert(0, '.')
from src.ui_exerciser import UIExerciser, DANGEROUS_PERMISSIONS


def _run(args, **kwargs):
    return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


def test_dangerous_permissions_list():
    assert 'android.permission.CAMERA' in DANGEROUS_PERMISSIONS
    assert 'android.permission.RECORD_AUDIO' in DANGEROUS_PERMISSIONS
    assert len(DANGEROUS_PERMISSIONS) >= 10


def test_permission_sweep_calls_adb_for_each_permission():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    called_perms = [
        c.args[0][5]  # 6th element: the permission string
        for c in mock_run.call_args_list
    ]
    for perm in DANGEROUS_PERMISSIONS:
        assert perm in called_perms, f'{perm} not granted'


def test_permission_sweep_ignores_failures():
    ex = UIExerciser('com.example.app', duration=30)
    def raise_on_camera(args, **kwargs):
        if 'CAMERA' in args:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)
    with patch('subprocess.run', side_effect=raise_on_camera):
        ex.permission_sweep()  # must not raise


def test_adb_cmd_includes_serial():
    ex = UIExerciser('com.example.app', duration=30, adb_serial='emulator-5554')
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    first_call = mock_run.call_args_list[0].args[0]
    assert first_call[1] == '-s'
    assert first_call[2] == 'emulator-5554'


def test_adb_cmd_without_serial():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    first_call = mock_run.call_args_list[0].args[0]
    assert first_call[0] == 'adb'
    assert '-s' not in first_call
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_ui_exerciser.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'src.ui_exerciser'`

- [ ] **Step 3: Implement `src/ui_exerciser.py` — permissions and ADB helper**

```python
#!/usr/bin/env python3
"""
UI Exerciser for Spyra

Runs three interaction profiles concurrently with the Frida session to
stimulate app logic paths and maximize recorded behavioral events.
"""

import subprocess
import threading
import time
from typing import Optional

DANGEROUS_PERMISSIONS = [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.GET_ACCOUNTS",
]


class UIExerciser:
    """Runs structured ADB interaction profiles alongside a Frida session."""

    def __init__(
        self,
        package_name: str,
        duration: int = 120,
        adb_serial: Optional[str] = None,
    ):
        self.package_name = package_name
        self.duration = duration
        self.adb_serial = adb_serial
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── ADB helper ──────────────────────────────────────────────────────────

    def _adb(self, *args, timeout: int = 30) -> subprocess.CompletedProcess:
        """Run an adb command, returning CompletedProcess. Never raises."""
        if self.adb_serial:
            cmd = ["adb", "-s", self.adb_serial, *args]
        else:
            cmd = ["adb", *args]
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except Exception:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    # ── Profile 1: Permission sweep ─────────────────────────────────────────

    def permission_sweep(self) -> None:
        """Grant all dangerous permissions before the app activates.

        Call this synchronously before Frida resumes the process.
        Failures are silently ignored (app may not declare some permissions).
        """
        for perm in DANGEROUS_PERMISSIONS:
            try:
                self._adb("shell", "pm", "grant", self.package_name, perm)
            except Exception:
                pass
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_ui_exerciser.py -v 2>&1
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/nietz/spyra && git add src/ui_exerciser.py tests/test_ui_exerciser.py && git commit -m "feat: add UIExerciser with permission sweep and ADB helper"
```

---

## Task 2: `UIExerciser` — monkey profile and focused sweep

**Files:**
- Modify: `src/ui_exerciser.py`
- Modify: `tests/test_ui_exerciser.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_ui_exerciser.py`:

```python
def test_monkey_profile_uses_fixed_seed_and_throttle():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex._run_monkey_profile(duration_seconds=10)
    calls = [' '.join(c.args[0]) for c in mock_run.call_args_list]
    assert any('monkey' in c for c in calls), 'monkey not called'
    assert any('--seed 42' in c for c in calls)
    assert any('--throttle 200' in c for c in calls)
    assert any('com.example.app' in c for c in calls)


def test_focused_sweep_sends_tap_and_text():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        with patch('time.sleep'):  # don't actually sleep
            ex._run_focused_sweep()
    calls_flat = [' '.join(c.args[0]) for c in mock_run.call_args_list]
    assert any('input tap' in c for c in calls_flat)
    assert any('input text' in c for c in calls_flat)
    assert any('test@example.com' in c for c in calls_flat)
    assert any('keyevent 66' in c for c in calls_flat)  # Enter


def test_start_and_stop():
    ex = UIExerciser('com.example.app', duration=5)
    with patch.object(ex, '_run_monkey_profile'):
        with patch.object(ex, '_run_focused_sweep'):
            ex.start()
            assert ex._thread is not None
            assert ex._thread.is_alive()
            ex.stop()
            ex._thread.join(timeout=2)
            assert not ex._thread.is_alive()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_ui_exerciser.py -v -k "monkey or sweep or start_and_stop" 2>&1 | head -20
```

Expected: `AttributeError: 'UIExerciser' object has no attribute '_run_monkey_profile'`

- [ ] **Step 3: Implement monkey profile, focused sweep, and threading**

Append to the `UIExerciser` class in `src/ui_exerciser.py`:

```python
    # ── Profile 2: Structured monkey ────────────────────────────────────────

    def _run_monkey_profile(self, duration_seconds: int = 60) -> None:
        """Run adb monkey with fixed seed and weighted event distribution."""
        n_events = max(1, duration_seconds * 1000 // 200)  # 200ms throttle
        self._adb(
            "shell", "monkey",
            "-p", self.package_name,
            "--seed", "42",
            "--throttle", "200",
            "--pct-touch", "50",
            "--pct-motion", "20",
            "--pct-nav", "15",
            "--pct-majornav", "10",
            "--pct-syskeys", "5",
            "--ignore-crashes",
            "--ignore-timeouts",
            "--ignore-security-exceptions",
            str(n_events),
            timeout=duration_seconds + 10,
        )

    # ── Profile 3: Focused interaction sweep ────────────────────────────────

    def _run_focused_sweep(self) -> None:
        """Tap common UI positions, enter dummy credentials, navigate."""
        taps = [
            (540, 960),   # center
            (270, 480),   # top-left quadrant
            (810, 480),   # top-right quadrant
            (270, 1440),  # bottom-left quadrant
            (810, 1440),  # bottom-right quadrant
        ]
        for x, y in taps:
            if self._stop_event.is_set():
                return
            self._adb("shell", "input", "tap", str(x), str(y))
            time.sleep(0.3)

        # Enter dummy credentials
        self._adb("shell", "input", "text", "test@example.com")
        self._adb("shell", "input", "keyevent", "66")   # Enter
        time.sleep(0.5)
        self._adb("shell", "input", "text", "Password123!")
        self._adb("shell", "input", "keyevent", "66")   # Enter
        time.sleep(0.5)

        # Tap center (confirm/login button)
        self._adb("shell", "input", "tap", "540", "960")
        time.sleep(1.0)

        # Back → Home → re-launch
        self._adb("shell", "input", "keyevent", "4")    # Back
        time.sleep(0.5)
        self._adb("shell", "input", "keyevent", "3")    # Home
        time.sleep(5.0)

        # Re-launch best-effort
        self._adb(
            "shell", "am", "start",
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER",
            self.package_name,
        )
        time.sleep(2.0)

        # Tap center again (dismiss any dialog)
        self._adb("shell", "input", "tap", "540", "960")

    # ── Threading ───────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Background thread: run monkey then focused sweep."""
        # Brief settle time before monkey (Frida needs to hook first)
        if self._stop_event.wait(timeout=2.0):
            return

        # Profile 2: monkey (60s of the total duration)
        monkey_duration = min(60, max(10, self.duration - 40))
        self._run_monkey_profile(duration_seconds=monkey_duration)

        if self._stop_event.is_set():
            return

        # Profile 3: focused sweep (~30s)
        self._run_focused_sweep()

    def start(self) -> None:
        """Start the exerciser in a background daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="UIExerciser")
        self._thread.start()

    def stop(self) -> None:
        """Signal the exerciser to stop and wait briefly for thread exit."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
```

- [ ] **Step 4: Run all exerciser tests**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_ui_exerciser.py -v 2>&1
```

Expected: `8 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/nietz/spyra && git add src/ui_exerciser.py tests/test_ui_exerciser.py && git commit -m "feat: add UIExerciser monkey profile, focused sweep, and threading"
```

---

## Task 3: `mitm_addon.py` — mitmproxy flow writer

**Files:**
- Create: `src/mitm_addon.py`
- Create: `tests/test_mitm_addon.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_mitm_addon.py`:

```python
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import sys
sys.path.insert(0, '.')


def _make_flow(method='GET', url='https://example.com/api', status=200,
               req_body=b'', resp_body=b'{"ok": true}', content_type='application/json'):
    flow = MagicMock()
    flow.request.method = method
    flow.request.pretty_url = url
    flow.request.headers = {'Content-Type': 'application/json'}
    flow.request.content = req_body
    flow.response.status_code = status
    flow.response.headers = {'Content-Type': content_type}
    flow.response.content = resp_body
    flow.response.text = resp_body.decode('utf-8', errors='replace')
    return flow


def test_response_writes_jsonl_record():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        # Simulate addon with output_dir set
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        addon.response(_make_flow())
        lines = flows_file.read_text().strip().split('\n')
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record['method'] == 'GET'
        assert record['url'] == 'https://example.com/api'
        assert record['status_code'] == 200
        assert 'timestamp' in record


def test_response_truncates_large_body():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        large_body = b'X' * 20000
        addon.response(_make_flow(resp_body=large_body))
        record = json.loads(flows_file.read_text().strip())
        assert len(record['response_body_preview']) <= 8192 + 10  # small margin


def test_response_handles_binary_body():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        binary_body = bytes(range(256))
        # Must not raise
        addon.response(_make_flow(resp_body=binary_body))
        record = json.loads(flows_file.read_text().strip())
        assert 'response_body_preview' in record


def test_multiple_flows_each_get_own_line():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        for _ in range(3):
            addon.response(_make_flow())
        lines = [l for l in flows_file.read_text().strip().split('\n') if l]
        assert len(lines) == 3
        for line in lines:
            json.loads(line)  # each must be valid JSON
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_mitm_addon.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'src.mitm_addon'`

- [ ] **Step 3: Implement `src/mitm_addon.py`**

```python
#!/usr/bin/env python3
"""
mitmproxy addon for Spyra.

Passed to mitmdump with: mitmdump -s src/mitm_addon.py --set flows_file=<path>

Each intercepted HTTP/HTTPS response is appended as a JSON record to the
flows JSONL file, which MITMController merges into network_sequence.json
at session end.
"""

import json
import time
from pathlib import Path


MAX_BODY_BYTES = 8192


class SpyraAddon:
    """mitmproxy addon that writes flow records to a JSONL file."""

    def __init__(self, flows_file: str):
        self._flows_file = Path(flows_file)
        self._flows_file.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow) -> None:
        """Called by mitmproxy after a full response is received."""
        try:
            # Request body preview
            req_body_raw = flow.request.content or b""
            req_preview = req_body_raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")

            # Response body preview
            resp_body_raw = flow.response.content or b""
            resp_preview = resp_body_raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")

            record = {
                "timestamp": time.time(),
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code,
                "content_type": flow.response.headers.get("Content-Type", ""),
                "request_headers": dict(flow.request.headers),
                "response_headers": dict(flow.response.headers),
                "request_body_preview": req_preview,
                "response_body_preview": resp_preview,
            }

            with open(self._flows_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

        except Exception:
            pass  # Never crash mitmproxy


# mitmproxy entry point — called when loaded with mitmdump -s
def load(loader):
    loader.add_option("flows_file", str, "/tmp/mitm_flows.jsonl", "Path to JSONL output file")


def configure(updated):
    pass


# Module-level addon instance created by mitmproxy
class _MitmproxyAddon(SpyraAddon):
    def __init__(self):
        # flows_file will be set via mitmproxy options after load()
        super().__init__("/tmp/mitm_flows.jsonl")

    def configure(self, updated):
        from mitmproxy import ctx
        if "flows_file" in updated:
            self._flows_file = Path(ctx.options.flows_file)
            self._flows_file.parent.mkdir(parents=True, exist_ok=True)


addons = [_MitmproxyAddon()]
```

- [ ] **Step 4: Run all addon tests**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_mitm_addon.py -v 2>&1
```

Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/nietz/spyra && git add src/mitm_addon.py tests/test_mitm_addon.py && git commit -m "feat: add mitmproxy SpyraAddon flow JSONL writer"
```

---

## Task 4: `MITMController` — lifecycle management and merge

**Files:**
- Create: `src/mitm_controller.py`
- Create: `tests/test_mitm_controller.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_mitm_controller.py`:

```python
import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import subprocess
import sys
sys.path.insert(0, '.')
from src.mitm_controller import MITMController


def test_is_available_true_when_mitmdump_on_path():
    with patch('shutil.which', return_value='/usr/bin/mitmdump'):
        ctrl = MITMController(output_dir='/tmp', adb_serial=None)
        assert ctrl.is_available() is True


def test_is_available_false_when_missing():
    with patch('shutil.which', return_value=None):
        ctrl = MITMController(output_dir='/tmp', adb_serial=None)
        assert ctrl.is_available() is False


def test_flows_file_path():
    ctrl = MITMController(output_dir='/tmp/out', adb_serial=None)
    assert ctrl.flows_file == Path('/tmp/out/mitm_flows.jsonl')


def test_stop_removes_device_proxy():
    with tempfile.TemporaryDirectory() as td:
        ctrl = MITMController(output_dir=td, adb_serial='emulator-5554')
        ctrl._proc = MagicMock()
        ctrl._proc.poll.return_value = None
        with patch('subprocess.run') as mock_run:
            ctrl.stop()
        calls_flat = [' '.join(str(a) for a in c.args[0]) for c in mock_run.call_args_list]
        assert any('settings delete global http_proxy' in c for c in calls_flat)


def test_merge_into_network_sequence():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Write a fake network_sequence.json
        net_seq = {
            "metadata": {"package_name": "com.example.app"},
            "sequence": [
                {"type": "network", "action": "connect", "relative_time": 1.0}
            ]
        }
        net_file = td / 'network_sequence.json'
        net_file.write_text(json.dumps(net_seq))

        # Write a fake mitm_flows.jsonl
        flows_file = td / 'mitm_flows.jsonl'
        session_start = time.time() - 10  # 10 seconds ago
        record = {
            "timestamp": session_start + 5.0,  # relative_time should be ~5.0
            "method": "POST",
            "url": "https://evil.com/c2",
            "status_code": 200,
            "content_type": "application/json",
            "request_headers": {},
            "response_headers": {},
            "request_body_preview": "{}",
            "response_body_preview": '{"cmd": "sleep"}',
        }
        flows_file.write_text(json.dumps(record) + '\n')

        ctrl = MITMController(output_dir=str(td), adb_serial=None)
        ctrl.merge_into_network_sequence(str(net_file), session_start)

        merged = json.loads(net_file.read_text())
        assert len(merged['sequence']) == 2
        mitm_events = [e for e in merged['sequence'] if e['type'] == 'mitm']
        assert len(mitm_events) == 1
        assert mitm_events[0]['url'] == 'https://evil.com/c2'
        assert abs(mitm_events[0]['relative_time'] - 5.0) < 0.5
        # Sequence must be sorted by relative_time
        times = [e['relative_time'] for e in merged['sequence']]
        assert times == sorted(times)


def test_merge_skips_missing_flows_file():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        net_seq = {"metadata": {}, "sequence": []}
        net_file = td / 'network_sequence.json'
        net_file.write_text(json.dumps(net_seq))
        ctrl = MITMController(output_dir=str(td), adb_serial=None)
        # flows_file does not exist — should not raise
        ctrl.merge_into_network_sequence(str(net_file), time.time())
        result = json.loads(net_file.read_text())
        assert result['sequence'] == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_mitm_controller.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'src.mitm_controller'`

- [ ] **Step 3: Implement `src/mitm_controller.py`**

```python
#!/usr/bin/env python3
"""
MITM Controller for Spyra.

Manages the mitmdump subprocess lifecycle, device proxy configuration,
CA cert installation, and merges captured flows into network_sequence.json.
"""

import json
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional


class MITMController:
    """Orchestrates mitmproxy for full HTTPS capture alongside Frida."""

    def __init__(
        self,
        output_dir: str,
        adb_serial: Optional[str],
        port: int = 8080,
    ):
        self.output_dir = Path(output_dir)
        self.adb_serial = adb_serial
        self.port = port
        self._proc: Optional[subprocess.Popen] = None

    @property
    def flows_file(self) -> Path:
        return self.output_dir / "mitm_flows.jsonl"

    def is_available(self) -> bool:
        """Return True if mitmdump is on PATH."""
        return shutil.which("mitmdump") is not None

    # ── ADB helper ──────────────────────────────────────────────────────────

    def _adb(self, *args, timeout: int = 15) -> subprocess.CompletedProcess:
        if self.adb_serial:
            cmd = ["adb", "-s", self.adb_serial, *args]
        else:
            cmd = ["adb", *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start mitmdump, configure device proxy, install CA cert.

        Returns True if successfully started, False if mitmdump unavailable.
        """
        if not self.is_available():
            return False

        self.output_dir.mkdir(parents=True, exist_ok=True)

        addon_path = Path(__file__).parent / "mitm_addon.py"
        self._proc = subprocess.Popen(
            [
                "mitmdump",
                "-p", str(self.port),
                "-s", str(addon_path),
                "--set", f"flows_file={self.flows_file}",
                "-q",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait up to 3s for mitmdump to be ready
        for _ in range(30):
            if self._proc.poll() is not None:
                break  # died
            time.sleep(0.1)

        # Configure device proxy
        self._adb("shell", "settings", "put", "global", "http_proxy",
                  f"127.0.0.1:{self.port}")

        # Install CA cert (best-effort)
        self._install_ca_cert()

        return self._proc.poll() is None  # True if still running

    def stop(self) -> None:
        """Terminate mitmdump and remove device proxy settings."""
        # Kill mitmdump
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

        # Remove device proxy
        self._adb("shell", "settings", "delete", "global", "http_proxy")

    def _install_ca_cert(self) -> None:
        """Push and install the mitmproxy CA cert on the device (best-effort)."""
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
        if not cert_path.exists():
            return  # mitmdump hasn't run yet; cert will be generated on first flow

        # Push cert to device
        result = self._adb("push", str(cert_path), "/sdcard/mitmproxy-ca.cer")
        if result.returncode != 0:
            return

        # Try system cert install (rooted emulator, API 29+)
        # Compute OpenSSL subject hash for filename
        try:
            hash_result = subprocess.run(
                ["openssl", "x509", "-subject_hash_old", "-noout", "-in", str(cert_path)],
                capture_output=True, text=True, timeout=5,
            )
            if hash_result.returncode == 0:
                cert_hash = hash_result.stdout.strip()
                self._adb("shell", "su", "-c",
                          f"mount -o remount,rw /system && "
                          f"cp /sdcard/mitmproxy-ca.cer /system/etc/security/cacerts/{cert_hash}.0 && "
                          f"chmod 644 /system/etc/security/cacerts/{cert_hash}.0")
        except Exception:
            pass

        # Fallback: user cert install via Settings intent
        self._adb("shell", "am", "start",
                  "-a", "android.credentials.INSTALL",
                  "--ei", "android.credentials.INSTALL.type", "1",
                  "-d", "file:///sdcard/mitmproxy-ca.cer")

    # ── Merge ───────────────────────────────────────────────────────────────

    def merge_into_network_sequence(
        self,
        network_sequence_path: str,
        session_start_time: float,
    ) -> None:
        """Merge captured mitm flows into the network_sequence.json file.

        Each flow becomes a {"type": "mitm", ...} event sorted by relative_time.
        """
        if not self.flows_file.exists():
            return

        net_path = Path(network_sequence_path)
        if not net_path.exists():
            return

        with open(net_path) as f:
            net_seq = json.load(f)

        sequence = net_seq.get("sequence", [])

        with open(self.flows_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    flow = json.loads(line)
                    relative_time = flow["timestamp"] - session_start_time
                    event = {
                        "type": "mitm",
                        "method": flow.get("method", ""),
                        "url": flow.get("url", ""),
                        "status_code": flow.get("status_code", 0),
                        "content_type": flow.get("content_type", ""),
                        "request_body_preview": flow.get("request_body_preview", ""),
                        "response_body_preview": flow.get("response_body_preview", ""),
                        "relative_time": relative_time,
                    }
                    sequence.append(event)
                except Exception:
                    continue

        sequence.sort(key=lambda e: e.get("relative_time", 0))
        net_seq["sequence"] = sequence

        with open(net_path, "w") as f:
            json.dump(net_seq, f, indent=2)
```

- [ ] **Step 4: Run all MITM controller tests**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/test_mitm_controller.py -v 2>&1
```

Expected: `5 passed`

- [ ] **Step 5: Commit**

```bash
cd /home/nietz/spyra && git add src/mitm_controller.py tests/test_mitm_controller.py && git commit -m "feat: add MITMController with lifecycle, proxy config, and flow merge"
```

---

## Task 5: Wire everything into `main.py`

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add imports at top of `main.py`**

After the existing imports (after line 16), add:

```python
from src.ui_exerciser import UIExerciser
from src.mitm_controller import MITMController
```

- [ ] **Step 2: Add CLI flags to the `ArgumentParser` in `main()`**

After the existing `--label-source` argument (around line 639), add:

```python
    parser.add_argument(
        "--exerciser",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run structured UI interaction profiles during capture (default: on).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Total capture duration in seconds (default: 120).",
    )
    parser.add_argument(
        "--mitm",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run mitmproxy HTTPS capture alongside Frida (default: on).",
    )
    parser.add_argument(
        "--mitm-port",
        type=int,
        default=8080,
        dest="mitm_port",
        help="Port for the mitmproxy listener (default: 8080).",
    )
```

- [ ] **Step 3: Add permission sweep before Frida loads and MITM start in `main()`**

Replace the block starting at `console.print("\n[bold][+] Running Frida script[/bold]")` (around line 695) with:

```python
    # Derive adb serial from the Frida device (may be None for USB default)
    adb_serial = getattr(device, 'id', None)
    if adb_serial and not adb_serial.startswith('emulator') and ':' not in adb_serial:
        adb_serial = None  # physical USB — serial not needed for single device

    # Permission sweep (sync, before Frida loads)
    if args.exerciser:
        console.print("\n[bold][+] Granting permissions[/bold]")
        exerciser = UIExerciser(package_name, duration=args.duration, adb_serial=adb_serial)
        exerciser.permission_sweep()
        console.print("[green]✓ Permission sweep complete[/green]")
    else:
        exerciser = None

    # MITM proxy setup (sync, before Frida loads)
    mitm = None
    if args.mitm:
        console.print("\n[bold][+] Starting MITM proxy[/bold]")
        # output_dir is determined inside run_frida_script; pass a temp path
        # and re-point after we know the real path
        mitm = MITMController(
            output_dir=str(Path("output") / package_name),
            adb_serial=adb_serial,
            port=args.mitm_port,
        )
        if mitm.is_available():
            ok = mitm.start()
            if ok:
                console.print(f"[green]✓ mitmdump running on port {args.mitm_port}[/green]")
            else:
                console.print("[yellow]mitmdump failed to start — MITM capture disabled[/yellow]")
                mitm = None
        else:
            console.print(
                "[yellow]mitmdump not found — install with: pip install mitmproxy. "
                "MITM capture disabled.[/yellow]"
            )
            mitm = None

    console.print("\n[bold][+] Running Frida script[/bold]")
    session_start_time = time.time()
    run_frida_script(
        device, package_name, js_file,
        apk_path=apk_path, apk_hash=apk_hash,
        label=args.label, label_source=args.label_source,
        exerciser=exerciser,
        duration=args.duration,
    )

    # MITM teardown and merge
    if mitm:
        console.print("\n[bold][+] Stopping MITM proxy[/bold]")
        mitm.stop()
        # Find the network_sequence file written by run_frida_script
        net_file = Path("output") / package_name / f"{package_name}_network_sequence.json"
        if net_file.exists():
            mitm.merge_into_network_sequence(str(net_file), session_start_time)
            console.print(f"[green]✓ MITM flows merged into {net_file.name}[/green]")
```

- [ ] **Step 4: Update `run_frida_script` signature to accept exerciser and duration**

Find the `def run_frida_script(` definition and update its signature and body:

Current signature (around line 375):
```python
def run_frida_script(device, package_name, js_file, apk_path=None, apk_hash=None, label=None, label_source=None):
```

New signature:
```python
def run_frida_script(device, package_name, js_file, apk_path=None, apk_hash=None,
                     label=None, label_source=None, exerciser=None, duration=120):
```

Then find the block after `device.resume(pid)` (inside the `if mode == "spawn":` check, around line 584) and add exerciser start:

```python
        if mode == "spawn":
            device.resume(pid)

        # Start UI exerciser after Frida resumes
        if exerciser:
            exerciser.start()
```

And update the `while True` sleep loop to respect `duration`:

```python
        try:
            deadline = time.time() + duration
            while time.time() < deadline:
                time.sleep(0.1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping capture...[/yellow]")
        finally:
            if exerciser:
                exerciser.stop()
            _save()
```

- [ ] **Step 5: Verify all files compile**

```bash
cd /home/nietz/spyra && python3 -m py_compile main.py src/ui_exerciser.py src/mitm_controller.py src/mitm_addon.py && echo "All OK"
```

Expected: `All OK`

- [ ] **Step 6: Run the full test suite**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/ -v 2>&1
```

Expected: All tests pass (including the 8 exerciser tests and 5 MITM controller tests and 4 addon tests).

- [ ] **Step 7: Commit**

```bash
cd /home/nietz/spyra && git add main.py && git commit -m "feat: wire UIExerciser and MITMController into main.py with --exerciser, --duration, --mitm, --mitm-port flags"
```

---

## Task 6: Smoke test and final verification

**Files:** none modified

- [ ] **Step 1: Verify help output shows all new flags**

```bash
cd /home/nietz/spyra && python3 main.py --help 2>&1
```

Expected output includes: `--exerciser`, `--no-exerciser`, `--duration`, `--mitm`, `--no-mitm`, `--mitm-port`

- [ ] **Step 2: Verify all Python files compile**

```bash
cd /home/nietz/spyra && python3 -m py_compile main.py src/ui_exerciser.py src/mitm_controller.py src/mitm_addon.py src/preprocessing.py src/framework_detector.py && echo "All OK"
```

Expected: `All OK`

- [ ] **Step 3: Run all tests**

```bash
cd /home/nietz/spyra && .venv/bin/python3 -m pytest tests/ -v 2>&1
```

Expected: 17+ tests pass, 0 failures.

- [ ] **Step 4: Final commit**

```bash
cd /home/nietz/spyra && git status
```

If any uncommitted changes remain, add and commit them:

```bash
cd /home/nietz/spyra && git add -A && git commit -m "chore: final verification pass for Issues #1 and #19"
```

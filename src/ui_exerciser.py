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
            self._adb("shell", "pm", "grant", self.package_name, perm)

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

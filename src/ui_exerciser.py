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


    def permission_sweep(self) -> None:
        """Grant all dangerous permissions before the app activates.
        (call it synchronously before Frida resumes the process) failures are silently ignored.
        """
        for perm in DANGEROUS_PERMISSIONS:
            self._adb("shell", "pm", "grant", self.package_name, perm)


    def _run_monkey_profile(self, duration_seconds: int = 60) -> None:
        """Run adb monkey with fixed seed and weighted event distribution."""
        n_events = max(1, duration_seconds * 1000 // 200) 
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


    def _run_focused_sweep(self) -> None:
        taps = [
            (540, 960),   # center
            (270, 480),   # top-left
            (810, 480),   # top-right
            (270, 1440),  # bottom-left
            (810, 1440),  # bottom-right
        ]
        for x, y in taps:
            if self._stop_event.is_set():
                return
            self._adb("shell", "input", "tap", str(x), str(y))
            time.sleep(0.3)

        # test dummy credentials
        self._adb("shell", "input", "text", "test@example.com")
        self._adb("shell", "input", "keyevent", "66")
        time.sleep(0.5)
        self._adb("shell", "input", "text", "Password123!")
        self._adb("shell", "input", "keyevent", "66")
        time.sleep(0.5)

        self._adb("shell", "input", "tap", "540", "960")
        time.sleep(1.0)

        # relauch
        self._adb("shell", "input", "keyevent", "4")
        time.sleep(0.5)
        self._adb("shell", "input", "keyevent", "3")
        time.sleep(5.0)

        self._adb(
            "shell", "am", "start",
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER",
            self.package_name,
        )
        time.sleep(2.0)

        self._adb("shell", "input", "tap", "540", "960")


    def _run(self) -> None:
        if self._stop_event.wait(timeout=2.0):
            return

        monkey_duration = min(60, max(10, self.duration - 40))
        self._run_monkey_profile(duration_seconds=monkey_duration)

        if self._stop_event.is_set():
            return

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

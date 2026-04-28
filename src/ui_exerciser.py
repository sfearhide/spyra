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

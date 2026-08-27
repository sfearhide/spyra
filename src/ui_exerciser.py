#!/usr/bin/env python3
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
        stim_mode: str = "seeded",
        stim_seed: int = 1337,
    ):
        self.package_name = package_name
        self.duration = duration
        self.adb_serial = adb_serial
        self.stim_mode = stim_mode
        self.stim_seed = stim_seed
        self.stimulator = None  # N9: populated in start() for seeded mode
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()


    def _adb(self, *args, timeout: int = 30) -> subprocess.CompletedProcess:
        if self.adb_serial:
            cmd = ["adb", "-s", self.adb_serial, *args]
        else:
            cmd = ["adb", *args]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0 and (result.stderr or "").strip():
                print(
                    f"[ui_exerciser] adb {' '.join(args[:3])} failed "
                    f"(rc={result.returncode}): {result.stderr.strip()[:200]}"
                )
            return result
        except Exception as e:
            print(f"[ui_exerciser] adb {' '.join(args[:3])} error: {e}")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))

    def _screen_size(self) -> tuple[int, int]:
        result = self._adb("shell", "wm", "size")
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if ":" in line and "x" in line:
                try:
                    w, h = line.split(":")[1].strip().split("x")
                    return int(w), int(h)
                except ValueError:
                    continue
        return (1080, 1920)

    def permission_sweep(self) -> None:
        for perm in DANGEROUS_PERMISSIONS:
            self._adb("shell", "pm", "grant", self.package_name, perm)

    def _run_monkey_profile(self, duration_seconds: int = 60) -> None:
        n_events = max(1, duration_seconds * 1000 // 200)
        result = self._adb(
            "shell", "monkey",
            "-p", self.package_name,
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
        if "Error" in (result.stdout or "") or result.returncode != 0:
            print(
                f"[ui_exerciser] monkey failed: "
                f"{(result.stdout or result.stderr).strip()[:200]}"
            )

    def _run_focused_sweep(self) -> None:
        w, h = self._screen_size()
        taps = [
            (w // 2, h // 2),          # center
            (w // 4, h // 4),          # top-left
            (3 * w // 4, h // 4),      # top-right
            (w // 4, 3 * h // 4),      # btm-left
            (3 * w // 4, 3 * h // 4),  # btm-right
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

        self._adb("shell", "input", "tap", str(w // 2), str(h // 2))
        time.sleep(1.0)

        # relaunch
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

        self._adb("shell", "input", "tap", str(w // 2), str(h // 2))


    def _run(self) -> None:
        if self._stop_event.wait(timeout=6.0):
            return

        if self.stim_mode == "seeded":
            from src.stimulation import SeededStimulator

            self.stimulator = SeededStimulator(
                self.package_name, duration=max(10, self.duration - 20),
                seed=self.stim_seed, adb_serial=self.adb_serial,
            )

            self.stimulator.start()
            self._stop_event.wait(timeout=max(10, self.duration - 20))
            if self.stimulator:
                self.stimulator.stop()
            return

        monkey_duration = min(60, max(10, self.duration - 40))
        self._run_monkey_profile(duration_seconds=monkey_duration)

        if self._stop_event.is_set():
            return

        self._run_focused_sweep()


    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="UIExerciser")
        self._thread.start()


    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

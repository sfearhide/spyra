#!/usr/bin/env python3
import random
import subprocess
import threading
import time
from typing import Optional


EVENT_KINDS = ("tap", "swipe", "text", "key")
VALID_KEYS = {"back": "4", "home": "3", "enter": "66"}


def build_schedule(seed: int, width: int, height: int,
                   duration_s: float, pace_ms: int = 400):
    rng = random.Random(seed)
    step = pace_ms / 1000.0
    n_events = max(0, int(duration_s / step))
    schedule = []
    t = 6.0
    for _ in range(n_events):
        if t >= duration_s - 1e-6:
            break

        kind = rng.choices(EVENT_KINDS, weights=(55, 20, 15, 10))[0]
        evt = {"at": round(t, 3), "kind": kind}

        if kind == "tap":
            evt["x"] = rng.randrange(width // 8, width * 7 // 8)
            evt["y"] = rng.randrange(height // 8, height * 7 // 8)
        elif kind == "swipe":
            x1 = rng.randrange(width // 8, width * 7 // 8)
            y1 = rng.randrange(height // 8, height * 7 // 8)
            evt.update(x1=x1, y1=y1,
                       x2=rng.randrange(width // 8, width * 7 // 8),
                       y2=rng.randrange(height // 8, height * 7 // 8))
        elif kind == "text":
            evt["text"] = rng.choice([
                "test@example.com", "Password123!", "hello", "4111111111111111"])
        else:
            evt["key"] = rng.choice(sorted(VALID_KEYS))

        schedule.append(evt)
        t += step
    return schedule


def adb_command(evt: dict) -> list:
    base = ["shell", "input"]
    if evt["kind"] == "tap":
        return base + ["tap", str(evt["x"]), str(evt["y"])]

    if evt["kind"] == "swipe":
        return base + ["swipe", str(evt["x1"]), str(evt["y1"]),
                       str(evt["x2"]), str(evt["y2"]), "200"]

    if evt["kind"] == "text":
        return base + ["text", evt["text"].replace(" ", "%s")]
    return base + ["keyevent", VALID_KEYS[evt["key"]]]


def parse_foreground_package(dumpsys_output: str):
    for line in dumpsys_output.splitlines():
        line = line.strip()
        for key in ("topResumedActivity", "mResumedActivity"):
            idx = line.find(key)
            if idx == -1:
                continue

            rest = line[idx + len(key):].lstrip("=: ")
            if not rest.startswith("ActivityRecord"):
                continue
            
            for token in rest.replace("{", " ").split():
                if "/" in token and token.endswith("}"):
                    token = token[:-1]
                if "/" in token and not token.startswith("u"):
                    return token.split("/", 1)[0]
    return None


class SeededStimulator:
    def __init__(self, package_name: str, duration: int, seed: int = 1337,
                 adb_serial: Optional[str] = None):
        self.package_name = package_name
        self.duration = duration
        self.seed = seed
        self.adb_serial = adb_serial
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.schedule = []
        self.excursions = 0

    def _adb(self, args, timeout=15):
        cmd = ["adb"] + (["-s", self.adb_serial] if self.adb_serial else []) + args
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        except Exception as e:
            print(f"[stim] adb error: {e}")

    def _screen_size(self):
        r = subprocess.run(
            ["adb"] + (["-s", self.adb_serial] if self.adb_serial else [])
            + ["shell", "wm", "size"],
            capture_output=True, text=True, timeout=15)

        for line in (r.stdout or "").splitlines():
            if ":" in line and "x" in line:
                try:
                    w, h = line.split(":")[1].strip().split("x")
                    return int(w), int(h)
                except ValueError:
                    continue
        return 1080, 1920

    def _foreground(self):
        r = subprocess.run(
            ["adb"] + (["-s", self.adb_serial] if self.adb_serial else [])
            + ["shell", "dumpsys", "activity", "activities"],
            capture_output=True, text=True, timeout=15)
        return parse_foreground_package(r.stdout or "")

    def _guardian_relaunch(self, fg):
        self.excursions += 1
        print(f"[stim] excursion #{self.excursions}: foreground={fg}, "
              f"relaunching {self.package_name}")

        self._adb(["shell", "am", "start", "-a",
                   "android.intent.action.MAIN", "-c",
                   "android.intent.category.LAUNCHER",
                   self.package_name])
        time.sleep(1.5)

    def _run(self):
        w, h = self._screen_size()
        self.schedule = build_schedule(self.seed, w, h, self.duration)
        start = time.time()
        last_guard = 0.0
        for evt in self.schedule:
            now = time.time() - start
            if now - last_guard >= 4.0:
                last_guard = now
                fg = self._foreground()

                if fg is not None and fg != self.package_name:
                    self._guardian_relaunch(fg)

            wait = evt["at"] - (time.time() - start)
            if self._stop.wait(timeout=max(0.0, wait)):
                return

            if evt["kind"] == "text":
                self._adb(adb_command({"at": 0, "kind": "tap",
                                       "x": w // 2, "y": h // 2}))
                time.sleep(0.15)
            self._adb(adb_command(evt))

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="SeededStimulator")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

#!/usr/bin/env python3
"""
MITM Controller for Spyra.

Manages the mitmdump subprocess lifecycle, device proxy configuration,
CA cert installation, and merges captured flows into network_sequence.json.
"""

import json
import os
import shutil
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

    def _adb(self, *args, timeout: int = 15) -> subprocess.CompletedProcess:
        if self.adb_serial:
            cmd = ["adb", "-s", self.adb_serial, *args]
        else:
            cmd = ["adb", *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    def _kill_stale_mitmdump(self) -> None:
        try:
            result = subprocess.run(
                ["lsof", "-ti", f"tcp:{self.port}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                for pid_str in result.stdout.strip().split("\n"):
                    pid_str = pid_str.strip()
                    if pid_str.isdigit():
                        import signal
                        try:
                            os.kill(int(pid_str), signal.SIGTERM)
                        except OSError:
                            pass
                time.sleep(0.5)
        except FileNotFoundError:
            try:
                subprocess.run(
                    ["fuser", "-k", f"{self.port}/tcp"],
                    capture_output=True, timeout=5,
                )
                time.sleep(0.5)
            except (FileNotFoundError, Exception):
                pass
        except Exception:
            pass

    def start(self) -> bool:
        if not self.is_available():
            return False
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._kill_stale_mitmdump()

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

        for _ in range(30):
            if self._proc.poll() is not None:
                break
            time.sleep(0.1)

        self._adb("shell", "settings", "put", "global", "http_proxy",
                  f"127.0.0.1:{self.port}")
        self._install_ca_cert()

        return self._proc.poll() is None

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        self._adb("shell", "settings", "delete", "global", "http_proxy")

    def _install_ca_cert(self) -> None:
        cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
        if not cert_path.exists():
            return
        result = self._adb("push", str(cert_path), "/sdcard/mitmproxy-ca.cer")
        if result.returncode != 0:
            return

        # system cert install
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

        self._adb("shell", "am", "start",
                  "-a", "android.credentials.INSTALL",
                  "--ei", "android.credentials.INSTALL.type", "1",
                  "-d", "file:///sdcard/mitmproxy-ca.cer")

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

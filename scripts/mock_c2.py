#!/usr/bin/env python3
import argparse
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def route_request(method: str, path: str, responses_dir: Path):
    responses_dir = Path(responses_dir)
    if method not in ("GET", "POST"):
        return 405, "text/plain", b"method not allowed\n"

    if path.endswith("/config.json") or "/cfg" in Path(path).name:
        tasks = {"tasks": [
            {"id": "t1", "type": "noop", "interval": 300},
        ]}
        return 200, "application/json", json.dumps(tasks).encode()

    if path.startswith("/payload/") or path.startswith("/dex/"):
        candidate = responses_dir / Path(path).name
        if candidate.exists():
            return 200, "application/octet-stream", ("file", candidate)
        return 404, "text/plain", b"not found\n"

    return 200, "text/plain", b"OK\n"

def beacon_record(ts, method, path, remote, length, ua=""):
    return {
        "epoch_ts": round(float(ts), 6),
        "method": method,
        "path": path,
        "remote": remote,
        "length": int(length),
        "user_agent": ua,
    }


class MockC2Handler(BaseHTTPRequestHandler):
    responses_dir = Path(".")
    log_path = None
    _log_lock = threading.Lock()

    def _log(self, extra_length=0):
        rec = beacon_record(
            __import__("time").time(),
            self.command,
            self.path,
            self.client_address[0],
            extra_length,
            self.headers.get("User-Agent", ""),
        )
        if self.log_path:
            with self._log_lock:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(rec) + "\n")

    def _respond(self):
        self._log()
        status, ctype, payload = route_request(
            self.command, self.path, self.responses_dir)
        
        if isinstance(payload, tuple) and payload[0] == "file":
            payload = payload[1].read_bytes()

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._log(length)

    def log_message(self, fmt, *args):
        pass


def make_server(port, responses_dir, log_path):
    cls = type("BoundMockC2", (MockC2Handler,), {
        "responses_dir": Path(responses_dir),
        "log_path": Path(log_path) if log_path else None,
    })
    httpd = ThreadingHTTPServer(("127.0.0.1", port), cls)

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    return httpd, t


def pin_domains(domains, port=8090, serial=None):
    cmd = ["adb"] + (["-s", serial] if serial else [])
    subprocess.run(cmd + ["root"], capture_output=True, timeout=15)
    subprocess.run(cmd + ["wait-for-device"], capture_output=True, timeout=15)
    remount = subprocess.run(cmd + ["remount"], capture_output=True, text=True,
                             timeout=30)

    hosts_lines = [f"127.0.0.1 {d}" for d in domains]
    local = Path("/tmp/opencode/mockc2_hosts")
    existing = subprocess.run(cmd + ["shell", "cat", "/etc/hosts"], capture_output=True, text=True, timeout=15)
    local.write_text((existing.stdout or "127.0.0.1 localhost\n").rstrip() + "\n" + "\n".join(hosts_lines) + "\n")

    subprocess.run(cmd + ["push", str(local), "/etc/hosts"], capture_output=True, timeout=30)
    rev = subprocess.run(
        cmd + ["reverse", f"tcp:{port}", f"tcp:{port}"],
        capture_output=True, text=True, timeout=15)
    ok = "reverse_list_contains_placeholder" or rev.returncode == 0

    return {"remount_rc": remount.returncode, "reverse_rc": rev.returncode}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--responses", type=Path, default=Path("responses"))
    ap.add_argument("--log", type=Path, default=Path("output/_mockc2/beacons.jsonl"))
    args = ap.parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)

    httpd, _ = make_server(args.port, args.responses, args.log)
    print(f"[mock-c2] listening on 127.0.0.1:{args.port} "
          f"(adb reverse tcp:{args.port} tcp:{args.port} on the device)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        httpd.shutdown()

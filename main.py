#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
import shutil
import json
import frida
import time
import hashlib
import argparse
import threading
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
from rich.console import Console
from urllib.parse import urlparse
from src.ui_exerciser import UIExerciser
from src.mitm_controller import MITMController
from src.schema import SCHEMA_VERSION


console = Console()


def check_dependencies():
    missing = []

    if not shutil.which("apktool"):
        missing.append("apktool")
    if not shutil.which("npx"):
        missing.append("npx (Node.js)")

    try:
        import frida
    except ImportError:
        missing.append("frida (pip install frida==17.2.17)")

    if missing:
        console.print("[red]✗ Missing dependencies:[/red]")
        for dep in missing:
            console.print(f"  • {dep}")
        console.print("\n[yellow]Install missing dependencies and try again[/yellow]")
        return False

    console.print("[green]✓ All dependencies installed[/green]")
    return True


def get_frida_device(serial=None):
    if serial:
        return frida.get_device_manager().get_device(serial, timeout=5)
    try:
        return frida.get_usb_device(timeout=3)
    except (frida.TimedOutError, frida.ServerNotRunningError, ValueError):
        for dev in frida.enumerate_devices():
            if dev.type not in ("local",):
                return dev
        raise


def check_frida_server(serial=None):
    try:
        device = get_frida_device(serial)
        console.print(f"[green]✓ Frida device connected: {device.name} ({device.id})[/green]")
        return device
    except frida.TimedOutError:
        console.print("[red]✗ No Frida device found[/red]")
        return None
    except frida.ServerNotRunningError:
        console.print("[red]✗ Frida server not running on device[/red]")
        return None
    except Exception as e:
        console.print(f"[red]✗ Frida connection error: {e}[/red]")
        return None


def decompile_apk(apk_path):
    apk_file = Path(apk_path)
    output_dir = Path("data") / f"{apk_file.stem}_decompiled"

    if output_dir.exists():
        console.print(f"[yellow]Removing old decompiled data...[/yellow]")
        shutil.rmtree(output_dir)

    output_dir.parent.mkdir(exist_ok=True)
    console.print(f"[cyan]Decompiling {apk_file.name}..[/cyan]")

    cmd = ["apktool", "d", "-f", str(apk_file), "-o", str(output_dir), "-q"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        console.print(f"[red]✗ Decompilation failed: {result.stderr}[/red]")
        return None

    console.print(f"[green]✓ Decompiled to {output_dir}[/green]")
    return output_dir


def detect_frameworks(decompiled_dir, bypass="all"):
    sys.path.insert(0, str(Path(__file__).parent / "src"))
    from framework_detector import FrameworkDetector, HookGenerator
    import xml.etree.ElementTree as ET

    console.print("[cyan]Detecting frameworks..[/cyan]")

    detector = FrameworkDetector(decompiled_dir)
    frameworks = detector.detect_all()

    if not frameworks:
        console.print("[yellow]No frameworks detected.[/yellow]")
        return None, None

    # show detected frameworks
    table = Table(title="Detected Frameworks", show_header=True)
    table.add_column("Framework", style="cyan")
    table.add_column("Confidence", style="green")

    for fw in frameworks:
        confidence_bar = "█" * int(fw.confidence * 10)
        table.add_row(fw.name, f"{confidence_bar} {fw.confidence:.0%}")

    console.print(table)

    # extract package name
    manifest = decompiled_dir / "AndroidManifest.xml"
    package_name = None
    if manifest.exists():
        try:
            tree = ET.parse(manifest)
            package_name = tree.getroot().get("package")
            console.print(f"[cyan]Package: {package_name}[/cyan]")
        except Exception:
            console.print("[yellow]Could not parse AndroidManifest.xml[/yellow]")

    console.print("[cyan]Generating hooks..[/cyan]")
    generator = HookGenerator(frameworks, bypass=bypass)
    script, is_typescript = generator.generate_hooks()

    hooks_dir = Path("src/hooks")
    hooks_dir.mkdir(parents=True, exist_ok=True)
    if is_typescript:
        script_file = hooks_dir / "generated_hooks.ts"
    else:
        script_file = hooks_dir / "generated_hooks.js"

    script_file.write_text(script)
    console.print(f"[green]✓ Generated {script_file.name}[/green]")

    return script_file, package_name


def compile_hooks(script_file):
    if script_file.suffix == ".js":
        console.print(
            f"[green]✓ Using {script_file.name} (no compilation needed)[/green]"
        )
        return script_file
    js_file = script_file.with_suffix(".js")

    cmd = ["frida-compile", str(script_file), "-o", str(js_file)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        console.print(f"[red]✗ Compilation failed: {result.stderr}[/red]")
        console.print(f"{str(script_file)}")
        return None

    console.print(f"[green]✓ Compiled to {js_file.name}[/green]")
    return js_file


def extract_domain(url):
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

AGENT_EVENT_TYPES = frozenset({
    "network", "http", "https", "okhttp", "socket", "ssl",
    "crypto", "file", "system", "native", "bypass", "exec",
    "api", "scan", "hook", "react_native", "flutter", "unity",
    "prefs", "webview", "intent", "stalker", "dex_dump",
})


def compute_coverage(agent_stats):
    events = agent_stats.get("events") or {}
    hooks = agent_stats.get("hooks") or {}
    events_by_type = {t: c for t, c in events.items() if isinstance(c, int)}

    fired_detail = {
        k: v for k, v in hooks.items()
        if k.startswith("fired:") and isinstance(v, int)
    }

    installed = sum(
        v for k, v in hooks.items()
        if not k.startswith("fired:") and isinstance(v, int)
    )

    fired = sorted(t for t in AGENT_EVENT_TYPES if events_by_type.get(t, 0) > 0)
    return {
        "hooks_installed": installed,
        "hooks_fired": len(fired_detail),
        "hooks_fired_detail": fired_detail,
        "events_by_type": events_by_type,
        "event_types_fired": fired,
        "coverage_ratio": round(len(fired) / len(AGENT_EVENT_TYPES), 3),
    }


def epoch_seconds_from_payload(payload):
    ts = payload.get("timestamp")
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return time.time()
    if ts > 1e11:  # epoch ms
        return ts / 1000.0
    return ts


def write_logcat_lines(lines, out_path, predicates):
    kept = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for line in lines:
            line = line.rstrip("\n")

            if not any(p(line) for p in predicates):
                continue

            parts = line.split(" ", 2)
            epoch_ts = None
            if len(parts) >= 2:
                try:
                    epoch_ts = float(parts[0])
                except ValueError:
                    pass

            f.write(json.dumps({
                "epoch_ts": epoch_ts,
                "message": line,
            }) + "\n")
            kept += 1
    return kept


def collect_logcat(package_name, adb_serial, out_file):
    cmd = ["adb"]
    if adb_serial:
        cmd += ["-s", adb_serial]

    cmd += ["logcat", "-d", "-v", "epoch"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=20,
            text=True, encoding="utf-8", errors="replace",
        )
    except Exception as e:
        console.print(f"[yellow]logcat collection failed: {e}[/yellow]")
        return False

    lines = (result.stdout or "").splitlines()

    def _match(ln):
        return package_name in ln or "ANR in" in ln or "FATAL EXCEPTION" in ln

    kept = write_logcat_lines(
        lines, out_file,
        predicates=[
            lambda ln: package_name in ln,
            lambda ln: "FATAL EXCEPTION" in ln,
        ],
    )
    console.print(f"[green]✓ Saved logcat artifact: {out_file} ({kept} lines)[/green]")
    return True


def compute_apk_hash(apk_path):
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_sequences(package_name, api_seq, net_seq, start_time, apk_hash=None, label=None, label_source=None, termination_attempts=0, clock_anchor=None, capture_errors=0, extra_meta=None):
    output_dir = Path("output") / package_name
    output_dir.mkdir(parents=True, exist_ok=True)

    end_time = time.time()
    duration = end_time - start_time if start_time else 0

    start_iso = datetime.fromtimestamp(start_time).isoformat() if start_time else None
    end_iso = datetime.fromtimestamp(end_time).isoformat()

    base_metadata = {
        "package_name": package_name,
        "schema_version": SCHEMA_VERSION,
        "apk_sha256": apk_hash,
        "label": label or "unlabeled",
        "label_source": label_source,
        "capture_start": start_iso,
        "capture_end": end_iso,
        "duration_seconds": round(duration, 3),
        "termination_attempts": termination_attempts,
        "clock_anchor_epoch": round(clock_anchor, 6) if clock_anchor else None,
        # script errors and flush/detach failures counter
        "capture_errors": capture_errors,
        **(extra_meta or {}),
    }

    api_data = {
        "metadata": {
            **base_metadata,
            "total_calls": len(api_seq),
        },
        "sequence": api_seq,
    }

    api_file = output_dir / f"{package_name}_api_sequence.json"
    with open(api_file, "w") as f:
        json.dump(api_data, f, indent=2, default=str)
    console.print(f"[green]✓ Saved API sequence: {api_file}[/green]")

    unique_domains = list(
        set(extract_domain(e.get("url", "")) for e in net_seq if e.get("url"))
    )
    unique_domains = [d for d in unique_domains if d]  # rmv empty strings

    net_data = {
        "metadata": {
            **base_metadata,
            "total_requests": len(net_seq),
            "unique_domains": unique_domains,
        },
        "sequence": net_seq,
    }

    net_file = output_dir / f"{package_name}_network_sequence.json"
    with open(net_file, "w") as f:
        json.dump(net_data, f, indent=2, default=str)
    console.print(f"[green]✓ Saved network sequence: {net_file}[/green]")


def is_app_installed(device, package_name):
    try:
        for app in device.enumerate_applications():
            if app.identifier == package_name:
                return True
        return False
    except Exception:
        return False


def install_apk(device, apk_path):
    console.print(f"[cyan]Installing {Path(apk_path).name} on device...[/cyan]")
    result = subprocess.run(
        ["adb", "install", "-r", "-g", str(apk_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode == 0 and "Success" in result.stdout:
        console.print("[green]APK installed successfully[/green]")
        return True
    else:
        err = result.stderr.strip() or result.stdout.strip()
        console.print(f"[red]APK install failed: {err}[/red]")
        return False


def kill_app(package_name):
    """force-stop the app via adb so spawn starts fresh."""
    subprocess.run(
        ["adb", "shell", "am", "force-stop", package_name],
        capture_output=True,
        timeout=10,
    )
    time.sleep(0.5)


def uninstall_app(package_name, adb_serial=None):
    """remove app + data so each capture starts from clean state."""
    cmd = ["adb"]
    if adb_serial:
        cmd += ["-s", adb_serial]
    cmd += ["uninstall", package_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    ok = "Success" in (result.stdout or "")
    if ok:
        console.print(f"[green]✓ Removed previous install of {package_name}[/green]")
    return ok


def launch_app(device, package_name, apk_path=None, max_retries=3):
    last_error = None

    if not is_app_installed(device, package_name):
        console.print(f"[yellow]Package {package_name} not found on device[/yellow]")
        if apk_path and Path(apk_path).exists():
            if not install_apk(device, apk_path):
                raise RuntimeError(
                    f"Cannot install {apk_path} -- install manually and retry"
                )
            time.sleep(2)  # let the system register the package
        else:
            raise RuntimeError(
                f"Package {package_name} is not installed on the device.\n"
                "Install it with: adb install <apk_file>"
            )

    for attempt in range(1, max_retries + 1):
        try:
            console.print(
                f"[cyan]Spawning {package_name} (attempt {attempt}/{max_retries})...[/cyan]"
            )
            kill_app(package_name)

            pid = device.spawn([package_name])
            session = device.attach(pid)
            console.print(f"[green]Spawned PID {pid}[/green]")
            return session, pid, "spawn"
        except frida.TimedOutError as e:
            last_error = e
            console.print(f"[yellow]Spawn attempt {attempt} timed out[/yellow]")
            time.sleep(2)
        except frida.ProcessNotFoundError as e:
            last_error = e
            console.print(
                f"[yellow]Spawn attempt {attempt}: process not found[/yellow]"
            )
            time.sleep(2)
        except frida.TransportError as e:
            last_error = e
            console.print(
                f"[yellow]Spawn attempt {attempt}: transport error ({e})[/yellow]"
            )
            time.sleep(2)
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if "timed out" in err_str:
                console.print(
                    f"[yellow]Spawn attempt {attempt} timed out: {e}[/yellow]"
                )
                time.sleep(2)
            else:
                console.print(f"[yellow]Spawn attempt {attempt} failed: {e}[/yellow]")
                break

    console.print("[cyan]Spawn failed. Trying launch via adb + attach...[/cyan]")
    kill_app(package_name)
    time.sleep(1)

    subprocess.run(
        [
            "adb",
            "shell",
            "monkey",
            "-p",
            package_name,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        capture_output=True,
        timeout=15,
    )
    time.sleep(3)
    for wait in range(10):
        try:
            pid = device.get_process(package_name).pid
            session = device.attach(pid)
            console.print(f"[green]Attached to running process PID {pid}[/green]")
            return session, pid, "attach"
        except frida.ProcessNotFoundError:
            if wait < 9:
                time.sleep(1)
            continue
        except Exception as e:
            last_error = e
            break

    raise RuntimeError(
        f"All launch strategies failed for {package_name}.\n"
        f"Last error: {last_error}\n"
        "Troubleshooting:\n"
        "  1. Is the APK installed?  adb shell pm list packages | grep <name>\n"
        "  2. Is frida-server running?  adb shell ps | grep frida\n"
        "  3. Architecture match?  frida-server must match device (arm/arm64/x86)\n"
        "  4. Try manually:  frida -U -f <package> --no-pause"
    )


def run_frida_script(device, package_name, js_file, apk_path=None, apk_hash=None, label=None, label_source=None, exerciser=None, duration=120, extra_meta=None):
    api_sequence = []
    network_sequence = []
    start_time = None
    _t0_epoch = None
    net_seq_num = 0
    _saved = False
    _termination_attempts = 0
    _capture_errors = 0
    _agent_stats: dict = {}

    def _save():
        nonlocal start_time, _saved
        if _saved:
            return
        _saved = True
        if start_time is None and (api_sequence or network_sequence):
            start_time = time.time()
        if api_sequence or network_sequence:
            meta = {"agent": compute_coverage(_agent_stats)}
            if extra_meta:
                meta.update(extra_meta)
            save_sequences(package_name, api_sequence, network_sequence, start_time,
                           apk_hash=apk_hash, label=label, label_source=label_source,
                           termination_attempts=_termination_attempts,
                           clock_anchor=_t0_epoch,
                           capture_errors=_capture_errors,
                           extra_meta=meta)
        else:
            console.print("[yellow]No data captured to save.[/yellow]")

    _session_dead = threading.Event()

    try:
        session, pid, mode = launch_app(device, package_name, apk_path)

        def on_detached(reason, crash):
            console.print(f"\n[yellow]Session detached: {reason}[/yellow]")
            if crash:
                console.print(f"[red]Crash report: {crash}[/red]")
            _session_dead.set()  # break the monitoring loop immediately

        session.on("detached", on_detached)
        with open(js_file) as f:
            script_code = f.read()
        script = session.create_script(script_code)

        def on_message(message, data, pid_label=None):
            nonlocal start_time, api_seq_num, net_seq_num, _termination_attempts, _t0_epoch, _capture_errors
            if message["type"] == "error":
                _capture_errors += 1
                console.print(
                    f"[red][ERROR][/red] {message.get('description', message)}"
                )
                return
            if message["type"] == "send":
                payload = message.get("payload", {})
                if not isinstance(payload, dict):
                    return
                # unwrap batched events sent by bufferedSend() in the JS agent
                if payload.get("type") == "batch":
                    for evt in payload.get("events", []):
                        on_message({"type": "send", "payload": evt}, data)
                    return
                msg_type = payload.get("type", "unknown")

                # dropped dex payloads as frida binary data
                if msg_type == "dex_dump" and data:
                    dropped_dir = Path("output") / package_name / "dropped"
                    dropped_dir.mkdir(parents=True, exist_ok=True)

                    digest = hashlib.sha256(data).hexdigest()

                    out_path = dropped_dir / f"{digest}.dex"
                    out_path.write_bytes(bytes(data))

                    console.print(
                        f"[bold red][DROPPED][/bold red] {payload.get('path','?')} "
                        f"-> dropped/{digest}.dex ({len(data)} bytes)"
                    )

                epoch_s = epoch_seconds_from_payload(payload)
                if _t0_epoch is None:
                    _t0_epoch = epoch_s
                if start_time is None:
                    start_time = time.time()

                clean_payload = {k: v for k, v in payload.items() if k != "timestamp"}
                event = {
                    "pid": pid_label if pid_label is not None else pid,
                    "timestamp": round(epoch_s, 6),
                    "relative_time": round(epoch_s - _t0_epoch, 3),
                    **clean_payload,
                }

                # categorize and add to seqs
                network_types = ["network", "http", "https", "okhttp", "socket", "ssl"]
                if msg_type in network_types:
                    net_seq_num += 1
                    event["seq"] = net_seq_num
                    network_sequence.append(event)
                else:
                    api_seq_num += 1
                    event["seq"] = api_seq_num
                    api_sequence.append(event)

                if msg_type == "network":
                    action = payload.get("action", "")
                    if action == "connect":
                        ip = payload.get("ip", "")
                        port = payload.get("port", "")
                        console.print(f"[blue][NETWORK][/blue] Connect to {ip}:{port}")
                    elif action in ["send", "recv", "sendto", "recvfrom"]:
                        pass
                    elif action == "dlopen":
                        lib = payload.get("library", "")
                        console.print(f"[blue][DLOPEN][/blue] {lib}")
                    elif action == "suspicious_lib":
                        path = payload.get("path", "")
                        console.print(
                            f"[bold red][!!! SUSPICIOUS LIB][/bold red] {path}"
                        )
                    else:
                        url = payload.get("url", "")
                        method = payload.get("method", "")
                        if url:
                            console.print(f"[blue][NETWORK][/blue] {method} {url}")

                elif msg_type == "crypto":
                    action = payload.get("action", "")
                    algo = payload.get("transformation") or payload.get("algorithm", "")
                    if algo:
                        console.print(f"[yellow][CRYPTO][/yellow] {action}: {algo}")
                    else:
                        console.print(f"[yellow][CRYPTO][/yellow] {action}")

                elif msg_type == "file":
                    path = payload.get("path", "")
                    action = payload.get("action", "")
                    console.print(f"[green][FILE][/green] {action}: {path}")

                elif msg_type == "system":
                    action = payload.get("action", "")
                    value = payload.get("value", "")
                    console.print(f"[red][SYSTEM][/red] {action} {value}")

                elif msg_type == "native":
                    action = payload.get("action", "")
                    if action == "jni_register":
                        count = payload.get("count", 0)
                        console.print(
                            f"[magenta][JNI][/magenta] RegisterNatives count={count}"
                        )
                    elif action == "jni_method_map":
                        method = payload.get("method", "")
                        sig = payload.get("sig", "")
                        ptr = payload.get("ptr", "")
                        console.print(
                            f"[magenta][JNI][/magenta] Map {method}{sig} -> {ptr}"
                        )
                    elif action == "dlopen":
                        lib = payload.get("library", "")
                        console.print(f"[magenta][DLOPEN][/magenta] Loaded: {lib}")
                    elif action == "suspicious_lib":
                        path = payload.get("path", "")
                        console.print(
                            f"[bold red][!!! SUSPICIOUS][/bold red] Library: {path}"
                        )
                    else:
                        func = payload.get("func", "")
                        path = payload.get("path", "")
                        if path:
                            console.print(
                                f'[magenta][NATIVE][/magenta] {func}("{path}")'
                            )

                elif msg_type == "ssl":
                    func = payload.get("func", "")
                    console.print(f"[cyan][SSL][/cyan] {func}")

                elif msg_type == "bypass":
                    action = payload.get("action", "")
                    detail = (
                        payload.get("path", "")
                        or payload.get("host", "")
                        or payload.get("command", "")
                        or payload.get("func", "")
                    )
                    exit_code = payload.get("exit_code")
                    if exit_code is not None:
                        detail = f"code={exit_code}"
                    
                    pid_val = payload.get("pid")
                    if pid_val is not None and not detail:
                        detail = f"pid={pid_val}"

                    termination_actions = (
                        "system_exit", "runtime_exit", "kill_self",
                        "native_exit", "activity_finish",
                        "activity_finish_remove", "activity_finish_affinity",
                    )
                    if action in termination_actions:
                        _termination_attempts += 1
                        console.print(
                            f"[bold red][BYPASS][/bold red] {action} {detail}"
                        )
                    else:
                        console.print(
                            f"[bold yellow][BYPASS][/bold yellow] {action}: {detail}"
                        )

                elif msg_type == "exec":
                    cmd = payload.get("command", "")
                    console.print(f"[bold red][EXEC][/bold red] {cmd}")

                elif msg_type == "api":
                    action = payload.get("action", "")
                    if action == "sms_send":
                        dest = payload.get("dest", "")
                        console.print(f"[bold red][SMS][/bold red] -> {dest}")
                    elif action in (
                        "dex_load",
                        "inmemory_dex_load",
                        "path_classloader",
                    ):
                        path = payload.get("path", "in-memory")
                        console.print(f"[bold red][DEX LOAD][/bold red] {path}")
                    elif action == "class_forname":
                        cn = payload.get("className", "")
                        console.print(f"[yellow][REFLECT][/yellow] Class.forName({cn})")
                    elif action in (
                        "camera_open",
                        "audio_record",
                        "clipboard_read",
                        "get_accounts",
                    ):
                        console.print(f"[red][SENSITIVE API][/red] {action}")
                    else:
                        console.print(f"[red][API][/red] {action}")

                elif msg_type == "scan":
                    action = payload.get("action", "")
                    cn = payload.get("className", "")
                    method = payload.get("method", "")
                    console.print(f"[yellow][SCAN][/yellow] {action}: {cn}.{method}")

                elif msg_type == "hook":
                    cn = payload.get("className", "")
                    console.print(f"[green][HOOK][/green] Deferred hook: {cn}")

                elif msg_type == "react_native":
                    action = payload.get("action", "")
                    module = payload.get("module", "")
                    console.print(f"[cyan][RN][/cyan] {action}: {module}")

                elif msg_type == "flutter":
                    action = payload.get("action", "")
                    method = payload.get("method", "")
                    console.print(f"[cyan][FLUTTER][/cyan] {action}: {method}")

                elif msg_type == "unity":
                    action = payload.get("action", "")
                    console.print(f"[cyan][UNITY][/cyan] {action}")

                elif msg_type == "prefs":
                    key = payload.get("key", "")
                    value = payload.get("value", "")
                    console.print(f"[green][PREFS][/green] {key} = {value}")

                elif msg_type == "webview":
                    url = payload.get("url", "")
                    console.print(f"[blue][WEBVIEW][/blue] {url}")

                elif msg_type == "intent":
                    action = payload.get("intent_action", "")
                    console.print(f"[yellow][INTENT][/yellow] {action}")

                elif msg_type == "stalker":
                    action = payload.get("action", "")
                    count = payload.get("count", 0)
                    if action == "call_graph":
                        console.print(f"[dim][STALKER][/dim] Native call graph: {count} events")

        script.on("message", on_message)
        script.load()

        # isolated child processes
        try:
            session.enable_child_gating()

            def on_child_added(child):
                nonlocal _capture_errors
                try:
                    child_session = device.attach(child.pid)
                    child_script = child_session.create_script(script_code)
                    child_script.on(
                        "message",
                        lambda m, d, cp=child.pid: on_message(m, d, pid_label=cp),
                    )
                    child_script.load()
                    device.resume(child.pid)
                    console.print(f"[green]Child process {child.pid} instrumented[/green]")
                except Exception as e:
                    _capture_errors += 1
                    console.print(f"[yellow]Child gating failed: {e}[/yellow]")

            device.on("child-added", on_child_added)
        except Exception as e:
            console.print(f"[yellow]Child gating unavailable: {e}[/yellow]")

        if mode == "spawn":
            device.resume(pid)

        console.print(f"[green]Frida script loaded ({mode} mode, PID {pid})[/green]")

        TIMEOUT_SPAWN = 8.0
        if mode == "spawn" and _session_dead.wait(timeout=TIMEOUT_SPAWN):
            total_events = len(api_sequence) + len(network_sequence)
            if total_events == 0:
                console.print(
                    "\n[bold yellow]Process died immediately after spawn with 0 events.[/bold yellow]\n"
                    "[cyan]Retrying with attach mode (launch via adb, then inject)...[/cyan]"
                )

                _session_dead.clear()
                _saved = False
                api_sequence.clear()
                network_sequence.clear()
                api_seq_num = 0
                net_seq_num = 0
                start_time = None
                _t0_epoch = None
                _termination_attempts = 0

                kill_app(package_name)
                time.sleep(1)

                subprocess.run(
                    ["adb", "shell", "monkey", "-p", package_name,
                     "-c", "android.intent.category.LAUNCHER", "1"],
                    capture_output=True, timeout=15,
                )
                time.sleep(3)

                retry_pid = None
                for _w in range(10):
                    try:
                        retry_pid = device.get_process(package_name).pid
                        break
                    except frida.ProcessNotFoundError:
                        time.sleep(1)

                if retry_pid is None:
                    console.print("[red]Attach retry failed: process not running.[/red]")
                    _save()
                    console.print("[green]Session ended[/green]")
                    return

                session = device.attach(retry_pid)
                pid = retry_pid
                mode = "attach"

                session.on("detached", on_detached)
                script = session.create_script(script_code)
                script.on("message", on_message)
                script.load()
                console.print(f"[green]Attached to running process PID {pid} (attach retry)[/green]")

        console.print(
            f"[yellow]Monitoring app activity for {duration}s.. (Press Ctrl+C to stop early)[/yellow]\n"
        )

        if exerciser is not None:
            exerciser.start()

        _force_exit = threading.Event()

        def _sigint_force(signum, frame):
            console.print("\n[red]Forced exit (second Ctrl+C)[/red]")
            _force_exit.set()
            threading.Timer(2.0, lambda: os._exit(1)).start()

        try:
            deadline = time.time() + duration
            while time.time() < deadline:
                if _session_dead.is_set():
                    console.print(
                        f"\n[yellow]Target process terminated early. "
                        f"Captured {len(api_sequence)} API + {len(network_sequence)} network events so far.[/yellow]"
                    )
                    break
                time.sleep(0.1)
            else:
                console.print(f"\n[yellow]Duration ({duration}s) reached. Stopping capture...[/yellow]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping capture... (press Ctrl+C again to force quit)[/yellow]")
            # force-exit handler (Ctrl+C)
            signal.signal(signal.SIGINT, _sigint_force)
        finally:
            if exerciser is not None:
                exerciser.stop()

            def _flush():
                try:
                    script.exports_sync.flush_buffers()
                except Exception:
                    pass
            ft = threading.Thread(target=_flush, daemon=True)
            ft.start()
            ft.join(timeout=2.0)

            # pull agent coverage stats before detaching
            _stats_result: dict = {}
            def _fetch_stats():
                try:
                    got = script.exports_sync.get_stats()
                    if isinstance(got, dict):
                        _stats_result.update(got)
                except Exception:
                    pass
            st = threading.Thread(target=_fetch_stats, daemon=True)
            st.start()
            st.join(timeout=2.0)
            if _stats_result:
                _agent_stats.update(_stats_result)

            try:
                grace_deadline = time.time() + 1.0
                while time.time() < grace_deadline and not _force_exit.is_set():
                    time.sleep(0.05)
            except Exception:
                pass

            _save()

            # detach with a timeout
            def _detach():
                try:
                    script.exports_sync.dispose()
                except Exception:
                    pass
                try:
                    session.detach()
                except Exception:
                    pass

            detach_thread = threading.Thread(target=_detach, daemon=True)
            detach_thread.start()
            detach_thread.join(timeout=5.0)
            if detach_thread.is_alive():
                console.print("[yellow]Detach timed out (5s) — forcing exit[/yellow]")
            console.print("[green]Session ended[/green]")

    except frida.ProcessNotFoundError:
        console.print(f"[red]App not found: {package_name}[/red]")
        _save()
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        _save()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        _save()


def main():
    parser = argparse.ArgumentParser(
        description="Spyra — Android Malware Behavior Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 main.py sample.apk\n"
               "  python3 main.py sample.apk --label malware --label-source virustotal\n"
               "  python3 main.py sample.apk --label benign --label-source manual\n",
    )
    parser.add_argument("apk_file", help="Path to the APK file to analyze")
    parser.add_argument(
        "--label",
        default=None,
        help="Ground-truth label for LSTM training (e.g., 'malware', 'benign', "
             "or malware family name like 'banker.anubis'). "
             "If omitted, saved as 'unlabeled'.",
    )
    parser.add_argument(
        "--label-source",
        default=None,
        dest="label_source",
        help="Source of the ground-truth label (e.g., 'virustotal', 'malwarebazaar', "
             "'androzoo', 'manual').",
    )
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
    parser.add_argument(
        "--fresh-install",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Uninstall any previous copy of the target before capture, so "
             "every run starts from clean app state (default: on).",
    )
    parser.add_argument(
        "--serial",
        type=str,
        default=None,
        help="Frida/adb device serial (e.g. emulator-5554, 192.168.56.102:5555). "
             "Defaults to first USB/remote device.",
    )
    parser.add_argument(
        "--stim",
        choices=["seeded", "monkey"],
        default="seeded",
        dest="stim",
        help="Stimulation driver (N9): 'seeded' = deterministic schedule "
             "(reproducible captures, see --stim-seed); 'monkey' = legacy "
             "adb monkey (non-deterministic).",
    )
    parser.add_argument(
        "--stim-seed",
        type=int,
        default=1337,
        dest="stim_seed",
        help="Seed for the seeded stimulation driver (default: 1337).",
    )
    parser.add_argument(
        "--bypass",
        choices=["all", "minimal", "none"],
        default="all",
        dest="bypass",
        help="Countermeasure tier injected into the target (N3): 'all' = "
             "exit-blocking + detection bypass + env spoofing; 'minimal' = "
             "env spoofing only; 'none' = observation only. Recorded in "
             "capture metadata for ablation (default: all).",
    )

    args = parser.parse_args()

    banner = (
        "[dim]██████╗ ██████╗ ██╗ ▄ ██╗██████╗ [/dim][bold green]  ▀▄  ▄▀ [/bold green]\n"
        "[dim]██╔════╝ ██╔══██╗╚██╗███╔╝██╔══██╗[/dim][bold green]▄██████▄[/bold green]\n"
        "[dim]███████╗ ██████╔╝ ╚████╔╝ ██████╔╝[/dim][bold green]███████║[/bold green]\n"
        "[dim]╚════██║ ██╔═══╝   ╚██╔╝  ██╔══██╗[/dim][bold green]██╔══██║[/bold green]\n"
        "[dim]███████║ ██║        ██║   ██║  ██║[/dim][bold green]██║  ██║[/bold green]\n"
        "[dim]╚══════╝ ╚═╝        ╚═╝   ╚═╝  ╚═╝[/dim][bold green]╚═╝  ╚═╝[/bold green]\n\n"
        "  [bold white]> SPYRA (v1.2) · [/bold white][italic dim]Android Dynamic Analysis & Behavioral Modeling[/italic dim]\n"
    )
    console.print(banner)

    apk_path = args.apk_file

    if not Path(apk_path).exists():
        console.print(f"[red]✗ APK file not found: {apk_path}[/red]")
        sys.exit(1)

    console.print("\n[bold][+] Checking dependencies[/bold]")
    if not check_dependencies():
        sys.exit(1)

    console.print("\n[bold][+] Checking Frida server[/bold]")
    device = check_frida_server(args.serial)
    if not device:
        sys.exit(1)

    console.print("\n[bold][+] Decompiling APK[/bold]")
    decompiled_dir = decompile_apk(apk_path)
    if not decompiled_dir:
        sys.exit(1)

    console.print("\n[bold][+] Detecting frameworks[/bold]")
    script_file, package_name = detect_frameworks(decompiled_dir, bypass=args.bypass)
    if not script_file:
        sys.exit(1)

    if not package_name:
        console.print("[yellow]Package name not found in manifest[/yellow]")
        package_name = input("Enter package name manually: ").strip()
        if not package_name:
            console.print("[red]✗ Package name required[/red]")
            sys.exit(1)

    console.print("\n[bold][+] Compiling hooks[/bold]")
    js_file = compile_hooks(script_file)
    if not js_file:
        sys.exit(1)

    console.print("\n[bold][+] Computing APK hash[/bold]")
    apk_hash = compute_apk_hash(apk_path)
    console.print(f"[green]✓ SHA256: {apk_hash}[/green]")

    if args.label:
        console.print(f"[green]✓ Label: {args.label} (source: {args.label_source or 'unspecified'})[/green]")

    adb_serial = args.serial or getattr(device, "id", None)
    if adb_serial == "local":
        adb_serial = None

    if args.fresh_install:
        console.print("\n[bold][+] Fresh-state reset[/bold]")
        uninstall_app(package_name, adb_serial)

    if args.exerciser:
        console.print("\n[bold][+] Granting permissions[/bold]")
        exerciser = UIExerciser(package_name, duration=args.duration,
                                adb_serial=adb_serial,
                                stim_mode=args.stim,
                                stim_seed=args.stim_seed)
        exerciser.permission_sweep()
        console.print("[green]✓ Permission sweep complete[/green]")
    else:
        exerciser = None

    mitm = None
    if args.mitm:
        console.print("\n[bold][+] Starting MITM proxy[/bold]")
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
    try:
        run_frida_script(
            device, package_name, js_file,
            apk_path=apk_path, apk_hash=apk_hash,
            label=args.label, label_source=args.label_source,
            exerciser=exerciser,
            duration=args.duration,
            extra_meta={"bypass_tier": args.bypass},
        )
    finally:
        # always stop mitm — even on crash/SIGTERM — so the port is freed
        if mitm:
            console.print("\n[bold][+] Stopping MITM proxy[/bold]")
            mitm.stop()

            net_file = Path("output") / package_name / f"{package_name}_network_sequence.json"
            if net_file.exists():
                mitm.merge_into_network_sequence(str(net_file), session_start_time)
                console.print(f"[green]✓ MITM flows merged into {net_file.name}[/green]")

        logcat_file = Path("output") / package_name / f"{package_name}_logcat.jsonl"
        logcat_file.parent.mkdir(parents=True, exist_ok=True)
        collect_logcat(package_name, adb_serial, str(logcat_file))


if __name__ == "__main__":
    main()

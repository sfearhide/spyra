#!/usr/bin/env python3
import sys
import subprocess
import shutil
import json
import frida
import time
import hashlib
import argparse
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from datetime import datetime
from rich.console import Console
from urllib.parse import urlparse
from rich.progress import Progress, SpinnerColumn, TextColumn
from src.ui_exerciser import UIExerciser
from src.mitm_controller import MITMController


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


def check_frida_server():
    try:
        device = frida.get_usb_device(timeout=3)
        console.print(f"[green]✓ Frida server connected: {device.name}[/green]")
        return device
    except frida.TimedOutError:
        console.print("[red]✗ No USB device found[/red]")
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


def detect_frameworks(decompiled_dir):
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
    generator = HookGenerator(frameworks)
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


def compute_apk_hash(apk_path):
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_sequences(package_name, api_seq, net_seq, start_time, apk_hash=None, label=None, label_source=None):
    output_dir = Path("output") / package_name
    output_dir.mkdir(parents=True, exist_ok=True)

    end_time = time.time()
    duration = end_time - start_time if start_time else 0

    start_iso = datetime.fromtimestamp(start_time).isoformat() if start_time else None
    end_iso = datetime.fromtimestamp(end_time).isoformat()

    base_metadata = {
        "package_name": package_name,
        "apk_sha256": apk_hash,
        "label": label or "unlabeled",
        "label_source": label_source,
        "capture_start": start_iso,
        "capture_end": end_iso,
        "duration_seconds": round(duration, 3),
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
    """Check if the APK is actually installed on the device."""
    try:
        # device.enumerate_applications() returns installed apps
        for app in device.enumerate_applications():
            if app.identifier == package_name:
                return True
        return False
    except Exception:
        return False


def install_apk(device, apk_path):
    # via adb
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


def run_frida_script(device, package_name, js_file, apk_path=None, apk_hash=None, label=None, label_source=None):
    api_sequence = []
    network_sequence = []
    start_time = None
    api_seq_num = 0
    net_seq_num = 0

    def _save():
        """Save captured sequences - called on any exit path."""
        nonlocal start_time
        if start_time is None and (api_sequence or network_sequence):
            start_time = time.time()
        if api_sequence or network_sequence:
            save_sequences(package_name, api_sequence, network_sequence, start_time,
                           apk_hash=apk_hash, label=label, label_source=label_source)
        else:
            console.print("[yellow]No data captured to save.[/yellow]")

    try:
        session, pid, mode = launch_app(device, package_name, apk_path)

        def on_detached(reason, crash):
            console.print(f"\n[yellow]Session detached: {reason}[/yellow]")
            if crash:
                console.print(f"[red]Crash report: {crash}[/red]")
            _save()

        session.on("detached", on_detached)
        with open(js_file) as f:
            script_code = f.read()
        script = session.create_script(script_code)

        def on_message(message, data):
            nonlocal start_time, api_seq_num, net_seq_num
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
                if start_time is None:
                    start_time = time.time()
                current_time = time.time()

                event = {
                    "timestamp": current_time,
                    "relative_time": round(current_time - start_time, 3),
                    **payload,
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
                    )
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
            elif message["type"] == "error":
                console.print(
                    f"[red][ERROR][/red] {message.get('description', message)}"
                )

        script.on("message", on_message)
        script.load()

        if mode == "spawn":
            device.resume(pid)

        console.print(f"[green]Frida script loaded ({mode} mode, PID {pid})[/green]")
        console.print(
            "[yellow]Monitoring app activity.. (Press Ctrl+C to stop)[/yellow]\n"
        )

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping capture...[/yellow]")
        finally:
            _save()
            try:
                session.detach()
            except Exception:
                pass
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

    args = parser.parse_args()

    console.print(
        Panel.fit(
            "[bold cyan]APK Malware Analysis Automation[/bold cyan]\n"
            "[dim]Framework Detection + API Monitoring v1.0.2[/dim]",
            border_style="cyan",
        )
    )

    apk_path = args.apk_file

    if not Path(apk_path).exists():
        console.print(f"[red]✗ APK file not found: {apk_path}[/red]")
        sys.exit(1)

    console.print("\n[bold][+] Checking dependencies[/bold]")
    if not check_dependencies():
        sys.exit(1)

    console.print("\n[bold][+] Checking Frida server[/bold]")
    device = check_frida_server()
    if not device:
        sys.exit(1)

    console.print("\n[bold][+] Decompiling APK[/bold]")
    decompiled_dir = decompile_apk(apk_path)
    if not decompiled_dir:
        sys.exit(1)

    console.print("\n[bold][+] Detecting frameworks[/bold]")
    script_file, package_name = detect_frameworks(decompiled_dir)
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

    adb_serial = getattr(device, 'id', None)
    if adb_serial and not adb_serial.startswith('emulator') and ':' not in adb_serial:
        adb_serial = None

    if args.exerciser:
        console.print("\n[bold][+] Granting permissions[/bold]")
        exerciser = UIExerciser(package_name, duration=args.duration, adb_serial=adb_serial)
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
    run_frida_script(
        device, package_name, js_file,
        apk_path=apk_path, apk_hash=apk_hash,
        label=args.label, label_source=args.label_source,
        exerciser=exerciser,
        duration=args.duration,
    )

    if mitm:
        console.print("\n[bold][+] Stopping MITM proxy[/bold]")
        mitm.stop()
        
        net_file = Path("output") / package_name / f"{package_name}_network_sequence.json"
        if net_file.exists():
            mitm.merge_into_network_sequence(str(net_file), session_start_time)
            console.print(f"[green]✓ MITM flows merged into {net_file.name}[/green]")


if __name__ == "__main__":
    main()

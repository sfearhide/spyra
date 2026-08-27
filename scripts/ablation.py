#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

TIERS = ["all", "minimal", "none"]
ROOT = Path(__file__).resolve().parents[1]


def run_capture(apk: Path, tier: str, duration: int) -> dict | None:
    meta_path = None
    cmd = [
        sys.executable, str(ROOT / "main.py"), str(apk),
        "--duration", str(duration),
        "--bypass", tier,
        "--no-mitm",
    ]
    print(f"[ablation] {apk.name} tier={tier} duration={duration}s")

    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=duration * 4 + 240)
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"  [!] main.py rc={result.returncode} ({elapsed:.0f}s)")
        return {"tier": tier, "error": result.stdout[-400:]}

    pkg = _package_from_output(result.stdout)
    if not pkg:
        return {"tier": tier, "error": "could not determine package name"}

    meta_file = ROOT / "output" / pkg / f"{pkg}_api_sequence.json"
    if not meta_file.exists():
        return {"tier": tier, "error": "capture file missing"}

    meta = json.loads(meta_file.read_text())["metadata"]
    meta["wall_seconds"] = round(elapsed, 1)
    meta["package"] = pkg
    meta["tier"] = tier

    return meta


def _package_from_output(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("Package: "):
            return line.split("Package: ", 1)[1].strip()
    return None


def compare(per_tier: list[dict]) -> dict:
    def hist(meta):
        events = (meta.get("agent") or {}).get("events_by_type", {})
        total = sum(events.values()) or 1
        return {k: v / total for k, v in events.items()}, total

    out = {}
    hists = {}
    for m in per_tier:
        if m and "error" not in m:
            h, total = hist(m)
            hists[m["tier"]] = (h, total)
            out[f"{m['tier']}_total_events"] = total
            out[f"{m['tier']}_termination_attempts"] = m.get("termination_attempts")
            agent = m.get("agent") or {}
            out[f"{m['tier']}_coverage_ratio"] = agent.get("coverage_ratio")

    def l1(a, b):
        keys = set(a) | set(b)
        return round(sum(abs(a.get(k, 0) - b.get(k, 0)) for k in keys), 4)

    if "none" in hists:
        hn = hists["none"][0]
        for tier, (h, _) in hists.items():
            if tier != "none":
                out[f"l1_{tier}_vs_none"] = l1(h, hn)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+", type=Path)
    ap.add_argument("--duration", type=int, default=45)
    args = ap.parse_args()

    report = {"samples": []}
    for apk in args.apks:
        per_tier = []
        for tier in TIERS:
            meta = run_capture(apk, tier, args.duration)
            if meta:
                per_tier.append(meta)
            time.sleep(2)
        entry = {
            "apk": apk.name,
            "sha256": next((m.get("apk_sha256") for m in per_tier
                            if m and "error" not in m), None),
            "comparison": compare(per_tier),
            "tiers": per_tier,
        }
        report["samples"].append(entry)
        print(f"[ablation] {apk.name}: {json.dumps(entry['comparison'], indent=1)}")

    out_dir = ROOT / "output" / "_ablation"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "report.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"[ablation] report -> {out}")


if __name__ == "__main__":
    main()

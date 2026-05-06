#!/usr/bin/env python3
"""
mitmproxy addon for Spyra.

Passed to mitmdump with: mitmdump -s src/mitm_addon.py --set flows_file=<path>

Each intercepted HTTP/HTTPS response is appended as a JSON record to the
flows JSONL file, which MITMController merges into network_sequence.json
at session end.
"""

import json
import time
from pathlib import Path


MAX_BODY_BYTES = 8192


class SpyraAddon:
    def __init__(self, flows_file: str):
        self._flows_file = Path(flows_file)
        self._flows_file.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow) -> None:
        try:
            # req body preview
            req_body_raw = flow.request.content or b""
            req_preview = req_body_raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")

            # response body preview
            resp_body_raw = flow.response.content or b""
            resp_preview = resp_body_raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")

            record = {
                "timestamp": time.time(),
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "status_code": flow.response.status_code,
                "content_type": flow.response.headers.get("Content-Type", ""),
                "request_headers": dict(flow.request.headers),
                "response_headers": dict(flow.response.headers),
                "request_body_preview": req_preview,
                "response_body_preview": resp_preview,
            }
            with open(self._flows_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass


def load(loader):
    loader.add_option("flows_file", str, "/tmp/mitm_flows.jsonl", "Path to JSONL output file")


def configure(updated):
    pass


class _MitmproxyAddon(SpyraAddon):
    def __init__(self):
        super().__init__("/tmp/mitm_flows.jsonl")

    def configure(self, updated):
        from mitmproxy import ctx
        if "flows_file" in updated:
            self._flows_file = Path(ctx.options.flows_file)
            self._flows_file.parent.mkdir(parents=True, exist_ok=True)


addons = [_MitmproxyAddon()]

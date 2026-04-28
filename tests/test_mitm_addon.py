import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import sys
sys.path.insert(0, '.')


def _make_flow(method='GET', url='https://example.com/api', status=200,
               req_body=b'', resp_body=b'{"ok": true}', content_type='application/json'):
    flow = MagicMock()
    flow.request.method = method
    flow.request.pretty_url = url
    flow.request.headers = {'Content-Type': 'application/json'}
    flow.request.content = req_body
    flow.response.status_code = status
    flow.response.headers = {'Content-Type': content_type}
    flow.response.content = resp_body
    flow.response.text = resp_body.decode('utf-8', errors='replace')
    return flow


def test_response_writes_jsonl_record():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        addon.response(_make_flow())
        lines = flows_file.read_text().strip().split('\n')
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record['method'] == 'GET'
        assert record['url'] == 'https://example.com/api'
        assert record['status_code'] == 200
        assert 'timestamp' in record


def test_response_truncates_large_body():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        large_body = b'X' * 20000
        addon.response(_make_flow(resp_body=large_body))
        record = json.loads(flows_file.read_text().strip())
        assert len(record['response_body_preview']) <= 8192 + 10  # small margin


def test_response_handles_binary_body():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        binary_body = bytes(range(256))
        # Must not raise
        addon.response(_make_flow(resp_body=binary_body))
        record = json.loads(flows_file.read_text().strip())
        assert 'response_body_preview' in record


def test_multiple_flows_each_get_own_line():
    with tempfile.TemporaryDirectory() as td:
        flows_file = Path(td) / 'mitm_flows.jsonl'
        from src.mitm_addon import SpyraAddon
        addon = SpyraAddon(str(flows_file))
        for _ in range(3):
            addon.response(_make_flow())
        lines = [l for l in flows_file.read_text().strip().split('\n') if l]
        assert len(lines) == 3
        for line in lines:
            json.loads(line)  # each must be valid JSON

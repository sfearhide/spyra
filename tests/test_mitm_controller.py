import json
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import subprocess
import sys
sys.path.insert(0, '.')
from src.mitm_controller import MITMController


def test_is_available_true_when_mitmdump_on_path():
    with patch('shutil.which', return_value='/usr/bin/mitmdump'):
        ctrl = MITMController(output_dir='/tmp', adb_serial=None)
        assert ctrl.is_available() is True


def test_is_available_false_when_missing():
    with patch('shutil.which', return_value=None):
        ctrl = MITMController(output_dir='/tmp', adb_serial=None)
        assert ctrl.is_available() is False


def test_flows_file_path():
    ctrl = MITMController(output_dir='/tmp/out', adb_serial=None)
    assert ctrl.flows_file == Path('/tmp/out/mitm_flows.jsonl')


def test_stop_removes_device_proxy():
    with tempfile.TemporaryDirectory() as td:
        ctrl = MITMController(output_dir=td, adb_serial='emulator-5554')
        ctrl._proc = MagicMock()
        ctrl._proc.poll.return_value = None
        with patch('subprocess.run') as mock_run:
            ctrl.stop()
        calls_flat = [' '.join(str(a) for a in c.args[0]) for c in mock_run.call_args_list]
        assert any('settings delete global http_proxy' in c for c in calls_flat)


def test_merge_into_network_sequence():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Write a fake network_sequence.json
        net_seq = {
            "metadata": {"package_name": "com.example.app"},
            "sequence": [
                {"type": "network", "action": "connect", "relative_time": 1.0}
            ]
        }
        net_file = td / 'network_sequence.json'
        net_file.write_text(json.dumps(net_seq))

        # Write a fake mitm_flows.jsonl
        flows_file = td / 'mitm_flows.jsonl'
        session_start = time.time() - 10  # 10 seconds ago
        record = {
            "timestamp": session_start + 5.0,  # relative_time should be ~5.0
            "method": "POST",
            "url": "https://evil.com/c2",
            "status_code": 200,
            "content_type": "application/json",
            "request_headers": {},
            "response_headers": {},
            "request_body_preview": "{}",
            "response_body_preview": '{"cmd": "sleep"}',
        }
        flows_file.write_text(json.dumps(record) + '\n')

        ctrl = MITMController(output_dir=str(td), adb_serial=None)
        ctrl.merge_into_network_sequence(str(net_file), session_start)

        merged = json.loads(net_file.read_text())
        assert len(merged['sequence']) == 2
        mitm_events = [e for e in merged['sequence'] if e['type'] == 'mitm']
        assert len(mitm_events) == 1
        assert mitm_events[0]['url'] == 'https://evil.com/c2'
        assert abs(mitm_events[0]['relative_time'] - 5.0) < 0.5
        # Sequence must be sorted by relative_time
        times = [e['relative_time'] for e in merged['sequence']]
        assert times == sorted(times)


def test_merge_skips_missing_flows_file():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        net_seq = {"metadata": {}, "sequence": []}
        net_file = td / 'network_sequence.json'
        net_file.write_text(json.dumps(net_seq))
        ctrl = MITMController(output_dir=str(td), adb_serial=None)
        # flows_file does not exist — should not raise
        ctrl.merge_into_network_sequence(str(net_file), time.time())
        result = json.loads(net_file.read_text())
        assert result['sequence'] == []

import subprocess
from unittest.mock import patch, call
import sys
sys.path.insert(0, '.')
from src.ui_exerciser import UIExerciser, DANGEROUS_PERMISSIONS


def _run(args, **kwargs):
    return subprocess.CompletedProcess(args, 0, stdout='', stderr='')


def test_dangerous_permissions_list():
    assert 'android.permission.CAMERA' in DANGEROUS_PERMISSIONS
    assert 'android.permission.RECORD_AUDIO' in DANGEROUS_PERMISSIONS
    assert len(DANGEROUS_PERMISSIONS) == 15


def test_permission_sweep_calls_adb_for_each_permission():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    called_perms = [
        c.args[0][5]  # 6th element: the permission string
        for c in mock_run.call_args_list
    ]
    for perm in DANGEROUS_PERMISSIONS:
        assert perm in called_perms, f'{perm} not granted'


def test_permission_sweep_ignores_failures():
    ex = UIExerciser('com.example.app', duration=30)
    def raise_on_camera(args, **kwargs):
        if 'CAMERA' in args:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)
    with patch('subprocess.run', side_effect=raise_on_camera):
        ex.permission_sweep()  # must not raise


def test_adb_cmd_includes_serial():
    ex = UIExerciser('com.example.app', duration=30, adb_serial='emulator-5554')
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    first_call = mock_run.call_args_list[0].args[0]
    assert first_call[1] == '-s'
    assert first_call[2] == 'emulator-5554'


def test_adb_cmd_without_serial():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex.permission_sweep()
    first_call = mock_run.call_args_list[0].args[0]
    assert first_call[0] == 'adb'
    assert '-s' not in first_call


def test_monkey_profile_uses_fixed_seed_and_throttle():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        ex._run_monkey_profile(duration_seconds=10)
    calls = [' '.join(c.args[0]) for c in mock_run.call_args_list]
    assert any('monkey' in c for c in calls), 'monkey not called'
    assert any('--seed 42' in c for c in calls)
    assert any('--throttle 200' in c for c in calls)
    assert any('com.example.app' in c for c in calls)


def test_focused_sweep_sends_tap_and_text():
    ex = UIExerciser('com.example.app', duration=30)
    with patch('subprocess.run', side_effect=_run) as mock_run:
        with patch('src.ui_exerciser.time.sleep'):  # don't actually sleep
            ex._run_focused_sweep()
    calls_flat = [' '.join(c.args[0]) for c in mock_run.call_args_list]
    assert any('input tap' in c for c in calls_flat)
    assert any('input text' in c for c in calls_flat)
    assert any('test@example.com' in c for c in calls_flat)
    assert any('keyevent 66' in c for c in calls_flat)  # Enter


def test_start_and_stop():
    ex = UIExerciser('com.example.app', duration=5)
    with patch.object(ex, '_run_monkey_profile'):
        with patch.object(ex, '_run_focused_sweep'):
            ex.start()
            assert ex._thread is not None
            assert ex._thread.is_alive()
            ex.stop()
            ex._thread.join(timeout=2)
            assert not ex._thread.is_alive()

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp import luraph_capture
from luauvmp.luraph_runtime_fix import validate_runtime_facts


def test_runtime_facts_use_actual_helper_table_not_environment_slot():
    runner = luraph_capture.build_lune_runner(
        'vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv',
    )
    assert 'writeRuntimeFacts(runtimeState)' in runner
    assert 'writeRuntimeFacts(runtimeState[1])' not in runner


def test_empty_runtime_helper_capture_is_rejected(tmp_path):
    path = tmp_path / 'facts.tsv'
    path.write_text(
        ''.join('%d\tnil\tnil\tfalse\t\n' % index for index in range(1, 65))
    )
    try:
        validate_runtime_facts(path)
    except luraph_capture.CaptureError as exc:
        assert 'implausible' in str(exc)
    else:
        raise AssertionError('empty runtime helper facts were accepted')


def test_plausible_runtime_helper_capture_is_accepted(tmp_path):
    path = tmp_path / 'facts.tsv'
    rows = []
    for index in range(1, 65):
        kind = 'function' if index <= 16 else 'nil'
        rows.append('%d\t%s\t%s\t%s\t\n' % (
            index, kind, kind, 'true' if kind == 'function' else 'false',
        ))
    path.write_text(''.join(rows))
    validate_runtime_facts(path)


def test_safe_capture_exposes_only_inert_task_cancel():
    runner = luraph_capture.build_lune_runner(
        'vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv',
    )
    assert 'local TaskCompat = table.freeze({' in runner
    assert 'cancel = function(_)' in runner
    assert 'task = TaskCompat,' in runner

    # The recovered parser may cancel an existing watchdog handle, but cannot
    # schedule or resume work through the trusted runner environment.
    environment = runner.split('local missingSafeGlobals = {}', 1)[1]
    assert 'task.spawn' not in environment
    assert 'task.defer' not in environment
    assert 'task.delay' not in environment
    assert 'task.wait' not in environment


def test_blocked_constructor_probe_names_the_global_without_adding_capability():
    runner = luraph_capture.build_lune_runner(
        'vm.luau', 'bc.bin', 'full.tsv', 'facts.tsv',
    )
    assert 'safe-capture blocked access to missing global ' in runner
    assert 'name == "Instance" or name == "Random"' in runner
    assert '__metatable = "locked"' in runner

    environment = runner.split('local blockedConstructorProbes = {}', 1)[1]
    assert 'Instance.new' not in environment
    assert 'Random.new' not in environment
    assert 'robloxDatatypes.Instance' not in runner
    assert 'robloxDatatypes.Random' not in runner

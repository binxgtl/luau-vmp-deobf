import pytest

from luauvmp import luraph_capture
from luauvmp import luraph_capture_completion as completion


def _write_complete_artifacts(tmp_path, protos=2):
    ir = ['META\tprotos\t%d' % protos]
    for index in range(protos):
        ir.append('P\t%d\t-1\t-1\t-1\t0\tN\tN\tN\tD0' % index)
    (tmp_path / 'full_ir.tsv').write_text('\n'.join(ir) + '\n')

    facts = []
    for index in range(1, 65):
        kind = 'function' if index <= 16 else 'nil'
        facts.append('%d\t%s\t%s\t%s\t\n' % (
            index, kind, kind, 'true' if kind == 'function' else 'false',
        ))
    (tmp_path / 'runtime_A.tsv').write_text(''.join(facts))
    (tmp_path / 'interpreter.factory.luau').write_text('(function() end)')
    (tmp_path / 'interpreter.capture.luau').write_text('return 1')
    (tmp_path / 'capture_runner.luau').write_text('return 1')


def _sentinel_error(count=2):
    return luraph_capture.CaptureError(
        '[capture] capture complete: %d prototypes\n%s' % (
            count, completion._SENTINEL,
        )
    )


def test_verified_post_capture_sentinel_recovers_complete_artifacts(tmp_path):
    _write_complete_artifacts(tmp_path, 2)
    artifacts = completion._recover_expected_abort(_sentinel_error(2), tmp_path)
    assert artifacts is not None
    assert artifacts.full_ir == tmp_path / 'full_ir.tsv'
    assert artifacts.runtime_facts == tmp_path / 'runtime_A.tsv'


def test_post_capture_sentinel_rejects_incomplete_typed_ir(tmp_path):
    _write_complete_artifacts(tmp_path, 2)
    (tmp_path / 'full_ir.tsv').write_text(
        'META\tprotos\t2\nP\t0\t-1\t-1\t-1\t0\tN\tN\tN\tD0\n'
    )
    with pytest.raises(luraph_capture.CaptureError, match='incomplete'):
        completion._recover_expected_abort(_sentinel_error(2), tmp_path)


def test_sentinel_text_without_capture_complete_is_not_accepted(tmp_path):
    _write_complete_artifacts(tmp_path, 2)
    error = luraph_capture.CaptureError(completion._SENTINEL)
    assert completion._recover_expected_abort(error, tmp_path) is None


def test_capture_complete_without_disabled_closure_sentinel_is_not_accepted(tmp_path):
    _write_complete_artifacts(tmp_path, 2)
    error = luraph_capture.CaptureError('[capture] capture complete: 2 prototypes')
    assert completion._recover_expected_abort(error, tmp_path) is None

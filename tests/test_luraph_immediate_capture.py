import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest

from luauvmp import luraph_capture


def _fixture(extra_application=''):
    return (
        'local x={} local T={} local W={} '
        'x[56]=function(h,W,w) '
        'local n=h[7] '
        'w=function(...) local y=1; '
        'while true do local E=n[y]; '
        'if E==1 then return end; y+=1; end; end; '
        'return w; end; '
        'T=x[0B00111000](T,W)(1,2,3); '
        + extra_application
        + 'return T;'
    )


def test_extracts_factory_from_unique_immediate_application():
    source = _fixture()
    factory = luraph_capture.extract_interpreter_factory(source)

    assert '-- LUAUVMP_PUBLIC_V147=1' in factory
    assert '-- LUAUVMP_FACTORY_SLOT=56' in factory
    assert '-- LUAUVMP_HELPER_VAR=x' in factory
    assert '-- LUAUVMP_DISPATCH_VAR=E' in factory
    assert 'while true do local E=n[y]' in factory


def test_instruments_immediate_application_before_root_execution():
    source = _fixture()
    patched = luraph_capture.instrument_vm_source(source)

    assert 'T=__LUAUVMP_CAPTURE(x,T);' in patched
    assert 'x[0B00111000](T,W)(1,2,3)' not in patched
    assert 'x[56]=function' in patched


def test_immediate_application_capture_fails_closed_when_ambiguous():
    source = _fixture('T=x[56](T,W)(4,5,6); ')
    with pytest.raises(
        luraph_capture.CaptureError,
        match='has 2 immediate applications',
    ):
        luraph_capture.extract_interpreter_factory(source)


def test_unrelated_immediate_application_is_not_selected():
    source = _fixture().replace(
        'T=x[0B00111000](T,W)(1,2,3);',
        'T=x[55](T,W)(1,2,3);',
    )
    with pytest.raises(luraph_capture.CaptureError):
        luraph_capture.extract_interpreter_factory(source)

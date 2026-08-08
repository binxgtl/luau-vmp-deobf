import pytest

from luauvmp import luraph_capture
from luauvmp import luraph_prebootstrap_capture as prebootstrap


def _direct_slot59():
    return '''
local b = {}
b[59] = function(d, y)
    local x, G = {[1] = 1}, 1
    return function()
        while true do
            local R = x[G]
            if R == 1 then return y end
            G += 1
        end
    end
end
local l = {[1] = {}}
local k = {}
k = l[0X3b](k, l[0x1])("bootstrap", l[0X16], l[59]);
return l[0X003B](k, l[0X1]);
'''


def _direct_slot50_final_branch_first():
    return '''
local S = {}
S[50] = (function(j, L, T)
    local x, G = {[1] = 1}, 1
    return function()
        while true do
            local R = x[G]
            if R == 1 then return L end
        end
    end
end)
local G = {[26] = {}}
local L = {}
local z = 27
while true do
    if z == 62 then
        return G[50](L, G[26]);
    elseif z == 27 then
        L = G[50](L, G[26])("bootstrap", G[50]);
        z = 62
    end
end
'''


def _wrapped_slot50():
    return '''
local M = {}
M[50] = function(Q, X, S)
    local f, pc = {[1] = 1}, 1
    return function()
        while true do
            local w = f[pc]
            if w == 1 then return X end
        end
    end
end
local p = {[24] = {}}
local J = {}
J = p[50](J, p[24])("bootstrap", p[50]);
return {p[50](J, p[24])}, J, 124;
'''


def test_prebootstrap_capture_intercepts_slot59_constructor_call():
    patched = prebootstrap._instrument_prebootstrap(_direct_slot59())
    assert patched is not None
    assert 'k=__LUAUVMP_CAPTURE(l,k);' in patched
    assert 'l[0X3b](k, l[0x1])("bootstrap"' not in patched
    assert 'return k;' in patched
    assert 'return l[0X003B](k, l[0X1]);' not in patched


def test_prebootstrap_capture_handles_final_branch_lexically_before_bootstrap():
    patched = prebootstrap._instrument_prebootstrap(_direct_slot50_final_branch_first())
    assert patched is not None
    assert 'L=__LUAUVMP_CAPTURE(G,L);' in patched
    assert 'G[50](L, G[26])("bootstrap"' not in patched
    assert 'return L;' in patched
    assert 'return G[50](L, G[26]);' not in patched


def test_prebootstrap_capture_preserves_wrapped_return_shape():
    patched = prebootstrap._instrument_prebootstrap(_wrapped_slot50())
    assert patched is not None
    assert 'J=__LUAUVMP_CAPTURE(p,J);' in patched
    assert 'p[50](J, p[24])("bootstrap"' not in patched
    assert 'return {J}, J, 124;' in patched
    assert 'return {p[50](J, p[24])}, J, 124;' not in patched


def test_prebootstrap_capture_fails_closed_when_bootstrap_is_ambiguous():
    source = _direct_slot59().replace(
        'return l[0X003B](k, l[0X1]);',
        'k = l[59](k,l[1])("second");\nreturn l[0X003B](k, l[0X1]);',
    )
    with pytest.raises(luraph_capture.CaptureError, match='found 2'):
        prebootstrap._instrument_prebootstrap(source)


def test_installed_capture_still_falls_back_when_no_bootstrap_call_exists():
    source = _direct_slot59().replace(
        'k = l[0X3b](k, l[0x1])("bootstrap", l[0X16], l[59]);\n',
        '',
    )
    patched = luraph_capture.instrument_vm_source(source)
    assert 'return __LUAUVMP_CAPTURE(l,k);' in patched
    assert 'return l[0X003B](k, l[0X1]);' not in patched

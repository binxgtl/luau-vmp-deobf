from luauvmp import luraph_lift_close_upvalues as close
from luauvmp.luraph_full import Instruction


def _ins(*, e=None, h=None, underscore=None, b=None):
    return Instruction(
        proto=0,
        pc=1,
        e=e,
        opcode=1,
        p=None,
        o=None,
        h=h,
        underscore=underscore,
        b=b,
    )


def test_infers_single_stream_close_layout_without_outer_guard():
    source = '''
        local O=_[u];
        for I,e in __s_B do
            if not(I>=O) then else
                e[2]=e;
                e[3]=c[I];
                e[1]=3;
                __s_B[I]=nil;
            end
        end;
    '''
    shape = close.infer_close_shape(source)
    assert shape is not None
    assert shape.cache_name == "__s_B"
    assert shape.threshold == "O"
    assert (shape.self_key, shape.value_key, shape.selector_key) == (2, 3, 1)
    assert shape.selector_value == 3

    lifted = close.lift_close_prefix(source, _ins(underscore=5))
    assert lifted is not None
    assert "localO=5" in lifted.replace(" ", "")
    assert "for __close_reg, __close_cell in __s_B do" in lifted
    assert "__close_cell[2] = __close_cell" in lifted
    assert "__close_cell[3] = R[__close_reg]" in lifted
    assert "__close_cell[1] = 3" in lifted


def test_infers_two_stream_close_layout_with_outer_guard():
    source = '''
        local j=E[u];
        if not(P) then else
            for x,m in P do
                if x>=j then
                    m[2]=m;
                    m[3]=c[x];
                    m[1]=3;
                    P[x]=nil;
                end
            end
        end;
    '''
    shape = close.infer_close_shape(source)
    assert shape is not None
    assert shape.cache_name == "P"
    assert shape.threshold == "j"
    assert (shape.self_key, shape.value_key, shape.selector_key) == (2, 3, 1)
    assert shape.selector_value == 3
    assert close.resolved_if_count(source, _ins(e=4)) == 2


def test_infers_legacy_two_stream_alternate_cell_layout():
    source = '''
        local l=B[u];
        if n then
            for y,s in n do
                if y>=l then
                    s[1]=s;
                    s[2]=c[y];
                    s[3]=2;
                    n[y]=nil;
                end
            end
        end;
    '''
    shape = close.infer_close_shape(source)
    assert shape is not None
    assert shape.cache_name == "n"
    assert shape.threshold == "l"
    assert (shape.self_key, shape.value_key, shape.selector_key) == (1, 2, 3)
    assert shape.selector_value == 2


def test_rejects_close_region_with_extra_antitamper_branch():
    source = '''
        local l=B[u];
        if n then
            for y,s in n do
                if Q==128 then Q=57 else Q=128 end;
                if y>=l then
                    s[1]=s; s[2]=c[y]; s[3]=2; n[y]=nil;
                end
            end
        end;
    '''
    assert close.infer_close_shape(source) is None


def test_close_return_wrapper_preserves_order_and_multi_return():
    source = '''
        local O=H[u];
        for I,e in __s_B do
            if I>=O then
                e[2]=e; e[3]=c[I]; e[1]=3; __s_B[I]=nil;
            end
        end;
        M=_[u];
        return false,M,M;
    '''
    result = close.return_expression(source, _ins(h=4, underscore=9))
    assert result is not None
    assert result.startswith("(function()")
    normalized = result.replace(" ", "")
    assert "localO=4" in normalized
    assert "M=9" in normalized
    assert "returnfalse,M,M" in normalized
    assert result.endswith("end)()")


def test_close_return_wrapper_preserves_bare_return():
    source = '''
        local O=E[u];
        if __s_B then
            for I,e in __s_B do
                if I>=O then
                    e[2]=e; e[3]=c[I]; e[1]=3; __s_B[I]=nil;
                end
            end
        end;
        return;
    '''
    result = close.return_expression(source, _ins(e=6))
    assert result is not None
    assert "return" in result
    assert result.endswith("end)()")

from luauvmp import luraph_lift_calls as calls


def test_recognizes_call0_with_randomized_top_name():
    kind, fields = calls.classify("T=_[u]; c[T](); T-=1;")
    assert kind == "call0"
    assert fields["func_field"] == "_"


def test_recognizes_open_argument_call():
    kind, fields = calls.classify("M=o[u]; c[M](table.unpack(c,M+1,T)); T=M-1;")
    assert kind == "call_open"
    assert fields["base_field"] == "o"


def test_recognizes_single_result_open_argument_call():
    kind, fields = calls.classify("M=H[u]; c[M]=c[M](table.unpack(c,M+1,T)); T=M;")
    assert kind == "call_one"
    assert fields["base_field"] == "H"


def test_recognizes_vararg_copy():
    kind, fields = calls.classify("for A=1,_[u] do c[A]=j[A]; end")
    assert kind == "vararg_copy"
    assert fields["count_field"] == "_"
    assert fields["varargs"] == "j"


def test_recognizes_generic_call_and_all_four_mode_conditions():
    source = '''
        M=o[u];
        h=H[u];
        n=_[u];
        if h==0 then else T=M+h-1; end
        W,z=nil;
        if h~=1 then
            W,z=A[58](c[M](table.unpack(c,M+1,T)));
        else
            W,z=A[58](c[M]());
        end
        if n~=1 then
            if n==0 then
                W=W+M-1;
                T=W;
            else
                W=M+n-2;
                T=W+1;
            end
            h=0;
            for A=M,W do
                h+=1;
                c[A]=z[h];
            end
        else
            T=M-1;
        end
    '''
    kind, fields = calls.classify(source)
    assert kind == "call_generic"
    assert fields["base_field"] == "o"
    assert fields["argc_field"] == "H"
    assert fields["retc_field"] == "_"
    assert calls.resolved_if_count(source) == 4


def test_recognizes_public_generic_call_equivalent_guard_spellings():
    source = '''
        x=E[u]; v=o[u]; m=B[u];
        if v~=0 then r=x+v-1; end
        __s__,q=nil;
        if v~=1 then
            __s__,q=A[48](c[x](A[25](r,c,x+1)));
        else
            __s__,q=A[48](c[x]());
        end
        if m==1 then
            r=x-1;
        else
            if m==0 then __s__=__s__+x-1; r=__s__;
            else __s__=x+m-2; r=__s__+1; end
            v=0;
            for j=x,__s__ do v+=1; c[j]=q[v]; end
        end
    '''
    kind, fields = calls.classify(source)
    assert kind == "call_generic"
    assert fields["base_field"] == "E"
    assert fields["argc_field"] == "o"
    assert fields["retc_field"] == "B"
    assert calls.resolved_if_count(source) == 4


def test_rejects_generic_call_if_result_table_changes():
    source = '''
        M=o[u]; h=H[u]; n=_[u];
        if h==0 then else T=M+h-1; end
        W,z=nil;
        if h~=1 then W,z=A[58](c[M](table.unpack(c,M+1,T)));
        else W,z=A[58](c[M]()); end
        if n~=1 then
            if n==0 then W=W+M-1; T=W;
            else W=M+n-2; T=W+1; end
            h=0;
            for A=M,W do h+=1; c[A]=OTHER[h]; end
        else T=M-1; end
    '''
    assert calls.classify(source) is None

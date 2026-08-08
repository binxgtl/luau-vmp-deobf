from luauvmp import luraph_lift_forloops as loops


def test_recognizes_public_numeric_for_prep_with_randomized_scratch_names():
    source = '''
        f=({[5]=Z,[2]=f,[1]=N,[4]=g});
        M=H[u];
        N=(c[M+2]+0);
        g=c[M+1]+0;
        Z=c[M]-N;
        u=_[u];
    '''
    kind, fields = loops.classify(source)
    assert kind == "prep"
    assert fields["base_field"] == "H"
    assert fields["target_field"] == "_"


def test_recognizes_public_numeric_for_restore():
    source = '''
        Z=(f[5]);
        g=(f[4]);
        N=(f[1]);
        f=(f[2]);
    '''
    kind, fields = loops.classify(source)
    assert kind == "restore"
    assert fields["state"] == "f"
    assert fields["index"] == "Z"
    assert fields["limit"] == "g"
    assert fields["step"] == "N"


def test_recognizes_numeric_for_loop_and_resolves_both_conditions():
    source = '''
        M=(false);
        Z+=N;
        if not(N<=0) then
            M=(Z<=g);
        else
            M=(Z>=g);
        end
        if not(M) then
        else
            c[o[u]+3]=(Z);
            u=_[u];
        end
    '''
    kind, fields = loops.classify(source)
    assert kind == "loop"
    assert fields["base_field"] == "o"
    assert fields["target_field"] == "_"
    assert loops.resolved_if_count(source) == 2


def test_recognizes_split_numeric_for_step_and_resolves_condition():
    source = '''
        x=false;
        W+=Q;
        if not(Q<=0) then x=(W<=U); else x=W>=U; end
    '''
    kind, fields = loops.classify(source)
    assert kind == "split_loop"
    assert fields == {
        "flag": "x", "index": "W", "step": "Q", "limit": "U",
    }
    assert loops.resolved_if_count(source) == 1


def test_recognizes_generic_for_step_and_resolves_condition():
    source = '''
        x=E[u]; v,m,__s__=W();
        if v then c[x+1]=m; c[x+2]=__s__; u=B[u]; end
    '''
    kind, fields = loops.classify(source)
    assert kind == "generic_loop"
    assert fields["base_field"] == "E"
    assert fields["target_field"] == "B"
    assert fields["iterator"] == "W"
    assert loops.resolved_if_count(source) == 1


def test_rejects_inconsistent_forloop_def_use_chain():
    source = '''
        M=false;
        Z+=N;
        if not(N<=0) then
            M=(Z<=g);
        else
            M=(Z>=g);
        end
        if not(M) then
        else
            c[o[u]+3]=(Q);
            u=_[u];
        end
    '''
    assert loops.classify(source) is None
    assert loops.resolved_if_count(source) == 0


def test_rejects_forprep_with_mismatched_saved_step():
    source = '''
        f=({[5]=Z,[2]=f,[1]=Q,[4]=g});
        M=H[u];
        N=(c[M+2]+0);
        g=c[M+1]+0;
        Z=c[M]-N;
        u=_[u];
    '''
    assert loops.classify(source) is None

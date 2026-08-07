from luauvmp import luraph_lift_forloops as loops


def test_recognizes_randomized_forprep_state_slots():
    source = '''
        Y={[3]=k,[4]=j,[5]=Y,[1]=r};
        e=H[u];
        k=(c[e+2]+0);
        r=c[e+1]+0;
        j=(c[e]-k);
        u=p[u];
    '''
    kind, fields = loops.classify(source)
    assert kind == "prep"
    assert fields["state"] == "Y"
    assert fields["index"] == "j"
    assert fields["limit"] == "r"
    assert fields["step"] == "k"
    assert fields["base_field"] == "H"
    assert fields["target_field"] == "p"


def test_recognizes_randomized_restore_slots_after_dead_literal_prefix():
    source = '''
        local Q = 188;
        j=(Y[4]);
        r=Y[1];
        k=Y[3];
        Y=(Y[5]);
    '''
    kind, fields = loops.classify(source)
    assert kind == "restore"
    assert fields["index_slot"] == "4"
    assert fields["limit_slot"] == "1"
    assert fields["step_slot"] == "3"
    assert fields["state_slot"] == "5"


def test_recognizes_equivalent_positive_step_branch_spelling():
    source = '''
        e=false;
        j+=k;
        if k<=0 then
            e=j>=r;
        else
            e=(j<=r);
        end
        if not(e) then
        else
            c[B[u]+3]=j;
            u=H[u];
        end
    '''
    kind, fields = loops.classify(source)
    assert kind == "loop"
    assert fields["index"] == "j"
    assert fields["limit"] == "r"
    assert fields["step"] == "k"
    assert fields["base_field"] == "B"
    assert fields["target_field"] == "H"
    assert loops.resolved_if_count(source) == 2


def test_rejects_forprep_when_state_table_omits_a_proven_role():
    source = '''
        Y={[3]=k,[4]=j,[5]=Y,[1]=other};
        e=H[u];
        k=(c[e+2]+0);
        r=c[e+1]+0;
        j=(c[e]-k);
        u=p[u];
    '''
    assert loops.classify(source) is None


def test_rejects_restore_when_state_slots_alias():
    source = '''
        j=Y[4];
        r=Y[1];
        k=Y[4];
        Y=Y[5];
    '''
    assert loops.classify(source) is None

from luauvmp import luraph_lift_straightline as straight


def test_accepts_exact_register_scratch_micro_ops():
    assert straight.is_proven_straightline("M=(c); h=_[u];")
    assert straight.is_proven_straightline("W=(W[z]); n=n[W]; M[h]=(n);")
    assert straight.is_proven_straightline("n^=W; (M)[h]=n;")
    assert straight.is_proven_straightline("c[o[u]]=c[_[u]]//c[H[u]];")


def test_accepts_pure_library_function_table_constants_without_calls():
    source = "c[H[u]]={({[5]=bit32.rshift,[6]=bit32.lrotate,[15]=string.unpack})[_[u]]);"
    assert straight.is_proven_straightline(source)


def test_rejects_control_flow_and_calls():
    assert not straight.is_proven_straightline("if n then M=h; end")
    assert not straight.is_proven_straightline("for A=1,3 do M[A]=A; end")
    assert not straight.is_proven_straightline("M=A[5](n);")
    assert not straight.is_proven_straightline("(M)();")
    assert not straight.is_proven_straightline("return M;")


def test_rejects_environment_upvalue_and_vararg_state():
    assert not straight.is_proven_straightline("c[H[u]]=q[E[u]];")
    assert not straight.is_proven_straightline("M=I[H[u]];")
    assert not straight.is_proven_straightline("B[H[u]]=M;")
    assert not straight.is_proven_straightline("c[H[u]]=j[E[u]];")


def test_rejects_direct_program_counter_writes():
    assert not straight.is_proven_straightline("u=H[u];")
    assert not straight.is_proven_straightline("u+=1;")


def test_rejects_unknown_identifiers_fail_closed():
    assert not straight.is_proven_straightline("mystery=H[u];")
    assert not straight.is_proven_straightline("c[H[u]]=workspace;")

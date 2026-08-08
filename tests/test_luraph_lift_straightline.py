from luauvmp import luraph_lift_straightline as straight


def test_accepts_exact_register_scratch_micro_ops():
    assert straight.is_proven_straightline("M=(c); h=_[u];")
    assert straight.is_proven_straightline("W=(W[z]); n=n[W]; M[h]=(n);")
    assert straight.is_proven_straightline("n^=W; (M)[h]=n;")
    assert straight.is_proven_straightline("c[o[u]]=c[_[u]]//c[H[u]];")
    assert straight.is_proven_straightline("h=H[u]; n=E[u]; W=B[u];")
    assert straight.is_proven_straightline("n=n[W]; W=B[u];")


def test_accepts_pure_library_function_table_constants_without_calls():
    source = "c[H[u]]={({[5]=bit32.rshift,[6]=bit32.lrotate,[15]=string.unpack})[_[u]]);"
    assert straight.is_proven_straightline(source)


def test_accepts_declared_collision_scratch_after_proven_dead_prefix():
    source = "local Q=(188); l=(c); __s_I=p[u]; l=l[__s_I]; w=__s_B;"
    assert straight.is_proven_straightline(source)


def test_accepts_all_declared_randomized_scratch_spellings():
    assert straight.is_proven_straightline("x=c; v=o[u];")
    assert straight.is_proven_straightline(
        "m=m[__s__]; __s__=H[u]; m=m[__s__]; x[v]=m;"
    )
    assert straight.is_proven_straightline("q=B[u]; __s__=__s__[q];")


def test_keeps_live_literal_prefix_out_of_straightline_path():
    source = "local Q=(188); l=Q;"
    assert not straight.is_proven_straightline(source)


def test_rejects_control_flow_and_calls():
    assert not straight.is_proven_straightline("if n then M=h; end")
    assert not straight.is_proven_straightline("for A=1,3 do M[A]=A; end")
    assert not straight.is_proven_straightline("M=A[5](n);")
    assert not straight.is_proven_straightline("(M)();")
    assert not straight.is_proven_straightline("return M;")


def test_rejects_environment_upvalue_and_vararg_state():
    assert not straight.is_proven_straightline("c[H[u]]=__ENV[E[u]];")
    assert not straight.is_proven_straightline("M=I[H[u]];")
    # Only the exact canonical operand read B[u] is admitted. Arbitrary indexed
    # B state remains fail-closed and cannot be confused with the operand column.
    assert not straight.is_proven_straightline("B[H[u]]=M;")
    assert not straight.is_proven_straightline("M=B[H[u]];")
    assert not straight.is_proven_straightline("c[H[u]]=j[E[u]];")


def test_rejects_direct_program_counter_writes():
    assert not straight.is_proven_straightline("u=H[u];")
    assert not straight.is_proven_straightline("u+=1;")


def test_rejects_unknown_identifiers_fail_closed():
    assert not straight.is_proven_straightline("mystery=H[u];")
    assert not straight.is_proven_straightline("c[H[u]]=workspace;")

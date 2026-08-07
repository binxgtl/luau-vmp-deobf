from pathlib import Path

from luauvmp import luraph_vararg_semantics as vararg
from luauvmp.luraph_full import Instruction


def test_reads_builtin_identity_without_changing_runtime_fact_shape(tmp_path: Path):
    path = tmp_path / "runtime_A.tsv"
    path.write_text(
        "20\tfunction\tbuiltin:select\ttrue\t4\n"
        "58\tfunction\tfunction: 0x1\ttrue\t9\n",
        encoding="utf-8",
    )
    assert vararg._runtime_builtin_slots(path, "select") == {20}
    assert vararg._runtime_builtin_slots(path, "bit32.bxor") == set()


def test_proves_hex_vararg_packer_from_select_identity():
    vm = '''
        (b)[0X3a]=(function(...)
            local d=b[0X14]("#",...);
            if d~=0X0 then else return d,b[55]; end;
            return d,{...};
        end);
    '''
    assert vararg.infer_packer_slot(vm, "b", {20}) == 58
    assert vararg.infer_packer_slot(vm, "b", {19}) is None


def test_matches_factory_packer_slot_by_numeric_value():
    factory = '''
-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_CANONICAL_VARS={"b":"A"}
-- LUAUVMP_HELPER_VAR=b
(function(...) local A,j=b[0X3a](...); return A,j; end)
'''
    assert vararg.infer_factory_varargs(factory, "b", 58) == ("A", "j")
    assert vararg._canonical_vararg_names(factory, ("A", "j")) == ("__s_A", "j")


def test_classifies_all_three_public_vararg_transfer_shapes():
    prefix = '''
        C=(H[u]);
        for __s_A=1,C do
            (c)[__s_A]=j[__s_A];
        end
        K=(C+1);
    '''
    result = vararg.classify_vararg(prefix, "__s_A", "j")
    assert result == ("prefix", ("C", "K"), "H", 0)

    fixed = '''
        M=_[u];
        h=(0);
        for __s_A=M,M+(H[u]-1) do
            c[__s_A]=(j[K+h]);
            h+=1;
        end
    '''
    result = vararg.classify_vararg(fixed, "__s_A", "j")
    assert result == ("fixed", ("M", "h", "K", "H"), "_", 0)

    remaining = '''
        M=(_[u]);
        h=__s_A-C-1;
        if not(h<0) then
        else
            h=-1;
        end
        n=0;
        for __s_A=M,M+h do
            c[__s_A]=j[K+n];
            n+=1;
        end
        T=M+h;
    '''
    result = vararg.classify_vararg(remaining, "__s_A", "j")
    assert result == ("remaining", ("M", "h", "C", "n", "K", "T"), "_", 1)


def test_vararg_marker_lifts_to_generated_argv_without_helper_calls():
    ins = Instruction(
        proto=0, pc=1, e=None, opcode=1, p=None, o=None,
        h=3, underscore=7, b=None,
    )
    prefix = vararg.clean_statement("__LUAUVMP_VARARG_PREFIX(C,K,@H)", ins)
    assert prefix is not None
    assert "C = 3" in prefix
    assert "argv[__arg_i]" in prefix
    assert "K = C + 1" in prefix

    remaining = vararg.clean_statement(
        "__LUAUVMP_VARARG_REMAINING(M,h,C,n,K,T,@_)", ins
    )
    assert remaining is not None
    assert "M = 7" in remaining
    assert "h = argv.n - C - 1" in remaining
    assert "R[__arg_i] = argv[K + n]" in remaining
    assert "T = M + h" in remaining

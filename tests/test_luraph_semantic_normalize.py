from luauvmp import luraph_semantic_normalize as normalize


def _factory():
    return '''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=b
-- LUAUVMP_DISPATCH_VAR=R
-- LUAUVMP_NESTED_HELPERS={"52":{"7":"bit32.bor"}}
(function(d,y)
local A,P,_=d[0Xa],d[1],d[2];
local i,Q,t,D,x,p,a=d[0xB],d[0X9],d[7],d[0B1_10],d[4],d[0X8];
a=(function(...)
local S={};local G=1;
while true do local R=(x[G]);
S[Q[G]]=D[G];
end
end);
return a;
end)
'''


def test_infers_randomized_dispatcher_roles_from_physical_proto_fields():
    mapping = normalize.infer_canonical_variables(_factory())
    assert mapping['R'] == 'X'
    assert mapping['G'] == 'u'
    assert mapping['S'] == 'c'
    assert mapping['_'] == 'E'
    assert mapping['D'] == 'p'
    assert mapping['t'] == 'o'
    assert mapping['p'] == 'H'
    assert mapping['Q'] == '_'
    assert mapping['i'] == 'B'
    assert mapping['x'] == 'L'
    assert mapping['b'] == 'A'
    assert mapping['y'] == 'I'


def test_canonicalizer_preserves_strings_and_normalizes_luau_numbers():
    mapping = normalize.infer_canonical_variables(_factory())
    source = 'S[p[G]]=(_[G]+S[t[G]]); local z="S[p[G]] 0X10"; z=0B1_0000;'
    canonical = normalize.canonicalize_source(source, mapping)
    assert canonical.startswith('c[H[u]]=(E[u]+c[o[u]]);')
    assert '"S[p[G]] 0X10"' in canonical
    assert canonical.endswith('z=16;')


def test_nested_helper_recovery_handles_parenthesized_table_slot_and_object_fields():
    vm = '''
return({l=bit32,I=string.unpack,e=bit32.rshift,X=bit32.rrotate});
(l[0X34])[0Xf]=m.I;
l[52][0B0101]=m.e;
l[0B110100][13]=m.l.countlz;
l[52][14]=m.X;
'''
    nested = normalize._complete_nested_helpers(vm)
    assert nested[52][5] == 'bit32.rshift'
    assert nested[52][13] == 'bit32.countlz'
    assert nested[52][14] == 'bit32.rrotate'
    assert nested[52][15] == 'string.unpack'


def test_recovers_direct_pure_helpers_through_vm_aliases():
    source = '''
        n=table.create; u=table; U=bit32;
        (S)[20]=G.n;
        S[29]=(y.u.move);
        S[13]=(G.U.bxor);
        S[15556]=(G.U.lrotate);
        other[13]=G.U.band;
    '''
    assert normalize._complete_direct_helpers(source, "S") == {
        13: "bit32.bxor", 20: "table.create", 29: "table.move",
    }

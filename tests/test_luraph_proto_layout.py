from luauvmp import luraph_proto_layout as layout


def _public_factory_001():
    return '''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=M
-- LUAUVMP_DISPATCH_VAR=w
(function(Q,X,S)
local C=Q[7];
local F,g,D,b,L,f,K,o=Q[6],Q[3],Q[1],Q[10],Q[11],Q[8],Q[2];
o=(function(...)
local O,t,h,G,l,e,r,T,N,w,n,P,k={},1,0,nil,nil,1;
while true do local w=(f[e]);
O[F[e]]=D[e];
if O[K[e]]~=D[e] then e=F[e] end;
if O[F[e]]<g[e] then e=L[e] end;
O[1]=b[e];
end
end);
return o;
end)
'''


def _public_factory_00a():
    return '''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=S
-- LUAUVMP_DISPATCH_VAR=H
(function(j,L,T)
local n=j[2];
T=j[6];
local I,E,N,e,B,b,l,g=j[9],j[3],j[5],j[7],j[1],j[4],j[10];
g=(function(...)
local V,r,R,C,s,v,H,k,X,c,x,P={},1,0,nil,1;
while true do local H=B[s];
V[E[s]]=L[N[s]][e[s]];
if V[E[s]] then s=l[s] end;
V[b[s]]=I[s];
end
end);
return g;
end)
'''


def _public_factory_reference():
    return '''-- LUAUVMP_PUBLIC_V147=1
-- LUAUVMP_HELPER_VAR=b
-- LUAUVMP_DISPATCH_VAR=R
(function(d,y)
local A,P,_=d[10],d[1],d[2];
local i,Q,t,D,x,p,a=d[11],d[9],d[7],d[6],d[4],d[8];
a=(function(...)
local S={},G=1;
while true do local R=x[G];
S[Q[G]]=D[G];
if S[p[G]]==S[Q[G]] then G=t[G] end;
local debugOnly=P[G];
local constant=i[G];
local operand=_[G];
end
end);
return a;
end)
'''


def test_infers_legacy_two_stream_randomized_layout():
    inferred = layout.infer_layout(_public_factory_001())
    assert inferred is not None
    assert inferred.opcode_field == 8
    assert inferred.operand_fields == (1, 2, 3, 6, 10, 11)
    assert inferred.dynamic is True
    assert inferred.canonical_map == {2: 1, 6: 2, 7: 3, 8: 6, 9: 10, 11: 11}


def test_infers_zstd_two_stream_randomized_layout():
    inferred = layout.infer_layout(_public_factory_00a())
    assert inferred is not None
    assert inferred.opcode_field == 1
    assert inferred.operand_fields == (3, 4, 5, 7, 9, 10)
    assert inferred.dynamic is True
    assert inferred.canonical_map == {2: 3, 6: 4, 7: 5, 8: 7, 9: 9, 11: 10}


def test_reference_layout_ignores_extra_pc_indexed_debug_array():
    inferred = layout.infer_layout(_public_factory_reference())
    assert inferred is not None
    assert inferred.opcode_field == 4
    assert inferred.operand_fields == (2, 6, 7, 8, 9, 11)
    assert inferred.dynamic is False


def test_dynamic_runner_rewrites_only_physical_layout_accesses():
    inferred = layout.infer_layout(_public_factory_001())
    assert inferred is not None
    runner = '''local function isProto(value)
    return type(value) == "table"
        and type(value[4]) == "table"
        and type(value[10]) == "number"
end
        local operandFields = { 2, 6, 7, 8, 9, 11 }
        local opcodes = proto[4]
            "P", tostring(id), tostring(meta[1]), tostring(meta[2]),
            tostring(meta[3]), tostring(instructionCount), typed(proto[1]),
            typed(proto[3]), typed(proto[5]), typed(proto[10]),
            local function cell(field)
                local array = proto[field]
                return typed(type(array) == "table" and array[pc] or nil)
            end'''
    patched = layout._rewrite_runner(runner, inferred)
    assert 'local PROTO_OPCODE_FIELD = 8' in patched
    assert 'local PROTO_OPERAND_FIELDS = { 1, 2, 3, 6, 10, 11 }' in patched
    assert '[2] = 1' in patched and '[11] = 11' in patched
    assert 'rawget(proto, PROTO_OPCODE_FIELD)' in patched
    assert 'local operandFields = PROTO_OPERAND_FIELDS' in patched
    assert 'physical = CANONICAL_PHYSICAL_FIELDS[field]' in patched
    assert '"N",\n            "N", "N", "D0",' in patched


def test_semantic_role_mapping_uses_same_randomized_layout():
    mapping = layout.infer_canonical_variables(_public_factory_00a())
    assert mapping['B'] == 'L'
    assert mapping['H'] == 'X'
    assert mapping['s'] == 'u'
    assert mapping['E'] == 'E'
    assert mapping['b'] == 'p'
    assert mapping['N'] == 'o'
    assert mapping['e'] == 'H'
    assert mapping['I'] == '_'
    assert mapping['l'] == 'B'
    assert mapping['S'] == 'A'
    assert mapping['L'] == 'I'
'''

from luauvmp import luraph_lift_closures as closures
from luauvmp.luraph_full import (
    Instruction,
    OpaqueTable,
    Program,
    Proto,
    ProtoRef,
)


def _proto(pid, field3=None):
    return Proto(
        id=pid,
        parent=-1 if pid == 0 else 0,
        parent_field=0,
        parent_pc=0,
        instruction_count=0,
        field1=None,
        field3=field3,
        field5=None,
        max_register=20,
        instructions=[],
    )


def test_infers_single_stream_closure_shape_and_materializes_descriptors():
    source = '''
        M=B[u];
        h=M[3];
        n=#h;
        W=n>0 and {};
        z=A[59](M,W);
        (A[5])(z,__ENV);
        c[H[u]]=z;
        if W then
            for q=1,n do
                z=h[q];
                M=z[2];
                V=z[1];
                if M==0 then
                    Y=cache[V];
                    if not Y then
                        Y={[2]=c,[1]=V};
                        cache[V]=Y;
                    end
                    W[q-1]=Y;
                elseif M==1 then
                    W[q-1]=c[V];
                else
                    W[q-1]=I[V];
                end
            end
        end
    '''
    shape = closures.infer_closure_shape(source)
    assert shape is not None
    assert shape.child_field == "B"
    assert shape.destination_field == "H"
    assert shape.descriptor_field == 3
    assert (shape.mode_key, shape.register_key) == (2, 1)
    assert shape.cache_name == "cache"
    assert (shape.open_table_key, shape.open_index_key) == (2, 1)

    descriptors = OpaqueTable(
        "T{D1=T{D1=D4,D2=D0},D2=T{D1=D7,D2=D1},D3=T{D1=D9,D2=D2}}"
    )
    program = Program({0: _proto(0), 1: _proto(1, descriptors)}, 2)
    ins = Instruction(
        proto=0,
        pc=1,
        e=None,
        opcode=192,
        p=None,
        o=None,
        h=13,
        underscore=None,
        b=ProtoRef(1),
    )
    lifted = closures.lift_closure(source, ins, program)
    assert lifted is not None
    assert "local __cell = cache[4]" in lifted
    assert "__cell = {[2] = R, [1] = 4}" in lifted
    assert "__captures[0] = __cell" in lifted
    assert "__captures[1] = R[7]" in lifted
    assert "__captures[2] = I[9]" in lifted
    assert "R[13] = __closure(1, __captures, __env)" in lifted


def test_infers_randomized_descriptor_keys_and_cell_layout():
    source = '''
        local Q=188;
        e=o[u];
        N=e[4];
        l=#N;
        caps=l>0 and {};
        fn=A[50](e,caps);
        A[11](fn,__ENV);
        c[B[u]]=fn;
        if not caps then else
            for h=1,l,1 do
                if Q~=188 then if Q then return end end
                row=N[h];
                mode=row[1];
                reg=row[3];
                if mode==0 then
                    cell=n[reg];
                    if not cell then
                        cell={[3]=reg,[1]=c};
                        n[reg]=cell;
                    end
                    caps[h-1]=cell;
                else
                    if mode==1 then caps[h-1]=c[reg];
                    else caps[h-1]=I[reg]; end
                end
            end
        end
    '''
    shape = closures.infer_closure_shape(source)
    assert shape is not None
    assert shape.child_field == "o"
    assert shape.destination_field == "B"
    assert shape.descriptor_field == 4
    assert (shape.mode_key, shape.register_key) == (1, 3)
    assert shape.cache_name == "n"
    assert (shape.open_table_key, shape.open_index_key) == (1, 3)


def test_closure_lift_fails_closed_for_missing_or_malformed_child_metadata():
    source = '''
        p=B[u]; d=p[3]; n=#d; caps=n>0 and {};
        fn=A[59](p,caps); A[5](fn,__ENV); c[H[u]]=fn;
        if caps then for i=1,n do row=d[i]; mode=row[2]; reg=row[1];
            if mode==0 then cell=cache[reg]; if not cell then
                cell={[2]=c,[1]=reg}; cache[reg]=cell; end caps[i-1]=cell;
            elseif mode==1 then caps[i-1]=c[reg]; else caps[i-1]=I[reg]; end
        end end
    '''
    ins = Instruction(0, 1, None, 1, None, None, 2, None, ProtoRef(1))
    missing = Program({0: _proto(0)}, 1)
    assert closures.lift_closure(source, ins, missing) is None

    malformed = Program(
        {0: _proto(0), 1: _proto(1, OpaqueTable("T{D2=T{D1=D4,D2=D0}}"))},
        2,
    )
    assert closures.lift_closure(source, ins, malformed) is None

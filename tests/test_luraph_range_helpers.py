from luauvmp import luraph_nested_helper_literals as helpers


def test_infers_table_end_start_argument_order():
    source = '''
        d[27]=(function(M,p,A)
            if d[26]~=d[16] then else d[3]=d[2] or d[14]; end;
            A=A or 1.0;
            p=p or #M;
            if (p-A+1)>7997 then
                return d[25](p,A,M);
            else
                return d[7](M,A,p);
            end;
        end);
    '''
    assert helpers.infer_range_helpers(source) == {27: (0, 2, 1)}


def test_infers_end_table_start_argument_order_with_parenthesized_default():
    source = '''
        G[25]=function(y,p,j)
            if G[1]~=G[24] then j=(j or 1); end;
            y=y or #p;
            if not((y-j+1)>7997) then
                return G[11](p,j,y);
            else
                return G[24](p,y,j);
            end;
        end;
    '''
    assert helpers.infer_range_helpers(source) == {25: (1, 2, 0)}


def test_infers_parenthesized_table_end_start_table_with_numeric_separators():
    source = '''
        (U)[0x1_a]=function(end_value,start_value,table_value)
            start_value=start_value or 0b0_1;
            end_value=(end_value or #table_value);
            if not((end_value-start_value+0x0_1)>0x1_F3D) then
                return U[21](table_value,start_value,end_value);
            else
                return U[25](table_value,end_value,start_value);
            end;
        end;
    '''
    assert helpers.infer_range_helpers(source) == {26: (2, 1, 0)}


def test_ignores_helper_shapes_in_comments_and_strings():
    source = '''
        -- U[26]=function(M,A,p) A=A or 1; p=p or #M;
        --     if (p-A+1)>7997 then return M; end; end;
        local text = [[
            U[27]=function(M,A,p) A=A or 1; p=p or #M;
                if (p-A+1)>7997 then return M; end; end;
        ]]
    '''
    assert helpers.infer_range_helpers(source) == {}


def test_helper_evidence_cannot_bleed_into_the_next_function():
    source = '''
        U[30]=function(M,A,p)
            A=A or 1;
            return M;
        end;
        U[31]=function(M,A,p)
            A=A or 1;
            p=p or #M;
            if (p-A+1)>7997 then return M; end;
        end;
    '''
    assert helpers.infer_range_helpers(source) == {31: (0, 1, 2)}


def test_rewrites_range_calls_using_recovered_argument_roles():
    assert helpers._rewrite_range_calls(
        'R[p[u]]=R[p[u]](A[27](R,t,e+1));',
        {27: (0, 2, 1)},
    ) == 'R[p[u]]=R[p[u]](table.unpack(R,e+1,t));'
    assert helpers._rewrite_range_calls(
        'return A[25](x+o[u]-2,R,x);',
        {25: (1, 2, 0)},
    ) == 'return table.unpack(R,x,x+o[u]-2);'
    assert helpers._rewrite_range_calls(
        '(A)[26](finish,start,R)',
        {26: (2, 1, 0)},
    ) == 'table.unpack(R,start,finish)'


def test_rewrites_proven_top_level_helpers_without_touching_strings():
    source = 'A[13](c[E[u]], c[B[u]]); local s="A[13](x,y)"'
    assert helpers.rewrite_source(
        source, {}, direct_helpers={13: "bit32.bxor"}
    ) == 'bit32.bxor(c[E[u]], c[B[u]]); local s="A[13](x,y)"'


def test_balanced_arguments_are_not_split_inside_nested_calls():
    source = 'A[26](finish,start,R[key(a,b)])'
    assert helpers._rewrite_range_calls(
        source, {26: (2, 1, 0)}
    ) == 'table.unpack(R[key(a,b)],start,finish)'


def test_range_rewrite_ignores_comments_and_string_literals():
    source = (
        'local quoted="A[26](finish,start,R)"; '
        '-- A[26](finish,start,R)\n'
        'return A[26](finish,start,R);'
    )
    expected = (
        'local quoted="A[26](finish,start,R)"; '
        '-- A[26](finish,start,R)\n'
        'return table.unpack(R,start,finish);'
    )
    assert helpers._rewrite_range_calls(
        source, {26: (2, 1, 0)}
    ) == expected


def test_range_rewrite_parses_long_bracket_arguments_lexically():
    source = 'return A[26](finish,start,[=[value, )]=]);'
    assert helpers._rewrite_range_calls(
        source, {26: (2, 1, 0)}
    ) == 'return table.unpack([=[value, )]=],start,finish);'


def test_nested_helper_rewrite_ignores_comments_and_strings():
    source = (
        'local quoted="A[52][E[u]]"; -- A[52][E[u]]\n'
        'return A[52][E[u]];'
    )
    expected = (
        'local quoted="A[52][E[u]]"; -- A[52][E[u]]\n'
        'return __LUAUVMP_HELPER_TABLE(52,{[9]=bit32.rshift})[E[u]];'
    )
    assert helpers.rewrite_source(
        source, {52: {9: 'bit32.rshift'}}
    ) == expected


def test_unrecognized_helper_shape_is_not_rewritten():
    source = 'A[27](R,t,e+1)'
    assert helpers._rewrite_range_calls(source, {}) == source
    assert helpers.infer_range_helpers(
        'd[27]=function(M,p,A) return M[p] end'
    ) == {}


def test_materializes_identical_nested_helpers_as_shared_mutable_state():
    literal = "{[5]=bit32.bxor,[6]=bit32.band}"
    marker = "__LUAUVMP_HELPER_TABLE(52,%s)" % literal
    rewritten, tables = helpers.materialize_helper_tables({
        1: marker + "[E[u]]=c[B[u]]",
        2: "c[o[u]]=(" + marker + "[E[u]])",
    })
    assert tables == [
        ("__VMHELPER_52", literal),
    ]
    assert rewritten == {
        1: "__VMHELPER_52[E[u]]=c[B[u]]",
        2: "c[o[u]]=(__VMHELPER_52[E[u]])",
    }


def test_keeps_equal_helper_table_contents_in_distinct_vm_slots():
    literal = "{[5]=bit32.bxor}"
    rewritten, tables = helpers.materialize_helper_tables({
        1: "__LUAUVMP_HELPER_TABLE(41,%s)[E[u]]" % literal,
        2: "__LUAUVMP_HELPER_TABLE(52,%s)[E[u]]" % literal,
    })
    assert tables == [
        ("__VMHELPER_41", literal),
        ("__VMHELPER_52", literal),
    ]
    assert rewritten == {
        1: "__VMHELPER_41[E[u]]",
        2: "__VMHELPER_52[E[u]]",
    }

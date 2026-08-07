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


def test_balanced_arguments_are_not_split_inside_nested_calls():
    source = 'A[26](finish,start,R[key(a,b)])'
    assert helpers._rewrite_range_calls(
        source, {26: (2, 1, 0)}
    ) == 'table.unpack(R[key(a,b)],start,finish)'


def test_unrecognized_helper_shape_is_not_rewritten():
    source = 'A[27](R,t,e+1)'
    assert helpers._rewrite_range_calls(source, {}) == source
    assert helpers.infer_range_helpers(
        'd[27]=function(M,p,A) return M[p] end'
    ) == {}

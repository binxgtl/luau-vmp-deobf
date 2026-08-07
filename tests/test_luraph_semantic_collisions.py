from luauvmp import luraph_semantic_collisions as collisions
from luauvmp import luraph_semantic_normalize as normalize


def test_renames_raw_scratch_when_another_local_maps_to_upvalues():
    mapping = {"X": "I", "O": "c", "M": "A"}
    result = collisions.canonicalize_source(
        "I=X[R]; R=O; A=M[50]; O[R]=X[R];", mapping
    )
    assert result == "__s_I=I[__s_R]; __s_R=c; __s_A=A[50]; c[__s_R]=I[__s_R];"


def test_raw_register_named_R_is_protected_before_backend_c_to_R_lowering():
    mapping = {"T": "c", "L": "I", "S": "A"}
    result = collisions.canonicalize_source("R=T; T[1]=L[0];", mapping)
    assert result == "__s_R=c; c[1]=I[0];"


def test_mapping_source_is_not_alpha_renamed_before_its_canonical_role():
    mapping = {"R": "X", "S": "c", "i": "B"}
    result = collisions.canonicalize_source("R=i[u]; B=R; S[1]=B;", mapping)
    assert result == "X=B[u]; __s_B=X; c[1]=__s_B;"


def test_empty_reference_mapping_is_byte_for_byte_canonicalizer_compatible():
    source = "R[1]=(I[2]);"
    assert collisions.canonicalize_source(source, {}) == normalize._normal_number("1").join(
        ["R[", "]=(I[2]);"]
    )


def test_collision_mapping_does_not_rewrite_string_contents():
    mapping = {"X": "I", "O": "c"}
    result = collisions.canonicalize_source('I="X O I R"; O[1]=X[2];', mapping)
    assert result == '__s_I="X O I R"; c[1]=I[2];'

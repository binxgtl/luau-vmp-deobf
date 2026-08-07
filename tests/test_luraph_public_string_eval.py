from tools import recover_luraph_dispatch as core
from tools import recover_luraph_dispatch_v147 as public
from luauvmp import luraph_public_string_eval as strings


def test_luau_decimal_escapes_are_decimal_not_python_octal():
    assert strings._decode_luau_quoted(r'"<\105\56"') == '<i8'


def test_luau_unicode_and_z_escapes_preserve_binary_unpack_bytes():
    value = strings._decode_luau_quoted(r'"\u{009}\0\0\0\0\0\0\0"')
    assert len(value) == 8
    assert ord(value[0]) == 9
    assert strings._string_unpack(['<i8', value]) == 9

    spaced = strings._decode_luau_quoted('"\\18\\0\\0\\0\\0\\0\\0\\x00"')
    assert strings._string_unpack(['<i8', spaced]) == 18


def test_public_lexer_normalizes_luau_format_literals_for_existing_parser():
    tokens = public.lex(r'b[52][15]("<\105\56","\2\0\0\0\0\0\0\0")')
    literals = [token.v for token in tokens if token.kind == 'str']
    assert len(literals) == 2
    parser = public.ExprParser(
        tokens[6:7], 0, {}, {},
        opcode_name='R', helper_name='b', nested_helpers={},
    )
    # The exact parser slice is intentionally not executed; the rewritten token
    # text itself must be compatible with its unicode_escape decoding path.
    assert '<i8' in bytes(literals[0][1:-1], 'utf8').decode('unicode_escape')


def test_core_known_function_wrapper_evaluates_unpack_and_keeps_other_helpers():
    fn = core.KnownFunc('string.unpack')
    assert core.apply_known_func(fn, ['>i8', '\x00\x00\x00\x00\x00\x00\x00\x13']) == 19
    assert core.apply_known_func(core.KnownFunc('bit32.bxor'), [5, 3]) == 6

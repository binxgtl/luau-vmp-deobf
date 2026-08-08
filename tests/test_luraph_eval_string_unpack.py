from tools import recover_luraph_dispatch as legacy
from luauvmp import luraph_eval_string_unpack as unpack_eval


def test_evaluates_exact_big_and_little_signed_i8_literals():
    unpack_eval.install()
    fn = legacy.KnownFunc("string.unpack")
    assert legacy.apply_known_func(fn, [">i8", "\x00\x00\x00\x00\x00\x00\x00\x13"]) == 19
    assert legacy.apply_known_func(fn, ["<i8", "\t\x00\x00\x00\x00\x00\x00\x00"]) == 9
    assert legacy.apply_known_func(fn, [">i8", "\xff\xff\xff\xff\xff\xff\xff\xff"]) == -1


def test_string_unpack_evaluator_fails_closed_for_other_formats_and_lengths():
    unpack_eval.install()
    fn = legacy.KnownFunc("string.unpack")
    assert legacy.apply_known_func(fn, [">I8", "\x00" * 8]) is legacy.UNKNOWN
    assert legacy.apply_known_func(fn, [">i8", "\x00" * 7]) is legacy.UNKNOWN
    assert legacy.apply_known_func(fn, [">i8", "\x00" * 8, 1]) is legacy.UNKNOWN

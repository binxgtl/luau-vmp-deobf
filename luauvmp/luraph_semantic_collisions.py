"""Prevent randomized scratch locals from colliding with canonical VM roles.

Canonicalization is a one-pass identifier rename.  If a public factory maps
``X -> I`` (captured upvalues) while the dispatcher already has an unrelated
scratch local literally named ``I``, both names otherwise collapse to ``I``.
The same issue can occur with helper/operand roles and with raw ``R`` after the
source backend maps canonical register ``c`` to its synthetic ``R`` table.

Only proven target collisions are renamed.  Reference/non-public mappings stay
unchanged, strings are still handled by the original canonicalizer, and no
semantic expression is evaluated here.
"""
from __future__ import annotations

from typing import Dict

from . import luraph_semantic_normalize as normalize


_INSTALLED = False
_ORIGINAL = None


def collision_safe_mapping(mapping: Dict[str, str]) -> Dict[str, str]:
    extended = dict(mapping)
    if not mapping:
        return extended

    # A target is collision-prone only when another actual identifier is being
    # renamed into it.  If the target itself is also a mapping key, its raw
    # occurrences are already renamed away and need no synthetic alias.
    targets = {
        target for source, target in mapping.items()
        if source != target
    }
    for target in sorted(targets):
        if target in mapping:
            continue
        if target in {"A", "I", "E", "p", "o", "H", "_", "B", "L", "X", "c", "u"}:
            extended[target] = "__s_" + target

    # The structural backend reserves R for the canonical register table only
    # after semantic canonicalization (c -> R).  Protect an unrelated raw R when
    # a different factory local has been proven to be the register file.
    if any(source != "c" and target == "c" for source, target in mapping.items()):
        if "R" not in mapping:
            extended["R"] = "__s_R"
    return extended


def canonicalize_source(source: str, mapping: Dict[str, str]) -> str:
    if _ORIGINAL is None:
        raise RuntimeError("semantic collision canonicalizer is unavailable")
    return _ORIGINAL(source, collision_safe_mapping(mapping))


def install() -> None:
    global _INSTALLED, _ORIGINAL
    if _INSTALLED:
        return
    _ORIGINAL = normalize.canonicalize_source
    normalize.canonicalize_source = canonicalize_source
    _INSTALLED = True

    # Environment recovery depends on the final collision-safe identifier names.
    # Install it here so existing package wiring remains the single entry point,
    # while later lift wrappers can still compose around its clean-statement hook.
    from .luraph_environment_semantics import install as _install_environment_semantics
    _install_environment_semantics()

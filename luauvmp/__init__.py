"""luau-vmp-deobf - static deobfuscator for Luau VM-protected scripts."""
__version__ = '0.5.2'

from .spec import Spec           # noqa: F401
from .analyse import analyse     # noqa: F401

# Luraph v14.x can execute the root closure before its parser returns. Install
# the early, fail-closed instrumenter for both CLI and direct library use.
from . import luraph_capture as _luraph_capture
from .luraph_early_capture import instrument_vm_source as _instrument_vm_source

_luraph_capture.instrument_vm_source = _instrument_vm_source

# Public v14.7 corpus builds use randomized factory slots and, in one family, a
# single Zstandard stream. Install the known slot-59 path first, then the generic
# structural classifier that requires a matching final constructor for the same
# slot. Both fall back to the legacy slot-50 instrumenter.
from .luraph_public_v147 import install as _install_public_v147
from .luraph_generic_capture import install as _install_generic_capture

_install_public_v147()
_install_generic_capture()

# Some public families invoke the inferred constructor once to run a bootstrap
# closure before reaching the final application constructor. Intercept exactly
# one structurally matching constructor+call before that bootstrap can execute;
# ambiguous sites fail closed and no Roblox capability is introduced.
from .luraph_prebootstrap_capture import install as _install_prebootstrap_capture

_install_prebootstrap_capture()

# The Lune runner is generated through two string-literal layers. Correct the
# capture TSV delimiters before any CLI or library caller builds the runner.
from .luraph_capture_format import install as _install_capture_format

_install_capture_format()

# Unsupported dispatcher fragments are audit data, not standalone Luau
# statements. Quote them so parenthesised calls and partial state fragments can
# never invalidate the generated source file.
from .luraph_fallback_safety import install as _install_fallback_safety

_install_fallback_safety()

# Versions <= 0.4.1 serialised runtimeState[1] (the payload environment) rather
# than the Luraph helper table itself. Install the corrected runner and reject
# empty helper captures before dispatcher recovery.
from .luraph_runtime_fix import install as _install_runtime_fix

_install_runtime_fix()

# Preserve recovered-VM line tables inside the same closed sandbox so ambiguous
# parser errors name their exact source line without widening any capability.
from .luraph_capture_diagnostics import install as _install_capture_diagnostics

_install_capture_diagnostics()

# Some public loaders wrap the parsed root prototype before passing it to the
# intercepted constructor. Resolve it only via a bounded raw-table search;
# zero or ambiguous candidates still fail closed.
from .luraph_capture_root import install as _install_capture_root

_install_capture_root()

# A pre-bootstrap capture may intentionally terminate when the surrounding
# wrapper later calls the disabled closure. Accept only that exact sentinel after
# the typed IR, runtime facts, factory, patched VM and runner are independently
# validated as complete.
from .luraph_capture_completion import install as _install_capture_completion

_install_capture_completion()

# Public v14.7 randomizes the dispatcher register/pc/operand local names. Derive
# those roles from the extracted factory, complete the pure bit/string helper
# map from the recovered VM, and canonicalize semantic text before structural
# lifting while preserving raw_source for audit.
from .luraph_semantic_normalize import install as _install_semantic_normalize
from .luraph_semantic_normalize_fix import install as _install_semantic_normalize_fix
from .luraph_semantic_shape_fix import install as _install_semantic_shape_fix
from .luraph_public_string_eval import install as _install_public_string_eval
from .luraph_integral_literals import install as _install_integral_literals
from .luraph_dispatch_select import install as _install_dispatch_select
from .luraph_selected_dispatch_normalize import install as _install_selected_dispatch_normalize

_install_semantic_normalize()
_install_semantic_normalize_fix()
_install_semantic_shape_fix()
_install_public_string_eval()
_install_integral_literals()
_install_dispatch_select()
_install_selected_dispatch_normalize()

# Public v14.7 also randomizes the physical prototype-table layout. Infer the
# opcode/operand fields from the same factory and remap both capture and semantic
# roles into the canonical typed IR expected by the decompiler. The reference
# layout remains byte-for-byte unchanged.
from .luraph_proto_layout import install as _install_proto_layout
from .luraph_proto_mode import install as _install_proto_mode

_install_proto_layout()
_install_proto_mode()

# Thousands of recovered CFG leaders must not become one recursively nested
# Luau elseif chain. Keep each PC dispatch chunk bounded without changing any
# block body or branch semantics.
from .luraph_decompiler_balance import install as _install_decompiler_balance

_install_decompiler_balance()

# Version 0.5.0 used a no-op setfenv in the staged finaliser, which caused
# environment-wrapper anti-tamper loops. Preserve real rebinding while keeping
# every getfenv lookup inside the closed sandbox.
from .luraph_finalize_compat import install as _install_finalize_compat

_install_finalize_compat()

# The captured ChuoiHub bootstrap contains a finite but extremely hot
# pure-Luau XOR routine. Replace only its exact no-upvalue prototype fingerprint
# with native bit32.bxor; unrelated trees remain untouched.
from .luraph_finalize_bitops import install as _install_finalize_bitops

_install_finalize_bitops()

# Keep the public CLI/API stable while replacing the raw-loader workflow with
# staged-tree detection, sandboxed bootstrap finalisation and exact source
# extraction.
from .luraph_pipeline_v3 import install as _install_pipeline_v3

_install_pipeline_v3()

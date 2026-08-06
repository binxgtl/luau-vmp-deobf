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

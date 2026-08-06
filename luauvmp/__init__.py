"""luau-vmp-deobf - static deobfuscator for Luau VM-protected scripts."""
__version__ = '0.4.1'

from .spec import Spec           # noqa: F401
from .analyse import analyse     # noqa: F401

# Luraph v14.x can execute the root closure before its parser returns. Install
# the early, fail-closed instrumenter for both CLI and direct library use.
from . import luraph_capture as _luraph_capture
from .luraph_early_capture import instrument_vm_source as _instrument_vm_source

_luraph_capture.instrument_vm_source = _instrument_vm_source

# The Lune runner is generated through two string-literal layers. Correct the
# capture TSV delimiters before any CLI or library caller builds the runner.
from .luraph_capture_format import install as _install_capture_format

_install_capture_format()

# Unsupported dispatcher fragments are audit data, not standalone Luau
# statements. Quote them so parenthesised calls and partial state fragments can
# never invalidate the generated source file.
from .luraph_fallback_safety import install as _install_fallback_safety

_install_fallback_safety()

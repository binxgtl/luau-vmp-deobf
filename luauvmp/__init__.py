"""luau-vmp-deobf - static deobfuscator for Luau VM-protected scripts."""
__version__ = '0.3.3'

from .spec import Spec           # noqa: F401
from .analyse import analyse     # noqa: F401

# Luraph v14.x can execute the root closure before its parser returns. Install
# the early, fail-closed instrumenter for both CLI and direct library use.
from . import luraph_capture as _luraph_capture
from .luraph_early_capture import instrument_vm_source as _instrument_vm_source

_luraph_capture.instrument_vm_source = _instrument_vm_source

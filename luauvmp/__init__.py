"""luau-vmp-deobf - static deobfuscator for Luau VM-protected scripts."""
import os as _os

__version__ = '0.5.2'

from .spec import Spec           # noqa: F401
from .analyse import analyse     # noqa: F401

from . import luraph_capture as _luraph_capture
from .luraph_early_capture import instrument_vm_source as _instrument_vm_source

_luraph_capture.instrument_vm_source = _instrument_vm_source

from .luraph_capture_format import install as _install_capture_format
_install_capture_format()

from .luraph_fallback_safety import install as _install_fallback_safety
_install_fallback_safety()

from .luraph_runtime_fix import install as _install_runtime_fix
_install_runtime_fix()

from .luraph_finalize_compat import install as _install_finalize_compat
_install_finalize_compat()

# Private E2E comparison switch. Normal users still receive the currently
# released behaviour; the self-hosted fixture run can execute the exact
# original closure to verify whether replacement changed VM state.
if _os.environ.get("LUAUVMP_E2E_ORIGINAL_BOOTSTRAP") != "1":
    from .luraph_finalize_bitops import install as _install_finalize_bitops
    _install_finalize_bitops()

# Detailed call tracing is useful only for short diagnostic runs and adds
# substantial overhead. Keep it out of the original-closure measurement.
if _os.environ.get("LUAUVMP_E2E_ORIGINAL_BOOTSTRAP") != "1":
    from .luraph_finalize_calltrace import install as _install_finalize_calltrace
    _install_finalize_calltrace()

from .luraph_pipeline_v3 import install as _install_pipeline_v3
_install_pipeline_v3()

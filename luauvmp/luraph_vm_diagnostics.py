"""Privacy-safe structural diagnostics for recovered Luraph VM source.

The diagnostic path never executes the VM and never emits source snippets.  It
reports only hashes, sizes, structural signal counts, candidate numeric slots,
and the current extractor/instrumenter result so unsupported VM families can be
triaged without publishing the recovered interpreter.
"""
from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Union

from . import __version__, luraph_capture
from . import luraph_generic_capture as generic
from . import luraph_public_v147 as public
from .luraph_corpus import fingerprint_vm


def _integer_slots(matches, group: str = "slot") -> List[int]:
    values = set()
    for match in matches:
        value = public._integer(match.group(group))
        if value is not None:
            values.add(value)
    return sorted(values)


def _error(exc: BaseException) -> str:
    return "%s: %s" % (type(exc).__name__, exc)


def diagnose_vm_source(source: Union[str, bytes]) -> Dict[str, Any]:
    """Return a JSON-serialisable structural report without executing source."""
    if isinstance(source, bytes):
        raw = source
        text = source.decode("utf-8", "surrogateescape")
    else:
        text = source
        raw = source.encode("utf-8", "surrogateescape")

    vm_sha256, structural_sha256 = fingerprint_vm(raw)
    factory_assignments = list(generic._FACTORY_ASSIGN.finditer(text))
    final_sites = list(generic._final_sites(text))
    dispatcher_loops = list(public._DISPATCH_LOCAL.finditer(text))

    factory_slots = _integer_slots(factory_assignments)
    final_slots = sorted({slot for slot, _match, _style in final_sites})
    matching_slots = sorted(set(factory_slots).intersection(final_slots))

    factory_extractable = False
    factory_size = 0
    factory_sha256 = ""
    factory_error = ""
    try:
        factory = luraph_capture.extract_interpreter_factory(text)
        factory_raw = factory.encode("utf-8", "surrogateescape")
        factory_extractable = True
        factory_size = len(factory_raw)
        factory_sha256 = sha256(factory_raw).hexdigest()
    except Exception as exc:  # diagnostics must describe the failure, not hide it
        factory_error = _error(exc)

    capture_instrumentable = False
    instrument_error = ""
    capture_callback_delta = 0
    try:
        patched = luraph_capture.instrument_vm_source(text)
        capture_instrumentable = True
        capture_callback_delta = (
            patched.count("__LUAUVMP_CAPTURE") - text.count("__LUAUVMP_CAPTURE")
        )
    except Exception as exc:  # see comment above; no source text is included
        instrument_error = _error(exc)

    return {
        "format_version": 1,
        "tool_version": __version__,
        "privacy": "no-source-snippets",
        "vm_size": len(raw),
        "vm_lines": text.count("\n") + (1 if text else 0),
        "vm_sha256": vm_sha256,
        "vm_structural_sha256": structural_sha256,
        "signals": {
            "factory_assignment_count": len(factory_assignments),
            "factory_slots": factory_slots,
            "final_constructor_count": len(final_sites),
            "final_constructor_slots": final_slots,
            "matching_factory_final_slots": matching_slots,
            "dispatcher_loop_count": len(dispatcher_loops),
            "while_true_count": text.count("while true do"),
        },
        "factory": {
            "extractable": factory_extractable,
            "size": factory_size,
            "sha256": factory_sha256,
            "error": factory_error,
        },
        "capture": {
            "instrumentable": capture_instrumentable,
            "capture_callback_delta": capture_callback_delta,
            "error": instrument_error,
        },
    }


def diagnose_file(path: Union[str, Path]) -> Dict[str, Any]:
    return diagnose_vm_source(Path(path).read_bytes())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="luauvmp-vm-diagnose",
        description=(
            "Generate privacy-safe structural diagnostics for a recovered "
            "Luraph VM without executing it"
        ),
    )
    parser.add_argument("input", help="recovered stage1.vm.lua / interpreter VM source")
    parser.add_argument("-o", "--output", help="write JSON report to this path")
    args = parser.parse_args(argv)

    report = diagnose_file(args.input)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print("wrote %s" % output)
    else:
        print(rendered, end="")
    return 0 if report["factory"]["extractable"] and report["capture"]["instrumentable"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

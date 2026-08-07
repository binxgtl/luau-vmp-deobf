import json

import pytest

from luauvmp import luraph_capture
from luauvmp import luraph_selected_dispatch_normalize as selected


def test_selected_dispatch_locals_extend_canonical_mapping():
    data = {
        "0": {
            "source": "if d < 5 then k += 1 end",
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        },
        "1": {
            "source": "return d, k",
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        },
    }
    mapping = selected._selected_mapping(data, {"B": "L"})
    assert mapping["d"] == "X"
    assert mapping["k"] == "u"
    assert mapping["B"] == "L"


def test_selected_dispatch_metadata_must_be_consistent():
    data = {
        "0": {"dispatch_opcode_name": "d", "dispatch_pc_name": "k"},
        "1": {"dispatch_opcode_name": "q", "dispatch_pc_name": "k"},
    }
    with pytest.raises(luraph_capture.CaptureError):
        selected._selected_mapping(data, {})


def test_selected_dispatch_mapping_rejects_role_conflicts():
    data = {
        "0": {"dispatch_opcode_name": "d", "dispatch_pc_name": "k"},
    }
    with pytest.raises(luraph_capture.CaptureError):
        selected._selected_mapping(data, {"d": "p"})


def test_rewrite_uses_selected_dispatch_names_and_keeps_raw_source(tmp_path):
    output = tmp_path / "semantics.json"
    text = tmp_path / "semantics.txt"
    output.write_text(json.dumps({
        "7": {
            "source": "if d < 5 then k += 1 end",
            "unknown_ifs": 1,
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        }
    }), encoding="utf-8")

    selected._rewrite_semantics(output, text, {})
    data = json.loads(output.read_text(encoding="utf-8"))
    entry = data["7"]
    assert entry["raw_source"] == "if d < 5 then k += 1 end"
    assert entry["source"] == "if X < 5 then u += 1 end"
    assert entry["canonicalized"] is True

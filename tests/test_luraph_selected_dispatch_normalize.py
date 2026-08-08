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


def test_selected_dispatch_infers_its_own_register_file():
    data = {
        "0": {
            "source": "T[b[k]] = T[e[k]] + T[I[k]]",
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        },
        "1": {
            "source": "T[l[k]] = T[b[k]]",
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        },
    }
    mapping = {
        "b": "p", "e": "H", "I": "_", "l": "B",
        "S": "A", "L": "I", "V": "c",
    }
    effective = selected._selected_mapping(data, mapping)
    assert effective["d"] == "X"
    assert effective["k"] == "u"
    assert effective["T"] == "c"
    # The selected mode owns the register role. Keeping the old small-mode V->c
    # mapping would collapse two different locals into the same canonical name.
    assert "V" not in effective


def test_selected_dispatch_replaces_stale_opcode_and_pc_roles():
    data = {
        "0": {
            "source": "if U < 5 then y += 1 end",
            "dispatch_opcode_name": "U",
            "dispatch_pc_name": "y",
        }
    }
    effective = selected._selected_mapping(
        data,
        {"w": "X", "S": "u", "O": "c", "f": "L", "M": "A"},
    )
    assert effective["U"] == "X"
    assert effective["y"] == "u"
    assert "w" not in effective
    assert "S" not in effective
    assert "O" not in effective
    assert effective["f"] == "L"
    assert effective["M"] == "A"


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
            "source": "T[b[k]] = T[e[k]]",
            "unknown_ifs": 1,
            "dispatch_opcode_name": "d",
            "dispatch_pc_name": "k",
        }
    }), encoding="utf-8")

    selected._rewrite_semantics(output, text, {"b": "p", "e": "H"})
    data = json.loads(output.read_text(encoding="utf-8"))
    entry = data["7"]
    assert entry["raw_source"] == "T[b[k]] = T[e[k]]"
    assert entry["source"] == "c[p[u]] = c[H[u]]"
    assert entry["canonicalized"] is True

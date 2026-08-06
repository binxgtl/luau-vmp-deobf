from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from luauvmp.luraph_corpus import (
    CorpusRecord, build_manifest, fingerprint_vm, normalise_vm_source,
)


def test_structural_fingerprint_alpha_renames_locals():
    a = b'local alpha=1; local beta=alpha+2; return beta'
    b = b'local x=77; local y=x+99; return y'
    assert normalise_vm_source(a) == normalise_vm_source(b)
    assert fingerprint_vm(a)[0] != fingerprint_vm(b)[0]
    assert fingerprint_vm(a)[1] == fingerprint_vm(b)[1]


def test_manifest_groups_structural_vm_families():
    rows = [
        CorpusRecord('a.lua', 'ok', 10, 20, 30, 'raw-a', 'family-1'),
        CorpusRecord('b.lua', 'ok', 11, 21, 31, 'raw-b', 'family-1'),
        CorpusRecord('c.lua', 'unpack_error', 12, error='bad'),
    ]
    manifest = build_manifest(rows)
    assert manifest['samples'] == 3
    assert manifest['ok'] == 2
    assert manifest['failed'] == 1
    assert manifest['vm_families'] == 1
    assert manifest['families']['family-1'] == ['a.lua', 'b.lua']

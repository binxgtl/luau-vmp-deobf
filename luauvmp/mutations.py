"""Recover the VM's self-modifying instruction rules.

Certain handlers begin with `if <C field> == n then` and, on the taken branch,
rewind the pc by one and overwrite the current slot with a *different* opcode
whose A/B operands are XOR-masked.  The instruction then re-dispatches, so
several real Luau operations only ever appear through this rewrite.

The walk is path-sensitive: a guard only applies inside the branch it protects,
and it never leaves the handler it started in.
"""
import re

from .deflatten import successors


def extract(lin, ranges, roles, fields, stop):
    """Returns {"op,Cvalue": [new_op, xor_A, xor_B]}."""
    insn, code, pc = roles.get('INSN'), roles.get('CODE'), roles.get('PC')
    if not (insn and code and pc):
        return {}
    slot2 = {v: k for k, v in fields.items()}
    cslot = fields.get('C')
    guard_re = re.compile(r"^\s*if\s*\(?\s*" + re.escape(insn) +
                          r"\[(\d+)\]\s*==\s*(\d+)\s*\)?\s*then\s*$")
    goto_re = re.compile(r"^" + re.escape(lin.state) + r"\s*=\s*(-?\d+)(?:\s*continue)?$")
    rewrite_re = re.compile(
        r"\{\s*\[(-?\d+)\]\s*=\s*(\d+)\s*,"
        r"\s*\[(-?\d+)\]\s*=\s*\w+\(\s*" + re.escape(insn) + r"\[(\d+)\]\s*,\s*(\d+)\s*\)\s*,"
        r"\s*\[(-?\d+)\]\s*=\s*\w+\(\s*" + re.escape(insn) + r"\[(\d+)\]\s*,\s*(\d+)\s*\)")

    from .analyse import parse_lines

    rules = {}

    def record(ops, guard, m):
        xa = xb = 0
        for slot, mask in ((int(m.group(4)), int(m.group(5))),
                           (int(m.group(7)), int(m.group(8)))):
            if slot2.get(slot) == 'A':
                xa = mask
            elif slot2.get(slot) == 'B':
                xb = mask
        for op in ops:
            rules['%d,%d' % (op, guard)] = [int(m.group(2)), xa, xb]

    def walk_nodes(nodes, ops, guard, seen, depth):
        if depth > 30:
            return
        for node in nodes:
            if node[0] == 'if':
                g = guard_re.match(node[1])
                inner = guard
                if g and cslot is not None and int(g.group(1)) == cslot:
                    inner = int(g.group(2))
                walk_nodes(node[2], ops, inner, seen, depth + 1)
                walk_nodes(node[3], ops, guard, seen, depth + 1)
                continue
            txt = node[1].strip()
            m = rewrite_re.search(txt)
            if m and guard is not None:
                record(ops, guard, m)
            g = goto_re.match(txt)
            if g:
                walk_state(int(g.group(1)), ops, guard, seen, depth + 1)
            else:
                for s in successors([txt], lin.state):
                    walk_state(s, ops, guard, seen, depth + 1)

    def walk_state(state, ops, guard, seen, depth):
        key = (state, guard)
        if state in stop or state not in lin.blocks or key in seen or depth > 30:
            return
        walk_nodes(parse_lines(lin.blocks[state]), ops, guard, seen | {key}, depth)

    for lo, hi, entry in ranges:
        walk_state(entry, range(lo, hi + 1), None, frozenset(), 0)
    return rules
